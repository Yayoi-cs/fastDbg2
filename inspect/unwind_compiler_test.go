package inspect

import (
	"context"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"fastdbg2/target"
)

func TestUnwindCompilerCFIOmitFramePointer(t *testing.T) {
	const source = `volatile unsigned long result;
__attribute__((noinline)) unsigned long leaf(unsigned long value) { volatile unsigned long local[8]; local[value & 7] = value; return local[value & 7] + 1; }
__attribute__((noinline)) unsigned long middle(unsigned long value) { return leaf(value) + leaf(value + 1); }
int main(void) { result = middle(5); return (int)result; }
`
	for _, compiler := range []string{"gcc", "clang"} {
		t.Run(compiler, func(t *testing.T) {
			tool, err := exec.LookPath(compiler)
			if err != nil {
				t.Skipf("%s unavailable: %v", compiler, err)
			}
			for _, mode := range []struct {
				name string
				flag string
			}{{"exec", "-no-pie"}, {"pie", "-pie"}, {"static_pie", "-static-pie"}} {
				t.Run(mode.name, func(t *testing.T) {
					dir := t.TempDir()
					input, output := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
					if err := os.WriteFile(input, []byte(source), 0600); err != nil {
						t.Fatal(err)
					}
					command := exec.Command(tool, "-O2", "-g", "-fomit-frame-pointer", "-fno-optimize-sibling-calls", "-fasynchronous-unwind-tables", mode.flag, "-o", output, input)
					if data, err := command.CombinedOutput(); err != nil {
						t.Fatalf("compiler: %v: %s", err, data)
					}
					file, err := elf.Open(output)
					if err != nil {
						t.Fatal(err)
					}
					defer file.Close()
					section := file.Section(".eh_frame")
					if section == nil {
						t.Fatal("missing .eh_frame")
					}
					data, err := section.Data()
					if err != nil {
						t.Fatal(err)
					}
					index, err := ParseCFISection(context.Background(), CFISection{Kind: CFIEHFrame, Address: target.Address(section.Addr), Data: data, Source: "fixture"}, nil)
					if err != nil {
						t.Fatal(err)
					}
					symbols, err := file.Symbols()
					if err != nil {
						t.Fatal(err)
					}
					found := make(map[string]bool)
					for _, symbol := range symbols {
						if symbol.Name != "main" && symbol.Name != "middle" && symbol.Name != "leaf" {
							continue
						}
						if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Size == 0 {
							t.Fatalf("invalid fixture function %+v", symbol)
						}
						found[symbol.Name] = true
						for pc := symbol.Value; pc < symbol.Value+symbol.Size; pc++ {
							frame, err := index.Lookup(target.Address(pc))
							if err != nil {
								t.Fatalf("%s PC %#x: %v", symbol.Name, pc, err)
							}
							row, err := evaluateCFIRow(context.Background(), frame, target.Address(pc), &unwindBudget{operations: 100000})
							if err != nil || !row.cfa.defined || row.rules[16].kind != unwindOffset {
								t.Fatalf("%s PC %#x row=%+v err=%v", symbol.Name, pc, row, err)
							}
						}
					}
					if len(found) != 3 {
						t.Fatalf("functions=%v", found)
					}
				})
			}
		})
	}
}

func TestUnwindCFISharedConcurrentEvaluation(t *testing.T) {
	frame := unwindTestFrame(0x1000, 0x83, 2, 0x44, 0xc3, 0x0e, 16)
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 100; i++ {
				pc := target.Address(0x1000 + i%8)
				row, err := evaluateCFIRow(context.Background(), frame, pc, &unwindBudget{operations: 1000, profile: UnwindSysVAMD64})
				if err != nil {
					t.Error(err)
					return
				}
				want := unwindOffset
				if pc >= 0x1004 {
					want = unwindSame
				}
				if row.rules[3].kind != want {
					t.Errorf("PC %#x leaked another row: %+v", pc, row)
					return
				}
			}
		}()
	}
	group.Wait()
}

func TestUnwindGoDebugFrameStrictRegisterProvenance(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "main.go"), filepath.Join(dir, "fixture")
	source := "package main\nvar Value uint64\nfunc leaf(value uint64) uint64 { Value = value; return value + 1 }\nfunc middle(value uint64) uint64 { return leaf(value) + 1 }\nfunc main() { Value = middle(7) }\n"
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-gcflags=-l", "-o", output, input)
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Go compiler: %v: %s", err, data)
	}
	file, err := elf.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	section := file.Section(".debug_frame")
	if section == nil {
		t.Fatal("missing Go .debug_frame")
	}
	data, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	index, err := ParseCFISection(context.Background(), CFISection{Kind: CFIDebugFrame, Address: target.Address(section.Addr), Data: data, Source: "go-fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	var leaf, middle uint64
	for _, symbol := range symbols {
		switch symbol.Name {
		case "main.leaf":
			leaf = symbol.Value
		case "main.middle":
			middle = symbol.Value
		}
	}
	if leaf == 0 || middle == 0 {
		t.Fatal("missing fixture functions")
	}
	request := AMD64UnwindRequest{Registers: unwindTestRegisters(leaf, 0x8000), PC: target.Address(leaf), Find: func(ctx context.Context, pc target.Address) (*CFIFrame, error) { return index.Lookup(pc) }, Read: unwindTestMemory(map[target.Address]uint64{0x8000: middle + 1}), MaxFrames: 8}
	result, err := UnwindAMD64(context.Background(), request)
	if !errors.Is(err, target.ErrUnavailable) || len(result.Frames) != 2 || result.Complete {
		t.Fatalf("strict Go CFI result=%+v error=%v", result, err)
	}
	for _, register := range []uint64{3, 7, 12, 13, 14, 15} {
		if result.Frames[1].Registers.Known&(1<<register) != 0 || result.Frames[0].Saved[register].Available || result.Frames[0].Saved[register].Provenance != "unavailable" {
			t.Fatalf("Go caller register %d was invented: %+v", register, result)
		}
	}
	if result.Frames[1].PC != target.Address(middle+1) || result.Frames[0].Saved[16].Provenance != "cfi" {
		t.Fatalf("Go explicit return address lost: %+v", result)
	}
}
