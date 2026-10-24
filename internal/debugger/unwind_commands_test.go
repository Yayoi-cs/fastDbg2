package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestUnwindCommandNumbers(t *testing.T) {
	for _, test := range []struct {
		input                 string
		fallback, min, max, n int
	}{
		{"", 32, 1, 256, 32}, {" 1 ", 32, 1, 256, 1}, {"256", 32, 1, 256, 256},
		{"", 0, 0, 255, 0}, {"0", 0, 0, 255, 0}, {"255", 0, 0, 255, 255},
	} {
		value, err := unwindCommandNumber(test.input, test.fallback, test.min, test.max, "test")
		if value != test.n || err != nil {
			t.Fatalf("%q: value=%d error=%v", test.input, value, err)
		}
	}
	for _, input := range []string{"-1", "+1", "1 2", "0x10", "257", "4294967296", "1\x00"} {
		if _, err := unwindCommandNumber(input, 32, 1, 256, "backtrace"); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
	if _, err := unwindCommandNumber("0", 32, 1, 256, "backtrace"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("zero backtrace count: %v", err)
	}
}

func TestUnwindCommandABIProfilesAreExplicit(t *testing.T) {
	for _, test := range []struct {
		input   string
		profile inspect.AMD64UnwindProfile
		count   int
	}{
		{"", inspect.UnwindSysVAMD64, 32},
		{"2", inspect.UnwindSysVAMD64, 2},
		{"--abi strict", inspect.UnwindStrictCFI, 32},
		{"--abi sysv", inspect.UnwindSysVAMD64, 32},
		{"--abi sysv 256", inspect.UnwindSysVAMD64, 256},
	} {
		profile, count, err := unwindCommandArguments(test.input, 32, 1, 256, "backtrace")
		if err != nil || profile != test.profile || count != test.count {
			t.Fatalf("%q: profile=%d count=%d error=%v", test.input, profile, count, err)
		}
	}
	for _, input := range []string{"--abi", "--abi windows", "--abi SYSV", "--abi sysv --abi strict", "2 --abi sysv", "--abi sysv 0", "--abi strict -1"} {
		controller, fixture, output := newInspectionTestController()
		if err := controller.showBacktrace(context.Background(), input); !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || output.Len() != 0 {
			t.Fatalf("invalid ABI %q: error=%v reads=%d output=%q", input, err, fixture.snapshotReads, output.String())
		}
	}
}

func TestUnwindSeedUsesCurrentLocationAndUnmodifiedRawRegisters(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	oldPC := target.Address(0xdeadbeef)
	fixture.snapshot.Threads[0].Stop.RawPC = &oldPC
	seed, err := controller.readUnwindSeed(context.Background())
	if err != nil || seed.location.InstructionPC != 0x401000 || seed.location.RawPC != 0x401001 || seed.registers.Values[16] != 0x401001 ||
		fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != fixture.snapshot.Threads[0].Token ||
		len(fixture.locationTokens) != 1 || fixture.locationTokens[0] != fixture.snapshot.Threads[0].Token || output.Len() != 0 ||
		len(fixture.stackCalls) != 0 || len(fixture.codeCalls) != 0 {
		t.Fatalf("seed=%+v error=%v fixture=%+v", seed, err, fixture)
	}
}

func TestUnwindSeedFailsClosedOnStaleLocation(t *testing.T) {
	for _, issue := range []string{"raw-mismatch", "breakpoint-mismatch", "unproved-adjustment", "register-stale", "location-stale", "duplicate-rip"} {
		t.Run(issue, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			switch issue {
			case "raw-mismatch":
				fixture.location.RawPC++
			case "breakpoint-mismatch":
				point := *fixture.location.Breakpoint + 1
				fixture.location.Breakpoint = &point
			case "unproved-adjustment":
				fixture.location.Breakpoint = nil
			case "register-stale":
				fixture.registerErr = target.ErrStale
			case "location-stale":
				fixture.locationErr = target.ErrStale
			case "duplicate-rip":
				fixture.registers = append(fixture.registers, contextTestRegister("rip", 0x401001))
			}
			_, err := controller.readUnwindSeed(context.Background())
			if err == nil || output.Len() != 0 || len(fixture.stackCalls) != 0 || len(fixture.codeCalls) != 0 || len(fixture.registerTokens) > 1 || len(fixture.locationTokens) > 1 {
				t.Fatalf("invalid seed used: error=%v output=%q fixture=%+v", err, output.String(), fixture)
			}
		})
	}
}

func TestUnwindSeedCancellationAndSelection(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.onReadRegisters = cancel
	if _, err := controller.readUnwindSeed(ctx); !errors.Is(err, context.Canceled) || len(fixture.locationTokens) != 0 || output.Len() != 0 {
		t.Fatalf("canceled read continued: error=%v fixture=%+v", err, fixture)
	}
	controller, fixture, output = newInspectionTestController()
	controller.selected.ID++
	if _, err := controller.readUnwindSeed(context.Background()); !errors.Is(err, target.ErrNotFound) || len(fixture.registerTokens) != 0 || output.Len() != 0 {
		t.Fatalf("guessed selected thread: error=%v fixture=%+v", err, fixture)
	}
}

func TestUnwindCommandInvalidArgumentsDoNotInspectTarget(t *testing.T) {
	for _, command := range []struct {
		name string
		run  func(*Controller, context.Context, string) error
	}{
		{"backtrace", (*Controller).showBacktrace}, {"stackframe", (*Controller).showStackFrame},
	} {
		for _, input := range []string{"-1", "+1", "1 2", "256 0", "0x10", "4294967296"} {
			controller, fixture, output := newInspectionTestController()
			if err := command.run(controller, context.Background(), input); !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || output.Len() != 0 {
				t.Fatalf("%s %q: error=%v reads=%d output=%q", command.name, input, err, fixture.snapshotReads, output.String())
			}
		}
	}
}

func TestUnwindPrefixDiscardPolicy(t *testing.T) {
	prefix := inspect.UnwindResult{Frames: []inspect.UnwindFrame{{PC: 0x401000}}}
	for _, test := range []struct {
		name     string
		walk     error
		proof    error
		retained bool
	}{
		{"success", nil, nil, true},
		{"missing-cfi", target.ErrUnavailable, nil, true},
		{"partial-read", &target.PartialError{Completed: 4, Total: 8, Err: io.ErrUnexpectedEOF}, nil, true},
		{"stale", target.ErrStale, nil, false},
		{"cancel", context.Canceled, nil, false},
		{"deadline", context.DeadlineExceeded, nil, false},
		{"identity-stale", nil, target.ErrStale, false},
		{"identity-unavailable", nil, target.ErrUnavailable, false},
		{"identity-os-error", target.ErrUnavailable, io.EOF, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := unwindConfirmedResult(prefix, test.walk, test.proof)
			if (len(result.Frames) != 0) != test.retained || test.walk != nil && !errors.Is(err, test.walk) ||
				test.proof != nil && !errors.Is(err, test.proof) || test.walk == nil && test.proof == nil && err != nil {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
}

func TestStackFrameSuppressesOnlyItsExactSuccessfulLimit(t *testing.T) {
	result := inspect.UnwindResult{Frames: []inspect.UnwindFrame{{}}, Limited: true}
	limit := &inspect.UnwindLimitError{Limit: 1}
	if err := stackFrameUnwindError(result, 0, limit); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{target.ErrPartial, &target.PartialError{Completed: 4, Total: 8, Err: io.ErrUnexpectedEOF}, errors.Join(limit, io.EOF), fmt.Errorf("wrapped: %w", limit), &inspect.UnwindLimitError{Limit: 2}} {
		if got := stackFrameUnwindError(result, 0, err); got != err {
			t.Fatalf("suppressed nonmatching error %v", err)
		}
	}
	if got := stackFrameUnwindError(result, 1, limit); got != limit {
		t.Fatalf("suppressed unavailable frame limit: %v", got)
	}
	result.Limited = false
	if got := stackFrameUnwindError(result, 0, limit); got != limit {
		t.Fatalf("suppressed unconfirmed limit: %v", got)
	}
}

func unwindCommandTestIndex(t *testing.T, ranges ...[3]uint64) *inspect.CFIIndex {
	t.Helper()
	var data []byte
	appendRecord := func(body []byte) {
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(len(body)))
		data = append(data, size[:]...)
		data = append(data, body...)
	}
	appendRecord([]byte{0xff, 0xff, 0xff, 0xff, 4, 0, 8, 0, 1, 0x78, 16, 0x0c, 7, 8, 0x90, 1})
	for _, definition := range ranges {
		body := make([]byte, 20)
		binary.LittleEndian.PutUint64(body[4:], definition[0])
		binary.LittleEndian.PutUint64(body[12:], definition[1])
		if definition[2] != 0 {
			body = append(body, 0x07, 16)
		}
		appendRecord(body)
	}
	index, err := inspect.ParseCFISection(context.Background(), inspect.CFISection{Kind: inspect.CFIDebugFrame, Data: data, Source: "test-cfi\x1b[31m\n"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func unwindCommandTestModule() *runtimeELFModule {
	return &runtimeELFModule{ID: "main", Name: "/fixture", Proof: "runtime-test", Programs: []elf.ProgHeader{{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: 0x401000, Memsz: 0x2000}}}
}

func TestUnwindFinderUsesExactRuntimeModuleAndFDEExtent(t *testing.T) {
	module := unwindCommandTestModule()
	index := unwindCommandTestIndex(t, [3]uint64{0x401000, 0x20, 0})
	finder := unwindCFIFinder{view: &runtimeELFView{Modules: []*runtimeELFModule{module}}, cache: map[*runtimeELFModule]unwindCFICache{module: {index: index}}}
	if frame, err := finder.find(context.Background(), 0x401001); err != nil || frame == nil {
		t.Fatalf("exact FDE: frame=%v error=%v", frame, err)
	}
	if _, err := finder.find(context.Background(), 0x401020); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("used predecessor FDE beyond range: %v", err)
	}
	if _, err := finder.find(context.Background(), 0x400fff); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("guessed executable module: %v", err)
	}
	finder.view.Modules = append(finder.view.Modules, unwindCommandTestModule())
	if _, err := finder.find(context.Background(), 0x401001); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("selected first overlapping module: %v", err)
	}
	finder.view.Modules = finder.view.Modules[:1]
	finder.cache[module] = unwindCFICache{index: unwindCommandTestIndex(t, [3]uint64{0x401000, 0x2001, 0})}
	if _, err := finder.find(context.Background(), 0x401001); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("accepted FDE crossing module extent: %v", err)
	}
}

func TestUnwindModuleBounds(t *testing.T) {
	module := unwindCommandTestModule()
	if yes, err := unwindModuleContains(module, 0x401000, 0x2000, true); err != nil || !yes {
		t.Fatalf("full span: %t %v", yes, err)
	}
	if yes, err := unwindModuleContains(module, 0x401000, 0x2001, true); err != nil || yes {
		t.Fatalf("overrun span: %t %v", yes, err)
	}
	module.Programs[0].Flags = elf.PF_R
	if yes, err := unwindModuleContains(module, 0x401000, 1, true); err != nil || yes {
		t.Fatalf("inferred code from read permission: %t %v", yes, err)
	}
	module.LoadBias = math.MaxUint64
	if _, err := unwindModuleContains(module, 0x401000, 1, false); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("module range overflow: %v", err)
	}
}

func TestUnwindFileMetadataHasATotalCommandBudget(t *testing.T) {
	var finder unwindCFIFinder
	for range 2 {
		if err := finder.reserveFileMetadata(maxUnwindSectionBytes); err != nil {
			t.Fatal(err)
		}
	}
	if err := finder.reserveFileMetadata(1); !errors.Is(err, target.ErrOverflow) || finder.fileBytes != maxUnwindFileBytes {
		t.Fatalf("file metadata budget: bytes=%d error=%v", finder.fileBytes, err)
	}
	if err := finder.reserveFileMetadata(math.MaxUint64); !errors.Is(err, target.ErrOverflow) || finder.fileBytes != maxUnwindFileBytes {
		t.Fatalf("file metadata budget wrapped: bytes=%d error=%v", finder.fileBytes, err)
	}
}

func TestUnwindMetadataReaderCannotEscapeOwningModule(t *testing.T) {
	module := unwindCommandTestModule()
	var calls []target.Address
	memory, err := newRuntimeELFMemory(context.Background(), []procMap{{Start: 0x401000, End: 0x800000, Read: true}}, func(address target.Address, data []byte) (int, error) {
		calls = append(calls, address)
		clear(data)
		return len(data), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer memory.close()
	finder := unwindCFIFinder{view: &runtimeELFView{Modules: []*runtimeELFModule{module}, Memory: memory}}
	read := finder.metadataReader(module)
	var data [8]byte
	if n, err := read(context.Background(), 0x401000, data[:]); err != nil || n != 8 || len(calls) != 1 {
		t.Fatalf("owned metadata: n=%d error=%v calls=%v", n, err, calls)
	}
	for _, address := range []target.Address{0x700000, 0x402ffc} {
		if n, err := read(context.Background(), address, data[:]); !errors.Is(err, target.ErrUnavailable) || n != 0 || len(calls) != 1 {
			t.Fatalf("metadata escaped module at %#x: n=%d error=%v calls=%v", address, n, err, calls)
		}
	}
	if n, err := memory.Read(context.Background(), 0x700000, data[:]); err != nil || n != 8 || len(calls) != 2 {
		t.Fatalf("broad stack reader was incorrectly restricted: n=%d error=%v calls=%v", n, err, calls)
	}
	module.Programs[0].Flags = elf.PF_X
	if n, err := read(context.Background(), 0x401000, data[:]); !errors.Is(err, target.ErrUnavailable) || n != 0 || len(calls) != 2 {
		t.Fatalf("unreadable ELF segment accepted: n=%d error=%v calls=%v", n, err, calls)
	}
}

func TestUnwindBridgeFrameFactsAndReturnPCConvention(t *testing.T) {
	module := unwindCommandTestModule()
	index := unwindCommandTestIndex(t, [3]uint64{0x401000, 0x20, 0}, [3]uint64{0x402000, 0x20, 1})
	finder := unwindCFIFinder{view: &runtimeELFView{Modules: []*runtimeELFModule{module}}, cache: map[*runtimeELFModule]unwindCFICache{module: {index: index}}}
	registers := inspect.AMD64UnwindRegisters{Known: 1<<7 | 1<<16}
	registers.Values[7], registers.Values[16] = 0x700000, 0x401001
	var reads []target.Address
	result, err := inspect.UnwindAMD64(context.Background(), inspect.AMD64UnwindRequest{
		Registers: registers, PC: 0x401000, MaxFrames: 32, Find: finder.find, Profile: inspect.UnwindSysVAMD64,
		Read: func(_ context.Context, address target.Address, data []byte) (int, error) {
			reads = append(reads, address)
			if address != 0x700000 || len(data) != 8 {
				t.Fatalf("guessed stack read: %#x size=%d", address, len(data))
			}
			binary.LittleEndian.PutUint64(data, 0x402008)
			return len(data), nil
		},
	})
	if err != nil || !result.Complete || len(result.Frames) != 2 || len(reads) != 1 ||
		result.Frames[0].PC != 0x401000 || result.Frames[0].RawPC != 0x401001 || result.Frames[0].LookupPC != 0x401000 ||
		result.Frames[1].PC != 0x402008 || result.Frames[1].LookupPC != 0x402007 || !result.Frames[1].ReturnPC {
		t.Fatalf("result=%+v error=%v reads=%v", result, err, reads)
	}
	controller, _, _ := newInspectionTestController()
	seed := unwindCommandSeed{thread: target.ThreadInfo{Ref: target.ThreadRef{ID: 7}, TID: 1234}, profile: inspect.UnwindSysVAMD64}
	seed.location.RawPC = result.Frames[0].RawPC
	seed.location.InstructionPC = result.Frames[0].PC
	seed.location.Breakpoint = &result.Frames[0].PC
	text := controller.backtraceText(seed, result)
	for _, want := range []string{"[trace]", "Thread 7 (tid 1234)", "[*#0] 0x0000000000401000", "[ #1] 0x0000000000402008"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %q", want, text)
		}
	}
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\n\"") {
		t.Fatalf("unsafe metadata: %q", text)
	}
	frameText := controller.stackFrameText(seed, result.Frames[0], 0)
	for _, want := range []string{"[stackframe #0]", "CFA: 0x0000000000700008 ($rsp +8)", "0x0000000000700000", "0x0000000000402008", "$rax     unavailable"} {
		if !strings.Contains(frameText, want) {
			t.Fatalf("missing %q: %q", want, frameText)
		}
	}
}

func TestUnwindTextDoesNotInventUnknownCFAOrBottom(t *testing.T) {
	controller, _, _ := newInspectionTestController()
	result := inspect.UnwindResult{Frames: []inspect.UnwindFrame{{PC: 0x401000, RawPC: 0x401000, LookupPC: 0x401000}}}
	text := controller.backtraceText(unwindCommandSeed{}, result)
	if !strings.Contains(text, "Unwind incomplete: caller information unavailable.") || strings.Contains(text, "End of stack") || strings.Contains(text, "0x0000000000000000") {
		t.Fatalf("invented CFA or bottom: %q", text)
	}
	frameText := controller.stackFrameText(unwindCommandSeed{abiExplicit: true}, result.Frames[0], 0)
	if !strings.Contains(frameText, "CFA: <unavailable>") || strings.Contains(frameText, "($rax") || strings.Contains(frameText, "0x0000000000000000") {
		t.Fatalf("invented recovery facts: %q", frameText)
	}
}

func TestUnwindBridgeStrictCFIDoesNotInventCallerStackPointer(t *testing.T) {
	index := unwindCommandTestIndex(t, [3]uint64{0x401000, 0x20, 0}, [3]uint64{0x402000, 0x20, 1})
	registers := inspect.AMD64UnwindRegisters{Known: 1<<7 | 1<<16}
	registers.Values[7], registers.Values[16] = 0x700000, 0x401000
	result, err := inspect.UnwindAMD64(context.Background(), inspect.AMD64UnwindRequest{
		Registers: registers, PC: 0x401000, MaxFrames: 32, Find: func(_ context.Context, pc target.Address) (*inspect.CFIFrame, error) { return index.Lookup(pc) },
		Read: func(_ context.Context, _ target.Address, data []byte) (int, error) {
			binary.LittleEndian.PutUint64(data, 0x402008)
			return len(data), nil
		},
	})
	if !errors.Is(err, target.ErrUnavailable) || len(result.Frames) != 2 || result.Complete || result.Frames[1].Registers.Known&(1<<7) != 0 {
		t.Fatalf("strict caller SP was invented: result=%+v error=%v", result, err)
	}
	for _, saved := range result.Frames[0].Saved {
		if saved.Register == 7 && (saved.Available || saved.Provenance != "unavailable") {
			t.Fatalf("strict implicit SP rule: %+v", saved)
		}
	}
	controller, _, _ := newInspectionTestController()
	text := controller.stackFrameText(unwindCommandSeed{abiExplicit: true}, result.Frames[0], 0)
	if !strings.Contains(text, "ABI: strict-cfi") || strings.Contains(text, "SysV") {
		t.Fatalf("ABI defaults leaked into strict frame: %q", text)
	}
}

func TestUnwindPublicationCancellationAndOutputError(t *testing.T) {
	controller, _, output := newInspectionTestController()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.publishUnwind(ctx, "confirmed prefix", target.ErrUnavailable); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("canceled output committed: %v %q", err, output.String())
	}
	failure := errors.New("writer failed")
	controller.out = contextFailingWriter{err: failure}
	var outputError *OutputError
	err := controller.publishUnwind(context.Background(), "confirmed prefix", target.ErrUnavailable)
	if !errors.Is(err, failure) || !errors.Is(err, target.ErrUnavailable) || !errors.As(err, &outputError) {
		t.Fatalf("output or unwind failure lost: %v", err)
	}
	controller.out = &bytes.Buffer{}
	if err := controller.publishUnwind(context.Background(), "confirmed prefix", target.ErrUnavailable); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("unwind error hidden: %v", err)
	}
}

const unwindCommandNativeSource = `volatile int bridge_sink;
__attribute__((noinline)) int bridge_leaf(int value) {
    __asm__ volatile("" : "+r"(value) : : "memory");
    bridge_sink = value;
    return value + 1;
}
__attribute__((noinline)) int bridge_recursive(int depth) {
    volatile int retained = depth;
    int value;
    if (depth == 0) value = bridge_leaf(depth);
    else value = bridge_recursive(depth - 1);
    return value + retained;
}
int main(void) {
    return bridge_recursive(4) != 11;
}
`

func TestUnwindCommandsNativeOptimizedRecursion(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "unwind-commands"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			dir, err := os.MkdirTemp(root, "native-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			source, executable := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
			if err := os.WriteFile(source, []byte(unwindCommandNativeSource), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			flags := []string{"-O2", "-g", "-fomit-frame-pointer", "-fno-optimize-sibling-calls", "-fasynchronous-unwind-tables", "-fcf-protection=none", "-Wl,--eh-frame-hdr"}
			if pie {
				flags = append(flags, "-fPIE", "-pie")
			} else {
				flags = append(flags, "-fno-pie", "-no-pie")
			}
			flags = append(flags, "-o", executable, source)
			compiler := exec.CommandContext(ctx, "cc", flags...)
			compiler.Env = append(os.Environ(), "TMPDIR="+dir)
			if output, err := compiler.CombinedOutput(); err != nil {
				t.Fatalf("compile fixture: %v\n%s", err, output)
			}
			var output bytes.Buffer
			controller := New(&output, display.Renderer{})
			t.Cleanup(func() {
				if err := controller.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := controller.Configure(executable, nil); err != nil {
				t.Fatal(err)
			}
			for _, command := range []struct{ name, args string }{{"context", "off"}, {"break", "bridge_leaf"}, {"run", ""}} {
				if quit, err := controller.Execute(ctx, command.name, command.args); quit || err != nil {
					t.Fatalf("%s %s: quit=%t error=%v\n%s", command.name, command.args, quit, err, output.String())
				}
			}
			seed, result, err := controller.collectUnwind(ctx, 32, inspect.UnwindSysVAMD64)
			if err != nil || len(result.Frames) < 7 || !result.Complete || result.Frames[0].PC != seed.location.InstructionPC ||
				result.Frames[0].RawPC != seed.location.RawPC || seed.location.RawPC != seed.location.InstructionPC+1 {
				t.Fatalf("optimized recursion: seed=%+v frames=%+v error=%v", seed.location, result, err)
			}
			output.Reset()
			if err := controller.showBacktrace(ctx, "--abi sysv"); err != nil || strings.Contains(output.String(), "Unwind incomplete") ||
				!strings.Contains(output.String(), "[ #1]") || !unwindUIAllCFAKnown(result) {
				t.Fatalf("backtrace: error=%v\n%s", err, output.String())
			}
			output.Reset()
			if err := controller.showStackFrame(ctx, "--abi sysv 3"); err != nil || !strings.Contains(output.String(), "[stackframe #3]") ||
				!strings.Contains(output.String(), "CFA:") || !strings.Contains(output.String(), "Saved at / source") || !strings.Contains(output.String(), "SysV") {
				t.Fatalf("stackframe: error=%v\n%s", err, output.String())
			}
			output.Reset()
			var limit *inspect.UnwindLimitError
			err = controller.showBacktrace(ctx, "--abi sysv 2")
			if !errors.As(err, &limit) || !strings.Contains(output.String(), "Unwind partial: frame limit reached (2).") || strings.Contains(output.String(), "End of stack") {
				t.Fatalf("limited backtrace: error=%v\n%s", err, output.String())
			}
			output.Reset()
			if err := controller.showStackFrame(ctx, "--abi sysv 255"); !errors.Is(err, target.ErrUnavailable) || !strings.Contains(output.String(), "[trace]") {
				t.Fatalf("unknown frame: error=%v\n%s", err, output.String())
			}
			output.Reset()
			if err := controller.showBacktrace(ctx, "--abi strict"); !errors.Is(err, target.ErrUnavailable) || !strings.Contains(output.String(), "ABI: strict-cfi") || !strings.Contains(output.String(), "Unwind incomplete") {
				t.Fatalf("strict backtrace inferred ABI rules: error=%v\n%s", err, output.String())
			}
			output.Reset()
			if err := controller.showStackFrame(ctx, "--abi strict 0"); err != nil || !strings.Contains(output.String(), "ABI: strict-cfi") || strings.Contains(output.String(), "SysV") {
				t.Fatalf("strict frame facts: error=%v\n%s", err, output.String())
			}
			output.Reset()
			if err := controller.showExamine(ctx, "1xb", "bridge_leaf"); err != nil || !strings.Contains(output.String(), "0xcc") {
				t.Fatalf("unwind changed breakpoint: error=%v\n%s", err, output.String())
			}
		})
	}
}

func TestUnwindCommandsNativeGoStrictDebugFrame(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "unwind-commands"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "go-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	source, executable := filepath.Join(dir, "main.go"), filepath.Join(dir, "fixture")
	program := "package main\nvar sink int\nfunc leaf(value int) int { sink = value; return value + 1 }\nfunc middle(value int) int { return leaf(value) + 1 }\nfunc main() { sink = middle(3) }\n"
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	compiler := exec.CommandContext(ctx, "go", "build", "-gcflags=-l", "-o", executable, source)
	compiler.Env = append(os.Environ(), "TMPDIR="+dir, "GOTMPDIR="+dir)
	if output, err := compiler.CombinedOutput(); err != nil {
		t.Fatalf("compile Go fixture: %v\n%s", err, output)
	}
	var output bytes.Buffer
	controller := New(&output, display.Renderer{})
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := controller.Configure(executable, nil); err != nil {
		t.Fatal(err)
	}
	for _, command := range []struct{ name, args string }{{"context", "off"}, {"break", "`main.leaf`"}, {"run", ""}} {
		if quit, err := controller.Execute(ctx, command.name, command.args); quit || err != nil {
			t.Fatalf("%s %s: quit=%t error=%v\n%s", command.name, command.args, quit, err, output.String())
		}
	}
	for count := 0; controller.session.LastStop().Reason != target.StopBreakpoint; count++ {
		if count == 64 {
			t.Fatal("Go leaf breakpoint not reached after 64 stops")
		}
		if _, err := controller.Execute(ctx, "continue", "--deliver"); err != nil {
			t.Fatalf("continue Go fixture: %v\n%s", err, output.String())
		}
	}
	_, result, err := controller.collectUnwind(ctx, 32, inspect.UnwindStrictCFI)
	if !errors.Is(err, target.ErrUnavailable) || len(result.Frames) == 0 || result.Complete || !strings.Contains(result.Frames[0].Source, "file .debug_frame") {
		t.Fatalf("Go strict metadata: result=%+v error=%v", result, err)
	}
	for _, saved := range result.Frames[0].Saved {
		if (saved.Register == 7 || saved.Register == 3) && (saved.Available || saved.Provenance != "unavailable") {
			t.Fatalf("Go strict ABI defaults were invented: %+v", saved)
		}
	}
	output.Reset()
	if err := controller.showBacktrace(ctx, "--abi strict"); !errors.Is(err, target.ErrUnavailable) || !strings.Contains(output.String(), "ABI: strict-cfi") || !strings.Contains(output.String(), "Unwind incomplete") {
		t.Fatalf("Go strict command: error=%v\n%s", err, output.String())
	}
	output.Reset()
	if err := controller.showStackFrame(ctx, "--abi strict 0"); err != nil || !strings.Contains(output.String(), "CFI record:") || strings.Contains(output.String(), "SysV") {
		t.Fatalf("Go strict frame facts: error=%v\n%s", err, output.String())
	}
}
