package debugger

import (
	"bytes"
	"context"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestHeapMainArenaELFSymbolRequiresExactObject(t *testing.T) {
	valid := elf.Symbol{Name: "main_arena", Info: byte(elf.STT_OBJECT), Section: 1, Value: 0x400800, Size: 96}
	for _, test := range []struct {
		name    string
		symbols []elf.Symbol
		err     error
	}{
		{"valid", []elf.Symbol{valid}, nil},
		{"duplicate-same", []elf.Symbol{valid, valid}, nil},
		{"absent", nil, target.ErrNotFound},
		{"function", []elf.Symbol{{Name: "main_arena", Info: byte(elf.STT_FUNC), Section: 1, Value: valid.Value, Size: valid.Size}}, target.ErrUnsupported},
		{"absolute", []elf.Symbol{{Name: "main_arena", Info: byte(elf.STT_OBJECT), Section: elf.SHN_ABS, Value: valid.Value, Size: valid.Size}}, target.ErrUnsupported},
		{"undefined", []elf.Symbol{{Name: "main_arena", Info: byte(elf.STT_OBJECT), Section: elf.SHN_UNDEF}}, target.ErrNotFound},
		{"outside-section", []elf.Symbol{{Name: "main_arena", Info: byte(elf.STT_OBJECT), Section: 1, Value: 0x4007ff, Size: 96}}, target.ErrInvalidArgument},
		{"zero-size", []elf.Symbol{{Name: "main_arena", Info: byte(elf.STT_OBJECT), Section: 1, Value: valid.Value}}, target.ErrInvalidArgument},
		{"multiple", []elf.Symbol{valid, {Name: "main_arena", Info: byte(elf.STT_OBJECT), Section: 1, Value: 0x400900, Size: 96}}, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, _ := elfCommandTestELF(t, test.symbols, nil, nil)
			got, err := heapMainArenaSymbol(file)
			if !errors.Is(err, test.err) || err == nil && got.Value != valid.Value {
				t.Fatalf("got=%+v error=%v want=%v", got, err, test.err)
			}
		})
	}
}

func heapVariableDWARFTestData(t *testing.T, extraAttrs []byte, extraValues []byte, location []byte) *dwarf.Data {
	t.Helper()
	abbrev := []byte{1, byte(dwarf.TagCompileUnit), 1, 0, 0, 2, byte(dwarf.TagVariable), 0, byte(dwarf.AttrName), 0x08, byte(dwarf.AttrLocation), 0x18, byte(dwarf.AttrType), 0x13}
	abbrev = append(abbrev, extraAttrs...)
	abbrev = append(abbrev, 0, 0, 0)
	var unit bytes.Buffer
	_ = binary.Write(&unit, binary.LittleEndian, uint16(4))
	_ = binary.Write(&unit, binary.LittleEndian, uint32(0))
	unit.WriteByte(8)
	unit.Write([]byte{1, 2})
	unit.WriteString("main_arena\x00")
	unit.WriteByte(byte(len(location)))
	unit.Write(location)
	_ = binary.Write(&unit, binary.LittleEndian, uint32(0x40))
	unit.Write(extraValues)
	unit.WriteByte(0)
	var info bytes.Buffer
	_ = binary.Write(&info, binary.LittleEndian, uint32(unit.Len()))
	info.Write(unit.Bytes())
	data, err := dwarf.New(abbrev, nil, nil, info.Bytes(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHeapMainArenaDWARFAuthorityRejectsMalformedVariables(t *testing.T) {
	location := make([]byte, 9)
	location[0] = 3
	binary.LittleEndian.PutUint64(location[1:], 0x400800)
	for _, test := range []struct {
		name   string
		attrs  []byte
		values []byte
		err    error
	}{
		{"valid", nil, nil, nil},
		{"duplicate-type", []byte{byte(dwarf.AttrType), 0x13}, []byte{0x40, 0, 0, 0}, target.ErrInvalidArgument},
		{"duplicate-name", []byte{byte(dwarf.AttrName), 0x08}, []byte("main_arena\x00"), target.ErrInvalidArgument},
		{"duplicate-location", []byte{byte(dwarf.AttrLocation), 0x18}, append([]byte{9}, location...), target.ErrInvalidArgument},
		{"specification", []byte{byte(dwarf.AttrSpecification), 0x13}, []byte{0x40, 0, 0, 0}, target.ErrUnsupported},
		{"abstract-origin", []byte{byte(dwarf.AttrAbstractOrigin), 0x13}, []byte{0x40, 0, 0, 0}, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := heapVariableDWARFTestData(t, test.attrs, test.values, location)
			got, err := heapMainArenaType(context.Background(), data, elf.Symbol{Value: 0x400800})
			if !errors.Is(err, test.err) || err == nil && got != 0x40 {
				t.Fatalf("type=%#x error=%v want=%v", got, err, test.err)
			}
		})
	}
	data := heapVariableDWARFTestData(t, nil, nil, location)
	if _, err := heapMainArenaType(context.Background(), data, elf.Symbol{Value: 0x400801}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
	location[0] = 0xff
	if _, err := heapMainArenaType(context.Background(), heapVariableDWARFTestData(t, nil, nil, location), elf.Symbol{Value: 0x400800}); !errors.Is(err, target.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestHeapDWARFMetadataBounds(t *testing.T) {
	for _, test := range []struct {
		name     string
		sections []*elf.Section
		err      error
	}{
		{"absent", nil, target.ErrUnavailable},
		{"legacy-compression", []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Size: 8}}}, target.ErrUnsupported},
		{"oversized", []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: maxELFCommandMetadata + 1}}}, target.ErrUnsupported},
		{"duplicate", []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".debug_info"}}, {SectionHeader: elf.SectionHeader{Name: ".debug_info"}}}, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := heapDWARFData(&elf.File{Sections: test.sections}); !errors.Is(err, test.err) {
				t.Fatalf("error=%v want=%v", err, test.err)
			}
		})
	}
}

const heapDWARFIntegrationSource = `
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
struct malloc_chunk {
    unsigned long mchunk_prev_size;
    unsigned long mchunk_size;
    struct malloc_chunk *fd;
    struct malloc_chunk *bk;
    struct malloc_chunk *fd_nextsize;
    struct malloc_chunk *bk_nextsize;
};
struct malloc_state {
    int mutex;
    int flags;
    int have_fastchunks;
    struct malloc_chunk *fastbinsY[2];
    struct malloc_chunk *top;
    struct malloc_chunk *last_remainder;
    struct malloc_chunk *bins[4];
    unsigned int binmap[1];
    struct malloc_state *next;
    struct malloc_state *next_free;
    unsigned long attached_threads;
    unsigned long system_mem;
    unsigned long max_system_mem;
};
static struct malloc_state main_arena;
static struct malloc_state second_arena;
static struct malloc_chunk fast_chunk;
static struct malloc_chunk *normal_chunk;
__attribute__((noinline)) void heap_probe(void) { __asm__ volatile("nop" ::: "memory"); }
static void setup(struct malloc_state *arena) {
    for (int i = 0; i < 2; ++i) {
        struct malloc_chunk *sentinel = (struct malloc_chunk *)((char *)&arena->bins[2*i] - offsetof(struct malloc_chunk, fd));
        arena->bins[2*i] = sentinel;
        arena->bins[2*i+1] = sentinel;
    }
    arena->attached_threads = 1;
}
int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 90;
    char *mapping = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || munmap(mapping + page, (size_t)page)) return 91;
    normal_chunk = (struct malloc_chunk *)(mapping + page - 32);
    setup(&main_arena);
    setup(&second_arena);
    main_arena.next = &second_arena;
    second_arena.next = &main_arena;
    fast_chunk.mchunk_size = 0x41;
    main_arena.fastbinsY[0] = &fast_chunk;
    normal_chunk->mchunk_size = 0x21;
    normal_chunk->fd = main_arena.bins[0];
    normal_chunk->bk = main_arena.bins[0];
    main_arena.bins[0] = normal_chunk;
    main_arena.bins[1] = normal_chunk;
    heap_probe();
    return 0;
}
`

type heapPostProofSession struct {
	session
	read bool
}

func (session *heapPostProofSession) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	session.read = true
	return session.session.ReadSpaceMemory(token, address, dst)
}

func (session *heapPostProofSession) Snapshot() (target.Snapshot, error) {
	if session.read {
		return target.Snapshot{}, fmt.Errorf("injected post-observation snapshot failure: %w", target.ErrUnavailable)
	}
	return session.session.Snapshot()
}

func heapDWARFCompileFixture(t *testing.T, pie, separate bool) (string, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "heap", "tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	source, executable := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
	if err := os.WriteFile(source, []byte(heapDWARFIntegrationSource), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-std=gnu11", "-O0", "-gdwarf-5", "-fno-eliminate-unused-debug-types", "-Wl,--build-id=sha1", "-fno-pie", "-no-pie"}
	if pie {
		args[len(args)-2], args[len(args)-1] = "-fPIE", "-pie"
	}
	args = append(args, "-o", executable, source)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile heap fixture: %v\n%s", err, output)
	}
	debugFile := ""
	if separate {
		debugFile = executable + ".debug"
		for _, command := range [][]string{{"objcopy", "--only-keep-debug", executable, debugFile}, {"objcopy", "--compress-debug-sections=zlib-gabi", debugFile}, {"strip", "--strip-debug", executable}} {
			if output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("prepare separate debug file: %v\n%s", err, output)
			}
		}
	}
	return executable, debugFile
}

func TestHeapDWARFCommandsNativeExactMetadata(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native heap commands require linux/amd64")
	}
	for _, pie := range []bool{false, true} {
		for _, separate := range []bool{false, true} {
			t.Run(fmt.Sprintf("pie_%t/separate_%t", pie, separate), func(t *testing.T) {
				executable, debugFile := heapDWARFCompileFixture(t, pie, separate)
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
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				for _, command := range [][2]string{{"break", "heap_probe"}, {"run", ""}} {
					if _, err := controller.Execute(ctx, command[0], command[1]); err != nil {
						t.Fatalf("%s: %v\n%s", command[0], err, output.String())
					}
				}
				before, err := controller.session.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				args := "--module main --fast-link plain"
				if separate {
					output.Reset()
					if err := controller.showArenas(ctx, args); !errors.Is(err, target.ErrUnavailable) || output.Len() != 0 {
						t.Fatalf("stripped target silently discovered debug data: %v output=%q", err, output.String())
					}
					args += fmt.Sprintf(" --debug-file %q", debugFile)
				}
				output.Reset()
				if err := controller.showArenas(ctx, args+" --all"); err != nil || !strings.Contains(output.String(), "observed-arenas=2") || !strings.Contains(output.String(), "arena-address=main_arena-symbol+DWARF") {
					t.Fatalf("arena error=%v output=%q", err, output.String())
				}
				if separate && !strings.Contains(output.String(), "gnu-build-id-metadata") {
					t.Fatalf("missing debug association proof: %s", output.String())
				}
				output.Reset()
				if err := controller.showBins(ctx, args); err != nil || !strings.Contains(output.String(), "observed-nodes=3") || strings.Count(output.String(), "nodes=1 complete=true") != 2 {
					t.Fatalf("bins error=%v output=%q", err, output.String())
				}
				snapshot, thread, err := controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				pointerAddress, err := controller.evaluate(ctx, "normal_chunk", snapshot, thread)
				if err != nil {
					t.Fatal(err)
				}
				var pointer [8]byte
				if n, err := controller.session.ReadSpaceMemory(snapshot.Memory, pointerAddress, pointer[:]); err != nil || n != len(pointer) {
					t.Fatalf("read fixture pointer: n=%d error=%v", n, err)
				}
				var oversized [48]byte
				if n, err := controller.session.ReadSpaceMemory(snapshot.Memory, target.Address(binary.LittleEndian.Uint64(pointer[:])), oversized[:]); n != 32 || !errors.Is(err, target.ErrPartial) {
					t.Fatalf("guard boundary is not an exact 32-byte readable chunk extent: n=%d error=%v", n, err)
				}
				after, err := controller.session.Snapshot()
				if err != nil || before.Sequence != after.Sequence || before.Memory != after.Memory {
					t.Fatalf("heap inspection mutated the stopped target: before=%+v after=%+v error=%v", before, after, err)
				}
				if !pie && !separate {
					realSession := controller.session
					controller.session = &heapPostProofSession{session: realSession}
					output.Reset()
					err := controller.showArenas(ctx, args)
					controller.session = realSession
					var proofErr *heapGraphProofError
					if !errors.As(err, &proofErr) || !errors.Is(err, target.ErrUnavailable) || output.Len() != 0 {
						t.Fatalf("post-proof failure published observations: %v output=%q", err, output.String())
					}
				}
			})
		}
	}
}
