package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func deterministicBuild(t *testing.T, compiler, source string, pie bool, flags ...string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "integration"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path+".c", []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-std=gnu11", "-g", "-fcf-protection=none", "-pthread", "-Wl,--build-id=sha1"}
	args = append(args, flags...)
	if pie {
		args = append(args, "-fPIE", "-pie")
	} else {
		args = append(args, "-fno-pie", "-no-pie")
	}
	args = append(args, "-o", path, path+".c")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, compiler, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile %s: %v\n%s", compiler, err, output)
	}
	return path
}

func deterministicLaunch(t *testing.T, path, point string, args ...string) *expansionIntegration {
	t.Helper()
	f := &expansionIntegration{}
	f.controller = New(&f.output, display.Renderer{})
	t.Cleanup(func() {
		fd := -1
		if f.controller.session != nil && f.controller.session.State() != target.StateExited {
			fd, _ = unix.PidfdOpen(f.controller.session.PID(), 0)
		}
		if fd >= 0 {
			defer unix.Close(fd)
		}
		done := make(chan error, 1)
		go func() { done <- f.controller.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			if fd >= 0 {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			t.Error("deterministic fixture close exceeded deadline")
		}
		if f.pid != 0 {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", f.pid)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("deterministic fixture %d remains: %v", f.pid, err)
			}
		}
	})
	if err := f.controller.Configure(path, args); err != nil {
		t.Fatal(err)
	}
	f.command(t, "context off")
	f.command(t, "break "+point)
	f.command(t, "start")
	f.pid = f.controller.session.PID()
	return f
}

const deterministicUnwindSource = `#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
unsigned char alternate[65536] __attribute__((aligned(16)));
volatile uint64_t oracle_sink;
volatile sig_atomic_t oracle_altstack_used;
__attribute__((noinline)) uint64_t oracle_marker(uint64_t value) {
    __asm__ volatile("nop" ::: "memory");
    return value + 1;
}
__attribute__((noinline)) static uint64_t handler_inner(uint64_t value) {
    volatile uint64_t local[5] = {value,2,3,4,5};
    return oracle_marker(local[0]) + local[4];
}
static void handler(int signo, siginfo_t *info, void *context) {
    (void)info; (void)context;
    volatile unsigned char local;
    uintptr_t address = (uintptr_t)&local;
    oracle_altstack_used = address >= (uintptr_t)alternate && address < (uintptr_t)(alternate+sizeof(alternate));
    oracle_sink = handler_inner((uint64_t)signo);
}
__attribute__((noinline)) static uint64_t level3(uint64_t value,int signaling) {
    volatile uint64_t local[5] = {value,11,12,13,14};
    if (signaling) {
        if (raise(SIGUSR1)) _Exit(3);
        return oracle_sink + local[0];
    }
    return oracle_marker(local[0]) + local[4];
}
__attribute__((noinline)) static uint64_t level2(uint64_t value,int signaling) {
    volatile uint64_t local[3] = {value,21,22};
    return level3(local[0]+1,signaling) + local[2];
}
__attribute__((noinline)) static uint64_t level1(uint64_t value,int signaling) {
    volatile uint64_t local[3] = {value,31,32};
    return level2(local[0]+1,signaling) + local[2];
}
int main(int argc,char **argv) {
    int signaling=argc>1 && argv[1][0]=='s';
    stack_t stack={.ss_sp=alternate,.ss_size=sizeof(alternate)};
    struct sigaction action={.sa_sigaction=handler,.sa_flags=SA_SIGINFO|SA_ONSTACK};
    sigemptyset(&action.sa_mask);
    if (sigaltstack(&stack,0)||sigaction(SIGUSR1,&action,0)) return 2;
    oracle_sink=level1(41,signaling);
    return signaling && !oracle_altstack_used ? 4 : 0;
}
`

func TestDeterministicCommandsNativeCFIAndSignal(t *testing.T) {
	for _, compiler := range []string{"gcc", "clang"} {
		for _, pie := range []bool{false, true} {
			for _, signaling := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/pie_%t/signal_%t", compiler, pie, signaling), func(t *testing.T) {
					flags := []string{"-O2", "-fomit-frame-pointer", "-fno-inline", "-fno-optimize-sibling-calls", "-fasynchronous-unwind-tables"}
					if compiler == "gcc" {
						flags = append(flags, "-fno-ipa-cp", "-fno-ipa-sra")
					}
					path := deterministicBuild(t, compiler, deterministicUnwindSource, pie, flags...)
					mode := "normal"
					if signaling {
						mode = "signal"
					}
					f := deterministicLaunch(t, path, "oracle_marker", mode)
					f.command(t, "continue")
					if signaling {
						if f.controller.session.LastStop().Reason != target.StopSignal {
							t.Fatal("signal handler was entered without a signal decision")
						}
						f.command(t, "continue --deliver")
					}
					if f.controller.session.LastStop().Reason != target.StopBreakpoint {
						t.Fatalf("not at oracle marker: %+v", f.controller.session.LastStop())
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					seed, result, err := f.controller.collectUnwind(ctx, 32, inspect.UnwindSysVAMD64)
					if err != nil || !result.Complete || len(result.Frames) < 5 {
						t.Fatalf("SysV CFI result: %v\n%s", err, f.controller.backtraceText(seed, result))
					}
					if result.Frames[0].RawPC != result.Frames[0].PC+1 || result.Frames[0].PC != legacyNativeAddress(t, f, "oracle_marker") {
						t.Fatalf("core breakpoint provenance: %+v", result.Frames[0])
					}
					image, err := elf.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					symbols, err := image.Symbols()
					image.Close()
					if err != nil {
						t.Fatal(err)
					}
					wanted := []string{"oracle_marker", "level3", "level2", "level1", "main"}
					if signaling {
						wanted = []string{"oracle_marker", "handler_inner", "handler", "level3", "level2", "level1", "main"}
					}
					previous := -1
					for _, name := range wanted {
						address := legacyNativeAddress(t, f, name)
						var size uint64
						for _, symbol := range symbols {
							if symbol.Name == name {
								size = symbol.Size
							}
						}
						found := -1
						for index := previous + 1; index < len(result.Frames); index++ {
							pc := result.Frames[index].LookupPC
							if pc >= address && uint64(pc-address) < size {
								found = index
								break
							}
						}
						if found < 0 {
							t.Fatalf("exact ELF extent for %s absent in caller order: %s", name, f.controller.backtraceText(seed, result))
						}
						previous = found
					}
					alternate := legacyNativeAddress(t, f, "alternate")
					signalFrames := 0
					for index, frame := range result.Frames {
						if !frame.Signal {
							continue
						}
						signalFrames++
						if index+1 == len(result.Frames) {
							t.Fatal("signal CFI lacks recovered interrupted frame")
						}
						next := result.Frames[index+1]
						if next.ReturnPC || next.LookupPC != next.PC || next.Registers.Known&(1<<7) == 0 || next.Registers.Values[7] >= uint64(alternate) && next.Registers.Values[7] < uint64(alternate)+65536 {
							t.Fatalf("signal recovery invented return-PC bias or kept alternate stack: %+v", next)
						}
					}
					if signaling != (signalFrames == 1) || signaling && binary.LittleEndian.Uint32(f.read(t, "oracle_altstack_used", 4)) != 1 {
						t.Fatalf("signal CFI/alternate-stack facts: scenario=%t frames=%d", signaling, signalFrames)
					}
					strictSeed, strict, strictErr := f.controller.collectUnwind(ctx, 32, inspect.UnwindStrictCFI)
					if !errors.Is(strictErr, target.ErrUnavailable) || strict.Complete || len(strict.Frames) < 1 {
						t.Fatalf("strict profile fabricated completion: %v\n%s", strictErr, f.controller.backtraceText(strictSeed, strict))
					}
					for _, saved := range strict.Frames[0].Saved {
						if saved.Register == 7 || saved.Register == 3 || saved.Register >= 12 && saved.Register <= 15 {
							if saved.Available || saved.Provenance != "unavailable" {
								t.Fatalf("strict caller register was fabricated: %+v", saved)
							}
						}
					}
					if output, err := f.execute("bt --abi strict"); !errors.Is(err, target.ErrUnavailable) || !strings.Contains(output, "ABI: strict-cfi") || !strings.Contains(output, "Unwind incomplete: caller information unavailable") {
						t.Fatalf("default command profile: %v\n%s", err, output)
					}
					f.command(t, "bt --abi sysv")
					f.command(t, "stackframe --abi sysv 3")
					f.command(t, "stackframe 0")
					f.reject(t, "bt --abi sysv 2")
					t.Logf("compiler=%s PIE=%t signal=%t frames=%d signal-CFI=%d, strict prefix=%d; each expected caller belongs to its exact declared ELF extent", compiler, pie, signaling, len(result.Frames), signalFrames, len(strict.Frames))
				})
			}
		}
	}
}

func TestDeterministicCommandsNativeThreadApplyCFI(t *testing.T) {
	f := newExpansionIntegration(t, true)
	f.breakpoint(t)
	selected := f.controller.selected
	before, err := f.controller.session.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	stacks := make(map[uint64]bool)
	for _, thread := range before.Threads {
		f.command(t, fmt.Sprintf("thread %d", thread.Ref.ID))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		seed, result, err := f.controller.collectUnwind(ctx, 32, inspect.UnwindSysVAMD64)
		cancel()
		if err != nil || !result.Complete || len(result.Frames) < 3 || result.Frames[0].Registers.Known&(1<<7) == 0 {
			t.Fatalf("thread %d CFI: %v\n%s", thread.Ref.ID, err, f.controller.backtraceText(seed, result))
		}
		stacks[result.Frames[0].Registers.Values[7]] = true
	}
	if len(stacks) != 3 {
		t.Fatalf("thread frame seeds were not distinct: %v", stacks)
	}
	f.command(t, fmt.Sprintf("thread %d", selected.ID))
	for _, command := range []string{"thread apply all bt --abi sysv", "thread apply all stackframe --abi sysv 0"} {
		output := f.command(t, command)
		if uiApplyHeaderCount(output) != 3 || f.controller.selected != selected {
			t.Fatalf("CFI thread apply scope/selection: %s", output)
		}
	}
	output, err := f.execute("thread apply all bt --abi strict")
	if !errors.Is(err, target.ErrUnavailable) || uiApplyHeaderCount(output) != 1 || f.controller.selected != selected {
		t.Fatalf("strict apply did not stop and restore: %v\n%s", err, output)
	}
	after, err := f.controller.session.Snapshot()
	if err != nil || before.Sequence != after.Sequence || before.Memory != after.Memory {
		t.Fatalf("read-only CFI mutated target: %v", err)
	}
}

type deterministicReadAudit struct {
	session
	tokens []target.MemoryToken
	stale  bool
}

func (s *deterministicReadAudit) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	s.tokens = append(s.tokens, token)
	n, err := s.session.ReadSpaceMemory(token, address, dst)
	if s.stale {
		return n, errors.Join(err, target.ErrStale)
	}
	return n, err
}

func (s *deterministicReadAudit) ReadCodeMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	s.tokens = append(s.tokens, token)
	n, err := s.session.ReadCodeMemory(token, address, dst)
	if s.stale {
		return n, errors.Join(err, target.ErrStale)
	}
	return n, err
}

func TestDeterministicCommandsNativeRuntimeModules(t *testing.T) {
	f := newExpansionIntegration(t, true)
	f.breakpoint(t)
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	var associated, vdso bool
	err = f.controller.withELFModules(context.Background(), snapshot, thread, elfModuleSelection{All: true}, func(modules []*mappedELF) error {
		for _, module := range modules {
			associated = associated || module.Proof == kernelBuildIDMetadataProof && len(module.BuildID) > 0
			vdso = vdso || module.Runtime != nil && module.Proof == "auxv-vdso+runtime-dynamic-metadata" && module.Runtime.SymbolsComplete
		}
		return nil
	})
	if err != nil || !associated || !vdso {
		t.Fatalf("current kernel metadata association or exact vDSO absent: association=%t vdso=%t err=%v", associated, vdso, err)
	}
	for _, command := range []string{"sym __vdso_clock_gettime", "checksec all", "got all", "stdio"} {
		output := f.command(t, command)
		if strings.Contains(strings.ToLower(output), "incomplete") {
			t.Fatalf("verified module command remained partial: %s", output)
		}
		if command == "stdio" && !strings.Contains(output, "[FILE->_wide_data->_wide_vtable]") {
			t.Fatalf("runtime standard streams incomplete: %s", output)
		}
		if command == "sym __vdso_clock_gettime" && (!strings.Contains(output, "__vdso_clock_gettime") || !strings.Contains(output, "Runtime")) {
			t.Fatalf("vDSO dynamic-symbol proof missing: %s", output)
		}
	}
	real := f.controller.session
	audit := &deterministicReadAudit{session: real, stale: true}
	f.controller.session = audit
	output, err := f.execute("bt --abi sysv")
	f.controller.session = real
	if !errors.Is(err, target.ErrStale) || output != "" {
		t.Fatalf("stale unwind published a prefix: %v\n%s", err, output)
	}
}

func deterministicHeapSource() string {
	decls := `
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>
static _Atomic int deterministic_ready;
static _Atomic int deterministic_gate;
static void *deterministic_worker(void *value) {
    (void)value;
    atomic_fetch_add(&deterministic_ready, 1);
    syscall(SYS_futex, &deterministic_ready, FUTEX_WAKE_PRIVATE, 2, 0, 0, 0);
    for (;;) syscall(SYS_futex, &deterministic_gate, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
}
static struct malloc_chunk budget_nodes[4097];
unsigned long deterministic_layout[] = {
    sizeof(struct malloc_state), sizeof(struct malloc_chunk),
    offsetof(struct malloc_state, fastbinsY), offsetof(struct malloc_state, bins),
    offsetof(struct malloc_state, next), offsetof(struct malloc_state, attached_threads),
    offsetof(struct malloc_chunk, fd), offsetof(struct malloc_chunk, bk),
    offsetof(struct malloc_chunk, mchunk_prev_size), offsetof(struct malloc_chunk, mchunk_size)
};
`
	setup := `
    pthread_t threads[2];
    for (int i = 0; i < 2; ++i) if (pthread_create(&threads[i], 0, deterministic_worker, 0)) return 94;
    for (;;) {
        int ready = atomic_load(&deterministic_ready);
        if (ready == 2) break;
        syscall(SYS_futex, &deterministic_ready, FUTEX_WAIT_PRIVATE, ready, 0, 0, 0);
    }
    for (int i = 0; i < 4096; ++i) budget_nodes[i].fd = &budget_nodes[i+1];
`
	source := strings.Replace(heapDWARFIntegrationSource, "int main(void) {", decls+"\nint main(void) {", 1)
	return strings.Replace(source, "    heap_probe();", setup+"\n    heap_probe();", 1)
}

func TestDeterministicCommandsNativeHeapMetadata(t *testing.T) {
	for _, pie := range []bool{false, true} {
		for _, separate := range []bool{false, true} {
			t.Run(fmt.Sprintf("pie_%t/separate_%t", pie, separate), func(t *testing.T) {
				path := deterministicBuild(t, "gcc", deterministicHeapSource(), pie, "-O0", "-gdwarf-5", "-fno-eliminate-unused-debug-types")
				debug := ""
				if separate {
					debug = path + ".debug"
					for _, command := range [][]string{{"objcopy", "--only-keep-debug", path, debug}, {"objcopy", "--compress-debug-sections=zlib-gabi", debug}, {"strip", "--strip-debug", path}} {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
						cancel()
						if err != nil {
							t.Fatalf("debug preparation: %v\n%s", err, output)
						}
					}
				}
				f := deterministicLaunch(t, path, "heap_probe")
				f.breakpoint(t)
				raw := f.read(t, "deterministic_layout", 80)
				values := make([]uint64, 10)
				for index := range values {
					values[index] = binary.LittleEndian.Uint64(raw[index*8:])
				}
				field := func(offset, count uint64) inspect.HeapField {
					return inspect.HeapField{Offset: offset, Width: 8, Count: count, Stride: 8}
				}
				layout := inspect.HeapLayout{Schema: 1, Allocator: "glibc", Arch: "amd64", Endian: "little", Pointer: 8, FastLink: "plain",
					Arena: inspect.HeapRecord{Size: values[0], Fields: map[string]inspect.HeapField{"fastbinsY": field(values[2], 2), "bins": field(values[3], 4), "next": field(values[4], 1), "attached_threads": field(values[5], 1)}},
					Chunk: inspect.HeapRecord{Size: values[1], Fields: map[string]inspect.HeapField{"fd": field(values[6], 1), "bk": field(values[7], 1), "mchunk_prev_size": field(values[8], 1), "mchunk_size": field(values[9], 1)}}}
				encoded, err := json.Marshal(layout)
				if err != nil {
					t.Fatal(err)
				}
				layoutPath := path + ".layout.json"
				if err := os.WriteFile(layoutPath, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				dwarfArgs := "--module main --fast-link plain"
				if separate {
					if output, err := f.execute("arena " + dwarfArgs); !errors.Is(err, target.ErrUnavailable) || output != "" {
						t.Fatalf("stripped executable guessed metadata: %v\n%s", err, output)
					}
					dwarfArgs += " --debug-file " + strconv.Quote(debug)
				}
				before, err := f.controller.session.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				selected := f.controller.selected
				for _, arguments := range []string{dwarfArgs, "--layout-file " + strconv.Quote(layoutPath) + " main_arena"} {
					arenaArgs := "--all " + arguments
					output := f.command(t, "arena "+arenaArgs)
					if !strings.Contains(output, "observed-arenas=2") || strings.Contains(output, "thread ownership are not inferred") {
						t.Fatalf("exact arena observations: %s", output)
					}
					output = f.command(t, "bins "+arguments)
					if !strings.Contains(output, "observed-nodes=3") || strings.Count(output, "nodes=1 complete=true") != 2 {
						t.Fatalf("exact bins observations: %s", output)
					}
				}
				for _, command := range []string{"thread apply all arena --all " + dwarfArgs, "thread apply all bins " + dwarfArgs} {
					output := f.command(t, command)
					if strings.Count(output, "\nThread ") != 3 || f.controller.selected != selected {
						t.Fatalf("shared heap was assigned to a thread or selection changed: %s", output)
					}
				}
				after, err := f.controller.session.Snapshot()
				if err != nil || before.Sequence != after.Sequence || before.Memory != after.Memory {
					t.Fatalf("heap inspection mutated stopped target: %v", err)
				}
				fast := legacyNativeAddress(t, f, "fast_chunk")
				fd := fast + target.Address(values[6])
				f.command(t, fmt.Sprintf("set %#x %#x", fd, uint64(fd)>>12))
				safeArgs := strings.Replace(dwarfArgs, "--fast-link plain", "--fast-link safe-link-12", 1)
				if output := f.command(t, "bins "+safeArgs); !strings.Contains(output, "observed-nodes=3") {
					t.Fatal(output)
				}
				f.reject(t, "bins "+dwarfArgs)
				f.command(t, fmt.Sprintf("set %#x 0", fd))
				if !pie && !separate {
					arena := legacyNativeAddress(t, f, "main_arena")
					head := arena + target.Address(values[2])
					normal := binary.LittleEndian.Uint64(f.read(t, "normal_chunk", 8))
					f.command(t, fmt.Sprintf("set %#x %#x", head, normal+16))
					output, err := f.execute("bins " + dwarfArgs)
					if !errors.Is(err, target.ErrPartial) || !strings.Contains(output, "incomplete node: 16 confirmed bytes") {
						t.Fatalf("partial heap read invented a node: %v\n%s", err, output)
					}
					budget := legacyNativeAddress(t, f, "budget_nodes")
					f.command(t, fmt.Sprintf("set %#x %#x", head, budget))
					output, err = f.execute("bins " + dwarfArgs)
					if !errors.Is(err, target.ErrUnavailable) || !strings.Contains(err.Error(), "global 4096-node budget") || !strings.Contains(output, "observed-nodes=4096") {
						t.Fatalf("global heap budget: %v\n%s", err, output)
					}
					f.command(t, fmt.Sprintf("set %#x %#x", head, fast))
					real := f.controller.session
					f.controller.session = &deterministicReadAudit{session: real, stale: true}
					output, err = f.execute("bins " + dwarfArgs)
					f.controller.session = real
					if !errors.Is(err, target.ErrStale) || output != "" {
						t.Fatalf("stale heap observations escaped: %v\n%s", err, output)
					}
				}
			})
		}
	}
}

func TestDeterministicCommandsNativeKMPContract(t *testing.T) {
	f, _ := newLegacySearchIntegration(t, true)
	before, err := f.controller.session.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	real := f.controller.session
	audit := &deterministicReadAudit{session: real}
	f.controller.session = audit
	output, err := f.execute("search-string ABABA legacy_bytes legacy_bytes+131080")
	f.controller.session = real
	if err != nil || !strings.Contains(output, "Found 3 match(es)") || !strings.Contains(output, "match(es)\n") {
		t.Fatalf("KMP chunk/overlap regression: %v\n%s", err, output)
	}
	if len(audit.tokens) < 3 {
		t.Fatalf("fixture did not exercise multiple target chunks: %d", len(audit.tokens))
	}
	for _, token := range audit.tokens {
		if token != before.Memory {
			t.Fatalf("search combined target revisions: %+v, want %+v", token, before.Memory)
		}
	}
	output, err = f.execute("search-string --max-matches 2 ABA legacy_bytes legacy_bytes+131080")
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(output, "Found 2 match(es)") || !strings.Contains(output, "match(es) (partial)") {
		t.Fatalf("KMP match bound changed: %v\n%s", err, output)
	}
	f.controller.session = &deterministicReadAudit{session: real, stale: true}
	output, err = f.execute("search-string ABA legacy_bytes legacy_bytes+131080")
	f.controller.session = real
	if !errors.Is(err, target.ErrStale) || output != "" {
		t.Fatalf("stale KMP prefix published: %v\n%s", err, output)
	}
	data := bytes.Repeat([]byte{'a'}, 32768)
	pattern := bytes.Repeat([]byte{'a'}, 8192)
	matches, err := inspect.SearchBytes(context.Background(), 0x1000, data, pattern, 3)
	if err != nil || len(matches) != len(data)-len(pattern)+1 || matches[0] != 0x1000 || matches[len(matches)-1] != 0x1000+target.Address(len(data)-len(pattern)) {
		t.Fatalf("dense overlapping matcher result: %d, %v", len(matches), err)
	}
}
