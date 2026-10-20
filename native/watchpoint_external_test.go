package native_test

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const watchThreadSource = `#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
_Atomic int watched;
_Atomic int ready[3];
_Atomic int counters[3];
int tids[3];
static int inputs[3];
static int output;
static char **arguments;
__attribute__((noinline)) void checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void worker_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void second_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void newborn_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void after_exec_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void done_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void watch_increment(void) {
    __asm__ volatile(".global watch_store\nwatch_store:\nlock incl watched(%%rip)\n.global watch_after\nwatch_after:" : : : "memory", "cc");
}
static void fail(void) { _exit(91); }
static void announce(const char *name) {
    char buffer[128];
    int n = snprintf(buffer, sizeof(buffer), "%s %d %d %d\n", name, tids[0], tids[1], tids[2]);
    if (write(output, buffer, n) != n) fail();
}
static void take(int index) {
    char value;
    ssize_t n;
    do { n = read(inputs[index], &value, 1); } while (n < 0 && errno == EINTR);
    if (n != 1) fail();
}
static void ready_wait(int index) {
    while (!atomic_load_explicit(&ready[index], memory_order_acquire))
        syscall(SYS_futex, &ready[index], FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
}
static void *worker(void *argument) {
    int index = (int)(intptr_t)argument;
    tids[index] = (int)syscall(SYS_gettid);
    atomic_store_explicit(&ready[index], 1, memory_order_release);
    syscall(SYS_futex, &ready[index], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    for (int phase = 0; phase < 2; ++phase) {
        take(index);
        if (!strcmp(arguments[1], "exec")) {
            execl(arguments[0], arguments[0], "afterexec", arguments[2], arguments[3], arguments[4], arguments[5], (char *)0);
            fail();
        }
        watch_increment();
        atomic_fetch_add_explicit(&counters[index], 1, memory_order_relaxed);
        if (!phase) worker_checkpoint(); else second_checkpoint();
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 6) return 90;
    arguments = argv;
    for (int index = 0; index < 3; ++index) {
        inputs[index] = open(argv[index + 2], O_RDONLY);
        if (inputs[index] < 0) fail();
    }
    output = open(argv[5], O_WRONLY);
    if (output < 0) fail();
    tids[0] = (int)syscall(SYS_gettid);
    if (!strcmp(argv[1], "afterexec")) {
        announce("EXECREADY");
        after_exec_checkpoint();
        take(0);
        watch_increment();
        worker_checkpoint();
        take(0);
        watch_increment();
        done_checkpoint();
        return atomic_load(&watched) == 2 ? 0 : 92;
    }
    pthread_t threads[3];
    int count = !strcmp(argv[1], "newborn") || !strcmp(argv[1], "exec") ? 1 : 2;
    for (int index = 1; index <= count; ++index) {
        if (pthread_create(&threads[index], 0, worker, (void *)(intptr_t)index)) fail();
        ready_wait(index);
    }
    announce("READY");
    checkpoint();
    take(0);
    if (!strcmp(argv[1], "newborn")) {
        if (pthread_create(&threads[2], 0, worker, (void *)(intptr_t)2)) fail();
        ready_wait(2);
        count = 2;
        announce("CREATED");
        newborn_checkpoint();
    }
    for (int index = 1; index <= count; ++index) if (pthread_join(threads[index], 0)) fail();
    announce("DONE");
    done_checkpoint();
    for (int index = 1; index <= count; ++index) if (atomic_load(&counters[index]) != 2) return 93;
    return atomic_load(&watched) == 2 * count ? 0 : 94;
}
`

func newWatchThreadFixture(t *testing.T) *threadFixture {
	t.Helper()
	tmp, err := filepath.Abs(filepath.Join("..", ".cache", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	dir := t.TempDir()
	f := &threadFixture{path: filepath.Join(dir, "watch-threads"), symbols: make(map[string]target.Address)}
	if err := os.WriteFile(f.path+".c", []byte(watchThreadSource), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "cc", "-std=gnu11", "-O0", "-g", "-no-pie", "-pthread", "-Wl,--build-id=none", "-o", f.path, f.path+".c").CombinedOutput(); err != nil {
		t.Fatalf("build watchpoint fixture: %v\n%s", err, output)
	}
	binary, err := elf.Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	symbols, err := binary.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range symbols {
		f.symbols[symbol.Name] = target.Address(symbol.Value)
	}
	for index := 0; index < 4; index++ {
		path := filepath.Join(dir, fmt.Sprintf("channel-%d", index))
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		f.paths = append(f.paths, path)
		if index < 3 {
			f.inputs[index] = file
		} else {
			f.output, f.reader = file, bufio.NewReader(file)
		}
	}
	return f
}

func watchLaunch(t *testing.T, path string) *native.Session {
	t.Helper()
	s, err := threadCall(t, func() (*native.Session, error) { return native.Launch(path) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, s, true)
	return s
}

func watchAssembly(t *testing.T, bits int, body string, high bool) (string, map[string]target.Address) {
	t.Helper()
	exit := "mov $60, %eax\nxor %edi, %edi\nsyscall\n"
	if bits == 32 {
		exit = "mov $1, %eax\nxor %ebx, %ebx\nint $0x80\n"
	}
	source := ".data\n.balign 8\n.space 8\n.global watched\nwatched: .zero 64\n.text\n.global _start\n_start:\n" + body + exit
	if bits == 32 {
		return x86Fixture(t, source, high)
	}
	return nativeFixture(t, source)
}

func watchOperand(bits, offset int) string {
	result := fmt.Sprintf("watched%+d", offset)
	if bits == 64 {
		result += "(%rip)"
	}
	return result
}

func watchThread(t *testing.T, s *native.Session) target.ThreadInfo {
	t.Helper()
	snapshot := threadStopped(t, s, 1)
	for _, thread := range snapshot.Threads {
		if thread.State == target.StateStopped && !thread.Exiting {
			return thread
		}
	}
	t.Fatal("stopped watchpoint thread missing")
	return target.ThreadInfo{}
}

func watchSet(t *testing.T, s *native.Session, token target.ThreadToken, request target.WatchpointRequest) target.WatchpointResult {
	t.Helper()
	before := threadSnapshot(t, s)
	result, err := threadCall(t, func() (target.WatchpointResult, error) { return s.SetWatchpoint(token, request) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Ref.Thread != token.Thread || result.Ref.Slot != request.Slot || result.Ref.Generation == 0 || result.Token.Thread != token.Thread || result.Token.Stop != token.Stop || result.Token.Registers <= token.Registers {
		t.Fatalf("invalid watchpoint identity/token: before=%+v result=%+v", token, result)
	}
	after := threadSnapshot(t, s)
	if after.Memory != before.Memory {
		t.Fatalf("debug-register write changed memory token: before=%+v after=%+v", before.Memory, after.Memory)
	}
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(token) }); !errors.Is(err, target.ErrStale) {
		t.Fatalf("debug-register write retained old register token: %v", err)
	}
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(result.Token) }); err != nil {
		t.Fatalf("new watchpoint token is unusable: %v", err)
	}
	return result
}

func watchClear(t *testing.T, s *native.Session, token target.ThreadToken, ref target.WatchpointRef) target.ThreadToken {
	t.Helper()
	before := threadSnapshot(t, s)
	updated, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearWatchpoint(token, ref) })
	if err != nil {
		t.Fatal(err)
	}
	if updated.Thread != token.Thread || updated.Stop != token.Stop || updated.Registers <= token.Registers {
		t.Fatalf("clear did not invalidate register token: old=%+v new=%+v", token, updated)
	}
	if after := threadSnapshot(t, s); after.Memory != before.Memory {
		t.Fatalf("clear changed memory token: before=%+v after=%+v", before.Memory, after.Memory)
	}
	return updated
}

func watchHit(ref target.WatchpointRef, request target.WatchpointRequest) target.WatchpointHit {
	return target.WatchpointHit{Ref: ref, Address: request.Address, Size: request.Size, Access: request.Access}
}

func watchStop(t *testing.T, s *native.Session, result target.RunResult, pc target.Address, completed bool, hits ...target.WatchpointHit) {
	t.Helper()
	stop := result.Stop
	if stop.Reason != target.StopWatchpoint || stop.RawPC == nil || *stop.RawPC != pc || stop.StepCompleted != completed || len(stop.Watchpoints) != len(hits) || stop.RawDR6 == nil {
		var rawPC target.Address
		if stop.RawPC != nil {
			rawPC = *stop.RawPC
		}
		t.Fatalf("watchpoint stop: pc=%#x want=%#x completed=%t want=%t hits=%+v want=%+v stop=%+v", rawPC, pc, stop.StepCompleted, completed, stop.Watchpoints, hits, stop)
	}
	mask := uint64(0)
	for _, want := range hits {
		found := 0
		for _, got := range stop.Watchpoints {
			if got == want {
				found++
			}
		}
		if found != 1 || want.Ref.Thread != result.Thread {
			t.Fatalf("watchpoint hit identity: got=%+v want=%+v thread=%+v", stop.Watchpoints, want, result.Thread)
		}
		mask |= uint64(1) << want.Ref.Slot
	}
	if *stop.RawDR6&15 != mask || (*stop.RawDR6&(1<<14) != 0) != completed {
		t.Fatalf("raw DR6 lost hit or step status: %#x, hits=%#x step=%t", *stop.RawDR6, mask, completed)
	}
	registers, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(result.Token) })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, register := range registers {
		if register.Name != "rip" && register.Name != "eip" {
			continue
		}
		found = true
		var value uint64
		if register.Bits == 32 && len(register.Data) == 4 {
			value = uint64(binary.LittleEndian.Uint32(register.Data))
		} else if register.Bits == 64 && len(register.Data) == 8 {
			value = binary.LittleEndian.Uint64(register.Data)
		} else {
			t.Fatalf("invalid PC register: %+v", register)
		}
		if target.Address(value) != pc {
			t.Fatalf("watchpoint adjusted raw PC: %#x, want %#x", value, pc)
		}
	}
	if !found {
		t.Fatal("PC register missing")
	}
}

func TestNativeWatchpointRanges(t *testing.T) {
	for _, bits := range []int{64, 32} {
		for _, size := range []int{1, 2, 4, 8} {
			for _, access := range []target.WatchAccess{target.WatchWrite, target.WatchReadWrite} {
				t.Run(fmt.Sprintf("bits%d_size%d_access%d", bits, size, access), func(t *testing.T) {
					body := fmt.Sprintf("movb $1, %s\nmovb $0, %s\n.global after_first\nafter_first:\nmovzbl %s, %%eax\n.global after_read\nafter_read:\nmovb $0, %s\n.global after_last\nafter_last:\nmovb $1, %s\n",
						watchOperand(bits, -1), watchOperand(bits, 0), watchOperand(bits, 0), watchOperand(bits, size-1), watchOperand(bits, size))
					path, symbols := watchAssembly(t, bits, body, bits == 32 && size == 8)
					s := watchLaunch(t, path)
					request := target.WatchpointRequest{Slot: 0, Address: symbols["watched"], Size: size, Access: access}
					configured := watchSet(t, s, watchThread(t, s).Token, request)
					labels := []string{"after_first"}
					if access == target.WatchReadWrite {
						labels = append(labels, "after_read")
					}
					labels = append(labels, "after_last")
					for _, label := range labels {
						result := threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
						watchStop(t, s, result, symbols[label], false, watchHit(configured.Ref, request))
					}
					threadExit(t, s, 0)
				})
			}
		}
	}
}

func TestNativeWatchpointSlotsAndValidation(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(fmt.Sprintf("bits%d", bits), func(t *testing.T) {
			body := ""
			for slot := 0; slot < 4; slot++ {
				body += fmt.Sprintf("movb $0, %s\n.global after_slot%d\nafter_slot%d:\n", watchOperand(bits, slot*8), slot, slot)
			}
			path, symbols := watchAssembly(t, bits, body, bits == 32)
			s := watchLaunch(t, path)
			token := watchThread(t, s).Token
			var refs [4]target.WatchpointRef
			var requests [4]target.WatchpointRequest
			for slot := range refs {
				requests[slot] = target.WatchpointRequest{Slot: slot, Address: symbols["watched"] + target.Address(slot*8), Size: 1 << slot, Access: target.WatchWrite}
				result := watchSet(t, s, token, requests[slot])
				refs[slot], token = result.Ref, result.Token
			}
			invalid := []target.WatchpointRequest{
				{Slot: -1, Address: symbols["watched"], Size: 1, Access: target.WatchWrite},
				{Slot: 4, Address: symbols["watched"], Size: 1, Access: target.WatchWrite},
				{Slot: 0, Address: symbols["watched"], Size: 0, Access: target.WatchWrite},
				{Slot: 0, Address: symbols["watched"], Size: 3, Access: target.WatchWrite},
				{Slot: 0, Address: symbols["watched"], Size: 16, Access: target.WatchWrite},
				{Slot: 0, Address: symbols["watched"] + 1, Size: 8, Access: target.WatchWrite},
				{Slot: 0, Address: target.Address(math.MaxUint64), Size: 8, Access: target.WatchWrite},
				{Slot: 0, Address: symbols["watched"], Size: 1, Access: target.WatchUnknown},
				{Slot: 0, Address: symbols["watched"], Size: 1, Access: target.WatchAccess(255)},
			}
			if bits == 32 {
				invalid = append(invalid, target.WatchpointRequest{Slot: 0, Address: 1 << 32, Size: 1, Access: target.WatchWrite})
			}
			for _, request := range invalid {
				before := threadSnapshot(t, s)
				if _, err := threadCall(t, func() (target.WatchpointResult, error) { return s.SetWatchpoint(token, request) }); err == nil {
					t.Fatalf("invalid watchpoint accepted: %+v", request)
				}
				after := threadSnapshot(t, s)
				if after.Memory != before.Memory || watchThread(t, s).Token != token {
					t.Fatalf("invalid request changed target tokens: %+v", request)
				}
			}
			old := refs[1]
			replaced := watchSet(t, s, token, requests[1])
			refs[1], token = replaced.Ref, replaced.Token
			if refs[1].Generation <= old.Generation {
				t.Fatalf("owned slot replacement reused generation: old=%+v new=%+v", old, refs[1])
			}
			if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearWatchpoint(token, old) }); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old slot generation cleared replacement: %v", err)
			}
			old = refs[3]
			token = watchClear(t, s, token, old)
			if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearWatchpoint(token, old) }); !errors.Is(err, target.ErrStale) {
				t.Fatalf("cleared reference remained valid: %v", err)
			}
			reused := watchSet(t, s, token, requests[3])
			refs[3], token = reused.Ref, reused.Token
			if refs[3].Generation <= old.Generation {
				t.Fatalf("slot reuse lost generation: old=%+v new=%+v", old, refs[3])
			}
			for slot := range refs {
				result := threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
				watchStop(t, s, result, symbols[fmt.Sprintf("after_slot%d", slot)], false, watchHit(refs[slot], requests[slot]))
			}
			threadExit(t, s, 0)
		})
	}
}

func TestNativeWatchpointMultipleHitsAndStep(t *testing.T) {
	for _, bits := range []int{64, 32} {
		for _, step := range []bool{false, true} {
			t.Run(fmt.Sprintf("bits%d_step%t", bits, step), func(t *testing.T) {
				body := fmt.Sprintf("movw $0, %s\n.global after_store\nafter_store:\nnop\n.global after_nop\nafter_nop:\n", watchOperand(bits, 0))
				path, symbols := watchAssembly(t, bits, body, false)
				s := watchLaunch(t, path)
				token := watchThread(t, s).Token
				requests := []target.WatchpointRequest{
					{Slot: 0, Address: symbols["watched"], Size: 2, Access: target.WatchWrite},
					{Slot: 2, Address: symbols["watched"] + 1, Size: 1, Access: target.WatchReadWrite},
					{Slot: 3, Address: symbols["watched"], Size: 8, Access: target.WatchWrite},
				}
				var hits []target.WatchpointHit
				for _, request := range requests {
					configured := watchSet(t, s, token, request)
					token = configured.Token
					hits = append(hits, watchHit(configured.Ref, request))
				}
				var result target.RunResult
				if step {
					run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(target.StepRequest{Thread: token.Thread}) })
					if err != nil {
						t.Fatal(err)
					}
					result = threadWait(t, run)
				} else {
					result = threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
				}
				watchStop(t, s, result, symbols["after_store"], step, hits...)
				token = watchThread(t, s).Token
				for _, hit := range hits {
					token = watchClear(t, s, token, hit.Ref)
				}
				run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(target.StepRequest{Thread: token.Thread}) })
				if err != nil {
					t.Fatal(err)
				}
				result = threadWait(t, run)
				if result.Stop.Reason != target.StopStep || !result.Stop.StepCompleted || len(result.Stop.Watchpoints) != 0 || result.Stop.RawPC == nil || *result.Stop.RawPC != symbols["after_nop"] {
					t.Fatalf("cleared watchpoint status contaminated ordinary step: %+v", result)
				}
				threadExit(t, s, 0)
			})
		}
	}
}

func TestNativeWatchpointBreakpointStepOver(t *testing.T) {
	for _, bits := range []int{64, 32} {
		for _, step := range []bool{false, true} {
			t.Run(fmt.Sprintf("bits%d_step%t", bits, step), func(t *testing.T) {
				body := fmt.Sprintf(".global store_site\nstore_site:\nincb %s\n.global after_store\nafter_store:\nnop\ncmpb $1, %s\nje verified\nud2\nverified:\n", watchOperand(bits, 0), watchOperand(bits, 0))
				path, symbols := watchAssembly(t, bits, body, false)
				s := watchLaunch(t, path)
				request := target.WatchpointRequest{Slot: 1, Address: symbols["watched"], Size: 1, Access: target.WatchWrite}
				configured := watchSet(t, s, watchThread(t, s).Token, request)
				threadCommand(t, func() error { return s.AddBreakpoint(symbols["store_site"]) })
				threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), symbols["store_site"])
				var result target.RunResult
				if step {
					run, err := threadCall(t, func() (*native.Run, error) {
						return s.StepInstruction(target.StepRequest{Thread: configured.Ref.Thread})
					})
					if err != nil {
						t.Fatal(err)
					}
					result = threadWait(t, run)
				} else {
					result = threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
				}
				watchStop(t, s, result, symbols["after_store"], true, watchHit(configured.Ref, request))
				snapshot := threadSnapshot(t, s)
				var code, value [1]byte
				if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, symbols["store_site"], code[:]) }); err != nil || n != 1 || code[0] != 0xcc {
					t.Fatalf("watchpoint stop exposed unarmed software breakpoint: %x, %d, %v", code, n, err)
				}
				if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, symbols["watched"], value[:]) }); err != nil || n != 1 || value[0] != 1 {
					t.Fatalf("breakpoint/watchpoint instruction lost or repeated: %x, %d, %v", value, n, err)
				}
				threadCommand(t, func() error { return s.RemoveBreakpoint(symbols["store_site"]) })
				watchClear(t, s, watchThread(t, s).Token, configured.Ref)
				threadExit(t, s, 0)
			})
		}
	}
}

func TestNativeWatchpointDoesNotConsumeOtherTraps(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(fmt.Sprintf("bits%d", bits), func(t *testing.T) {
			body := fmt.Sprintf("movb $1, %s\n.global after_store\nafter_store:\n.byte 0xf1\n.global after_icebp\nafter_icebp:\n.byte 0xcc\n.global after_int3\nafter_int3:\n", watchOperand(bits, 0))
			path, symbols := watchAssembly(t, bits, body, false)
			s := watchLaunch(t, path)
			request := target.WatchpointRequest{Slot: 0, Address: symbols["watched"], Size: 1, Access: target.WatchWrite}
			configured := watchSet(t, s, watchThread(t, s).Token, request)
			watchStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), symbols["after_store"], false, watchHit(configured.Ref, request))
			run, err := threadCall(t, func() (*native.Run, error) {
				return s.StepInstruction(target.StepRequest{Thread: configured.Ref.Thread})
			})
			if err != nil {
				t.Fatal(err)
			}
			result := threadWait(t, run)
			for _, label := range []string{"after_icebp", "after_int3"} {
				if result.Stop.Reason != target.StopSignal || result.Stop.Signal.Number != uint32(unix.SIGTRAP) || len(result.Stop.Watchpoints) != 0 || result.Stop.RawPC == nil || *result.Stop.RawPC != symbols[label] {
					t.Fatalf("stale hardware status consumed %s: %+v", label, result)
				}
				thread := watchThread(t, s)
				run = threadStart(t, s, target.RunRequest{Threads: threadExact(thread.Ref), Signals: []target.ThreadSignal{{Thread: thread.Ref, Stop: thread.Token.Stop}}})
				result = threadWait(t, run)
			}
			if result.Stop.Reason != target.StopExited || result.Stop.ExitCode == nil || *result.Stop.ExitCode != 0 {
				t.Fatalf("trap fixture termination: %+v", result)
			}
		})
	}
}

func watchSharedValue(t *testing.T, s *native.Session, f *threadFixture) uint32 {
	t.Helper()
	snapshot := threadSnapshot(t, s)
	var data [4]byte
	n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, f.address(t, "watched"), data[:]) })
	if err != nil || n != len(data) {
		t.Fatalf("read watched shared value: %d, %v", n, err)
	}
	return binary.LittleEndian.Uint32(data[:])
}

func TestNativeWatchpointIsThreadLocal(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "existing")
	snapshot, tids := threadInitial(t, s, f, 3)
	a, b := threadByTID(t, snapshot, tids[1]), threadByTID(t, snapshot, tids[2])
	request := target.WatchpointRequest{Slot: 0, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite}
	configured := watchSet(t, s, a.Token, request)
	checkpoint, done := f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(checkpoint) })
	threadCommand(t, func() error { return s.AddBreakpoint(done) })
	f.send(t, 2, 'g')
	threadBreakpoint(t, threadRun(t, s, threadExact(b.Ref)), checkpoint)
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("unconfigured peer did not finish its write: %d", value)
	}
	f.send(t, 1, 'g')
	result := threadRun(t, s, threadExact(a.Ref))
	watchStop(t, s, result, f.address(t, "watch_after"), false, watchHit(configured.Ref, request))
	if value := watchSharedValue(t, s, f); value != 2 {
		t.Fatalf("configured thread's write was lost: %d", value)
	}
	watchClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[1]).Token, configured.Ref)
	threadBreakpoint(t, threadRun(t, s, threadExact(a.Ref)), checkpoint)
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	for index := range f.inputs {
		f.send(t, index, 'g')
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	f.receive(t, "DONE")
	if value := watchSharedValue(t, s, f); value != 4 {
		t.Fatalf("thread-local watchpoint duplicated an instruction: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}

func TestNativeWatchpointNewbornIsUnconfigured(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "newborn")
	snapshot, tids := threadInitial(t, s, f, 2)
	parent := threadByTID(t, snapshot, tids[0])
	request := target.WatchpointRequest{Slot: 0, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite}
	parentWatch := watchSet(t, s, parent.Token, request)
	newborn, checkpoint, done := f.address(t, "newborn_checkpoint"), f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	for _, address := range []target.Address{newborn, checkpoint, done} {
		threadCommand(t, func() error { return s.AddBreakpoint(address) })
	}
	f.send(t, 0, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), newborn)
	tids = f.receive(t, "CREATED")
	snapshot = threadStopped(t, s, 3)
	child := threadByTID(t, snapshot, tids[2])
	threadCommand(t, func() error { return s.RemoveBreakpoint(newborn) })
	f.send(t, 2, 'g')
	threadBreakpoint(t, threadRun(t, s, threadExact(child.Ref)), checkpoint)
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("newborn did not execute unconfigured write: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	child = threadByTID(t, threadSnapshot(t, s), tids[2])
	request.Slot = 2
	childWatch := watchSet(t, s, child.Token, request)
	f.send(t, 2, 'g')
	watchStop(t, s, threadRun(t, s, threadExact(child.Ref)), f.address(t, "watch_after"), false, watchHit(childWatch.Ref, request))
	watchClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[2]).Token, childWatch.Ref)
	watchClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[0]).Token, parentWatch.Ref)
	f.send(t, 1, 'g')
	f.send(t, 1, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	f.receive(t, "DONE")
	if value := watchSharedValue(t, s, f); value != 4 {
		t.Fatalf("newborn watchpoint execution count: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}

func TestNativeWatchpointExecInvalidation(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "exec")
	snapshot, tids := threadInitial(t, s, f, 2)
	parent, execer := threadByTID(t, snapshot, tids[0]), threadByTID(t, snapshot, tids[1])
	request := target.WatchpointRequest{Slot: 1, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite}
	watchSet(t, s, parent.Token, request)
	old := watchSet(t, s, execer.Token, request)
	f.send(t, 1, 'g')
	result := threadRun(t, s, threadExact(execer.Ref))
	if result.Stop.Reason != target.StopExec || len(result.Stop.Watchpoints) != 0 {
		t.Fatalf("exec inherited stale watchpoint stop: %+v", result)
	}
	execThread := watchThread(t, s)
	if execThread.TID != s.PID() {
		t.Fatalf("non-leader exec identity: %+v", execThread)
	}
	if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearWatchpoint(execThread.Token, old.Ref) }); !errors.Is(err, target.ErrStale) {
		t.Fatalf("exec retained old watchpoint reference: %v", err)
	}
	afterExec, checkpoint, done := f.address(t, "after_exec_checkpoint"), f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	for _, address := range []target.Address{afterExec, checkpoint, done} {
		threadCommand(t, func() error { return s.AddBreakpoint(address) })
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), afterExec)
	f.receive(t, "EXECREADY")
	threadCommand(t, func() error { return s.RemoveBreakpoint(afterExec) })
	f.send(t, 0, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), checkpoint)
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("new image did not execute with cleared hardware slots: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	fresh := watchSet(t, s, watchThread(t, s).Token, request)
	if fresh.Ref.Thread == old.Ref.Thread && fresh.Ref.Generation <= old.Ref.Generation {
		t.Fatalf("exec reused watchpoint generation: old=%+v new=%+v", old.Ref, fresh.Ref)
	}
	f.send(t, 0, 'g')
	watchStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), f.address(t, "watch_after"), false, watchHit(fresh.Ref, request))
	watchClear(t, s, watchThread(t, s).Token, fresh.Ref)
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}

func TestNativeWatchpointDetachAndClose(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(fmt.Sprintf("attached_close_%t", closeSession), func(t *testing.T) {
			f := newWatchThreadFixture(t)
			cmd := f.start(t, "existing")
			tids := f.receive(t, "READY")
			s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
			if err != nil {
				t.Fatal(err)
			}
			threadSessionCleanup(t, s, false)
			snapshot := threadStopped(t, s, 3)
			a, b := threadByTID(t, snapshot, tids[1]), threadByTID(t, snapshot, tids[2])
			request := target.WatchpointRequest{Slot: 0, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite}
			configured := watchSet(t, s, a.Token, request)
			peerRequest := request
			peerRequest.Slot = 3
			watchSet(t, s, b.Token, peerRequest)
			threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, "worker_checkpoint")) })
			f.send(t, 1, 'g')
			watchStop(t, s, threadRun(t, s, threadExact(a.Ref)), f.address(t, "watch_after"), false, watchHit(configured.Ref, request))
			if closeSession {
				threadCommand(t, s.Close)
				if s.State() != target.StateClosed {
					t.Fatalf("attached close state: %s", s.State())
				}
			} else {
				threadCommand(t, s.Detach)
				if s.State() != target.StateDetached {
					t.Fatalf("attached detach state: %s", s.State())
				}
			}
			f.send(t, 0, 'g')
			f.send(t, 1, 'g')
			f.send(t, 2, 'g')
			f.send(t, 2, 'g')
			f.receive(t, "DONE")
			threadCommand(t, cmd.Wait)
		})
	}
	t.Run("owned_pending_run", func(t *testing.T) {
		f := newWatchThreadFixture(t)
		s := f.launch(t, "existing")
		snapshot, tids := threadInitial(t, s, f, 3)
		for index := 1; index <= 2; index++ {
			request := target.WatchpointRequest{Slot: index, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite}
			watchSet(t, s, threadByTID(t, snapshot, tids[index]).Token, request)
		}
		run := threadStart(t, s, target.RunRequest{Threads: threadProcessSet(threadSnapshot(t, s))})
		threadCommand(t, s.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, err := run.Wait(ctx)
		if err != nil && !errors.Is(err, target.ErrClosed) && !errors.Is(err, target.ErrExited) {
			t.Fatalf("close left watchpoint run pending: %+v, %v", result, err)
		}
		if s.State() != target.StateClosed {
			t.Fatalf("owned close state: %s", s.State())
		}
	})
}

func watchDebugWrite(pid, register int, value uint64) error {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	n, err := unix.PtracePokeUser(pid, uintptr(848+8*register), data[:])
	if err == nil && n != len(data) {
		err = fmt.Errorf("debug register short write: %d", n)
	}
	return err
}

func watchDebugRead(pid, register int) (uint64, error) {
	var data [8]byte
	n, err := unix.PtracePeekUser(pid, uintptr(848+8*register), data[:])
	if err != nil {
		return 0, err
	}
	if n != len(data) {
		return 0, fmt.Errorf("debug register short read: %d", n)
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

func watchRawStop(pid int) error {
	var status unix.WaitStatus
	for {
		got, err := unix.Wait4(pid, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if got != pid || !status.Stopped() {
			return fmt.Errorf("raw fixture stop: pid=%d status=%#x", got, uint32(status))
		}
		return nil
	}
}

func TestNativeWatchpointForeignBankIsPreserved(t *testing.T) {
	f := newWatchThreadFixture(t)
	cmd := &threadProcess{Cmd: exec.Command(f.path, f.args("existing")...), done: make(chan struct{})}
	cmd.SysProcAttr = &unix.SysProcAttr{Ptrace: true}
	address := uint64(f.address(t, "watched"))
	control := uint64(1 | 13<<16)
	_, err := threadCall(t, func() (struct{}, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			return struct{}{}, err
		}
		t.Cleanup(func() {
			select {
			case <-cmd.done:
			default:
				_ = cmd.Process.Kill()
				_, _ = threadCall(t, func() (struct{}, error) { return struct{}{}, cmd.Wait() })
			}
		})
		if err := watchRawStop(cmd.Process.Pid); err != nil {
			return struct{}{}, err
		}
		if err := watchDebugWrite(cmd.Process.Pid, 0, address); err != nil {
			return struct{}{}, err
		}
		if err := watchDebugWrite(cmd.Process.Pid, 7, control); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, unix.PtraceDetach(cmd.Process.Pid)
	})
	if err != nil {
		t.Fatal(err)
	}
	tids := f.receive(t, "READY")
	s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, s, false)
	before := threadStopped(t, s, 3)
	parent := threadByTID(t, before, tids[0])
	request := target.WatchpointRequest{Slot: 2, Address: target.Address(address), Size: 4, Access: target.WatchWrite}
	if _, err := threadCall(t, func() (target.WatchpointResult, error) { return s.SetWatchpoint(parent.Token, request) }); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("foreign active bank was modified through a free slot: %v", err)
	}
	after := threadSnapshot(t, s)
	if after.Memory != before.Memory || threadByTID(t, after, tids[0]).Token != parent.Token {
		t.Fatalf("foreign-bank rejection modified target tokens: before=%+v after=%+v", before, after)
	}
	threadCommand(t, s.Detach)
	_, err = threadCall(t, func() (struct{}, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		pid := cmd.Process.Pid
		if err := unix.PtraceSeize(pid); err != nil {
			return struct{}{}, err
		}
		if err := unix.PtraceInterrupt(pid); err != nil {
			return struct{}{}, err
		}
		if err := watchRawStop(pid); err != nil {
			return struct{}{}, err
		}
		defer unix.PtraceDetach(pid)
		for slot := 0; slot < 4; slot++ {
			actualAddress, err := watchDebugRead(pid, slot)
			if err != nil {
				return struct{}{}, err
			}
			want := uint64(0)
			if slot == 0 {
				want = address
			}
			if actualAddress != want {
				return struct{}{}, fmt.Errorf("foreign debug state changed: DR%d=%#x want=%#x", slot, actualAddress, want)
			}
		}
		actualControl, err := watchDebugRead(pid, 7)
		if err != nil {
			return struct{}{}, err
		}
		if actualControl != control {
			return struct{}{}, fmt.Errorf("foreign debug state changed: DR7=%#x want=%#x", actualControl, control)
		}
		if err := watchDebugWrite(pid, 7, 0); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, watchDebugWrite(pid, 0, 0)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.send(t, 0, 'g')
	for index := 1; index <= 2; index++ {
		f.send(t, index, 'g')
		f.send(t, index, 'g')
	}
	f.receive(t, "DONE")
	threadCommand(t, cmd.Wait)
}

func watchRegisterValue(name string, bits int, value uint64) target.Register {
	data := make([]byte, bits/8)
	if bits == 32 {
		binary.LittleEndian.PutUint32(data, uint32(value))
	} else {
		binary.LittleEndian.PutUint64(data, value)
	}
	return target.Register{Name: name, Bits: bits, Data: data, Available: true}
}

func TestNativeWatchpointEntryStepPreservesInstruction(t *testing.T) {
	for _, bits := range []int{64, 32} {
		cases := []struct {
			name    string
			body    string
			reason  target.StopReason
			offset  target.Address
			ownedBP bool
			movePC  bool
			syscall bool
		}{
			{name: "icebp", body: ".byte 0xf1\n", reason: target.StopSignal, offset: 1},
			{name: "int3", body: ".byte 0xcc\n", reason: target.StopSignal, offset: 1},
			{name: "self_branch", body: "loop _start\n", reason: target.StopStep},
			{name: "owned_breakpoint", body: "nop\n", reason: target.StopBreakpoint, offset: 1, ownedBP: true},
			{name: "changed_pc_self_branch", body: "nop\n.global alternate_entry\nalternate_entry:\nloop alternate_entry\n", reason: target.StopStep, movePC: true},
		}
		if bits == 64 {
			cases = append(cases, struct {
				name    string
				body    string
				reason  target.StopReason
				offset  target.Address
				ownedBP bool
				movePC  bool
				syscall bool
			}{name: "read_bad_fd", body: "syscall\n", reason: target.StopStep, offset: 2, syscall: true})
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("bits%d_%s", bits, tc.name), func(t *testing.T) {
				trailer := ".global after_first\nafter_first:\nnop\n"
				if tc.syscall {
					trailer = fmt.Sprintf(".global after_first\nafter_first:\nincb %s\n.global after_followup\nafter_followup:\nnop\n", watchOperand(bits, 0))
				}
				path, symbols := watchAssembly(t, bits, tc.body+trailer, false)
				s := watchLaunch(t, path)
				request := target.WatchpointRequest{Slot: 0, Address: symbols["watched"], Size: 1, Access: target.WatchWrite}
				configured := watchSet(t, s, watchThread(t, s).Token, request)
				site := symbols["_start"]
				pcName := "rip"
				if bits == 32 {
					pcName = "eip"
				}
				if tc.movePC {
					site = symbols["alternate_entry"]
					threadCommand(t, func() error {
						return s.WriteThreadRegisters(watchThread(t, s).Token, []target.Register{watchRegisterValue(pcName, bits, uint64(site))})
					})
				}
				if tc.reason == target.StopStep && tc.offset == 0 {
					counter := "rcx"
					if bits == 32 {
						counter = "ecx"
					}
					threadCommand(t, func() error {
						return s.WriteThreadRegisters(watchThread(t, s).Token, []target.Register{watchRegisterValue(counter, bits, 2)})
					})
				}
				if tc.syscall {
					threadCommand(t, func() error {
						return s.WriteThreadRegisters(watchThread(t, s).Token, []target.Register{
							watchRegisterValue("rax", 64, 0), watchRegisterValue("rdi", 64, math.MaxUint64),
							watchRegisterValue("rsi", 64, 0), watchRegisterValue("rdx", 64, 0),
						})
					})
				}
				snapshot := threadSnapshot(t, s)
				var original [1]byte
				if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, site, original[:]) }); err != nil || n != 1 {
					t.Fatalf("entry instruction read: %d, %v", n, err)
				}
				if tc.ownedBP {
					threadCommand(t, func() error { return s.AddBreakpoint(site) })
				}
				run, err := threadCall(t, func() (*native.Run, error) {
					return s.StepInstruction(target.StepRequest{Thread: configured.Ref.Thread})
				})
				if err != nil {
					t.Fatal(err)
				}
				result := threadWait(t, run)
				if result.Stop.Reason != tc.reason || result.Stop.RawPC == nil || *result.Stop.RawPC != site+tc.offset || len(result.Stop.Watchpoints) != 0 {
					var pc target.Address
					if result.Stop.RawPC != nil {
						pc = *result.Stop.RawPC
					}
					t.Fatalf("entry step consumed a real instruction/trap: PC=%#x want=%#x stop=%+v", pc, site+tc.offset, result.Stop)
				}
				if tc.reason == target.StopStep && !result.Stop.StepCompleted {
					t.Fatal("actual entry instruction did not complete its step")
				}
				if tc.reason == target.StopStep && tc.offset == 0 {
					counter := "rcx"
					if bits == 32 {
						counter = "ecx"
					}
					registers, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(watchThread(t, s).Token) })
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, register := range registers {
						if register.Name != counter {
							continue
						}
						found = true
						value := uint64(0)
						if bits == 32 {
							value = uint64(binary.LittleEndian.Uint32(register.Data))
						} else {
							value = binary.LittleEndian.Uint64(register.Data)
						}
						if value != 1 {
							t.Fatalf("same-PC step did not execute exactly one LOOP: %s=%d", counter, value)
						}
					}
					if !found {
						t.Fatalf("loop counter register %s missing", counter)
					}
				}
				if tc.reason == target.StopSignal && result.Stop.Signal.Number != uint32(unix.SIGTRAP) {
					t.Fatalf("entry trap signal changed: %+v", result.Stop)
				}
				if tc.syscall {
					if value := threadRegister(t, s, watchThread(t, s).Token, "rax"); value != ^uint64(uint64(unix.EBADF)-1) {
						t.Fatalf("entry read(-1) syscall result: %#x", value)
					}
					run, err := threadCall(t, func() (*native.Run, error) {
						return s.StepInstruction(target.StepRequest{Thread: configured.Ref.Thread})
					})
					if err != nil {
						t.Fatal(err)
					}
					result = threadWait(t, run)
					watchStop(t, s, result, symbols["after_followup"], true, watchHit(configured.Ref, request))
					snapshot := threadSnapshot(t, s)
					var value [1]byte
					if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, symbols["watched"], value[:]) }); err != nil || n != 1 || value[0] != 1 {
						t.Fatalf("step after syscall did not execute one store: %x, %d, %v", value, n, err)
					}
				}
				snapshot = threadSnapshot(t, s)
				var restored [1]byte
				if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, site, restored[:]) }); err != nil || n != 1 {
					t.Fatalf("entry instruction restoration read: %d, %v", n, err)
				}
				want := original[0]
				if tc.ownedBP {
					want = 0xcc
				}
				if restored[0] != want {
					t.Fatalf("entry guard altered user code/breakpoint: got=%#x want=%#x", restored[0], want)
				}
				if tc.ownedBP {
					threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
				}
				if tc.reason == target.StopStep && tc.offset == 0 {
					threadCommand(t, func() error {
						return s.WriteThreadRegisters(watchThread(t, s).Token, []target.Register{watchRegisterValue(pcName, bits, uint64(symbols["after_first"]))})
					})
				}
				watchClear(t, s, watchThread(t, s).Token, configured.Ref)
				if tc.reason == target.StopSignal {
					thread := watchThread(t, s)
					run := threadStart(t, s, target.RunRequest{Threads: threadExact(thread.Ref), Signals: []target.ThreadSignal{{Thread: thread.Ref, Stop: thread.Token.Stop}}})
					result := threadWait(t, run)
					if result.Stop.Reason != target.StopExited || result.Stop.ExitCode == nil || *result.Stop.ExitCode != 0 {
						t.Fatalf("entry trap suppression did not resume cleanly: %+v", result)
					}
				} else {
					threadExit(t, s, 0)
				}
			})
		}
	}
}

func TestNativeWatchpointEntryStepPendingSignal(t *testing.T) {
	body := "incb watched(%rip)\n.global after_store\nafter_store:\nnop\n"
	path, symbols := watchAssembly(t, 64, body, false)
	s := watchLaunch(t, path)
	request := target.WatchpointRequest{Slot: 0, Address: symbols["watched"], Size: 1, Access: target.WatchWrite}
	configured := watchSet(t, s, watchThread(t, s).Token, request)
	threadCommand(t, func() error { return unix.Tgkill(s.PID(), s.PID(), unix.SIGUSR1) })
	run, err := threadCall(t, func() (*native.Run, error) {
		return s.StepInstruction(target.StepRequest{Thread: configured.Ref.Thread})
	})
	if err != nil {
		t.Fatal(err)
	}
	result := threadWait(t, run)
	if result.Stop.Reason != target.StopSignal || result.Stop.Signal.Number != uint32(unix.SIGUSR1) || result.Stop.StepCompleted || len(result.Stop.Watchpoints) != 0 {
		t.Fatalf("pending signal was hidden by entry step: %+v", result)
	}
	snapshot := threadSnapshot(t, s)
	var original, value [1]byte
	if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, symbols["_start"], original[:]) }); err != nil || n != 1 || original[0] != 0xfe {
		t.Fatalf("published signal stop retained an entry INT3: %x, %d, %v", original, n, err)
	}
	if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, symbols["watched"], value[:]) }); err != nil || n != 1 || value[0] != 0 {
		t.Fatalf("entry instruction ran before pending signal delivery: %x, %d, %v", value, n, err)
	}
	thread := watchThread(t, s)
	run, err = threadCall(t, func() (*native.Run, error) {
		return s.StepInstruction(target.StepRequest{Thread: thread.Ref, Signals: []target.ThreadSignal{{Thread: thread.Ref, Stop: thread.Token.Stop}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	watchStop(t, s, threadWait(t, run), symbols["after_store"], true, watchHit(configured.Ref, request))
	snapshot = threadSnapshot(t, s)
	if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, symbols["watched"], value[:]) }); err != nil || n != 1 || value[0] != 1 {
		t.Fatalf("suppressed entry signal caused missing/duplicate instruction: %x, %d, %v", value, n, err)
	}
	watchClear(t, s, watchThread(t, s).Token, configured.Ref)
	threadExit(t, s, 0)
}

func TestNativeWatchpointNewbornFirstStepAfterPCWrite(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "newborn")
	snapshot, tids := threadInitial(t, s, f, 2)
	parent := threadByTID(t, snapshot, tids[0])
	checkpoint, done := f.address(t, "newborn_checkpoint"), f.address(t, "done_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(checkpoint) })
	threadCommand(t, func() error { return s.AddBreakpoint(done) })
	f.send(t, 0, 'g')
	run := threadStart(t, s, target.RunRequest{Threads: threadExact(parent.Ref)})
	known := make(map[target.ThreadRef]bool)
	for _, thread := range snapshot.Threads {
		known[thread.Ref] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var childRef target.ThreadRef
	for sequence := snapshot.Sequence; childRef.ID == 0; {
		event, err := s.NextEvent(ctx, sequence)
		if err != nil {
			t.Fatal(err)
		}
		sequence = event.Sequence
		if event.Kind == target.EventThreadCreated && !known[event.Thread] {
			childRef = event.Thread
		}
	}
	threadCommand(t, func() error { return s.Interrupt(target.InterruptRequest{Threads: threadProcessSet(snapshot)}) })
	if result := threadWait(t, run); result.Stop.Reason != target.StopInterrupt {
		t.Fatalf("hold newborn before first instruction: %+v", result)
	}
	snapshot = threadStopped(t, s, 3)
	var child target.ThreadInfo
	for _, thread := range snapshot.Threads {
		if thread.Ref == childRef {
			child = thread
		}
	}
	if child.TID == 0 {
		t.Fatalf("newborn thread identity missing: %+v", snapshot)
	}
	if ready := threadValues(t, s, f, "ready"); ready != [3]uint32{0, 1, 0} {
		t.Fatalf("newborn already executed user code: %v", ready)
	}
	originalPC := threadRegister(t, s, child.Token, "rip")
	originalFlags := threadRegister(t, s, child.Token, "eflags")
	request := target.WatchpointRequest{Slot: 2, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite}
	configured := watchSet(t, s, child.Token, request)
	threadCommand(t, func() error {
		return s.WriteThreadRegisters(configured.Token, []target.Register{watchRegisterValue("rip", 64, uint64(f.address(t, "watch_store")))})
	})
	run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(target.StepRequest{Thread: child.Ref}) })
	if err != nil {
		t.Fatal(err)
	}
	watchStop(t, s, threadWait(t, run), f.address(t, "watch_after"), true, watchHit(configured.Ref, request))
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("newborn first step did not execute exactly one probe instruction: %d", value)
	}
	if ready := threadValues(t, s, f, "ready"); ready != [3]uint32{0, 1, 0} {
		t.Fatalf("newborn first step escaped probe instruction: %v", ready)
	}
	token := watchClear(t, s, threadByTID(t, threadSnapshot(t, s), child.TID).Token, configured.Ref)
	threadCommand(t, func() error {
		return s.WriteThreadRegisters(token, []target.Register{watchRegisterValue("rip", 64, originalPC), watchRegisterValue("eflags", 64, originalFlags)})
	})
	snapshot = threadSnapshot(t, s)
	if n, err := threadCall(t, func() (int, error) { return s.WriteSpaceMemory(snapshot.Memory, request.Address, []byte{0, 0, 0, 0}) }); err != nil || n != 4 {
		t.Fatalf("restore probe data: %d, %v", n, err)
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), checkpoint)
	tids = f.receive(t, "CREATED")
	if tids[2] != child.TID {
		t.Fatalf("restored newborn identity changed: %v, child=%+v", tids, child)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	for index := 1; index <= 2; index++ {
		f.send(t, index, 'g')
		f.send(t, index, 'g')
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	f.receive(t, "DONE")
	if value := watchSharedValue(t, s, f); value != 4 {
		t.Fatalf("newborn register restoration changed subsequent execution: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}
