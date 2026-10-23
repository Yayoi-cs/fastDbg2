package native_test

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const blockingSource = `#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
_Atomic int ready[3];
_Atomic int returned[3];
_Atomic int release_count;
_Atomic int user_signals;
_Atomic int futex_word;
int wake_result;
int observed_site;
long results[3];
char received[3];
int tids[3];
int data_read[2];
int data_write[2];
static int inputs[3];
static int output;
static char **arguments;
static const char *mode;
extern unsigned char blocking_site;
__attribute__((noinline)) void checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void owner_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void peer_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void done_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void after_exec_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void peer_marker(void) {
    __asm__ volatile(".global peer_site\npeer_site:\nlock incl release_count(%%rip)\n.global after_peer_site\nafter_peer_site:" : : : "memory", "cc");
}
static void fail(void) { _exit(91); }
static void announce(const char *name) {
    char buffer[128];
    int n = snprintf(buffer, sizeof(buffer), "%s %d %d %d\n", name, tids[0], tids[1], tids[2]);
    if (write(output, buffer, n) != n) fail();
}
static char take(int index) {
    char value;
    ssize_t n;
    do { n = read(inputs[index], &value, 1); } while (n < 0 && errno == EINTR);
    if (n != 1) fail();
    return value;
}
static void signal_handler(int number) {
    if (number == SIGUSR1) atomic_fetch_add_explicit(&user_signals, 1, memory_order_relaxed);
}
static void ready_wait(int index) {
    while (!atomic_load_explicit(&ready[index], memory_order_acquire))
        syscall(SYS_futex, &ready[index], FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
}
__attribute__((noinline)) long blocking_call(long number, long first, long second, long third, _Atomic int *completed) {
    register long result __asm__("rax") = number;
    register long arg0 __asm__("rdi") = first;
    register long arg1 __asm__("rsi") = second;
    register long arg2 __asm__("rdx") = third;
    register long arg3 __asm__("r10") = 0;
    register _Atomic int *counter __asm__("r8") = completed;
    register long arg5 __asm__("r9") = 0;
    __asm__ volatile(".global blocking_site\nblocking_site:\nsyscall\n.global after_blocking_site\nafter_blocking_site:\nlock incl (%[counter])\n.global after_completion\nafter_completion:"
        : "+a"(result) : "D"(arg0), "S"(arg1), "d"(arg2), "r"(arg3), [counter] "r"(counter), "r"(arg5) : "rcx", "r11", "memory", "cc");
    return result;
}
static void release_readers(int count) {
    peer_marker();
    observed_site = blocking_site;
    if (!strcmp(mode, "futex")) {
        long n;
        do { n = syscall(SYS_futex, &futex_word, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0); } while (n == 0);
        if (n != 1) fail();
        wake_result = (int)n;
        return;
    }
    for (int index = 0; index < count; ++index) {
        char packet[2] = {(char)('A' + index), (char)('Z' - index)};
        if (write(data_write[index], packet, 2) != 2) fail();
    }
}
static void *cloned_writer(void *argument) {
    (void)argument;
    tids[2] = (int)syscall(SYS_gettid);
    atomic_store_explicit(&ready[0], 1, memory_order_release);
    syscall(SYS_futex, &ready[0], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    take(2);
    release_readers(1);
    return 0;
}
static void *worker(void *argument) {
    int role = (int)(intptr_t)argument;
    tids[role] = (int)syscall(SYS_gettid);
    atomic_store_explicit(&ready[role], 1, memory_order_release);
    syscall(SYS_futex, &ready[role], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    take(role);
    if (role == 1 || !strcmp(mode, "two")) {
        int index = role - 1;
        if (!strcmp(mode, "futex"))
            results[index] = blocking_call(SYS_futex, (long)&futex_word, FUTEX_WAIT_PRIVATE, 0, &returned[index]);
        else
            results[index] = blocking_call(SYS_read, data_read[index], (long)&received[index], 1, &returned[index]);
        owner_checkpoint();
        take(role);
        return 0;
    }
    if (!strcmp(mode, "exec")) {
        execl(arguments[0], arguments[0], "afterexec", arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], (char *)0);
        fail();
    }
    if (!strcmp(mode, "clone")) {
        pthread_t child;
        if (pthread_create(&child, 0, cloned_writer, 0)) fail();
        ready_wait(0);
        announce("CREATED");
        if (pthread_join(child, 0)) fail();
    } else if (strcmp(mode, "hold")) {
        release_readers(1);
    }
    peer_checkpoint();
    take(2);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 8) return 90;
    arguments = argv;
    mode = argv[1];
    for (int index = 0; index < 3; ++index) {
        inputs[index] = open(argv[index + 2], O_RDONLY);
        if (inputs[index] < 0) fail();
    }
    output = open(argv[5], O_WRONLY);
    if (output < 0) fail();
    for (int index = 0; index < 2; ++index) {
        data_read[index] = open(argv[index + 6], O_RDONLY);
        data_write[index] = open(argv[index + 6], O_WRONLY);
        if (data_read[index] < 0 || data_write[index] < 0) fail();
    }
    tids[0] = (int)syscall(SYS_gettid);
    if (!strcmp(mode, "afterexec")) { announce("EXECREADY"); after_exec_checkpoint(); return 17; }
    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    if (!strcmp(mode, "signal_restart")) action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0)) fail();
    pthread_t threads[3];
    for (int role = 1; role <= 2; ++role) {
        if (pthread_create(&threads[role], 0, worker, (void *)(intptr_t)role)) fail();
        ready_wait(role);
    }
    announce("READY");
    dprintf(output, "FDS %d %d 0\n", data_read[0], data_read[1]);
    checkpoint();
    take(0);
    if (!strcmp(mode, "two")) release_readers(2);
    for (int role = 1; role <= 2; ++role) if (pthread_join(threads[role], 0)) fail();
    int count = !strcmp(mode, "two") ? 2 : 1;
    for (int index = 0; index < count; ++index) {
        if (atomic_load(&returned[index]) != 1) return 92;
        if (!strcmp(mode, "futex")) {
            if (results[index] != 0 || wake_result != 1) return 93;
        } else {
            int interrupted = !strcmp(mode, "signal_eintr");
            if (results[index] != (interrupted ? -EINTR : 1)) return 94;
            if (received[index] != (interrupted ? 0 : 'A' + index)) return 95;
            if (fcntl(data_read[index], F_SETFL, O_NONBLOCK)) fail();
            char tail[3];
            ssize_t n = read(data_read[index], tail, sizeof(tail));
            if (interrupted) {
                if (n != 2 || tail[0] != 'A' + index || tail[1] != 'Z' - index) return 96;
            } else if (n != 1 || tail[0] != 'Z' - index) return 97;
        }
    }
    if (atomic_load(&release_count) != (strcmp(mode, "hold") ? 1 : 0)) return 98;
    if (strcmp(mode, "hold") && observed_site != (!strcmp(mode, "detach") ? 0x0f : 0xcc)) return 99;
    int delivered = !strcmp(mode, "signal_restart") || !strcmp(mode, "signal_eintr");
    if (atomic_load(&user_signals) != delivered) return 100;
    announce("DONE");
    done_checkpoint();
    return 0;
}
`

type blockingFixture struct {
	*threadFixture
	data [2]*os.File
	fds  [2]int
	bits int
}

func newBlockingFixture(t *testing.T) *blockingFixture {
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
	f := &blockingFixture{threadFixture: &threadFixture{path: filepath.Join(dir, "blocking"), symbols: make(map[string]target.Address)}, bits: 64}
	if err := os.WriteFile(f.path+".c", []byte(blockingSource), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "cc", "-std=gnu11", "-O0", "-g", "-no-pie", "-pthread", "-Wl,--build-id=none", "-o", f.path, f.path+".c").CombinedOutput(); err != nil {
		t.Fatalf("build blocking fixture: %v\n%s", err, output)
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
	for index := 0; index < 6; index++ {
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
		switch {
		case index < 3:
			f.inputs[index] = file
		case index == 3:
			f.output, f.reader = file, bufio.NewReader(file)
		default:
			f.data[index-4] = file
		}
	}
	return f
}

func (f *blockingFixture) initial(t *testing.T, s *native.Session) (target.Snapshot, [3]int) {
	t.Helper()
	snapshot, tids := threadInitial(t, s, f.threadFixture, 3)
	fds := f.receive(t, "FDS")
	f.fds = [2]int{fds[0], fds[1]}
	return snapshot, tids
}

func blockingRead(t *testing.T, s *native.Session, address target.Address, size int) []byte {
	t.Helper()
	snapshot := threadSnapshot(t, s)
	data := make([]byte, size)
	n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, address, data) })
	if err != nil || n != size {
		t.Fatalf("blocking fixture memory at %#x: n=%d, %v", address, n, err)
	}
	return data
}

func blockingWord(t *testing.T, s *native.Session, f *blockingFixture, name string, index int) uint32 {
	t.Helper()
	return binary.LittleEndian.Uint32(blockingRead(t, s, f.address(t, name)+target.Address(index*4), 4))
}

func blockingKernelWait(t *testing.T, s *native.Session, f *blockingFixture, tid, index int, futex bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	number := uint64(unix.SYS_READ)
	arg0, arg1, arg2 := uint64(f.fds[index]), uint64(f.address(t, "received"))+uint64(index), uint64(1)
	if futex {
		number, arg0, arg1, arg2 = uint64(unix.SYS_FUTEX), uint64(f.address(t, "futex_word")), 128, 0
	}
	var last string
	for {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/syscall", s.PID(), tid))
		if err != nil {
			t.Fatal(err)
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", s.PID(), tid))
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(raw))
		state := ""
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "State:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					state = parts[1]
				}
			}
		}
		if len(fields) == 9 {
			values := make([]uint64, len(fields))
			valid := true
			for index, field := range fields {
				values[index], err = strconv.ParseUint(field, 0, 64)
				valid = valid && err == nil
			}
			if valid && values[0] == number && values[1] == arg0 && values[2] == arg1 && values[3] == arg2 && values[8] == uint64(f.address(t, "blocking_site"))+2 && (state == "S" || state == "D") {
				return
			}
		}
		last = fmt.Sprintf("state=%s syscall=%s", state, raw)
		if time.Now().After(deadline) {
			t.Fatalf("kernel did not report the declared blocking syscall: %s", last)
		}
		runtime.Gosched()
	}
}

func blockingPrepare(t *testing.T, s *native.Session, f *blockingFixture, tids [3]int) target.ThreadInfo {
	t.Helper()
	owner := threadByTID(t, threadSnapshot(t, s), tids[1])
	for _, name := range []string{"blocking_site", "owner_checkpoint", "done_checkpoint"} {
		threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, name)) })
	}
	f.send(t, 1, 'g')
	threadBreakpoint(t, threadRun(t, s, threadExact(owner.Ref)), f.address(t, "blocking_site"))
	return threadByTID(t, threadSnapshot(t, s), tids[1])
}

func blockingStep(t *testing.T, s *native.Session, request target.StepRequest) *native.Run {
	t.Helper()
	run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(request) })
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func blockingTypedExit(t *testing.T, result target.RunResult, owner target.ThreadRef, pc target.Address) {
	t.Helper()
	if result.Thread != owner || result.Stop.Reason != target.StopStep || !result.Stop.StepCompleted || result.Stop.RawDR6 != nil || result.Stop.RawPC == nil || *result.Stop.RawPC != pc {
		t.Fatalf("typed syscall EXIT did not finish the requested instruction: %+v", result)
	}
}

func blockingFinish(t *testing.T, s *native.Session, f *blockingFixture, sendMain bool) {
	t.Helper()
	for _, name := range []string{"blocking_site", "owner_checkpoint"} {
		threadCommand(t, func() error { return s.RemoveBreakpoint(f.address(t, name)) })
	}
	f.send(t, 1, 'f')
	f.send(t, 2, 'f')
	if sendMain {
		f.send(t, 0, 'g')
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), f.address(t, "done_checkpoint"))
	f.receive(t, "DONE")
	threadCommand(t, func() error { return s.RemoveBreakpoint(f.address(t, "done_checkpoint")) })
	threadExit(t, s, 0)
}

func TestNativeBlockingBreakpointPeerProgress(t *testing.T) {
	for _, mode := range []string{"read", "futex"} {
		for _, step := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_step_%t", mode, step), func(t *testing.T) {
				f := newBlockingFixture(t)
				s := f.launch(t, mode)
				snapshot, tids := f.initial(t, s)
				owner := blockingPrepare(t, s, f, tids)
				peer := threadByTID(t, snapshot, tids[2])
				var run *native.Run
				if step {
					run = blockingStep(t, s, target.StepRequest{Thread: owner.Ref, Continue: threadExact(peer.Ref)})
				} else {
					run = threadStart(t, s, target.RunRequest{Threads: threadProcessSet(snapshot)})
				}
				blockingKernelWait(t, s, f, tids[1], 0, mode == "futex")
				f.send(t, 2, 'g')
				result := threadWait(t, run)
				if step {
					blockingTypedExit(t, result, owner.Ref, f.address(t, "after_blocking_site"))
					if got := blockingWord(t, s, f, "returned", 0); got != 0 {
						t.Fatalf("syscall step executed the following instruction: %d", got)
					}
					result = threadWait(t, blockingStep(t, s, target.StepRequest{Thread: owner.Ref}))
					if result.Stop.Reason != target.StopStep || !result.Stop.StepCompleted || result.Stop.RawPC == nil || *result.Stop.RawPC != f.address(t, "after_completion") {
						t.Fatalf("step after typed EXIT did not execute one instruction: %+v", result)
					}
					if got := blockingWord(t, s, f, "returned", 0); got != 1 {
						t.Fatalf("post-syscall instruction count: %d", got)
					}
					result = threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
				}
				threadBreakpoint(t, result, f.address(t, "owner_checkpoint"))
				if got := blockingWord(t, s, f, "observed_site", 0); got != 0xcc {
					t.Fatalf("peer executed while shared breakpoint was disarmed: %#x", got)
				}
				if got := blockingWord(t, s, f, "release_count", 0); got != 1 {
					t.Fatalf("peer release count: %d", got)
				}
				blockingFinish(t, s, f, true)
			})
		}
	}
}

func TestNativeBlockingBreakpointPeerHold(t *testing.T) {
	f := newBlockingFixture(t)
	s := f.launch(t, "hold")
	snapshot, tids := f.initial(t, s)
	owner := blockingPrepare(t, s, f, tids)
	f.send(t, 2, 'g')
	run := blockingStep(t, s, target.StepRequest{Thread: owner.Ref})
	blockingKernelWait(t, s, f, tids[1], 0, false)
	current := threadSnapshot(t, s)
	if peer := threadByTID(t, current, tids[2]); peer.State != target.StateStopped {
		t.Fatalf("peer hold policy changed: %+v", peer)
	}
	if err := f.data[0].SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.data[0].Write([]byte{'A', 'Z'}); err != nil || n != 2 {
		t.Fatalf("external hold release: %d, %v", n, err)
	}
	blockingTypedExit(t, threadWait(t, run), owner.Ref, f.address(t, "after_blocking_site"))
	if got := blockingWord(t, s, f, "release_count", 0); got != 0 {
		t.Fatalf("held peer supplied data: %d", got)
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(snapshot)), f.address(t, "owner_checkpoint"))
	blockingFinish(t, s, f, true)
}

func TestNativeBlockingBreakpointSameSite(t *testing.T) {
	f := newBlockingFixture(t)
	s := f.launch(t, "two")
	snapshot, tids := f.initial(t, s)
	a := blockingPrepare(t, s, f, tids)
	b := threadByTID(t, snapshot, tids[2])
	f.send(t, 2, 'g')
	threadBreakpoint(t, threadRun(t, s, threadExact(b.Ref)), f.address(t, "blocking_site"))
	snapshot = threadStopped(t, s, 3)
	for _, tid := range []int{tids[1], tids[2]} {
		if pc := threadRegister(t, s, threadByTID(t, snapshot, tid).Token, "rip"); pc != uint64(f.address(t, "blocking_site"))+1 {
			t.Fatalf("same-site hit lost raw PC for %d: %#x", tid, pc)
		}
	}
	run := threadStart(t, s, target.RunRequest{Threads: threadProcessSet(snapshot)})
	blockingKernelWait(t, s, f, tids[1], 0, false)
	blockingKernelWait(t, s, f, tids[2], 1, false)
	f.send(t, 0, 'g')
	threadBreakpoint(t, threadWait(t, run), f.address(t, "owner_checkpoint"))
	snapshot = threadStopped(t, s, 3)
	var remaining []target.ThreadRef
	for _, ref := range []target.ThreadRef{a.Ref, b.Ref} {
		for _, thread := range snapshot.Threads {
			if thread.Ref == ref && (thread.Stop.Reason != target.StopBreakpoint || thread.Stop.Breakpoint == nil || *thread.Stop.Breakpoint != f.address(t, "owner_checkpoint")) {
				remaining = append(remaining, ref)
			}
		}
	}
	if len(remaining) > 1 {
		t.Fatalf("no owner completion after shared-site release: %+v", snapshot)
	}
	if len(remaining) == 1 {
		writer := threadByTID(t, snapshot, tids[0])
		threadBreakpoint(t, threadRun(t, s, threadExact(remaining[0], writer.Ref)), f.address(t, "owner_checkpoint"))
	}
	for index := 0; index < 2; index++ {
		if count := blockingWord(t, s, f, "returned", index); count != 1 {
			t.Fatalf("same-site owner %d completed %d times", index, count)
		}
	}
	if got := blockingWord(t, s, f, "observed_site", 0); got != 0xcc {
		t.Fatalf("writer ran before both original syscalls rearmed the site: %#x", got)
	}
	blockingFinish(t, s, f, false)
}

func blockingOwnerCheckpoint(t *testing.T, s *native.Session, f *blockingFixture, run *native.Run, owner target.ThreadRef) {
	t.Helper()
	result := threadWait(t, run)
	if result.Thread == owner && result.Stop.Reason == target.StopBreakpoint && result.Stop.Breakpoint != nil && *result.Stop.Breakpoint == f.address(t, "blocking_site") {
		result = threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
	}
	threadBreakpoint(t, result, f.address(t, "owner_checkpoint"))
	if result.Thread != owner {
		t.Fatalf("resumed wrong syscall owner: %+v", result)
	}
}

func TestNativeBlockingBreakpointPeerBreakpointAndWatchpoint(t *testing.T) {
	f := newBlockingFixture(t)
	s := f.launch(t, "read")
	snapshot, tids := f.initial(t, s)
	owner := blockingPrepare(t, s, f, tids)
	peer := threadByTID(t, threadSnapshot(t, s), tids[2])
	peerSite := f.address(t, "peer_site")
	threadCommand(t, func() error { return s.AddBreakpoint(peerSite) })
	request := target.WatchpointRequest{Slot: 1, Address: f.address(t, "release_count"), Size: 4, Access: target.WatchWrite}
	configured := watchSet(t, s, peer.Token, request)
	run := blockingStep(t, s, target.StepRequest{Thread: owner.Ref, Continue: threadExact(peer.Ref)})
	blockingKernelWait(t, s, f, tids[1], 0, false)
	f.send(t, 2, 'g')
	result := threadWait(t, run)
	threadBreakpoint(t, result, peerSite)
	if result.Thread != peer.Ref {
		t.Fatalf("peer breakpoint was hidden by owner syscall stop: %+v", result)
	}
	if code := blockingRead(t, s, f.address(t, "blocking_site"), 1); code[0] != 0xcc {
		t.Fatalf("peer stop found disarmed owner site: %x", code)
	}
	result = threadRun(t, s, threadExact(peer.Ref))
	watchStop(t, s, result, f.address(t, "after_peer_site"), true, watchHit(configured.Ref, request))
	if got := blockingWord(t, s, f, "returned", 0); got != 0 {
		t.Fatalf("owner completed before peer supplied data: %d", got)
	}
	watchClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[2]).Token, configured.Ref)
	threadCommand(t, func() error { return s.RemoveBreakpoint(peerSite) })
	blockingOwnerCheckpoint(t, s, f, threadStart(t, s, target.RunRequest{Threads: threadProcessSet(snapshot)}), owner.Ref)
	blockingFinish(t, s, f, true)
}

func TestNativeBlockingBreakpointRestartRecovery(t *testing.T) {
	for _, delivery := range []bool{false, true} {
		t.Run(fmt.Sprintf("signal_%t", delivery), func(t *testing.T) {
			f := newBlockingFixture(t)
			mode := "read"
			if delivery {
				mode = "signal_eintr"
			}
			s := f.launch(t, mode)
			snapshot, tids := f.initial(t, s)
			owner := blockingPrepare(t, s, f, tids)
			peer := threadByTID(t, snapshot, tids[2])
			peerCheckpoint := f.address(t, "peer_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(peerCheckpoint) })
			run := blockingStep(t, s, target.StepRequest{Thread: owner.Ref, Continue: threadExact(peer.Ref)})
			blockingKernelWait(t, s, f, tids[1], 0, false)
			if delivery {
				threadCommand(t, func() error { return unix.Tgkill(s.PID(), tids[1], unix.SIGUSR1) })
			} else {
				threadCommand(t, func() error { return s.Interrupt(target.InterruptRequest{Threads: threadProcessSet(snapshot)}) })
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := run.Wait(ctx)
			if result.Stop.StepCompleted {
				t.Fatalf("restart result falsely completed original syscall: %+v, %v", result, err)
			}
			if delivery {
				if !errors.Is(err, target.ErrUnsupported) || result.Stop.Reason != target.StopUnknown {
					t.Fatalf("unresolved signal restart boundary: %+v, %v", result, err)
				}
			} else if err != nil || result.Stop.Reason != target.StopInterrupt {
				t.Fatalf("interrupt restart boundary: %+v, %v", result, err)
			}
			threadStopped(t, s, 3)
			for phase := 0; phase < 2; phase++ {
				before := threadByTID(t, threadSnapshot(t, s), tids[1]).Token
				if next, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(target.StepRequest{Thread: owner.Ref}) }); !errors.Is(err, target.ErrUnsupported) || next != nil {
					t.Fatalf("fresh step accepted an unresolved restart: run=%+v, %v", next, err)
				}
				if after := threadByTID(t, threadSnapshot(t, s), tids[1]).Token; after != before {
					t.Fatalf("rejected restart step changed owner state: old=%+v new=%+v", before, after)
				}
				if phase == 0 {
					f.send(t, 2, 'g')
					threadBreakpoint(t, threadRun(t, s, threadExact(peer.Ref)), peerCheckpoint)
					if got := blockingWord(t, s, f, "returned", 0); got != 0 {
						t.Fatalf("peer-only run consumed owner completion: %d", got)
					}
				}
			}
			request := target.RunRequest{Threads: threadExact(owner.Ref)}
			if delivery {
				result = threadWait(t, threadStart(t, s, request))
				if result.Thread != owner.Ref || result.Stop.Reason != target.StopSignal || result.Stop.Signal.Number != uint32(unix.SIGUSR1) {
					t.Fatalf("explicit Run lost signal delivery stop: %+v", result)
				}
				current := threadByTID(t, threadSnapshot(t, s), tids[1])
				request.Signals = []target.ThreadSignal{{Thread: owner.Ref, Stop: current.Token.Stop, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}}}
			}
			blockingOwnerCheckpoint(t, s, f, threadStart(t, s, request), owner.Ref)
			threadCommand(t, func() error { return s.RemoveBreakpoint(peerCheckpoint) })
			blockingFinish(t, s, f, true)
		})
	}
}

func TestNativeBlockingBreakpointPeerExec(t *testing.T) {
	f := newBlockingFixture(t)
	s := f.launch(t, "exec")
	snapshot, tids := f.initial(t, s)
	owner := blockingPrepare(t, s, f, tids)
	oldMemory := threadSnapshot(t, s).Memory
	run := threadStart(t, s, target.RunRequest{Threads: threadProcessSet(snapshot)})
	blockingKernelWait(t, s, f, tids[1], 0, false)
	f.send(t, 2, 'g')
	result := threadWait(t, run)
	if result.Stop.Reason != target.StopExec {
		t.Fatalf("peer exec did not invalidate in-flight owner: %+v", result)
	}
	current := threadStopped(t, s, 1)
	if current.Memory.Space == oldMemory.Space {
		t.Fatal("peer exec retained old address space")
	}
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(owner.Token) }); err == nil {
		t.Fatal("peer exec retained old syscall owner token")
	}
	if _, err := threadCall(t, func() (struct{}, error) { return struct{}{}, s.RemoveBreakpoint(f.address(t, "blocking_site")) }); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("peer exec retained old syscall breakpoint: %v", err)
	}
	if code := blockingRead(t, s, f.address(t, "blocking_site"), 1); code[0] != 0x0f {
		t.Fatalf("old syscall restoration changed new image: %x", code)
	}
	address := f.address(t, "after_exec_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(address) })
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(current)), address)
	f.receive(t, "EXECREADY")
	threadCommand(t, func() error { return s.RemoveBreakpoint(address) })
	threadExit(t, s, 17)
}

func TestNativeBlockingBreakpointPendingStepClose(t *testing.T) {
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprintf("attached_%t", attached), func(t *testing.T) {
			f := newBlockingFixture(t)
			var s *native.Session
			var cmd *threadProcess
			var tids [3]int
			var snapshot target.Snapshot
			if attached {
				cmd = f.start(t, "detach")
				tids = f.receive(t, "READY")
				fds := f.receive(t, "FDS")
				f.fds = [2]int{fds[0], fds[1]}
				var err error
				s, err = threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
				if err != nil {
					t.Fatal(err)
				}
				threadSessionCleanup(t, s, false)
				snapshot = threadStopped(t, s, 3)
			} else {
				s = f.launch(t, "read")
				snapshot, tids = f.initial(t, s)
			}
			owner := blockingPrepare(t, s, f, tids)
			peer := threadByTID(t, snapshot, tids[2])
			threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, "peer_site")) })
			watchSet(t, s, peer.Token, target.WatchpointRequest{Slot: 0, Address: f.address(t, "release_count"), Size: 4, Access: target.WatchWrite})
			run := blockingStep(t, s, target.StepRequest{Thread: owner.Ref, Continue: threadExact(peer.Ref)})
			blockingKernelWait(t, s, f, tids[1], 0, false)
			threadCommand(t, s.Close)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := run.Wait(ctx)
			if err != nil && !errors.Is(err, target.ErrClosed) && !errors.Is(err, target.ErrDetached) && !errors.Is(err, target.ErrExited) {
				t.Fatalf("close left typed syscall step unresolved: %+v, %v", result, err)
			}
			if s.State() != target.StateClosed || result.Stop.StepCompleted {
				t.Fatalf("close falsely completed blocked syscall: state=%s result=%+v", s.State(), result)
			}
			if attached {
				if err == nil {
					t.Fatalf("attached close published a stale successful stop: %+v", result)
				}
				f.send(t, 2, 'g')
				f.send(t, 2, 'f')
				f.send(t, 1, 'f')
				f.send(t, 0, 'g')
				threadCommand(t, cmd.Wait)
				f.receive(t, "DONE")
			}
		})
	}
}
