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
	"sync"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const threadFixtureSource = `#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

_Atomic int ready[3];
_Atomic int counters[3];
_Atomic int delivered[3];
_Atomic int hidden_ready;
static unsigned char hidden_stack[65536] __attribute__((aligned(16)));
_Atomic int clone_data[3];
_Atomic int clone_tid;
static unsigned char clone_stack[65536] __attribute__((aligned(16), used));
int tids[3];
int inputs[3];
char received[3];
static int output;
static int mode;
static char **arguments;
static pthread_t main_thread;
static __thread int role;

extern long selected_clone(void);
__asm__(".text\n"
        ".global selected_clone\n"
        ".type selected_clone,@function\n"
        "selected_clone:\n"
        "lea clone_stack+65536(%rip), %rsi\n"
        "mov $0x1210900, %edi\n"
        "xor %edx, %edx\n"
        "lea clone_tid(%rip), %r10\n"
        "xor %r8d, %r8d\n"
        "mov $56, %eax\n"
        ".global clone_site\n"
        "clone_site:\n"
        "syscall\n"
        "movzbl clone_site(%rip), %ecx\n"
        "test %rax, %rax\n"
        "jz clone_child_entry\n"
        "ret\n"
        "clone_child_entry:\n"
        "mov %ecx, clone_data+8(%rip)\n"
        "lock incl clone_data(%rip)\n"
        "clone_child_wait:\n"
        "cmpl $0, clone_data+4(%rip)\n"
        "jne clone_child_exit\n"
        "pause\n"
        "jmp clone_child_wait\n"
        "clone_child_exit:\n"
        "xor %edi, %edi\n"
        "mov $60, %eax\n"
        "syscall\n"
        "ud2\n"
        ".size selected_clone,.-selected_clone\n");

__attribute__((noinline)) void checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void worker_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void done_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void after_exec_checkpoint(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void user_trap(void) { __asm__ volatile(".global icebp_site\nicebp_site:\n.byte 0xf1"); }

static void fail(void) { _exit(91); }

static int hidden_worker(void *argument) {
    (void)argument;
    atomic_store_explicit(&hidden_ready, 1, memory_order_release);
    for (;;) __asm__ volatile("pause");
}

static void announce(const char *name) {
    char data[128];
    int n = snprintf(data, sizeof(data), "%s %d %d %d\n", name, tids[0], tids[1], tids[2]);
    if (write(output, data, n) != n) fail();
}

static char take(int index) {
    char value;
    ssize_t n;
    do { n = read(inputs[index], &value, 1); } while (n < 0 && errno == EINTR);
    if (n != 1) fail();
    return value;
}

static void ready_wait(int index) {
    while (!atomic_load_explicit(&ready[index], memory_order_acquire))
        syscall(SYS_futex, &ready[index], FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
}

__attribute__((noinline)) void shared_increment(_Atomic int *value) {
    __asm__ volatile(".global shared_site\nshared_site:\nlock incl (%0)" : : "r"(value) : "memory", "cc");
}

__attribute__((noinline)) long selected_read(int fd, char *value) {
    register long result __asm__("rax") = SYS_read;
    register long descriptor __asm__("rdi") = fd;
    register char *buffer __asm__("rsi") = value;
    register long size __asm__("rdx") = 1;
    __asm__ volatile(".global read_site\nread_site:\nsyscall"
        : "+a"(result) : "D"(descriptor), "S"(buffer), "d"(size) : "rcx", "r11", "memory");
    return result;
}

__attribute__((noinline, noreturn)) void selected_exit(void) {
    __asm__ volatile(".global exit_site\nexit_site:\nsyscall" : : "a"((long)SYS_exit), "D"(0L) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static void handler(int signal) {
    if (signal == SIGUSR1) atomic_fetch_add_explicit(&delivered[role], 1, memory_order_relaxed);
}

static void *worker(void *arg) {
    int index = (int)(intptr_t)arg;
    role = index;
    tids[index] = (int)syscall(SYS_gettid);
    atomic_store_explicit(&ready[index], 1, memory_order_release);
    syscall(SYS_futex, &ready[index], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    take(index);
    if (mode == 3) {
        if (syscall(SYS_tgkill, getpid(), tids[index], SIGUSR1)) fail();
    }
    if (mode == 7 && index == 1) user_trap();
    if (mode == 4) {
        if (pthread_join(main_thread, 0)) fail();
        announce("SURVIVED");
    }
    if (mode == 5) {
        execl(arguments[0], arguments[0], "afterexec", arguments[2], arguments[3], arguments[4], arguments[5], (char *)0);
        fail();
    }
    if (mode == 6) {
        if (index == 1) {
            if (selected_read(inputs[1], &received[1]) != 1) fail();
        } else {
            atomic_fetch_add_explicit(&counters[2], 1, memory_order_relaxed);
            int fd = open(arguments[3], O_WRONLY);
            if (fd < 0 || write(fd, "p", 1) != 1) fail();
            close(fd);
            take(2);
            return 0;
        }
    }
    shared_increment(&counters[index]);
    worker_checkpoint();
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) return 90;
    arguments = argv;
    for (int i = 0; i != 3; ++i) {
        inputs[i] = open(argv[2 + i], O_RDONLY);
        if (inputs[i] < 0) fail();
    }
    output = open(argv[5], O_WRONLY);
    if (output < 0) fail();
    tids[0] = (int)syscall(SYS_gettid);
    main_thread = pthread_self();
    if (!strcmp(argv[1], "rawclone")) {
        announce("READY");
        checkpoint();
        take(0);
        long child = selected_clone();
        if (child <= 0) fail();
        tids[1] = (int)child;
        while (!atomic_load_explicit(&clone_data[0], memory_order_acquire)) __asm__ volatile("pause");
        announce("CLONED");
        worker_checkpoint();
        take(0);
        atomic_store_explicit(&clone_data[1], 1, memory_order_release);
        int tid;
        while ((tid = atomic_load_explicit(&clone_tid, memory_order_acquire)) != 0)
            syscall(SYS_futex, &clone_tid, FUTEX_WAIT, tid, 0, 0, 0);
        announce("DONE");
        done_checkpoint();
        return atomic_load(&clone_data[0]) == 1 ? 0 : 93;
    }
    if (!strcmp(argv[1], "hidden") || !strcmp(argv[1], "hiddenclose")) {
        announce("READY");
        checkpoint();
        take(0);
        tids[1] = clone(hidden_worker, hidden_stack + sizeof(hidden_stack), CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_UNTRACED, 0);
        if (tids[1] < 0) fail();
        while (!atomic_load_explicit(&hidden_ready, memory_order_acquire)) __asm__ volatile("pause");
        announce("HIDDEN");
        if (!strcmp(argv[1], "hiddenclose")) take(0);
        done_checkpoint();
        for (;;) __asm__ volatile("pause");
    }
    if (!strcmp(argv[1], "afterexec")) {
        announce("EXECREADY");
        after_exec_checkpoint();
        return 23;
    }
    if (!strcmp(argv[1], "signals")) mode = 3;
    if (!strcmp(argv[1], "leader") || !strcmp(argv[1], "leaderstep")) mode = 4;
    if (!strcmp(argv[1], "exec")) mode = 5;
    if (!strcmp(argv[1], "peer")) mode = 6;
    if (!strcmp(argv[1], "trap")) mode = 7;
    struct sigaction action = {0};
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0)) fail();
    pthread_t threads[3];
    int count = (mode == 4 || mode == 5 || !strcmp(argv[1], "creating")) ? 1 : 2;
    for (int i = 1; i <= count; ++i) {
        if (pthread_create(&threads[i], 0, worker, (void *)(intptr_t)i)) fail();
        ready_wait(i);
    }
    announce("READY");
    checkpoint();
    take(0);
    if (!strcmp(argv[1], "creating")) {
        if (pthread_create(&threads[2], 0, worker, (void *)(intptr_t)2)) fail();
        ready_wait(2);
        count = 2;
        announce("CREATED");
        done_checkpoint();
    }
    if (!strcmp(argv[1], "leaderstep")) selected_exit();
    if (mode == 4) pthread_exit(0);
    for (int i = 1; i <= count; ++i) if (pthread_join(threads[i], 0)) fail();
    announce("DONE");
    done_checkpoint();
    for (int i = 1; i <= count; ++i) if (atomic_load(&counters[i]) != 1) return 92;
    return 0;
}
`

type threadFixture struct {
	path    string
	symbols map[string]target.Address
	paths   []string
	inputs  [3]*os.File
	output  *os.File
	reader  *bufio.Reader
}

type threadResponse[T any] struct {
	value T
	err   error
}

func threadCall[T any](t *testing.T, operation func() (T, error)) (T, error) {
	t.Helper()
	done := make(chan threadResponse[T], 1)
	go func() {
		value, err := operation()
		done <- threadResponse[T]{value, err}
	}()
	select {
	case result := <-done:
		return result.value, result.err
	case <-time.After(10 * time.Second):
		t.Fatal("thread operation exceeded its deadline")
		var zero T
		return zero, context.DeadlineExceeded
	}
}

func threadCommand(t *testing.T, operation func() error) {
	t.Helper()
	_, err := threadCall(t, func() (struct{}, error) { return struct{}{}, operation() })
	if err != nil {
		t.Fatal(err)
	}
}

func newThreadFixture(t *testing.T) *threadFixture {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native pthread fixtures require linux/amd64")
	}
	tmp, err := filepath.Abs(filepath.Join("..", ".cache", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	dir := t.TempDir()
	f := &threadFixture{path: filepath.Join(dir, "threads"), symbols: make(map[string]target.Address)}
	if err := os.WriteFile(f.path+".c", []byte(threadFixtureSource), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	compiler := exec.CommandContext(ctx, "cc", "-std=gnu11", "-O0", "-g", "-no-pie", "-pthread", "-Wl,--build-id=none", "-o", f.path, f.path+".c")
	if out, err := compiler.CombinedOutput(); err != nil {
		t.Fatalf("build pthread fixture: %v\n%s", err, out)
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
	for i := 0; i != 4; i++ {
		path := filepath.Join(dir, fmt.Sprintf("channel-%d", i))
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		f.paths = append(f.paths, path)
		if i < 3 {
			f.inputs[i] = file
		} else {
			f.output, f.reader = file, bufio.NewReader(file)
		}
	}
	return f
}

func (f *threadFixture) address(t *testing.T, name string) target.Address {
	t.Helper()
	address := f.symbols[name]
	if address == 0 {
		t.Fatalf("fixture symbol %q missing", name)
	}
	return address
}

func (f *threadFixture) args(mode string) []string {
	return append([]string{mode}, f.paths...)
}

func (f *threadFixture) send(t *testing.T, index int, value byte) {
	t.Helper()
	if err := f.inputs[index].SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.inputs[index].Write([]byte{value}); err != nil || n != 1 {
		t.Fatalf("fixture channel %d: wrote %d, %v", index, n, err)
	}
}

func (f *threadFixture) receive(t *testing.T, name string) [3]int {
	t.Helper()
	if err := f.output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := f.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("fixture %s acknowledgement: %v", name, err)
	}
	fields := strings.Fields(line)
	if len(fields) != 4 || fields[0] != name {
		t.Fatalf("fixture acknowledgement: got %q, want %s", line, name)
	}
	var tids [3]int
	for i := range tids {
		tids[i], err = strconv.Atoi(fields[i+1])
		if err != nil {
			t.Fatal(err)
		}
	}
	return tids
}

func (f *threadFixture) launch(t *testing.T, mode string) *native.Session {
	t.Helper()
	s, err := threadCall(t, func() (*native.Session, error) { return native.Launch(f.path, f.args(mode)...) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, s, true)
	return s
}

func threadSessionCleanup(t *testing.T, s *native.Session, owned bool) {
	t.Helper()
	pidfd := -1
	if owned {
		var err error
		pidfd, err = unix.PidfdOpen(s.PID(), 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if pidfd >= 0 {
			defer unix.Close(pidfd)
		}
		done := make(chan error, 1)
		go func() { done <- s.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("close thread session: %v", err)
			}
		case <-time.After(5 * time.Second):
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			t.Error("thread session cleanup exceeded deadline")
		}
	})
}

func threadSnapshot(t *testing.T, s *native.Session) target.Snapshot {
	t.Helper()
	snapshot, err := threadCall(t, s.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func threadProcessSet(snapshot target.Snapshot) target.ThreadSet {
	return target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}
}

func threadExact(threads ...target.ThreadRef) target.ThreadSet {
	return target.ThreadSet{Scope: target.ExactThreads, Threads: threads}
}

func threadStart(t *testing.T, s *native.Session, request target.RunRequest) *native.Run {
	t.Helper()
	run, err := threadCall(t, func() (*native.Run, error) { return s.Run(request) })
	if err != nil {
		t.Fatal(err)
	}
	if run == nil || run.ID() == 0 {
		t.Fatalf("invalid accepted run: %+v", run)
	}
	return run
}

func threadWait(t *testing.T, run *native.Run) target.RunResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := run.Wait(ctx)
	if err != nil {
		t.Fatalf("run %d: %+v, %v", run.ID(), result, err)
	}
	return result
}

func threadRun(t *testing.T, s *native.Session, threads target.ThreadSet) target.RunResult {
	t.Helper()
	return threadWait(t, threadStart(t, s, target.RunRequest{Threads: threads}))
}

func threadByTID(t *testing.T, snapshot target.Snapshot, tid int) target.ThreadInfo {
	t.Helper()
	for _, thread := range snapshot.Threads {
		if thread.TID == tid && thread.State != target.StateExited && thread.State != target.StateDetached && !thread.Exiting {
			return thread
		}
	}
	t.Fatalf("live TID %d missing: %+v", tid, snapshot)
	return target.ThreadInfo{}
}

func threadStopped(t *testing.T, s *native.Session, count int) target.Snapshot {
	t.Helper()
	snapshot := threadSnapshot(t, s)
	if snapshot.State != target.StateStopped {
		t.Fatalf("all-stop state: %+v", snapshot)
	}
	live := 0
	seen := make(map[target.ThreadRef]bool)
	for _, thread := range snapshot.Threads {
		if thread.State == target.StateExited || thread.State == target.StateDetached || thread.Exiting {
			continue
		}
		live++
		if thread.State != target.StateStopped || thread.Listening || thread.Token.Thread != thread.Ref || thread.Token.Stop == 0 || seen[thread.Ref] {
			t.Fatalf("invalid stopped thread: %+v", thread)
		}
		seen[thread.Ref] = true
	}
	if live != count {
		t.Fatalf("live thread count: got %d, want %d: %+v", live, count, snapshot)
	}
	return snapshot
}

func threadRegister(t *testing.T, s *native.Session, token target.ThreadToken, name string) uint64 {
	t.Helper()
	registers, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(token) })
	if err != nil {
		t.Fatal(err)
	}
	for _, register := range registers {
		if register.Name == name {
			if !register.Available || register.Bits != 64 || len(register.Data) != 8 {
				t.Fatalf("invalid %s: %+v", name, register)
			}
			return binary.LittleEndian.Uint64(register.Data)
		}
	}
	t.Fatalf("register %s missing", name)
	return 0
}

func threadValues(t *testing.T, s *native.Session, f *threadFixture, name string) [3]uint32 {
	t.Helper()
	snapshot := threadSnapshot(t, s)
	var data [12]byte
	n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, f.address(t, name), data[:]) })
	if err != nil || n != len(data) {
		t.Fatalf("read %s: %d, %v", name, n, err)
	}
	return [3]uint32{binary.LittleEndian.Uint32(data[0:4]), binary.LittleEndian.Uint32(data[4:8]), binary.LittleEndian.Uint32(data[8:12])}
}

func threadBreakpoint(t *testing.T, result target.RunResult, address target.Address) {
	t.Helper()
	if result.Stop.Reason != target.StopBreakpoint || result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != address || result.Stop.RawPC == nil || *result.Stop.RawPC != address+1 {
		var pc target.Address
		if result.Stop.RawPC != nil {
			pc = *result.Stop.RawPC
		}
		t.Fatalf("breakpoint %#x: PC=%#x, %+v", address, pc, result)
	}
}

func threadInitial(t *testing.T, s *native.Session, f *threadFixture, count int) (target.Snapshot, [3]int) {
	t.Helper()
	address := f.address(t, "checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(address) })
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), address)
	tids := f.receive(t, "READY")
	snapshot := threadStopped(t, s, count)
	for _, tid := range tids {
		if tid != 0 {
			threadByTID(t, snapshot, tid)
		}
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(address) })
	return threadStopped(t, s, count), tids
}

func threadExit(t *testing.T, s *native.Session, code int) {
	t.Helper()
	result := threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
	if result.Stop.Reason != target.StopExited || result.Stop.ExitCode == nil || *result.Stop.ExitCode != code || s.State() != target.StateExited {
		t.Fatalf("expected process exit %d: %+v, state=%s", code, result, s.State())
	}
}

func TestNativeThreadsLifecycleAndRegisters(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "lifecycle")
	snapshot, tids := threadInitial(t, s, f, 3)
	if _, err := threadCall(t, s.ReadRegisters); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("legacy register read selected an arbitrary thread: %v", err)
	}
	first, second := threadByTID(t, snapshot, tids[1]), threadByTID(t, snapshot, tids[2])
	before := threadRegister(t, s, first.Token, "r15")
	peer := threadRegister(t, s, second.Token, "r15")
	var value [8]byte
	binary.LittleEndian.PutUint64(value[:], 0x123456789abcdef0)
	threadCommand(t, func() error {
		return s.WriteThreadRegisters(first.Token, []target.Register{{Name: "r15", Bits: 64, Data: value[:], Available: true}})
	})
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(first.Token) }); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old register token accepted: %v", err)
	}
	snapshot = threadStopped(t, s, 3)
	first = threadByTID(t, snapshot, tids[1])
	if got := threadRegister(t, s, first.Token, "r15"); got != 0x123456789abcdef0 {
		t.Fatalf("selected register write: %#x", got)
	}
	if got := threadRegister(t, s, threadByTID(t, snapshot, tids[2]).Token, "r15"); got != peer {
		t.Fatalf("peer register changed: got %#x, want %#x", got, peer)
	}
	binary.LittleEndian.PutUint64(value[:], before)
	threadCommand(t, func() error {
		return s.WriteThreadRegisters(first.Token, []target.Register{{Name: "r15", Bits: 64, Data: value[:], Available: true}})
	})
	worker := f.address(t, "worker_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(worker) })
	f.send(t, 1, 'g')
	result := threadRun(t, s, threadExact(first.Ref))
	threadBreakpoint(t, result, worker)
	if result.Thread != first.Ref {
		t.Fatalf("exact run stopped wrong thread: %+v", result)
	}
	threadStopped(t, s, 3)
	if got := threadValues(t, s, f, "counters"); got != [3]uint32{0, 1, 0} {
		t.Fatalf("exact run advanced peer: %v", got)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(worker) })
	end := f.address(t, "done_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(end) })
	f.send(t, 0, 'g')
	f.send(t, 2, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), end)
	f.receive(t, "DONE")
	threadStopped(t, s, 1)
	if got := threadValues(t, s, f, "counters"); got != [3]uint32{0, 1, 1} {
		t.Fatalf("thread completion counters: %v", got)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
	threadExit(t, s, 0)
}

func TestNativeThreadsSharedBreakpointPendingHits(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove_%t", remove), func(t *testing.T) {
			f := newThreadFixture(t)
			s := f.launch(t, "shared")
			snapshot, tids := threadInitial(t, s, f, 3)
			site, end := f.address(t, "shared_site"), f.address(t, "done_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(site) })
			threadCommand(t, func() error { return s.AddBreakpoint(end) })
			for i := 1; i <= 2; i++ {
				thread := threadByTID(t, snapshot, tids[i])
				f.send(t, i, 'g')
				result := threadRun(t, s, threadExact(thread.Ref))
				threadBreakpoint(t, result, site)
				if result.Thread != thread.Ref {
					t.Fatalf("hit attributed to peer: %+v", result)
				}
				snapshot = threadStopped(t, s, 3)
			}
			for i := 1; i <= 2; i++ {
				thread := threadByTID(t, snapshot, tids[i])
				if pc := threadRegister(t, s, thread.Token, "rip"); pc != uint64(site+1) {
					t.Fatalf("thread %d lost pending raw PC: %#x", i, pc)
				}
			}
			if got := threadValues(t, s, f, "counters"); got != [3]uint32{} {
				t.Fatalf("original instructions executed before breakpoint continuation: %v", got)
			}
			if remove {
				threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
				snapshot = threadStopped(t, s, 3)
				for i := 1; i <= 2; i++ {
					if pc := threadRegister(t, s, threadByTID(t, snapshot, tids[i]).Token, "rip"); pc != uint64(site) {
						t.Fatalf("remove did not rewind thread %d: %#x", i, pc)
					}
				}
			}
			f.send(t, 0, 'g')
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), end)
			f.receive(t, "DONE")
			if got := threadValues(t, s, f, "counters"); got != [3]uint32{0, 1, 1} {
				t.Fatalf("shared instruction was lost or repeated: %v", got)
			}
			if !remove {
				threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
			threadExit(t, s, 0)
		})
	}
}

func TestNativeThreadsPendingSignalsAreThreadSpecific(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "signals")
	snapshot, tids := threadInitial(t, s, f, 3)
	worker, end := f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(worker) })
	threadCommand(t, func() error { return s.AddBreakpoint(end) })
	for i := 1; i <= 2; i++ {
		thread := threadByTID(t, snapshot, tids[i])
		f.send(t, i, 'g')
		result := threadRun(t, s, threadExact(thread.Ref))
		if result.Thread != thread.Ref || result.Stop.Reason != target.StopSignal || result.Stop.Signal != (target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}) {
			t.Fatalf("thread %d signal stop: %+v", i, result)
		}
		snapshot = threadStopped(t, s, 3)
	}
	for i := 1; i <= 2; i++ {
		thread := threadByTID(t, threadSnapshot(t, s), tids[i])
		signal := target.Signal{}
		if i == 1 {
			signal = target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}
		}
		run := threadStart(t, s, target.RunRequest{
			Threads: threadExact(thread.Ref),
			Signals: []target.ThreadSignal{{Thread: thread.Ref, Stop: thread.Token.Stop, Signal: signal}},
		})
		threadBreakpoint(t, threadWait(t, run), worker)
		threadStopped(t, s, 3)
	}
	if got := threadValues(t, s, f, "delivered"); got != [3]uint32{0, 1, 0} {
		t.Fatalf("thread-specific delivery/suppression: %v", got)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(worker) })
	f.send(t, 0, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), end)
	f.receive(t, "DONE")
	threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
	threadExit(t, s, 0)
}

func TestNativeThreadsStepPeerPolicy(t *testing.T) {
	for _, continuePeer := range []bool{false, true} {
		t.Run(fmt.Sprintf("continue_%t", continuePeer), func(t *testing.T) {
			f := newThreadFixture(t)
			s := f.launch(t, "peer")
			snapshot, tids := threadInitial(t, s, f, 3)
			selected := threadByTID(t, snapshot, tids[1])
			peer := threadByTID(t, snapshot, tids[2])
			site := f.address(t, "read_site")
			threadCommand(t, func() error { return s.AddBreakpoint(site) })
			f.send(t, 1, 'g')
			threadBreakpoint(t, threadRun(t, s, threadExact(selected.Ref)), site)
			threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
			f.send(t, 2, 'g')
			request := target.StepRequest{Thread: selected.Ref}
			if continuePeer {
				request.Continue = threadExact(peer.Ref)
			}
			run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(request) })
			if err != nil {
				t.Fatal(err)
			}
			if !continuePeer {
				f.send(t, 1, 'r')
			}
			result := threadWait(t, run)
			if result.Thread != selected.Ref || result.Stop.Reason != target.StopStep || result.Stop.RawPC == nil || *result.Stop.RawPC != site+2 {
				var pc target.Address
				if result.Stop.RawPC != nil {
					pc = *result.Stop.RawPC
				}
				t.Fatalf("single syscall step: PC=%#x, want %#x: %+v", pc, site+2, result)
			}
			snapshot = threadStopped(t, s, 3)
			if result := threadRegister(t, s, threadByTID(t, snapshot, tids[1]).Token, "rax"); result != 1 {
				t.Fatalf("selected read result: %d", result)
			}
			want := [3]uint32{}
			if continuePeer {
				want[2] = 1
			}
			if got := threadValues(t, s, f, "counters"); got != want {
				t.Fatalf("peer policy counters: got %v, want %v", got, want)
			}
			end := f.address(t, "done_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(end) })
			f.send(t, 0, 'g')
			f.send(t, 2, 'f')
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), end)
			f.receive(t, "DONE")
			threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
			threadExit(t, s, 0)
		})
	}
	t.Run("icebp_remains_signal", func(t *testing.T) {
		f := newThreadFixture(t)
		s := f.launch(t, "trap")
		snapshot, tids := threadInitial(t, s, f, 3)
		selected := threadByTID(t, snapshot, tids[1])
		site := f.address(t, "icebp_site")
		threadCommand(t, func() error { return s.AddBreakpoint(site) })
		f.send(t, 1, 'g')
		threadBreakpoint(t, threadRun(t, s, threadExact(selected.Ref)), site)
		threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
		run, err := threadCall(t, func() (*native.Run, error) {
			return s.StepInstruction(target.StepRequest{Thread: selected.Ref})
		})
		if err != nil {
			t.Fatal(err)
		}
		result := threadWait(t, run)
		if result.Thread != selected.Ref || result.Stop.Reason != target.StopSignal || result.Stop.Signal != (target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGTRAP)}) || result.Stop.RawPC == nil || *result.Stop.RawPC != site+1 {
			t.Fatalf("ICEBP was misclassified as debugger step completion: %+v", result)
		}
		snapshot = threadStopped(t, s, 3)
		selected = threadByTID(t, snapshot, tids[1])
		worker := f.address(t, "worker_checkpoint")
		threadCommand(t, func() error { return s.AddBreakpoint(worker) })
		run = threadStart(t, s, target.RunRequest{
			Threads: threadExact(selected.Ref),
			Signals: []target.ThreadSignal{{Thread: selected.Ref, Stop: selected.Token.Stop, Signal: target.Signal{}}},
		})
		threadBreakpoint(t, threadWait(t, run), worker)
		threadCommand(t, func() error { return s.RemoveBreakpoint(worker) })
		f.send(t, 0, 'g')
		f.send(t, 2, 'g')
		threadExit(t, s, 0)
		f.receive(t, "DONE")
	})
}

type threadProcess struct {
	*exec.Cmd
	once sync.Once
	done chan struct{}
	err  error
}

func (p *threadProcess) Wait() error {
	p.once.Do(func() {
		go func() {
			p.err = p.Cmd.Wait()
			close(p.done)
		}()
	})
	<-p.done
	return p.err
}

func (f *threadFixture) start(t *testing.T, mode string) *threadProcess {
	t.Helper()
	cmd := &threadProcess{Cmd: exec.Command(f.path, f.args(mode)...), done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-cmd.done:
		default:
			_ = cmd.Process.Kill()
			_, _ = threadCall(t, func() (struct{}, error) { return struct{}{}, cmd.Wait() })
		}
	})
	return cmd
}

func TestNativeThreadsAttachDetachAndCreation(t *testing.T) {
	for _, creating := range []bool{false, true} {
		t.Run(fmt.Sprintf("creating_%t", creating), func(t *testing.T) {
			f := newThreadFixture(t)
			mode := "attach"
			if creating {
				mode = "creating"
			}
			cmd := f.start(t, mode)
			tids := f.receive(t, "READY")
			if creating {
				f.send(t, 0, 'g')
			}
			s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
			if err != nil {
				t.Fatal(err)
			}
			threadSessionCleanup(t, s, false)
			snapshot := threadSnapshot(t, s)
			entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", cmd.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			threadStopped(t, s, len(entries))
			for _, entry := range entries {
				tid, err := strconv.Atoi(entry.Name())
				if err != nil {
					t.Fatal(err)
				}
				thread := threadByTID(t, snapshot, tid)
				threadRegister(t, s, thread.Token, "rip")
			}
			worker := f.address(t, "worker_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(worker) })
			f.send(t, 1, 'g')
			threadBreakpoint(t, threadRun(t, s, threadExact(threadByTID(t, snapshot, tids[1]).Ref)), worker)
			threadCommand(t, s.Detach)
			if s.State() != target.StateDetached {
				t.Fatalf("detach state: %s", s.State())
			}
			if !creating {
				f.send(t, 0, 'g')
			} else {
				tids = f.receive(t, "CREATED")
				if tids[2] == 0 {
					t.Fatal("newborn thread was not acknowledged")
				}
			}
			f.send(t, 2, 'g')
			f.receive(t, "DONE")
			threadCommand(t, cmd.Wait)
			if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
				t.Fatalf("detached fixture did not complete: %v", cmd.ProcessState)
			}
		})
	}
	t.Run("group_stop_close", func(t *testing.T) {
		f := newThreadFixture(t)
		cmd := f.start(t, "attach")
		tids := f.receive(t, "READY")
		threadCommand(t, func() error { return cmd.Process.Signal(unix.SIGSTOP) })
		var status unix.WaitStatus
		pid, err := threadCall(t, func() (int, error) { return unix.Wait4(cmd.Process.Pid, &status, unix.WUNTRACED, nil) })
		if err != nil || pid != cmd.Process.Pid || !status.Stopped() || status.StopSignal() != unix.SIGSTOP {
			t.Fatalf("fixture group-stop: pid=%d status=%#x, %v", pid, uint32(status), err)
		}
		s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
		if err != nil {
			t.Fatal(err)
		}
		threadSessionCleanup(t, s, false)
		snapshot := threadStopped(t, s, 3)
		for _, tid := range tids {
			thread := threadByTID(t, snapshot, tid)
			if !thread.GroupStopped || thread.Stop.Reason != target.StopGroupStop {
				t.Fatalf("thread group-stop was lost: %+v", thread)
			}
			threadRegister(t, s, thread.Token, "rip")
		}
		threadCommand(t, s.Close)
		for _, tid := range tids {
			deadline := time.Now().Add(5 * time.Second)
			for {
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", cmd.Process.Pid, tid))
				if err != nil {
					t.Fatal(err)
				}
				fields := make(map[string]string)
				for _, line := range strings.Split(string(data), "\n") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						fields[parts[0]] = parts[1]
					}
				}
				if fields["TracerPid:"] != "0" {
					t.Fatalf("close retained tracing on TID %d: %s", tid, fields["TracerPid:"])
				}
				if fields["State:"] == "T" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("close lost group-stop on TID %d: %s", tid, fields["State:"])
				}
				runtime.Gosched()
			}
		}
		for i := range f.inputs {
			f.send(t, i, 'g')
		}
		poll := []unix.PollFd{{Fd: int32(f.output.Fd()), Events: unix.POLLIN}}
		if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
			t.Fatalf("group-stopped fixture acknowledged before SIGCONT: %d, %v", n, err)
		}
		threadCommand(t, func() error { return cmd.Process.Signal(unix.SIGCONT) })
		f.receive(t, "DONE")
		threadCommand(t, cmd.Wait)
	})
}

func TestNativeThreadsLeaderExitKeepsPeerUsable(t *testing.T) {
	for _, stepExit := range []bool{false, true} {
		t.Run(fmt.Sprintf("step_%t", stepExit), func(t *testing.T) {
			f := newThreadFixture(t)
			mode := "leader"
			if stepExit {
				mode = "leaderstep"
			}
			s := f.launch(t, mode)
			snapshot, tids := threadInitial(t, s, f, 2)
			leader, peer := threadByTID(t, snapshot, tids[0]), threadByTID(t, snapshot, tids[1])
			worker := f.address(t, "worker_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(worker) })
			f.send(t, 0, 'g')
			if stepExit {
				site := f.address(t, "exit_site")
				threadCommand(t, func() error { return s.AddBreakpoint(site) })
				threadBreakpoint(t, threadRun(t, s, threadExact(leader.Ref)), site)
				threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
				run, err := threadCall(t, func() (*native.Run, error) {
					return s.StepInstruction(target.StepRequest{Thread: leader.Ref})
				})
				if err != nil {
					t.Fatal(err)
				}
				result := threadWait(t, run)
				if result.Thread != leader.Ref || result.Stop.Reason != target.StopExited {
					t.Fatalf("exiting selected leader did not finish step: %+v", result)
				}
				threadStopped(t, s, 1)
			}
			f.send(t, 1, 'g')
			result := threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
			threadBreakpoint(t, result, worker)
			f.receive(t, "SURVIVED")
			if result.Thread != peer.Ref || s.State() == target.StateExited {
				t.Fatalf("leader exit ended process: %+v", result)
			}
			snapshot = threadStopped(t, s, 1)
			threadRegister(t, s, threadByTID(t, snapshot, tids[1]).Token, "rip")
			if got := threadValues(t, s, f, "counters"); got != [3]uint32{0, 1, 0} {
				t.Fatalf("surviving peer memory access: %v", got)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(worker) })
			threadExit(t, s, 0)
		})
	}
	for _, tc := range []struct {
		closeSession bool
		stepExit     bool
	}{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("attached_close_%t_step_%t", tc.closeSession, tc.stepExit), func(t *testing.T) {
			f := newThreadFixture(t)
			mode := "leader"
			if tc.stepExit {
				mode = "leaderstep"
			}
			cmd := f.start(t, mode)
			tids := f.receive(t, "READY")
			s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
			if err != nil {
				t.Fatal(err)
			}
			threadSessionCleanup(t, s, false)
			snapshot := threadStopped(t, s, 2)
			leader, peer := threadByTID(t, snapshot, tids[0]), threadByTID(t, snapshot, tids[1])
			worker := f.address(t, "worker_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(worker) })
			f.send(t, 0, 'g')
			wantCounters := [3]uint32{0, 1, 0}
			if tc.stepExit {
				site := f.address(t, "exit_site")
				threadCommand(t, func() error { return s.AddBreakpoint(site) })
				threadBreakpoint(t, threadRun(t, s, threadExact(leader.Ref)), site)
				threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
				run, err := threadCall(t, func() (*native.Run, error) {
					return s.StepInstruction(target.StepRequest{Thread: leader.Ref})
				})
				if err != nil {
					t.Fatal(err)
				}
				result := threadWait(t, run)
				if result.Thread != leader.Ref || result.Stop.Reason != target.StopExited {
					t.Fatalf("attached leader exit step without peer event: %+v", result)
				}
				wantCounters = [3]uint32{}
			} else {
				f.send(t, 1, 'g')
				result := threadRun(t, s, threadProcessSet(snapshot))
				threadBreakpoint(t, result, worker)
				f.receive(t, "SURVIVED")
				if result.Thread != peer.Ref {
					t.Fatalf("survivor identity changed: %+v", result)
				}
			}
			snapshot = threadStopped(t, s, 1)
			threadRegister(t, s, threadByTID(t, snapshot, tids[1]).Token, "rip")
			if got := threadValues(t, s, f, "counters"); got != wantCounters {
				t.Fatalf("attached survivor memory: %v", got)
			}
			if tc.closeSession {
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
			if tc.stepExit {
				f.send(t, 1, 'g')
				f.receive(t, "SURVIVED")
			}
			threadCommand(t, cmd.Wait)
		})
	}
}

func TestNativeThreadsNonLeaderExecInvalidatesImage(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "exec")
	snapshot, tids := threadInitial(t, s, f, 2)
	oldMemory := snapshot.Memory
	beforeExec := snapshot.Sequence
	peer := threadByTID(t, snapshot, tids[1])
	site := f.address(t, "shared_site")
	threadCommand(t, func() error { return s.AddBreakpoint(site) })
	f.send(t, 1, 'g')
	result := threadRun(t, s, threadExact(peer.Ref))
	if result.Stop.Reason != target.StopExec {
		t.Fatalf("non-leader exec stop: %+v", result)
	}
	snapshot = threadStopped(t, s, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	execEvents := 0
	for sequence := beforeExec; sequence < snapshot.Sequence; {
		event, err := s.NextEvent(ctx, sequence)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == target.EventProcessExec {
			execEvents++
		}
		sequence = event.Sequence
	}
	if execEvents != 1 {
		t.Fatalf("exec event published %d times", execEvents)
	}
	execThread := threadByTID(t, snapshot, s.PID())
	if execThread.TID == tids[1] || snapshot.Memory.Space == oldMemory.Space {
		t.Fatalf("exec failed to replace identity/address space: %+v", snapshot)
	}
	threadRegister(t, s, execThread.Token, "rip")
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(peer.Token) }); err == nil {
		t.Fatal("pre-exec thread token remained valid")
	}
	var code [1]byte
	if _, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(oldMemory, site, code[:]) }); !errors.Is(err, target.ErrStale) {
		t.Fatalf("pre-exec memory token: %v", err)
	}
	if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, site, code[:]) }); err != nil || n != 1 || code[0] == 0xcc {
		t.Fatalf("old image breakpoint survived exec: %x, %d, %v", code, n, err)
	}
	end := f.address(t, "after_exec_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(end) })
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), end)
	f.receive(t, "EXECREADY")
	threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
	threadExit(t, s, 23)
}

func TestNativeThreadsSessionsDoNotStealWaits(t *testing.T) {
	aFixture, bFixture := newThreadFixture(t), newThreadFixture(t)
	a, b := aFixture.launch(t, "wait"), bFixture.launch(t, "wait")
	aSnapshot, _ := threadInitial(t, a, aFixture, 3)
	bSnapshot, _ := threadInitial(t, b, bFixture, 3)
	aRun := threadStart(t, a, target.RunRequest{Threads: threadProcessSet(aSnapshot)})
	bRun := threadStart(t, b, target.RunRequest{Threads: threadProcessSet(bSnapshot)})
	command := exec.Command("/bin/sh", "-c", "exit 17")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_, err := threadCall(t, func() (struct{}, error) { return struct{}{}, command.Wait() })
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("ordinary exec wait was consumed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := aRun.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	threadCommand(t, func() error { return a.Interrupt(target.InterruptRequest{Threads: threadProcessSet(aSnapshot)}) })
	result := threadWait(t, aRun)
	if result.Stop.Reason != target.StopInterrupt {
		t.Fatalf("session interrupt: %+v", result)
	}
	threadStopped(t, a, 3)
	if b.State() != target.StateRunning {
		t.Fatalf("interrupt changed other session: %s", b.State())
	}
	threadCommand(t, b.Close)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err = bRun.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) || (err != nil && !errors.Is(err, target.ErrClosed)) {
		t.Fatalf("closed run did not terminate: %+v, %v", result, err)
	}
	if err == nil && result.Stop.Reason != target.StopSignaled && result.Stop.Reason != target.StopExited {
		t.Fatalf("close returned stale success stop: %+v", result)
	}
	if b.State() != target.StateClosed {
		t.Fatalf("closed session: %s", b.State())
	}
	if pid, err := unix.Wait4(b.PID(), nil, unix.WNOHANG|unix.WALL, nil); pid != -1 || !errors.Is(err, unix.ECHILD) {
		t.Fatalf("closed target was not reaped: pid=%d, %v", pid, err)
	}
}

func threadWaitForRead(t *testing.T, pid, tid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/syscall", pid, tid))
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data))
		if len(fields) > 0 && fields[0] == strconv.Itoa(unix.SYS_READ) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("thread never entered the fixture read syscall: %s", data)
		}
		runtime.Gosched()
	}
}

func TestNativeThreadsBlockingBreakpointCanInterruptOrClose(t *testing.T) {
	for _, closeRunning := range []bool{false, true} {
		t.Run(fmt.Sprintf("close_%t", closeRunning), func(t *testing.T) {
			f := newThreadFixture(t)
			s := f.launch(t, "peer")
			snapshot, tids := threadInitial(t, s, f, 3)
			selected := threadByTID(t, snapshot, tids[1])
			site := f.address(t, "read_site")
			threadCommand(t, func() error { return s.AddBreakpoint(site) })
			f.send(t, 1, 'g')
			threadBreakpoint(t, threadRun(t, s, threadExact(selected.Ref)), site)
			f.send(t, 2, 'g')
			run := threadStart(t, s, target.RunRequest{Threads: threadExact(selected.Ref)})
			threadWaitForRead(t, s.PID(), tids[1])
			if closeRunning {
				threadCommand(t, s.Close)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := run.Wait(ctx)
				if errors.Is(err, context.DeadlineExceeded) || (err != nil && !errors.Is(err, target.ErrClosed)) {
					t.Fatalf("close during blocked step-over: %+v, %v", result, err)
				}
				return
			}
			threadCommand(t, func() error { return s.Interrupt(target.InterruptRequest{Threads: threadProcessSet(snapshot)}) })
			result := threadWait(t, run)
			if result.Stop.Reason != target.StopInterrupt {
				t.Fatalf("blocked step-over interrupt: %+v", result)
			}
			threadStopped(t, s, 3)
			if got := threadValues(t, s, f, "counters"); got != [3]uint32{} {
				t.Fatalf("exact-thread run unexpectedly ran peers: %v", got)
			}
			stopped := threadSnapshot(t, s)
			var armed [1]byte
			if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(stopped.Memory, site, armed[:]) }); err != nil || n != 1 || armed[0] != 0xcc {
				t.Fatalf("syscall entry did not rearm the shared breakpoint: %x, %d, %v", armed, n, err)
			}
			peer := threadByTID(t, threadSnapshot(t, s), tids[2])
			peerRun := threadStart(t, s, target.RunRequest{Threads: threadExact(peer.Ref)})
			threadCommand(t, func() error { return s.Interrupt(target.InterruptRequest{Threads: threadExact(peer.Ref)}) })
			if result := threadWait(t, peerRun); result.Stop.Reason != target.StopInterrupt {
				t.Fatalf("peer-only run after syscall entry: %+v", result)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
			end := f.address(t, "done_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(end) })
			f.send(t, 0, 'g')
			f.send(t, 2, 'f')
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), end)
			f.receive(t, "DONE")
			if got := threadValues(t, s, f, "counters"); got != [3]uint32{0, 1, 1} {
				t.Fatalf("blocked step-over recovery counters: %v", got)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
			threadExit(t, s, 0)
		})
	}
}

func TestNativeThreadsNewbornResumeScope(t *testing.T) {
	for _, processScope := range []bool{false, true} {
		t.Run(fmt.Sprintf("process_%t", processScope), func(t *testing.T) {
			f := newThreadFixture(t)
			s := f.launch(t, "creating")
			snapshot, tids := threadInitial(t, s, f, 2)
			leader := threadByTID(t, snapshot, tids[0])
			end := f.address(t, "done_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(end) })
			set := threadExact(leader.Ref)
			if processScope {
				set = threadProcessSet(snapshot)
			}
			f.send(t, 0, 'g')
			run := threadStart(t, s, target.RunRequest{Threads: set})
			if !processScope {
				known := make(map[target.ThreadRef]bool)
				for _, thread := range snapshot.Threads {
					known[thread.Ref] = true
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				for sequence := snapshot.Sequence; ; {
					event, err := s.NextEvent(ctx, sequence)
					if err != nil {
						t.Fatal(err)
					}
					sequence = event.Sequence
					if event.Kind == target.EventThreadCreated && !known[event.Thread] {
						break
					}
				}
				threadCommand(t, func() error { return s.Interrupt(target.InterruptRequest{Threads: threadProcessSet(snapshot)}) })
				result := threadWait(t, run)
				if result.Stop.Reason != target.StopInterrupt {
					t.Fatalf("exact creator interrupt: %+v", result)
				}
				threadStopped(t, s, 3)
				if got := threadValues(t, s, f, "ready"); got != [3]uint32{0, 1, 0} {
					t.Fatalf("newborn ran outside exact run scope: %v", got)
				}
				run = threadStart(t, s, target.RunRequest{Threads: threadProcessSet(threadSnapshot(t, s))})
			}
			threadBreakpoint(t, threadWait(t, run), end)
			tids = f.receive(t, "CREATED")
			snapshot = threadStopped(t, s, 3)
			threadByTID(t, snapshot, tids[2])
			if got := threadValues(t, s, f, "ready"); got != [3]uint32{0, 1, 1} {
				t.Fatalf("process scope failed to run newborn: %v", got)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(end) })
			f.send(t, 1, 'g')
			f.send(t, 2, 'g')
			threadExit(t, s, 0)
			f.receive(t, "DONE")
		})
	}
}

func TestNativeThreadsUntracedCloneRejectsAllStop(t *testing.T) {
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprintf("attached_%t", attached), func(t *testing.T) {
			f := newThreadFixture(t)
			var s *native.Session
			if attached {
				cmd := f.start(t, "hiddenclose")
				f.receive(t, "READY")
				var err error
				s, err = threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
				if err != nil {
					t.Fatal(err)
				}
				threadSessionCleanup(t, s, false)
				threadStopped(t, s, 1)
			} else {
				s = f.launch(t, "hidden")
				threadInitial(t, s, f, 1)
			}
			pidfd, err := unix.PidfdOpen(s.PID(), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pidfd)
			site := f.address(t, "done_checkpoint")
			threadCommand(t, func() error { return s.AddBreakpoint(site) })
			before := threadSnapshot(t, s)
			f.send(t, 0, 'g')
			run := threadStart(t, s, target.RunRequest{Threads: threadProcessSet(before)})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var tids [3]int
			if attached {
				tids = f.receive(t, "HIDDEN")
				_, err := threadCall(t, func() (struct{}, error) { return struct{}{}, s.Close() })
				if !errors.Is(err, target.ErrPartial) || s.State() == target.StateClosed || s.State() == target.StateDetached || s.State() == target.StateStopped {
					t.Fatalf("unsafe detach was not reported as retained partial cleanup: state=%s, %v", s.State(), err)
				}
			}
			result, err := run.Wait(ctx)
			if !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("hidden clone was accepted as complete all-stop: %+v, %v", result, err)
			}
			if !attached {
				tids = f.receive(t, "HIDDEN")
			}
			if tids[1] <= 0 || tids[1] == s.PID() {
				t.Fatalf("invalid hidden thread identity: %v", tids)
			}
			after := threadSnapshot(t, s)
			if after.State == target.StateStopped || s.State() == target.StateStopped || after.Memory.Revision != 0 {
				t.Fatalf("incomplete closure exposed stopped state or usable memory: %+v", after)
			}
			for _, thread := range after.Threads {
				if thread.TID == tids[1] {
					t.Fatalf("untraced task was claimed as owned: %+v", thread)
				}
			}
			for sequence := before.Sequence; sequence < after.Sequence; {
				event, err := s.NextEvent(ctx, sequence)
				if err != nil {
					t.Fatal(err)
				}
				if event.Kind == target.EventAllStopped {
					t.Fatalf("all-stopped event published without kernel closure: %+v", event)
				}
				sequence = event.Sequence
			}
			status, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", s.PID(), tids[1]))
			if err != nil || !strings.Contains(string(status), "TracerPid:\t0\n") {
				t.Fatalf("untraced fixture child was acquired: %v\n%s", err, status)
			}
			var memory [1]byte
			if _, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(before.Memory, site, memory[:]) }); err == nil {
				t.Fatal("memory read accepted after incomplete all-stop")
			}
			if attached {
				file, err := os.Open(fmt.Sprintf("/proc/%d/mem", s.PID()))
				if err != nil {
					t.Fatal(err)
				}
				n, readErr := file.ReadAt(memory[:], int64(site))
				file.Close()
				if readErr != nil || n != 1 || memory[0] != 0xcc {
					t.Fatalf("unsafe detach altered breakpoint bytes: %x, %d, %v", memory, n, readErr)
				}
				threadCommand(t, s.Kill)
				threadCommand(t, s.Close)
			} else {
				threadCommand(t, s.Close)
			}
			poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
			if n, err := unix.Poll(poll, 5000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
				t.Fatalf("cleanup left hidden group member alive: n=%d events=%#x, %v", n, poll[0].Revents, err)
			}
			if s.State() != target.StateClosed {
				t.Fatalf("hidden thread cleanup state: %s", s.State())
			}
		})
	}
}

func TestNativeThreadsCloneInstructionStep(t *testing.T) {
	for _, tc := range []struct {
		name     string
		process  bool
		inlineBP bool
	}{
		{name: "hold"},
		{name: "process", process: true},
		{name: "breakpoint_process", process: true, inlineBP: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newThreadFixture(t)
			s := f.launch(t, "rawclone")
			snapshot, tids := threadInitial(t, s, f, 1)
			parent := threadByTID(t, snapshot, tids[0])
			site, checkpoint, done := f.address(t, "clone_site"), f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
			var original [1]byte
			if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, site, original[:]) }); err != nil || n != 1 || original[0] != 0x0f {
				t.Fatalf("clone syscall encoding: %x, %d, %v", original, n, err)
			}
			for _, address := range []target.Address{site, checkpoint, done} {
				threadCommand(t, func() error { return s.AddBreakpoint(address) })
			}
			f.send(t, 0, 'g')
			threadBreakpoint(t, threadRun(t, s, threadExact(parent.Ref)), site)
			if !tc.inlineBP {
				threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
			}
			before := threadStopped(t, s, 1)
			var result target.RunResult
			var child target.ThreadInfo
			if tc.inlineBP {
				result = threadRun(t, s, threadProcessSet(before))
				threadBreakpoint(t, result, checkpoint)
				snapshot = threadStopped(t, s, 2)
			} else {
				request := target.StepRequest{Thread: parent.Ref}
				if tc.process {
					request.Continue = threadProcessSet(before)
				}
				run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(request) })
				if err != nil {
					t.Fatal(err)
				}
				result = threadWait(t, run)
				if result.Thread != parent.Ref || result.Stop.Reason != target.StopStep || result.Stop.RawPC == nil || *result.Stop.RawPC != site+2 {
					t.Fatalf("clone syscall did not finish the original single-step: %+v", result)
				}
				snapshot = threadStopped(t, s, 2)
				childTID := int(threadRegister(t, s, threadByTID(t, snapshot, tids[0]).Token, "rax"))
				if childTID <= 0 || childTID == tids[0] {
					t.Fatalf("clone syscall result: %d", childTID)
				}
				child = threadByTID(t, snapshot, childTID)
				if !tc.process {
					if pc := threadRegister(t, s, child.Token, "rip"); pc != uint64(site+2) {
						t.Fatalf("held newborn executed before selected step completed: PC=%#x, want %#x", pc, site+2)
					}
					if values := threadValues(t, s, f, "clone_data"); values != [3]uint32{} {
						t.Fatalf("held newborn changed memory: %v", values)
					}
				}
			}
			if tc.inlineBP {
				for _, thread := range snapshot.Threads {
					if thread.Ref != parent.Ref && thread.State == target.StateStopped && !thread.Exiting {
						child = thread
					}
				}
			}
			if child.Ref.ID == 0 || child.Ref == parent.Ref {
				t.Fatalf("clone did not publish one distinct child: %+v", snapshot)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			created := 0
			for sequence := before.Sequence; sequence < snapshot.Sequence; {
				event, err := s.NextEvent(ctx, sequence)
				if err != nil {
					t.Fatal(err)
				}
				sequence = event.Sequence
				if event.Kind == target.EventThreadCreated {
					if event.Thread != child.Ref {
						t.Fatalf("clone generated an unexpected child: %+v", event)
					}
					created++
				}
				if event.Thread == child.Ref && event.Kind == target.EventThreadResumed {
					if created != 1 || !tc.process {
						t.Fatalf("newborn resumed before ownership or outside run policy: %+v", event)
					}
				}
			}
			if created != 1 {
				t.Fatalf("clone instruction generated %d child events", created)
			}
			if !tc.inlineBP {
				threadBreakpoint(t, threadRun(t, s, threadProcessSet(snapshot)), checkpoint)
				snapshot = threadStopped(t, s, 2)
			}
			tids = f.receive(t, "CLONED")
			if tids[1] != child.TID {
				t.Fatalf("clone return value changed: reported %d, child %d", tids[1], child.TID)
			}
			observedByte := uint32(original[0])
			if tc.inlineBP {
				observedByte = 0xcc
				var armed [1]byte
				if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, site, armed[:]) }); err != nil || n != 1 || armed[0] != 0xcc {
					t.Fatalf("clone breakpoint was not rearmed: %x, %d, %v", armed, n, err)
				}
			}
			if values := threadValues(t, s, f, "clone_data"); values != [3]uint32{1, 0, observedByte} {
				t.Fatalf("clone count or newborn's first instruction observed an unsafe patch: %v", values)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
			if tc.inlineBP {
				threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
			}
			f.send(t, 0, 'g')
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
			f.receive(t, "DONE")
			threadStopped(t, s, 1)
			if values := threadValues(t, s, f, "clone_data"); values != [3]uint32{1, 1, observedByte} {
				t.Fatalf("original clone syscall was lost or repeated: %v", values)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
			threadExit(t, s, 0)
		})
	}
}
