package native

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func coreCall[T any](t *testing.T, operation func() (T, error)) (T, error) {
	t.Helper()
	done := make(chan response[T], 1)
	go func() {
		value, err := operation()
		done <- response[T]{value: value, err: err}
	}()
	select {
	case result := <-done:
		return result.value, result.err
	case <-time.After(10 * time.Second):
		var zero T
		return zero, context.DeadlineExceeded
	}
}

func coreClose(t *testing.T, s *Session) error {
	t.Helper()
	pidfd := -1
	var pinErr error
	if state := s.State(); state == target.StateStopped || state == target.StateRunning {
		pidfd, pinErr = unix.PidfdOpen(s.PID(), 0)
		if pidfd >= 0 {
			defer unix.Close(pidfd)
		}
	}
	_, err := coreCall(t, func() (struct{}, error) { return struct{}{}, s.Close() })
	if errors.Is(err, context.DeadlineExceeded) {
		if pidfd >= 0 {
			pinErr = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			if errors.Is(pinErr, unix.ESRCH) {
				pinErr = nil
			}
		}
		_, retry := coreCall(t, func() (struct{}, error) { return struct{}{}, s.Close() })
		return errors.Join(err, pinErr, retry)
	}
	return err
}

func coreOwnSession(t *testing.T, s *Session) {
	t.Helper()
	t.Cleanup(func() {
		if err := coreClose(t, s); err != nil {
			t.Error(err)
		}
	})
}

func coreWait(t *testing.T, run *Run) (target.RunResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return run.Wait(ctx)
}

func coreContinue(t *testing.T, s *Session) (target.Stop, error) {
	t.Helper()
	return coreCall(t, func() (target.Stop, error) { return s.Continue(target.Signal{}) })
}

func coreReaped(t *testing.T, pid int) {
	t.Helper()
	var status unix.WaitStatus
	if got, err := unix.Wait4(pid, &status, unix.WALL|unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("PID %d remained waitable: pid=%d status=%#x error=%v", pid, got, uint32(status), err)
	}
}

func coreSymbol(t *testing.T, path, name string) target.Address {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range symbols {
		if symbol.Name == name {
			return target.Address(symbol.Value)
		}
	}
	t.Fatalf("missing fixture symbol %q", name)
	return 0
}

func coreTempDir(t *testing.T) string {
	t.Helper()
	tmp, err := filepath.Abs(filepath.Join("..", ".cache", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	return t.TempDir()
}

func coreFixture(t *testing.T) string {
	t.Helper()
	dir := coreTempDir(t)
	source := filepath.Join(dir, "fixture.c")
	path := filepath.Join(dir, "fixture")
	code := `#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void *spin(void *p) { for (;;) __asm__ volatile(""); return p; }
__attribute__((noinline)) void core_checkpoint(void) { __asm__ volatile("nop"); }
int main(int n, char **v) {
    if (n > 1 && !strcmp(v[1], "exit")) return 7;
    if (n > 1 && !strcmp(v[1], "exec")) { execl(v[0], v[0], "exit", (char *)0); return 99; }
    if (n > 1 && (!strcmp(v[1], "thread") || !strcmp(v[1], "readythread"))) {
        pthread_t t;
        if (pthread_create(&t, 0, spin, 0)) return 98;
        core_checkpoint();
        if (!strcmp(v[1], "readythread")) { puts("ready"); fflush(stdout); }
    }
    if (n > 1 && !strcmp(v[1], "fork")) { if (fork() < 0) return 97; }
    spin(0);
    return 0;
}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "cc", "-O0", "-no-pie", "-pthread", "-o", path, source).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, out)
	}
	return path
}

func TestCoreLaunchFailures(t *testing.T) {
	if _, err := Launch("/does/not/exist/fastdbg2"); err == nil {
		t.Fatal("missing executable accepted")
	}
	path := coreFixture(t)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Launch(path); err == nil {
		t.Fatal("non-executable ELF accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[18], data[19] = 183, 0
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Launch(path); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("foreign ELF: %v", err)
	}
}

func TestCoreExitAndClose(t *testing.T) {
	s, err := Launch(coreFixture(t), "exit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := coreClose(t, s); err != nil {
			t.Error(err)
		}
	})
	stop, err := coreContinue(t, s)
	if err != nil || stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 7 {
		t.Fatalf("exit stop=%+v error=%v", stop, err)
	}
	if _, err := s.Step(target.Signal{}); !errors.Is(err, target.ErrExited) {
		t.Fatalf("step after exit: %v", err)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	if s.State() != target.StateClosed {
		t.Fatalf("state=%v", s.State())
	}
	if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
}

func TestCoreTaskAndImageChanges(t *testing.T) {
	path := coreFixture(t)
	for _, mode := range []string{"thread", "fork", "exec"} {
		t.Run(mode, func(t *testing.T) {
			s, err := Launch(path, mode)
			if err != nil {
				t.Fatal(err)
			}
			coreOwnSession(t, s)
			before, err := s.Snapshot()
			if err != nil || len(before.Threads) != 1 {
				t.Fatalf("initial snapshot=%+v error=%v", before, err)
			}
			switch mode {
			case "thread":
				address := coreSymbol(t, path, "core_checkpoint")
				var original, patched, restored [1]byte
				if n, err := s.ReadMemory(address, original[:]); err != nil || n != 1 {
					t.Fatalf("original instruction: n=%d error=%v", n, err)
				}
				if err := s.AddBreakpoint(address); err != nil {
					t.Fatal(err)
				}
				run, err := s.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: before.Process}})
				if err != nil {
					t.Fatal(err)
				}
				result, err := coreWait(t, run)
				if err != nil || result.Stop.Reason != target.StopBreakpoint || result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != address {
					t.Fatalf("thread creation run=%+v error=%v", result, err)
				}
				after, err := s.Snapshot()
				if err != nil || after.State != target.StateStopped || after.Process != before.Process || len(after.Threads) != 2 || after.Memory.Space != before.Memory.Space {
					t.Fatalf("thread closure=%+v error=%v", after, err)
				}
				seen := make(map[target.ThreadRef]bool)
				for _, info := range after.Threads {
					if seen[info.Ref] || info.Ref.ID == 0 || info.Process != before.Process || info.State != target.StateStopped || info.Listening || info.Exiting {
						t.Fatalf("thread identity=%+v", info)
					}
					seen[info.Ref] = true
					if registers, err := s.ReadThreadRegisters(info.Token); err != nil || len(registers) == 0 {
						t.Fatalf("thread %d registers=%v error=%v", info.TID, registers, err)
					}
				}
				if !seen[before.Threads[0].Ref] || result.Thread != before.Threads[0].Ref {
					t.Fatalf("leader identity changed: before=%+v result=%+v after=%+v", before.Threads[0], result, after.Threads)
				}
				if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrAmbiguous) {
					t.Fatalf("implicit thread selection: %v", err)
				}
				if n, err := s.ReadMemory(address, patched[:]); err != nil || n != 1 || patched[0] != 0xcc {
					t.Fatalf("armed instruction=%x n=%d error=%v", patched, n, err)
				}
				if err := s.RemoveBreakpoint(address); err != nil {
					t.Fatal(err)
				}
				if n, err := s.ReadMemory(address, restored[:]); err != nil || n != 1 || restored != original {
					t.Fatalf("restored instruction=%x want=%x n=%d error=%v", restored, original, n, err)
				}
			case "fork":
				stop, err := coreContinue(t, s)
				if !errors.Is(err, target.ErrUnsupported) || stop.Reason != target.StopFork {
					t.Fatalf("unsupported stop=%+v error=%v", stop, err)
				}
				if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrUnsupported) {
					t.Fatalf("data after unsupported: %v", err)
				}
				after, err := s.Snapshot()
				if err != nil || after.State != target.StateStopped || len(after.Threads) != 2 {
					t.Fatalf("fork closure=%+v error=%v", after, err)
				}
				for _, info := range after.Threads {
					if info.State != target.StateStopped || info.Process.ID == 0 {
						t.Fatalf("fork ownership=%+v", info)
					}
				}
				if err := coreClose(t, s); err != nil {
					t.Fatal(err)
				}
				for _, info := range after.Threads {
					coreReaped(t, info.TID)
				}
			case "exec":
				stop, err := coreContinue(t, s)
				if err != nil || stop.Reason != target.StopExec || stop.RawPC != nil {
					t.Fatalf("exec stop=%+v error=%v", stop, err)
				}
				after, err := s.Snapshot()
				if err != nil || len(after.Threads) != 1 || after.Process != before.Process || after.Threads[0].Ref != before.Threads[0].Ref || after.Memory.Space == before.Memory.Space {
					t.Fatalf("exec identity=%+v before=%+v error=%v", after, before, err)
				}
				if _, err := s.ReadThreadRegisters(before.Threads[0].Token); !errors.Is(err, target.ErrStale) {
					t.Fatalf("pre-exec register token: %v", err)
				}
				if _, err := s.ReadSpaceMemory(before.Memory, 0, nil); !errors.Is(err, target.ErrStale) {
					t.Fatalf("pre-exec memory token: %v", err)
				}
				if _, err := s.ReadThreadRegisters(after.Threads[0].Token); err != nil {
					t.Fatalf("new image registers: %v", err)
				}
				stop, err = coreContinue(t, s)
				if err != nil || stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 7 {
					t.Fatalf("new image exit=%+v error=%v", stop, err)
				}
			}
			if err := coreClose(t, s); err != nil {
				t.Fatal(err)
			}
			coreReaped(t, s.PID())
		})
	}
}

func TestCoreLegacyRunStopsAtThreadCreation(t *testing.T) {
	s, err := Launch(coreFixture(t), "thread")
	if err != nil {
		t.Fatal(err)
	}
	coreOwnSession(t, s)
	stop, err := coreContinue(t, s)
	if !errors.Is(err, target.ErrAmbiguous) || stop.Reason != target.StopClone {
		t.Fatalf("legacy thread creation stop=%+v error=%v", stop, err)
	}
	snapshot, err := s.Snapshot()
	if err != nil || snapshot.State != target.StateStopped || len(snapshot.Threads) != 2 {
		t.Fatalf("legacy thread closure=%+v error=%v", snapshot, err)
	}
	for _, info := range snapshot.Threads {
		if info.State != target.StateStopped || info.Process != snapshot.Process {
			t.Fatalf("newborn state=%+v", info)
		}
		if _, err := s.ReadThreadRegisters(info.Token); err != nil {
			t.Fatalf("newborn register access: %v", err)
		}
	}
	if _, err := coreContinue(t, s); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("legacy resume after clone: %v", err)
	}
}

func startUntraced(t *testing.T, path, mode string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, path, mode)
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if _, err := coreCall(t, func() (struct{}, error) { return struct{}{}, cmd.Wait() }); errors.Is(err, context.DeadlineExceeded) {
			t.Error(err)
		}
	})
	return cmd
}

func TestCoreAttachAndDetach(t *testing.T) {
	cmd := startUntraced(t, coreFixture(t), "loop")
	s, err := Attach(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := coreClose(t, s); err != nil {
			t.Error(err)
		}
	})
	if s.LastStop().Reason != target.StopAttach {
		t.Fatalf("initial stop=%+v", s.LastStop())
	}
	if _, err := s.ReadRegisters(); err != nil {
		t.Fatal(err)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(unix.Signal(0)); err != nil {
		t.Fatalf("attach close killed target: %v", err)
	}
}

func TestCoreAttachSupportsMultipleThreads(t *testing.T) {
	path := coreFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, path, "readythread")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if _, err := coreCall(t, func() (struct{}, error) { return struct{}{}, cmd.Wait() }); errors.Is(err, context.DeadlineExceeded) {
			t.Error(err)
		}
	})
	line, err := coreCall(t, func() (string, error) { return bufio.NewReader(stdout).ReadString('\n') })
	if err != nil || line != "ready\n" {
		t.Fatalf("fixture readiness %q: %v", line, err)
	}
	s, err := Attach(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("multi-thread attach: %v", err)
	}
	coreOwnSession(t, s)
	snapshot, err := s.Snapshot()
	if err != nil || snapshot.State != target.StateStopped || len(snapshot.Threads) != 2 {
		t.Fatalf("attach closure=%+v error=%v", snapshot, err)
	}
	tracer, err := call(s, func(e *engine) (int, error) { return unix.Gettid(), nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range snapshot.Threads {
		if info.State != target.StateStopped || info.Process != snapshot.Process || info.Ref.ID == 0 || info.Token.Stop == 0 {
			t.Fatalf("attached thread=%+v", info)
		}
		status, err := readTaskStatus(info.TID)
		if err != nil || status.tgid != s.PID() || status.tracer != tracer {
			t.Fatalf("attached kernel ownership=%+v error=%v", status, err)
		}
		if _, err := s.ReadThreadRegisters(info.Token); err != nil {
			t.Fatalf("attached thread registers: %v", err)
		}
	}
	if snapshot.Threads[0].Ref == snapshot.Threads[1].Ref {
		t.Fatal("distinct tasks share a thread identity")
	}
	address := coreSymbol(t, path, "core_checkpoint")
	var original [1]byte
	if n, err := s.ReadMemory(address, original[:]); err != nil || n != 1 {
		t.Fatalf("original instruction: n=%d error=%v", n, err)
	}
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(unix.Signal(0)); err != nil {
		t.Fatalf("attach close killed target: %v", err)
	}
	for _, info := range snapshot.Threads {
		status, err := readTaskStatus(info.TID)
		if err != nil || status.tracer != 0 || status.tgid != cmd.Process.Pid {
			t.Fatalf("detached kernel ownership=%+v error=%v", status, err)
		}
	}
	reopened, err := Attach(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("reattach after multi-thread close: %v", err)
	}
	coreOwnSession(t, reopened)
	var restored [1]byte
	if n, err := reopened.ReadMemory(address, restored[:]); err != nil || n != 1 || restored != original {
		t.Fatalf("detach instruction restoration=%x want=%x n=%d error=%v", restored, original, n, err)
	}
}

func TestCoreAttachPreservesGroupStop(t *testing.T) {
	cmd := startUntraced(t, coreFixture(t), "loop")
	if err := cmd.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	ws, err := coreCall(t, func() (unix.WaitStatus, error) {
		var status unix.WaitStatus
		_, err := unix.Wait4(cmd.Process.Pid, &status, unix.WUNTRACED, nil)
		return status, err
	})
	if err != nil || !ws.Stopped() || ws.StopSignal() != unix.SIGSTOP {
		t.Fatalf("initial group stop=%v error=%v", ws, err)
	}
	s, err := Attach(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("group-stop attach: %v", err)
	}
	coreOwnSession(t, s)
	if stop := s.LastStop(); stop.Reason != target.StopGroupStop {
		t.Fatalf("attached group stop=%+v", stop)
	}
	snapshot, err := s.Snapshot()
	if err != nil || len(snapshot.Threads) != 1 || !snapshot.Threads[0].GroupStopped || snapshot.Threads[0].State != target.StateStopped {
		t.Fatalf("attached group-stop snapshot=%+v error=%v", snapshot, err)
	}
	if _, err := s.Step(target.Signal{}); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("instruction step through group stop: %v", err)
	}
	run, err := s.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}})
	if err != nil {
		t.Fatalf("group-stop listen: %v", err)
	}
	snapshot, err = s.Snapshot()
	if err != nil || len(snapshot.Threads) != 1 || !snapshot.Threads[0].Listening || !snapshot.Threads[0].GroupStopped {
		t.Fatalf("listening group-stop snapshot=%+v error=%v", snapshot, err)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	if _, err := coreWait(t, run); !errors.Is(err, target.ErrDetached) {
		t.Fatalf("listening run after detach: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/status")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(status), "State:\tT (stopped)") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kernel group-stop transition did not complete:\n%s", status)
		}
		runtime.Gosched()
	}
	status, err := readTaskStatus(cmd.Process.Pid)
	if err != nil || status.tracer != 0 {
		t.Fatalf("group-stop detach ownership=%+v error=%v", status, err)
	}
}

func TestCoreChildExitCompletesUnsupported(t *testing.T) {
	s := &Session{id: 1, pid: 41}
	s.state.Store(uint32(target.StateRunning))
	e := &engine{s: s, unsupported: target.ErrUnsupported}
	p := e.newProcess(41, -1, true)
	e.primary = p
	e.life.births = map[int]*birth{43: {parent: p}}
	parent := e.newThread(p, 41, true)
	parent.state, parent.stopEpoch = target.StateStopped, 1
	child := e.newThread(nil, 42, true)
	stop := target.Stop{Reason: target.StopClone}
	run := newRun(1)
	e.run = &runOperation{handle: run}
	e.barrier = &stopBarrier{thread: parent, stop: stop, err: target.ErrUnsupported}
	e.handleWait(waitResult{pid: 42, status: unix.WaitStatus(unix.SIGKILL)})
	if child.state != target.StateExited || e.barrier == nil || e.run == nil || len(e.life.births) != 1 {
		t.Fatal("child terminal lost the pending ownership barrier")
	}
	select {
	case <-run.done:
		t.Fatal("unresolved ownership completed the pending run")
	default:
	}
	if s.LastStop().Reason != target.StopUnknown {
		t.Fatalf("unresolved ownership published a stop: %+v", s.LastStop())
	}
	delete(e.life.births, 43)
	e.completeBarrier()
	select {
	case <-run.done:
	default:
		t.Fatal("child terminal did not resolve the pending run")
	}
	result, err := coreWait(t, run)
	if result.Stop.Reason != target.StopClone || result.Thread != parent.ref || err != target.ErrUnsupported {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if child.state != target.StateExited || parent.state != target.StateStopped || e.run != nil || e.barrier != nil || s.State() != target.StateStopped {
		t.Fatalf("terminal closure: parent=%+v child=%+v state=%v", parent, child, s.State())
	}
	if result.Sequence == 0 || result.Sequence != s.LastStop().Generation {
		t.Fatalf("completed stop sequence=%d last=%+v", result.Sequence, s.LastStop())
	}
}

func TestCoreTerminalDoesNotRepublishOldStop(t *testing.T) {
	s := &Session{id: 1, pid: 41}
	s.state.Store(uint32(target.StateRunning))
	e := &engine{s: s, unsupported: target.ErrUnsupported}
	p := e.newProcess(41, -1, true)
	e.primary = p
	parent := e.newThread(p, 41, true)
	child := e.newThread(p, 42, true)
	e.barrier = &stopBarrier{thread: parent, stop: target.Stop{Reason: target.StopFork}, err: target.ErrUnsupported}
	e.handleWait(waitResult{pid: 41, status: unix.WaitStatus(unix.SIGKILL)})
	if e.barrier == nil || child.state == target.StateExited {
		t.Fatal("terminal barrier completed before all owned tasks exited")
	}
	e.handleWait(waitResult{pid: 42, status: unix.WaitStatus(unix.SIGKILL)})
	last := s.LastStop()
	if s.State() != target.StateExited || last.Reason != target.StopSignaled || last.Signal.Number != uint32(unix.SIGKILL) || last.ThreadID == nil || *last.ThreadID != 42 || last.Generation == 0 {
		t.Fatalf("state=%v last=%+v", s.State(), last)
	}
	if e.barrier != nil || e.run != nil {
		t.Fatal("terminal completion retained an old barrier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var sequence uint64
	for sequence < last.Generation {
		event, err := s.NextEvent(ctx, sequence)
		if err != nil {
			t.Fatal(err)
		}
		if event.Stop.Reason == target.StopFork {
			t.Fatalf("old stop was republished: %+v", event)
		}
		sequence = event.Sequence
	}
}

func TestCoreELFProfiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		class   elf.Class
		machine elf.Machine
		order   elf.Data
		want    target.Architecture
	}{
		{"i386", elf.ELFCLASS32, elf.EM_386, elf.ELFDATA2LSB, target.X86},
		{"amd64", elf.ELFCLASS64, elf.EM_X86_64, elf.ELFDATA2LSB, target.AMD64},
		{"x32", elf.ELFCLASS32, elf.EM_X86_64, elf.ELFDATA2LSB, ""},
		{"arm32", elf.ELFCLASS32, elf.EM_ARM, elf.ELFDATA2LSB, ""},
		{"wrong_class", elf.ELFCLASS64, elf.EM_386, elf.ELFDATA2LSB, ""},
		{"big_endian", elf.ELFCLASS32, elf.EM_386, elf.ELFDATA2MSB, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Create(filepath.Join(coreTempDir(t), "header.elf"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var ident [elf.EI_NIDENT]byte
			copy(ident[:], elf.ELFMAG)
			ident[elf.EI_CLASS], ident[elf.EI_DATA], ident[elf.EI_VERSION] = byte(tc.class), byte(tc.order), byte(elf.EV_CURRENT)
			var order binary.ByteOrder = binary.LittleEndian
			if tc.order == elf.ELFDATA2MSB {
				order = binary.BigEndian
			}
			if tc.class == elf.ELFCLASS32 {
				err = binary.Write(f, order, elf.Header32{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(tc.machine), Version: 1, Ehsize: 52, Phentsize: 32, Shentsize: 40})
			} else {
				err = binary.Write(f, order, elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(tc.machine), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64})
			}
			if err != nil {
				t.Fatal(err)
			}
			profile, err := profileForELF(f)
			if tc.want == "" {
				if !errors.Is(err, target.ErrUnsupported) {
					t.Fatalf("profile=%+v error=%v", profile, err)
				}
			} else if err != nil || profile.Architecture != tc.want {
				t.Fatalf("profile=%+v error=%v", profile, err)
			}
		})
	}
}

func TestCoreBreakpointAddressWidths(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		t.Run(string(profile.Architecture), func(t *testing.T) {
			e := &engine{primary: &process{profile: &profile}}
			maximum, err := profile.MaxAddress()
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range []target.Address{0, 0xf0000000, maximum - 1} {
				if err := e.checkBreakpointAddress(address); err != nil {
					t.Errorf("address=%x: %v", address, err)
				}
			}
			if err := e.checkBreakpointAddress(maximum); !errors.Is(err, target.ErrOverflow) {
				t.Fatalf("maximum: %v", err)
			}
			if profile.Architecture == target.X86 {
				for _, address := range []target.Address{maximum + 1, math.MaxUint64} {
					if err := e.checkBreakpointAddress(address); !errors.Is(err, target.ErrOverflow) {
						t.Errorf("address=%x: %v", address, err)
					}
				}
			}
		})
	}
	if err := (&engine{}).checkBreakpointAddress(0); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("unknown profile: %v", err)
	}
}

func TestCoreExecInvalidatesBeforeRegisterDecode(t *testing.T) {
	to, entry := coreAssembly(t, 32, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	body := ".text\n.global _start\n.global exec_site\n_start:\n mov $59, %eax\n lea destination(%rip), %rdi\n xor %esi, %esi\n xor %edx, %edx\nexec_site:\n syscall\n ud2\n"
	from, _ := coreAssembly(t, 64, body+fmt.Sprintf(".section .rodata\ndestination: .asciz %q\n", to))
	s, err := Launch(from)
	if err != nil {
		t.Fatal(err)
	}
	coreOwnSession(t, s)
	address := coreSymbol(t, from, "exec_site")
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	stop, err := coreContinue(t, s)
	if err != nil || stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != address {
		t.Fatalf("exec syscall breakpoint=%+v error=%v", stop, err)
	}
	before, err := s.Snapshot()
	if err != nil || len(before.Threads) != 1 {
		t.Fatalf("pre-exec snapshot=%+v error=%v", before, err)
	}
	oldSpace, err := call(s, func(e *engine) (*addressSpace, error) { return e.primary.space, nil })
	if err != nil {
		t.Fatal(err)
	}
	stop, err = coreContinue(t, s)
	if err != nil || stop.Reason != target.StopExec || stop.RawPC != nil {
		t.Fatalf("exec during breakpoint step=%+v error=%v", stop, err)
	}
	clean, err := call(s, func(e *engine) (bool, error) {
		owner := e.threads[e.s.pid]
		return e.primary.profile.Architecture == target.X86 && e.primary.space != oldSpace &&
			len(e.primary.space.breakpoints) == 0 && e.primary.space.stepping == nil &&
			len(oldSpace.breakpoints) == 0 && oldSpace.stepping == nil &&
			owner.hit == nil && owner.suspended == nil && e.run == nil && e.barrier == nil && e.unsupported == nil, nil
	})
	if err != nil || !clean {
		t.Fatalf("old image breakpoint/step state survived exec: clean=%v error=%v", clean, err)
	}
	after, err := s.Snapshot()
	if err != nil || after.Architecture != target.X86 || len(after.Threads) != 1 || after.Process != before.Process || after.Threads[0].Ref != before.Threads[0].Ref || after.Memory.Space == before.Memory.Space {
		t.Fatalf("post-exec identity=%+v before=%+v error=%v", after, before, err)
	}
	if _, err := s.ReadThreadRegisters(before.Threads[0].Token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old register token: %v", err)
	}
	if _, err := s.ReadSpaceMemory(before.Memory, address, nil); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old address-space token: %v", err)
	}
	registers, err := s.ReadThreadRegisters(after.Threads[0].Token)
	if err != nil {
		t.Fatalf("register decode after image replacement: %v", err)
	}
	found := false
	for _, register := range registers {
		if register.Name == "eip" {
			found = register.Available && register.Bits == 32 && len(register.Data) == 4 && target.Address(binary.LittleEndian.Uint32(register.Data)) == entry
		}
	}
	if !found {
		t.Fatalf("new image PC not decoded with i386 profile: %+v", registers)
	}
	var instruction [1]byte
	if n, err := s.ReadMemory(entry, instruction[:]); err != nil || n != 1 || instruction[0] != 0x90 {
		t.Fatalf("new image instruction=%x n=%d error=%v", instruction, n, err)
	}
	if err := s.RemoveBreakpoint(address); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("old image breakpoint lookup: %v", err)
	}
}

func coreAssembly(t *testing.T, bits int, code string) (string, target.Address) {
	t.Helper()
	dir := coreTempDir(t)
	source, object, path := filepath.Join(dir, "fixture.S"), filepath.Join(dir, "fixture.o"), filepath.Join(dir, "fixture")
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "as", fmt.Sprintf("--%d", bits), "-o", object, source).CombinedOutput(); err != nil {
		t.Fatalf("assemble: %v\n%s", err, out)
	}
	emulation := "elf_x86_64"
	if bits == 32 {
		emulation = "elf_i386"
	}
	if out, err := exec.CommandContext(ctx, "ld", "-m", emulation, "-o", path, object).CombinedOutput(); err != nil {
		t.Fatalf("link: %v\n%s", err, out)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return path, target.Address(f.Entry)
}

func TestCoreExecArchitectureChanges(t *testing.T) {
	for _, bits := range []int{32, 64} {
		t.Run(fmt.Sprintf("from_%d", bits), func(t *testing.T) {
			toBits := 64
			if bits == 64 {
				toBits = 32
			}
			to, destination := coreAssembly(t, toBits, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
			body := "mov $11, %eax\n mov $destination, %ebx\n xor %ecx, %ecx\n xor %edx, %edx\n int $0x80\n ud2\n"
			want := target.X86
			if bits == 64 {
				body = "mov $59, %eax\n lea destination(%rip), %rdi\n xor %esi, %esi\n xor %edx, %edx\n syscall\n ud2\n"
				want = target.AMD64
			}
			from, entry := coreAssembly(t, bits, ".text\n.global _start\n_start:\n"+body+fmt.Sprintf(".section .rodata\ndestination: .asciz %q\n", to))
			s, err := Launch(from)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := coreClose(t, s); err != nil {
					t.Error(err)
				}
			})
			if s.Architecture() != want {
				t.Fatalf("architecture=%s", s.Architecture())
			}
			before, err := s.Snapshot()
			if err != nil || len(before.Threads) != 1 {
				t.Fatalf("initial snapshot=%+v error=%v", before, err)
			}
			if err := s.AddBreakpoint(entry); err != nil {
				t.Fatal(err)
			}
			stop, err := coreContinue(t, s)
			if err != nil || stop.Reason != target.StopBreakpoint {
				t.Fatalf("first stop=%+v error=%v", stop, err)
			}
			stop, err = coreContinue(t, s)
			if err != nil || stop.Reason != target.StopExec || stop.RawPC != nil {
				t.Fatalf("exec stop=%+v error=%v", stop, err)
			}
			count, err := call(s, func(e *engine) (int, error) { return len(e.primary.space.breakpoints), nil })
			if err != nil || count != 0 {
				t.Fatalf("old breakpoints=%d error=%v", count, err)
			}
			want = target.AMD64
			if toBits == 32 {
				want = target.X86
			}
			after, err := s.Snapshot()
			if err != nil || after.Architecture != want || s.Architecture() != want || len(after.Threads) != 1 || after.Process != before.Process || after.Threads[0].Ref != before.Threads[0].Ref || after.Memory.Space == before.Memory.Space {
				t.Fatalf("changed architecture snapshot=%+v error=%v", after, err)
			}
			registers, err := s.ReadThreadRegisters(after.Threads[0].Token)
			if err != nil || len(registers) == 0 {
				t.Fatalf("changed architecture registers=%+v error=%v", registers, err)
			}
			if _, err := s.ReadThreadRegisters(before.Threads[0].Token); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old register token: %v", err)
			}
			if _, err := s.ReadSpaceMemory(before.Memory, entry, nil); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old memory token: %v", err)
			}
			var instruction [1]byte
			if n, err := s.ReadMemory(destination, instruction[:]); err != nil || n != 1 || instruction[0] != 0x90 {
				t.Fatalf("new image instruction=%x n=%d error=%v", instruction, n, err)
			}
			if err := s.AddBreakpoint(destination); err != nil {
				t.Fatal(err)
			}
			stop, err = coreContinue(t, s)
			if err != nil || stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != destination {
				t.Fatalf("new image breakpoint=%+v error=%v", stop, err)
			}
			if err := s.RemoveBreakpoint(destination); err != nil {
				t.Fatal(err)
			}
			if n, err := s.ReadMemory(destination, instruction[:]); err != nil || n != 1 || instruction[0] != 0x90 {
				t.Fatalf("new image instruction restoration=%x n=%d error=%v", instruction, n, err)
			}
			if err := coreClose(t, s); err != nil {
				t.Fatal(err)
			}
			coreReaped(t, s.PID())
		})
	}
}

func TestCoreForkOwnershipBeforeRegisterViewRejection(t *testing.T) {
	path, _ := coreAssembly(t, 32, ".text\n.global _start\n.code32\n_start:\n ljmp $0x33, $long_mode\n.code64\nlong_mode:\n mov $57, %eax\n syscall\nloop:\n jmp loop\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := coreClose(t, s); err != nil {
			t.Error(err)
		}
	})
	stop, err := coreContinue(t, s)
	if !errors.Is(err, target.ErrUnsupported) || stop.Reason != target.StopFork || stop.RawPC != nil {
		t.Fatalf("fork stop=%+v error=%v", stop, err)
	}
	child, err := call(s, func(e *engine) (int, error) {
		if len(e.threads) != 2 || !e.allStopped() {
			return 0, target.ErrInvalidState
		}
		for pid, thread := range e.threads {
			if pid != e.s.pid {
				if thread.process == nil || e.processes[thread.process.tgid] != thread.process || !thread.process.owned || thread.process.pidfd < 0 {
					return 0, target.ErrUnavailable
				}
				return pid, nil
			}
		}
		return 0, target.ErrNotFound
	})
	if err != nil || child <= 0 {
		t.Fatalf("child ownership=%d error=%v", child, err)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(child, &ws, unix.WALL|unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("child remained waitable after close: %v", err)
	}
}
