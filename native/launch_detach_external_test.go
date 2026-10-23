package native_test

import (
	"bufio"
	"context"
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

func launchDetachTrack(t *testing.T, s *native.Session) int {
	t.Helper()
	fd, err := unix.PidfdOpen(s.PID(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer unix.Close(fd)
		done := make(chan error, 1)
		go func() { done <- s.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("close launch-detach session: %v", err)
			}
		case <-time.After(5 * time.Second):
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			t.Error("launch-detach session cleanup exceeded deadline")
		}
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			t.Errorf("cleanup detached process: %v", err)
		}
		launchDetachReaped(t, s.PID(), fd)
	})
	return fd
}

func launchDetachReaped(t *testing.T, pid, fd int) {
	t.Helper()
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(fds, 5000); err != nil || n != 1 || fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
		t.Fatalf("detached process did not terminate: pid=%d n=%d events=%#x error=%v", pid, n, fds[0].Revents, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, unix.ECHILD) {
			return
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			t.Fatalf("observe detached child reap: %v", err)
		}
		if time.Now().After(deadline) {
			_ = unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG, nil)
			t.Fatal("detached launch child remained unreaped")
		}
		runtime.Gosched()
	}
}

func launchDetachStatus(t *testing.T, pid, tid int, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", pid, tid))
		if err != nil {
			t.Fatal(err)
		}
		fields := make(map[string]string)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				fields[parts[0]] = parts[1]
			}
		}
		if fields["TracerPid:"] != "0" {
			t.Fatalf("detach retained tracer on TID %d: %s", tid, fields["TracerPid:"])
		}
		if state == "" || fields["State:"] == state {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("detached TID %d state=%s want=%s", tid, fields["State:"], state)
		}
		runtime.Gosched()
	}
}

func launchDetachMemory(t *testing.T, pid int, address target.Address) byte {
	t.Helper()
	file, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var value [1]byte
	if n, err := file.ReadAt(value[:], int64(address)); err != nil || n != len(value) {
		t.Fatalf("detached memory read: n=%d error=%v", n, err)
	}
	return value[0]
}

func launchDetachClosed(t *testing.T, s *native.Session, before target.Snapshot, run *native.Run) {
	t.Helper()
	if s.State() != target.StateDetached {
		t.Fatalf("launch detach state: %s", s.State())
	}
	threadCommand(t, s.Close)
	if s.State() != target.StateDetached {
		t.Fatalf("close changed detached state: %s", s.State())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if run != nil {
		if result, err := run.Wait(ctx); !errors.Is(err, target.ErrDetached) {
			t.Fatalf("detach did not resolve pending run: %+v, %v", result, err)
		}
	}
	closed := 0
	for sequence := before.Sequence; ; {
		event, err := s.NextEvent(ctx, sequence)
		if errors.Is(err, target.ErrClosed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if closed != 0 {
			t.Fatalf("event followed terminal close: %+v", event)
		}
		if event.Kind == target.EventSessionClosed {
			closed++
		}
		sequence = event.Sequence
	}
	if closed != 1 {
		t.Fatalf("detach terminal event count: %d", closed)
	}
	if _, err := s.Snapshot(); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("detached session retained snapshot access: %v", err)
	}
	if len(before.Threads) > 0 {
		if _, err := s.ReadThreadRegisters(before.Threads[0].Token); !errors.Is(err, target.ErrClosed) {
			t.Fatalf("detached session retained thread token access: %v", err)
		}
	}
	var value [1]byte
	if _, err := s.ReadSpaceMemory(before.Memory, 0, value[:]); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("detached session retained memory token access: %v", err)
	}
	if err := s.Kill(); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("detached session retained kill authority: %v", err)
	}
}

func launchDetachHardware(t *testing.T, s *native.Session, token target.ThreadToken, address target.Address) {
	t.Helper()
	result, err := threadCall(t, func() (target.HardwareBreakpointResult, error) {
		return s.SetHardwareBreakpoint(token, target.HardwareBreakpointRequest{Slot: 3, Address: address})
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ref.Thread != token.Thread || result.Ref.Slot != 3 || result.Ref.Generation == 0 || result.Token.Thread != token.Thread || result.Token.Stop != token.Stop || result.Token.Registers <= token.Registers {
		t.Fatalf("invalid hardware-execution breakpoint identity: %+v", result)
	}
}

func launchDetachSingleFixture(t *testing.T, bits int) *threadFixture {
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
	f := &threadFixture{}
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
	data := ".data\n.balign 8\n.global watched\nwatched: .quad 0\ninput_byte: .byte 0\ninput_path: .asciz " + strconv.Quote(f.paths[0]) + "\noutput_path: .asciz " + strconv.Quote(f.paths[3]) + "\nready: .ascii \"READY 0 0 0\\n\"\ndone: .ascii \"DONE 0 0 0\\n\"\n.text\n.global _start, breakpoint_site\n_start:\n"
	body := `mov $2, %eax
lea input_path(%rip), %rdi
xor %esi, %esi
syscall
test %eax, %eax
js failed
mov %eax, %r12d
mov $2, %eax
lea output_path(%rip), %rdi
mov $1, %esi
syscall
test %eax, %eax
js failed
mov %eax, %r13d
mov $1, %eax
mov %r13d, %edi
lea ready(%rip), %rsi
mov $12, %edx
syscall
cmp $12, %eax
jne failed
xor %eax, %eax
mov %r12d, %edi
lea input_byte(%rip), %rsi
mov $1, %edx
syscall
cmp $1, %eax
jne failed
breakpoint_site:
incl watched(%rip)
mov $1, %eax
mov %r13d, %edi
lea done(%rip), %rsi
mov $11, %edx
syscall
cmp $11, %eax
jne failed
xor %edi, %edi
jmp leave
failed:
mov $91, %edi
leave:
mov $60, %eax
syscall
`
	if bits == 32 {
		body = `mov $5, %eax
mov $input_path, %ebx
xor %ecx, %ecx
int $0x80
test %eax, %eax
js failed
mov %eax, %ebp
mov $5, %eax
mov $output_path, %ebx
mov $1, %ecx
int $0x80
test %eax, %eax
js failed
mov %eax, %edi
mov $4, %eax
mov %edi, %ebx
mov $ready, %ecx
mov $12, %edx
int $0x80
cmp $12, %eax
jne failed
mov $3, %eax
mov %ebp, %ebx
mov $input_byte, %ecx
mov $1, %edx
int $0x80
cmp $1, %eax
jne failed
breakpoint_site:
incl watched
mov $4, %eax
mov %edi, %ebx
mov $done, %ecx
mov $11, %edx
int $0x80
cmp $11, %eax
jne failed
xor %ebx, %ebx
jmp leave
failed:
mov $91, %ebx
leave:
mov $1, %eax
int $0x80
`
		f.path, f.symbols = x86Fixture(t, data+body, false)
	} else {
		f.path, f.symbols = nativeFixture(t, data+body)
	}
	return f
}

func TestNativeLaunchDetachInitialStop(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			f := launchDetachSingleFixture(t, bits)
			s := watchLaunch(t, f.path)
			fd := launchDetachTrack(t, s)
			snapshot := threadStopped(t, s, 1)
			site := f.address(t, "breakpoint_site")
			var original [1]byte
			if n, err := s.ReadSpaceMemory(snapshot.Memory, site, original[:]); err != nil || n != 1 {
				t.Fatalf("read original breakpoint instruction: n=%d error=%v", n, err)
			}
			threadCommand(t, func() error { return s.AddBreakpoint(site) })
			configured := watchSet(t, s, snapshot.Threads[0].Token, target.WatchpointRequest{Slot: 0, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite})
			launchDetachHardware(t, s, configured.Token, site)
			before := threadSnapshot(t, s)
			threadCommand(t, s.Detach)
			f.receive(t, "READY")
			launchDetachClosed(t, s, before, nil)
			launchDetachStatus(t, s.PID(), s.PID(), "")
			if actual := launchDetachMemory(t, s.PID(), site); actual != original[0] {
				t.Fatalf("detach did not restore software breakpoint: got=%#x want=%#x", actual, original[0])
			}
			f.send(t, 0, 'g')
			f.receive(t, "DONE")
			launchDetachReaped(t, s.PID(), fd)
		})
	}
}

func TestNativeLaunchDetachThreads(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending_%t", pending), func(t *testing.T) {
			f := newWatchThreadFixture(t)
			s := f.launch(t, "existing")
			fd := launchDetachTrack(t, s)
			snapshot, tids := threadInitial(t, s, f, 3)
			for index := 1; index <= 2; index++ {
				configured := watchSet(t, s, threadByTID(t, snapshot, tids[index]).Token, target.WatchpointRequest{Slot: index, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite})
				launchDetachHardware(t, s, configured.Token, f.address(t, "second_checkpoint"))
			}
			worker := f.address(t, "worker_checkpoint")
			var original [1]byte
			if n, err := s.ReadSpaceMemory(threadSnapshot(t, s).Memory, worker, original[:]); err != nil || n != 1 {
				t.Fatalf("read original instruction: n=%d error=%v", n, err)
			}
			threadCommand(t, func() error { return s.AddBreakpoint(worker) })
			var run *native.Run
			if pending {
				run = threadStart(t, s, target.RunRequest{Threads: threadProcessSet(threadSnapshot(t, s))})
			} else {
				peer := threadByTID(t, threadSnapshot(t, s), tids[1])
				f.send(t, 1, 'g')
				result := threadRun(t, s, threadExact(peer.Ref))
				if result.Stop.Reason != target.StopWatchpoint || result.Thread != peer.Ref {
					t.Fatalf("expected selected thread hardware stop: %+v", result)
				}
				threadBreakpoint(t, threadRun(t, s, threadExact(peer.Ref)), worker)
			}
			before := threadSnapshot(t, s)
			threadCommand(t, s.Detach)
			launchDetachClosed(t, s, before, run)
			for _, tid := range tids {
				launchDetachStatus(t, s.PID(), tid, "")
			}
			if actual := launchDetachMemory(t, s.PID(), worker); actual != original[0] {
				t.Fatalf("thread detach did not restore shared software breakpoint: got=%#x want=%#x", actual, original[0])
			}
			f.send(t, 0, 'g')
			if pending {
				f.send(t, 1, 'g')
			}
			f.send(t, 1, 'g')
			f.send(t, 2, 'g')
			f.send(t, 2, 'g')
			f.receive(t, "DONE")
			launchDetachReaped(t, s.PID(), fd)
		})
	}
}

func TestNativeLaunchDetachReattach(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "existing")
	fd := launchDetachTrack(t, s)
	_, tids := threadInitial(t, s, f, 3)
	before := threadSnapshot(t, s)
	threadCommand(t, s.Detach)
	launchDetachClosed(t, s, before, nil)
	again, err := threadCall(t, func() (*native.Session, error) { return native.Attach(s.PID()) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, again, false)
	snapshot := threadStopped(t, again, 3)
	if snapshot.Process == before.Process {
		t.Fatal("reattach reused a session-scoped process identity")
	}
	worker := f.address(t, "worker_checkpoint")
	threadCommand(t, func() error { return again.AddBreakpoint(worker) })
	f.send(t, 1, 'g')
	threadBreakpoint(t, threadRun(t, again, threadExact(threadByTID(t, snapshot, tids[1]).Ref)), worker)
	threadCommand(t, s.Close)
	threadCommand(t, func() error { return again.RemoveBreakpoint(worker) })
	ordinary := exec.Command("/bin/sh", "-c", "exit 17")
	if err := ordinary.Start(); err != nil {
		t.Fatal(err)
	}
	_, err = threadCall(t, func() (struct{}, error) { return struct{}{}, ordinary.Wait() })
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("launch reaper consumed unrelated child status: %v", err)
	}
	f.send(t, 0, 'g')
	f.send(t, 2, 'g')
	threadExit(t, again, 0)
	f.receive(t, "DONE")
	threadCommand(t, again.Close)
	launchDetachReaped(t, s.PID(), fd)
}

func TestNativeLaunchDetachReattachClose(t *testing.T) {
	f := launchDetachSingleFixture(t, 64)
	s := watchLaunch(t, f.path)
	fd := launchDetachTrack(t, s)
	before := threadSnapshot(t, s)
	threadCommand(t, s.Detach)
	f.receive(t, "READY")
	launchDetachClosed(t, s, before, nil)
	again, err := threadCall(t, func() (*native.Session, error) { return native.Attach(s.PID()) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, again, false)
	snapshot := threadStopped(t, again, 1)
	configured := watchSet(t, again, snapshot.Threads[0].Token, target.WatchpointRequest{Slot: 0, Address: f.address(t, "watched"), Size: 4, Access: target.WatchWrite})
	launchDetachHardware(t, again, configured.Token, f.address(t, "breakpoint_site"))
	threadCommand(t, func() error { return again.AddBreakpoint(f.address(t, "breakpoint_site")) })
	threadCommand(t, again.Close)
	if again.State() != target.StateClosed {
		t.Fatalf("reattached session Close state: %s", again.State())
	}
	launchDetachStatus(t, s.PID(), s.PID(), "")
	f.send(t, 0, 'g')
	f.receive(t, "DONE")
	launchDetachReaped(t, s.PID(), fd)
}

func TestNativeLaunchDetachLeaderExit(t *testing.T) {
	for _, reattach := range []bool{false, true} {
		t.Run(fmt.Sprintf("reattach_%t", reattach), func(t *testing.T) {
			f := newThreadFixture(t)
			s := f.launch(t, "leaderstep")
			fd := launchDetachTrack(t, s)
			snapshot, tids := threadInitial(t, s, f, 2)
			leader, peer := threadByTID(t, snapshot, tids[0]), threadByTID(t, snapshot, tids[1])
			site := f.address(t, "exit_site")
			threadCommand(t, func() error { return s.AddBreakpoint(site) })
			f.send(t, 0, 'g')
			threadBreakpoint(t, threadRun(t, s, threadExact(leader.Ref)), site)
			threadCommand(t, func() error { return s.RemoveBreakpoint(site) })
			run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(target.StepRequest{Thread: leader.Ref}) })
			if err != nil {
				t.Fatal(err)
			}
			if result := threadWait(t, run); result.Thread != leader.Ref || result.Stop.Reason != target.StopExited {
				t.Fatalf("selected leader exit did not complete: %+v", result)
			}
			snapshot = threadStopped(t, s, 1)
			configured := watchSet(t, s, threadByTID(t, snapshot, tids[1]).Token, target.WatchpointRequest{Slot: 0, Address: f.address(t, "counters") + 4, Size: 4, Access: target.WatchWrite})
			launchDetachHardware(t, s, configured.Token, f.address(t, "worker_checkpoint"))
			threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, "worker_checkpoint")) })
			before := threadSnapshot(t, s)
			threadCommand(t, s.Detach)
			launchDetachClosed(t, s, before, nil)
			launchDetachStatus(t, s.PID(), tids[1], "")
			if peer.Ref != threadByTID(t, before, tids[1]).Ref {
				t.Fatal("leader exit changed surviving thread identity")
			}
			if reattach {
				launchDetachStatus(t, s.PID(), s.PID(), "Z")
				again, err := threadCall(t, func() (*native.Session, error) { return native.Attach(s.PID()) })
				if err != nil {
					t.Fatal(err)
				}
				threadSessionCleanup(t, again, false)
				current := threadStopped(t, again, 1)
				survivor := threadByTID(t, current, tids[1])
				threadRegister(t, again, survivor.Token, "rip")
				if survivor.Ref == peer.Ref || current.Process == before.Process {
					t.Fatal("zombie-leader reattach reused old session identities")
				}
				if values := threadValues(t, again, f, "counters"); values != [3]uint32{} {
					t.Fatalf("reattach advanced the held survivor: %v", values)
				}
				threadCommand(t, again.Close)
				if again.State() != target.StateClosed {
					t.Fatalf("zombie-leader reattached Close state: %s", again.State())
				}
				launchDetachStatus(t, s.PID(), tids[1], "")
			}
			f.send(t, 1, 'g')
			f.receive(t, "SURVIVED")
			launchDetachReaped(t, s.PID(), fd)
		})
	}
}

func TestNativeLaunchDetachNonleaderExec(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "exec")
	fd := launchDetachTrack(t, s)
	snapshot, tids := threadInitial(t, s, f, 2)
	peer := threadByTID(t, snapshot, tids[1])
	watchSet(t, s, peer.Token, target.WatchpointRequest{Slot: 1, Address: f.address(t, "counters") + 4, Size: 4, Access: target.WatchWrite})
	threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, "shared_site")) })
	f.send(t, 1, 'g')
	if result := threadRun(t, s, threadExact(peer.Ref)); result.Stop.Reason != target.StopExec {
		t.Fatalf("nonleader exec did not stop at exec boundary: %+v", result)
	}
	current := threadStopped(t, s, 1)
	if current.Memory.Space == snapshot.Memory.Space {
		t.Fatal("nonleader exec reused its old address space")
	}
	if _, err := s.ReadThreadRegisters(peer.Token); err == nil {
		t.Fatal("nonleader exec retained old thread token")
	}
	var value [1]byte
	if _, err := s.ReadSpaceMemory(snapshot.Memory, f.address(t, "shared_site"), value[:]); !errors.Is(err, target.ErrStale) {
		t.Fatalf("nonleader exec retained old memory token: %v", err)
	}
	threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, "after_exec_checkpoint")) })
	before := threadSnapshot(t, s)
	threadCommand(t, s.Detach)
	launchDetachClosed(t, s, before, nil)
	f.receive(t, "EXECREADY")
	launchDetachReaped(t, s.PID(), fd)
}

func TestNativeLaunchDetachGroupStop(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "existing")
	fd := launchDetachTrack(t, s)
	snapshot, tids := threadInitial(t, s, f, 3)
	run := threadStart(t, s, target.RunRequest{Threads: threadProcessSet(snapshot)})
	threadCommand(t, func() error { return unix.PidfdSendSignal(fd, unix.SIGSTOP, nil, 0) })
	result := threadWait(t, run)
	if result.Stop.Reason != target.StopSignal || result.Stop.Signal.Number != uint32(unix.SIGSTOP) {
		t.Fatalf("launched SIGSTOP delivery stop: %+v", result)
	}
	run = threadStart(t, s, target.RunRequest{
		Threads: threadProcessSet(threadSnapshot(t, s)),
		Signals: []target.ThreadSignal{{Thread: result.Thread, Stop: result.Token.Stop, Signal: result.Stop.Signal}},
	})
	result = threadWait(t, run)
	if result.Stop.Reason != target.StopGroupStop {
		t.Fatalf("launched SIGSTOP group stop: %+v", result)
	}
	before := threadSnapshot(t, s)
	run = threadStart(t, s, target.RunRequest{Threads: threadProcessSet(before)})
	threadCommand(t, s.Detach)
	launchDetachClosed(t, s, before, run)
	for _, tid := range tids {
		launchDetachStatus(t, s.PID(), tid, "T")
	}
	for index := range f.inputs {
		f.send(t, index, 'g')
	}
	fds := []unix.PollFd{{Fd: int32(f.output.Fd()), Events: unix.POLLIN}}
	if n, err := unix.Poll(fds, 0); err != nil || n != 0 {
		t.Fatalf("detached group-stop executed before SIGCONT: n=%d error=%v", n, err)
	}
	threadCommand(t, func() error { return unix.PidfdSendSignal(fd, unix.SIGCONT, nil, 0) })
	f.receive(t, "DONE")
	launchDetachReaped(t, s.PID(), fd)
}

func TestNativeLaunchDetachIncompleteClosure(t *testing.T) {
	f := newThreadFixture(t)
	s := f.launch(t, "hiddenclose")
	fd := launchDetachTrack(t, s)
	threadInitial(t, s, f, 1)
	site := f.address(t, "done_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(site) })
	before := threadSnapshot(t, s)
	run := threadStart(t, s, target.RunRequest{Threads: threadProcessSet(before)})
	f.send(t, 0, 'g')
	tids := f.receive(t, "HIDDEN")
	_, err := threadCall(t, func() (struct{}, error) { return struct{}{}, s.Detach() })
	if !errors.Is(err, target.ErrPartial) {
		t.Fatalf("incomplete launch closure detach did not retain ownership: %v", err)
	}
	after := threadSnapshot(t, s)
	if after.State == target.StateStopped || after.State == target.StateDetached || after.State == target.StateClosed || after.Memory.Revision != 0 {
		t.Fatalf("incomplete detach exposed coherent terminal state: %+v", after)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if result, err := run.Wait(ctx); !errors.Is(err, target.ErrUnsupported) && !errors.Is(err, target.ErrPartial) {
		t.Fatalf("incomplete detach left run unresolved: %+v error=%v", result, err)
	}
	for sequence := before.Sequence; sequence < after.Sequence; {
		event, err := s.NextEvent(ctx, sequence)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == target.EventSessionClosed || event.Kind == target.EventAllStopped {
			t.Fatalf("incomplete detach published successful closure: %+v", event)
		}
		sequence = event.Sequence
	}
	if actual := launchDetachMemory(t, s.PID(), site); actual != 0xcc {
		t.Fatalf("unsafe detach restored shared breakpoint without closure: %#x", actual)
	}
	launchDetachStatus(t, s.PID(), tids[1], "")
	threadCommand(t, s.Kill)
	threadCommand(t, s.Close)
	launchDetachReaped(t, s.PID(), fd)
}
