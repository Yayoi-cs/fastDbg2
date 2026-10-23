package native

import (
	"encoding/binary"
	"errors"
	"fastdbg2/target"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestChildExitStatusRequiresTerminalIdentity(t *testing.T) {
	for _, tc := range []struct {
		code   int32
		value  uint32
		status unix.WaitStatus
		valid  bool
	}{
		{1, 42, 42 << 8, true},
		{2, uint32(unix.SIGKILL), unix.WaitStatus(unix.SIGKILL), true},
		{3, uint32(unix.SIGABRT), unix.WaitStatus(unix.SIGABRT) | 0x80, true},
		{4, uint32(unix.SIGTRAP), 0, false},
		{5, uint32(unix.SIGSTOP), 0, false},
	} {
		info := signalInfo{Signo: int32(unix.SIGCHLD), Code: tc.code}
		binary.LittleEndian.PutUint32(info.Data[:4], 42)
		binary.LittleEndian.PutUint32(info.Data[8:12], tc.value)
		status, err := childExitStatus(42, info)
		if tc.valid {
			if err != nil || status != tc.status {
				t.Fatalf("code=%d status=%#x error=%v", tc.code, status, err)
			}
		} else if !errors.Is(err, target.ErrUnavailable) {
			t.Fatalf("nonterminal code=%d error=%v", tc.code, err)
		}
		if _, err := childExitStatus(43, info); !errors.Is(err, target.ErrUnknown) {
			t.Fatalf("wrong child identity code=%d: %v", tc.code, err)
		}
	}
}

func TestChildWaitHandoffRetainsPartialOwnership(t *testing.T) {
	s := &Session{id: sessionSequence.Add(1)}
	e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
	p := e.newProcess(2147483001, -1, true)
	p.osProcess = &os.Process{Pid: p.tgid}
	task := e.newThread(p, p.tgid, true)
	task.state = target.StateStopped
	if err := e.registerLaunchedChild(p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		childWaitRegistry.Lock()
		delete(childWaitRegistry.children, p.tgid)
		childWaitRegistry.Unlock()
	})
	if err := e.handoffReleasedChildren(); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("partial handoff=%v", err)
	}
	if p.osProcess == nil || s.detachedChild.owner != s.id || s.detachedChild.finished {
		t.Fatal("partial handoff discarded child ownership")
	}
	other := &engine{s: &Session{id: sessionSequence.Add(1)}}
	if child, err := other.claimLaunchedChild(p.tgid); child != nil || !errors.Is(err, target.ErrBusy) {
		t.Fatalf("claimed retained child=%v error=%v", child, err)
	}
	if !errors.Is(s.detachedChildError(), target.ErrUnavailable) {
		t.Fatalf("retained handoff fault=%v", s.detachedChildError())
	}
}

func TestDetachedReaperKeepsUnexpectedWaitFailure(t *testing.T) {
	child := &detachedChild{pid: 2147483002, pidfd: -1, lease: 1, stop: make(chan struct{}), done: make(chan struct{})}
	childWaitRegistry.Lock()
	childWaitRegistry.children[child.pid] = child
	childWaitRegistry.Unlock()
	stopped := make(chan struct{})
	go func() {
		child.reapDetached(1, make(chan os.Signal, 1), child.stop)
		close(stopped)
	}()
	defer func() {
		childWaitRegistry.Lock()
		close(child.stop)
		delete(childWaitRegistry.children, child.pid)
		childWaitRegistry.Unlock()
		<-stopped
	}()
	until := time.Now().Add(time.Second)
	for {
		childWaitRegistry.Lock()
		err, finished := child.fault, child.finished
		retained := childWaitRegistry.children[child.pid] == child
		childWaitRegistry.Unlock()
		if err != nil {
			if finished || !retained {
				t.Fatalf("wait failure lost ownership: finished=%t retained=%t error=%v", finished, retained, err)
			}
			if !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EINVAL) {
				t.Fatalf("unexpected wait failure=%v", err)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("reaper did not report invalid pidfd")
		}
		runtime.Gosched()
	}
	select {
	case <-child.done:
		t.Fatal("wait failure was reported as child completion")
	default:
	}
}

func TestChildReapPeekDoesNotConsumePtraceStop(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gate, err := startLaunch(coreFixture(t), []string{"loop"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		gate.close()
		unix.PidfdSendSignal(gate.pidfd, unix.SIGKILL, nil, 0)
		for {
			var status unix.WaitStatus
			_, err := unix.Wait4(gate.process.Pid, &status, unix.WALL, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil || status.Exited() || status.Signaled() {
				break
			}
		}
		gate.process.Release()
		unix.Close(gate.pidfd)
	}()
	if err := seize(gate.process.Pid, unix.PTRACE_O_EXITKILL); err != nil {
		t.Fatal(err)
	}
	if err := unix.PtraceInterrupt(gate.process.Pid); err != nil {
		t.Fatal(err)
	}
	info, err := waitChildInfo(gate.pidfd, unix.WSTOPPED|unix.WNOWAIT)
	if err != nil || info.Code != 4 {
		t.Fatalf("peek initial ptrace stop=%+v error=%v", info, err)
	}
	if _, ready, err := reapChild(gate.process.Pid, gate.pidfd); ready || !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("reaper accepted ptrace stop: ready=%t error=%v", ready, err)
	}
	var status unix.WaitStatus
	pid, err := unix.Wait4(gate.process.Pid, &status, unix.WALL|unix.WNOHANG, nil)
	if err != nil || pid != gate.process.Pid || !status.Stopped() || status.TrapCause() != unix.PTRACE_EVENT_STOP {
		t.Fatalf("original ptrace notification was consumed: pid=%d status=%#x error=%v", pid, status, err)
	}
}

func TestChildPartialDetachCloseKillsUntracedOwnedProcess(t *testing.T) {
	s, err := Launch(coreFixture(t), "loop")
	if err != nil {
		t.Fatal(err)
	}
	coreOwnSession(t, s)
	child := s.detachedChild
	err = command(s, func(e *engine) error {
		if err := e.restoreBreakpoints(); err != nil {
			return err
		}
		if err := e.restoreWatchpoints(); err != nil {
			return err
		}
		task := e.threads[s.PID()]
		if err := ptraceDetach(task.tid, 0); err != nil {
			return err
		}
		task.state, task.seized = target.StateDetached, false
		e.life.shutdownKind = "detach"
		e.finishShutdown(target.ErrUnavailable)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if state := s.State(); state == target.StateClosed || state == target.StateDetached || state == target.StateExited {
		t.Fatalf("partial detach prematurely terminated session: %v", state)
	}
	childWaitRegistry.Lock()
	owner, finished := child.owner, child.finished
	childWaitRegistry.Unlock()
	if owner != s.id || finished {
		t.Fatalf("partial detach child ownership: owner=%d finished=%t", owner, finished)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.done:
	default:
		t.Fatal("owned Close did not reap detached child")
	}
	if !child.status.Signaled() || child.status.Signal() != unix.SIGKILL {
		t.Fatalf("owned Close did not kill child: status=%#x", child.status)
	}
}

func TestChildDetachExtendedStatePreflight(t *testing.T) {
	e := &engine{threads: make(map[int]*thread)}
	task := &thread{tid: 41, state: target.StateStopped, extendedFault: target.ErrUnavailable}
	e.threads[41] = task
	if err := e.validateDetachResume(); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("unresolved extended state resumed: %v", err)
	}
	task.exiting = true
	if err := e.validateDetachResume(); err != nil {
		t.Fatalf("exiting task cleanup blocked: %v", err)
	}
	task.exiting, task.extendedFault = false, nil
	if err := e.validateDetachResume(); err != nil {
		t.Fatalf("recovered state blocked: %v", err)
	}
}

func TestChildDetachedReaperReleasesHandles(t *testing.T) {
	warm, err := Launch("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := coreClose(t, warm); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := count()
	childWaitRegistry.Lock()
	beforeChildren := len(childWaitRegistry.children)
	childWaitRegistry.Unlock()
	for i := 0; i < 25; i++ {
		s, err := Launch("/bin/true")
		if err != nil {
			t.Fatal(err)
		}
		coreOwnSession(t, s)
		child := s.detachedChild
		pidfd, err := unix.PidfdOpen(s.PID(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Detach(); err != nil {
			unix.Close(pidfd)
			t.Fatal(err)
		}
		<-s.done
		select {
		case <-child.done:
		case <-time.After(time.Second):
			unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			<-child.done
			unix.Close(pidfd)
			t.Fatal("detached child did not exit and reap")
		}
		unix.Close(pidfd)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if !child.status.Exited() || child.status.ExitStatus() != 0 {
			t.Fatalf("detached child exit=%#x", child.status)
		}
	}
	if after := count(); after != before {
		t.Fatalf("detached child descriptor leak: before=%d after=%d", before, after)
	}
	childWaitRegistry.Lock()
	afterChildren := len(childWaitRegistry.children)
	childWaitRegistry.Unlock()
	if afterChildren != beforeChildren {
		t.Fatalf("detached child registry leak: before=%d after=%d", beforeChildren, afterChildren)
	}
}

func TestChildZombieAliasRequiresFormalZombieLeader(t *testing.T) {
	s, err := Launch(coreFixture(t), "loop")
	if err != nil {
		t.Fatal(err)
	}
	coreOwnSession(t, s)
	if err := command(s, func(e *engine) error {
		if handled, err := e.registerZombieLeader(e.primary, e.primary.tgid+1); handled || err != nil {
			return errors.New("non-leader was accepted as a zombie alias")
		}
		if handled, err := e.registerZombieLeader(e.primary, e.primary.tgid); handled || err != nil {
			return errors.New("live traced leader was accepted as a zombie alias")
		}
		if len(e.life.aliases) != 0 || e.threads[e.primary.tgid].exitComplete {
			return errors.New("rejected alias changed lifecycle ownership")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
