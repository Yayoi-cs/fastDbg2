package native

import (
	"encoding/binary"
	"errors"
	"fastdbg2/target"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type detachedChild struct {
	pid      int
	pidfd    int
	process  *os.Process
	owner    uint64
	lease    uint64
	stop     chan struct{}
	done     chan struct{}
	finished bool
	status   unix.WaitStatus
	fault    error
}

var childWaitRegistry = struct {
	sync.Mutex
	children map[int]*detachedChild
}{children: make(map[int]*detachedChild)}

func (s *Session) detachedChildError() error {
	childWaitRegistry.Lock()
	defer childWaitRegistry.Unlock()
	if s.detachedChild == nil {
		return nil
	}
	return s.detachedChild.fault
}

func (e *engine) registerLaunchedChild(p *process) error {
	childWaitRegistry.Lock()
	defer childWaitRegistry.Unlock()
	if childWaitRegistry.children[p.tgid] != nil {
		return fmt.Errorf("child wait ownership for PID %d already exists: %w", p.tgid, target.ErrBusy)
	}
	child := &detachedChild{pid: p.tgid, pidfd: p.pidfd, process: p.osProcess, owner: e.s.id, done: make(chan struct{})}
	childWaitRegistry.children[p.tgid] = child
	if e.life.childWaits == nil {
		e.life.childWaits = make(map[*process]*detachedChild)
	}
	e.life.childWaits[p] = child
	e.s.detachedChild = child
	return nil
}

func pidfdProcessID(fd int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Pid:" {
			return strconv.Atoi(fields[1])
		}
	}
	return 0, fmt.Errorf("pidfd has no process identity: %w", target.ErrUnknown)
}

func (e *engine) claimLaunchedChild(tgid int) (*detachedChild, error) {
	childWaitRegistry.Lock()
	defer childWaitRegistry.Unlock()
	child := childWaitRegistry.children[tgid]
	if child == nil {
		return nil, nil
	}
	if child.owner != 0 {
		return nil, fmt.Errorf("child PID %d is managed by another session: %w", tgid, target.ErrBusy)
	}
	identity, err := pidfdProcessID(child.pidfd)
	if err != nil {
		return nil, fmt.Errorf("validate detached child identity: %w", err)
	}
	if identity == -1 {
		finishDetachedChildLocked(child, 0, fmt.Errorf("detached child was reaped outside its owner: %w", unix.ECHILD), true)
		return nil, nil
	}
	if identity != tgid {
		return nil, fmt.Errorf("detached child identity changed: %w", target.ErrStale)
	}
	child.owner = e.s.id
	if child.stop != nil {
		close(child.stop)
		child.stop = nil
	}
	return child, nil
}

func (e *engine) bindLaunchedChild(p *process, child *detachedChild) {
	if e.life.childWaits == nil {
		e.life.childWaits = make(map[*process]*detachedChild)
	}
	e.life.childWaits[p] = child
	e.s.detachedChild = child
}

func (e *engine) registerZombieLeader(p *process, tid int) (bool, error) {
	if p == nil || tid != p.tgid {
		return false, nil
	}
	status, err := readTaskStatus(tid)
	if err != nil {
		return false, err
	}
	if status.tgid != tid || status.state != 'Z' || status.tracer != 0 {
		return false, nil
	}
	identity, err := pidfdProcessID(p.pidfd)
	if err != nil {
		return false, err
	}
	if identity != tid {
		return false, fmt.Errorf("zombie leader pidfd identity changed: %w", target.ErrStale)
	}
	t := e.newThread(p, tid, false)
	t.name = status.name
	t.state, t.exiting, t.exitComplete = target.StateExited, true, true
	if e.life.aliases == nil {
		e.life.aliases = make(map[int]*process)
	}
	e.life.aliases[tid] = p
	return true, nil
}

func waitChildInfo(pidfd int, options int) (signalInfo, error) {
	var info signalInfo
	for {
		err := unix.Waitid(unix.P_PIDFD, pidfd, (*unix.Siginfo)(unsafe.Pointer(&info)), options, nil)
		if !errors.Is(err, unix.EINTR) {
			return info, err
		}
	}
}

func childExitStatus(pid int, info signalInfo) (unix.WaitStatus, error) {
	if info.Signo != int32(unix.SIGCHLD) || int(binary.LittleEndian.Uint32(info.Data[:4])) != pid {
		return 0, fmt.Errorf("invalid child exit identity: %w", target.ErrUnknown)
	}
	value := binary.LittleEndian.Uint32(info.Data[8:12])
	switch info.Code {
	case 1:
		return unix.WaitStatus((value & 0xff) << 8), nil
	case 2:
		return unix.WaitStatus(value & 0x7f), nil
	case 3:
		return unix.WaitStatus(value&0x7f | 0x80), nil
	}
	return 0, fmt.Errorf("child wait returned nonterminal code %d: %w", info.Code, target.ErrUnavailable)
}

func reapChild(pid, pidfd int) (unix.WaitStatus, bool, error) {
	info, err := waitChildInfo(pidfd, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT)
	if err != nil {
		return 0, false, err
	}
	if info.Signo == 0 {
		return 0, false, nil
	}
	if _, err := childExitStatus(pid, info); err != nil {
		return 0, false, err
	}
	info, err = waitChildInfo(pidfd, unix.WEXITED|unix.WNOHANG)
	if err != nil {
		return 0, false, err
	}
	if info.Signo == 0 {
		return 0, false, fmt.Errorf("child exit notification disappeared: %w", target.ErrUnavailable)
	}
	status, err := childExitStatus(pid, info)
	return status, err == nil, err
}

func finishDetachedChildLocked(child *detachedChild, status unix.WaitStatus, err error, release bool) {
	if child.finished {
		return
	}
	child.finished, child.status, child.fault = true, status, err
	if childWaitRegistry.children[child.pid] == child {
		delete(childWaitRegistry.children, child.pid)
	}
	if child.stop != nil {
		close(child.stop)
		child.stop = nil
	}
	if release {
		if child.pidfd >= 0 {
			child.fault = errors.Join(child.fault, unix.Close(child.pidfd))
		}
		if child.process != nil {
			child.fault = errors.Join(child.fault, child.process.Release())
		}
	}
	child.pidfd, child.process = -1, nil
	close(child.done)
}

func (e *engine) childReaped(p *process, status unix.WaitStatus) {
	child := e.life.childWaits[p]
	if child == nil {
		return
	}
	childWaitRegistry.Lock()
	defer childWaitRegistry.Unlock()
	if child.owner == e.s.id {
		finishDetachedChildLocked(child, status, nil, false)
	}
}

func (e *engine) childHasTraceOwnership(p *process) bool {
	for _, thread := range e.threads {
		if thread.process == p && thread.live() && thread.seized {
			return true
		}
	}
	return false
}

func (e *engine) reapReleasedChildren() error {
	for p, child := range e.life.childWaits {
		if p.osProcess == nil || e.childHasTraceOwnership(p) {
			continue
		}
		childWaitRegistry.Lock()
		if child.finished || child.owner != e.s.id {
			childWaitRegistry.Unlock()
			continue
		}
		status, ready, err := reapChild(p.tgid, p.pidfd)
		if ready {
			finishDetachedChildLocked(child, status, nil, false)
		} else if err != nil {
			child.fault = fmt.Errorf("reap released child PID %d: %w", p.tgid, err)
		}
		childWaitRegistry.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *engine) childWaitsComplete() bool {
	childWaitRegistry.Lock()
	defer childWaitRegistry.Unlock()
	for p, child := range e.life.childWaits {
		if p.osProcess != nil && !child.finished {
			return false
		}
	}
	return true
}

func (e *engine) prepareChildDetach() error {
	for p, child := range e.life.childWaits {
		if p.osProcess == nil {
			continue
		}
		childWaitRegistry.Lock()
		if child.finished {
			childWaitRegistry.Unlock()
			continue
		}
		if child.owner != e.s.id || child.pidfd != p.pidfd || child.process != p.osProcess {
			childWaitRegistry.Unlock()
			return fmt.Errorf("child detach ownership changed: %w", target.ErrStale)
		}
		_, err := waitChildInfo(p.pidfd, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT)
		if err == nil {
			child.fault = nil
		}
		childWaitRegistry.Unlock()
		if err != nil {
			return fmt.Errorf("validate child reap backend before detach: %w", err)
		}
	}
	return nil
}

func (e *engine) handoffReleasedChildren() error {
	for p, child := range e.life.childWaits {
		if p.osProcess == nil {
			continue
		}
		childWaitRegistry.Lock()
		if child.finished {
			childWaitRegistry.Unlock()
			continue
		}
		if child.owner != e.s.id || child.pidfd != p.pidfd || child.process != p.osProcess || e.childHasTraceOwnership(p) {
			child.fault = fmt.Errorf("child wait transfer has unresolved ownership: %w", target.ErrUnavailable)
			err := child.fault
			childWaitRegistry.Unlock()
			return err
		}
		child.owner = 0
		child.lease++
		lease := child.lease
		child.stop = make(chan struct{})
		stop := child.stop
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, unix.SIGCHLD)
		p.pidfd, p.osProcess = -1, nil
		delete(e.life.aliases, p.tgid)
		childWaitRegistry.Unlock()
		go child.reapDetached(lease, signals, stop)
	}
	return nil
}

func (child *detachedChild) reapDetached(lease uint64, signals chan os.Signal, stop <-chan struct{}) {
	defer signal.Stop(signals)
	for {
		childWaitRegistry.Lock()
		if child.finished || child.owner != 0 || child.lease != lease {
			childWaitRegistry.Unlock()
			return
		}
		status, ready, err := reapChild(child.pid, child.pidfd)
		if ready || errors.Is(err, unix.ECHILD) {
			if err != nil {
				err = fmt.Errorf("detached child PID %d was reaped outside its owner: %w", child.pid, err)
			}
			finishDetachedChildLocked(child, status, err, true)
			childWaitRegistry.Unlock()
			return
		}
		if err != nil {
			child.fault = fmt.Errorf("reap detached child PID %d: %w", child.pid, err)
		} else {
			child.fault = nil
		}
		childWaitRegistry.Unlock()
		select {
		case <-signals:
		case <-stop:
			return
		}
	}
}
