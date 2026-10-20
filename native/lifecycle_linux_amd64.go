package native

import (
	"errors"
	"fastdbg2/target"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type lifecycleState struct {
	ready            chan response[*Session]
	initializing     bool
	tracer           int
	startError       error
	finished         bool
	terminal         target.State
	signals          chan os.Signal
	launch           *launchGate
	launchReleased   bool
	launchExec       bool
	attaching        bool
	births           map[int]*birth
	lost             map[int]error
	missing          map[int]*thread
	exitStops        map[*thread]target.Stop
	syscallSteps     map[*thread]syscallStep
	cloneChildren    map[*thread]*thread
	detachedExits    map[*thread]bool
	exitTicker       *time.Ticker
	aliases          map[int]*process
	shutdownKind     string
	shutdownReply    []chan error
	closeAfter       bool
	awaitProcessExit bool
	killSent         map[int]bool
}

type birth struct {
	parent    *process
	creator   *thread
	decoded   bool
	cause     int
	message   bool
	stopped   bool
	announced bool
	fault     error
}

type taskStatus struct {
	tid    int
	tgid   int
	count  int
	tracer int
	state  byte
	name   string
}

func readTaskStatus(tid int) (taskStatus, error) {
	var result taskStatus
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if key == "Name" {
			result.name = value
			continue
		}
		if key == "State" && len(value) != 0 {
			result.state = value[0]
			continue
		}
		var dst *int
		switch key {
		case "Pid":
			dst = &result.tid
		case "Tgid":
			dst = &result.tgid
		case "Threads":
			dst = &result.count
		case "TracerPid":
			dst = &result.tracer
		default:
			continue
		}
		*dst, err = strconv.Atoi(value)
		if err != nil {
			return result, err
		}
	}
	if result.tid != tid || result.tgid <= 0 || result.count <= 0 || result.state == 0 {
		return result, fmt.Errorf("invalid task identity for %d: %w", tid, target.ErrUnknown)
	}
	return result, nil
}

func threadStatus(tid int) (int, int, error) {
	status, err := readTaskStatus(tid)
	return status.tgid, status.count, err
}

func taskIDs(tgid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", tgid))
	if err != nil {
		return nil, err
	}
	result := make([]int, 0, len(entries))
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil || tid <= 0 {
			return nil, fmt.Errorf("invalid task entry %q: %w", entry.Name(), target.ErrUnknown)
		}
		result = append(result, tid)
	}
	sort.Ints(result)
	return result, nil
}

func traceOptions(owned bool) int {
	options := unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACEVFORKDONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACEEXIT
	if owned {
		options |= unix.PTRACE_O_EXITKILL
	}
	return options
}

func seize(tid, options int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SEIZE, uintptr(tid), 0, uintptr(options), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (e *engine) launch(path string, args []string) error {
	gate, err := startLaunch(path, args)
	if err != nil {
		return err
	}
	e.life.launch = gate
	p := e.newProcess(gate.process.Pid, gate.pidfd, true)
	p.osProcess, p.profile, p.exeInfo = gate.process, gate.profile, gate.exeInfo
	e.primary, e.s.pid = p, p.tgid
	t := e.newThread(p, p.tgid, false)
	if err := seize(t.tid, traceOptions(true)); err != nil {
		return fmt.Errorf("seize launch gate: %w", err)
	}
	t.seized = true
	if err := unix.PtraceInterrupt(t.tid); err != nil {
		return fmt.Errorf("interrupt launch gate: %w", err)
	}
	t.interruptRequested = true
	return nil
}

func (e *engine) attach(pid int) error {
	status, err := readTaskStatus(pid)
	if err != nil {
		return err
	}
	fd, err := unix.PidfdOpen(status.tgid, 0)
	if err != nil {
		return fmt.Errorf("pidfd_open: %w", err)
	}
	p := e.newProcess(status.tgid, fd, false)
	e.primary, e.s.pid, e.life.attaching = p, p.tgid, true
	return e.scanAttach()
}

func (e *engine) scanAttach() error {
	p := e.primary
	tids, err := taskIDs(p.tgid)
	if err != nil {
		return fmt.Errorf("enumerate process threads: %w", err)
	}
	for _, tid := range tids {
		if t := e.threads[tid]; t != nil && t.live() {
			continue
		}
		auto := false
		if err := seize(tid, traceOptions(false)); err != nil {
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			if !errors.Is(err, unix.EPERM) {
				return fmt.Errorf("seize TID %d: %w", tid, err)
			}
			if ownerErr := unix.PtraceInterrupt(tid); ownerErr != nil {
				return fmt.Errorf("seize TID %d: %w", tid, errors.Join(err, ownerErr))
			}
			auto = true
		}
		t := e.newThread(p, tid, true)
		if auto {
			e.life.births[tid] = &birth{parent: p}
		}
		status, err := readTaskStatus(tid)
		if err != nil || status.tgid != p.tgid {
			if err == nil {
				err = target.ErrStale
			}
			return fmt.Errorf("attach identity TID %d: %w", tid, err)
		}
		t.name = status.name
		if !auto {
			if err := unix.PtraceInterrupt(tid); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("interrupt TID %d: %w", tid, err)
			}
		}
		t.interruptRequested = true
	}
	return nil
}

func (e *engine) attachClosed() (bool, error) {
	if !e.allStopped() || len(e.life.births) != 0 || len(e.life.lost) != 0 {
		return false, nil
	}
	p := e.primary
	if processTerminated(p) {
		return false, target.ErrStale
	}
	var members []*thread
	for _, t := range e.threads {
		if t.process == p && (t.live() || e.life.aliases[t.tid] == p) {
			members = append(members, t)
		}
	}
	if len(members) == 0 {
		return false, target.ErrExited
	}
	status, err := readTaskStatus(members[0].tid)
	if err != nil {
		return false, err
	}
	if status.tgid != p.tgid || status.count != len(members) {
		return false, nil
	}
	for _, t := range members {
		status, err := readTaskStatus(t.tid)
		if err != nil || status.tgid != p.tgid || status.tracer != e.life.tracer && !(t.exitComplete && status.state == 'Z' && !t.seized && e.life.aliases[t.tid] == p) {
			if err == nil {
				err = target.ErrStale
			}
			return false, err
		}
		if t.exiting && t.exitComplete && status.state == 'Z' {
			continue
		}
		if t.state != target.StateStopped || t.listening {
			return false, nil
		}
		if _, err := readSignalInfo(t.tid); err != nil {
			return false, fmt.Errorf("validate stopped owner TID %d: %w", t.tid, err)
		}
	}
	return true, nil
}

func (e *engine) loadImage(p *process, tid int, initial bool) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", tid))
	if err != nil {
		return err
	}
	defer f.Close()
	profile, err := profileForELF(f)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if initial && p.exeInfo != nil && !os.SameFile(p.exeInfo, info) {
		return fmt.Errorf("executed file changed during launch: %w", target.ErrStale)
	}
	if initial && p.profile != nil && p.profile.Architecture != profile.Architecture {
		return fmt.Errorf("executed architecture changed during launch: %w", target.ErrStale)
	}
	p.profile, p.exeInfo = profile, info
	return nil
}

func (e *engine) advanceInitialization() {
	if e.unsupported != nil {
		e.failInitialization(e.unsupported)
		return
	}
	if e.life.launch != nil {
		if !e.life.launchExec {
			return
		}
	} else {
		if err := e.scanAttach(); err != nil {
			e.failInitialization(err)
			return
		}
		closed, err := e.attachClosed()
		if err != nil {
			e.failInitialization(err)
			return
		}
		if !closed {
			if e.allStopped() && len(e.life.births) == 0 {
				e.failInitialization(fmt.Errorf("thread membership closure is incomplete: %w", target.ErrUnavailable))
			}
			return
		}
	}
	if !e.allStopped() || len(e.life.births) != 0 {
		return
	}
	if err := e.validateAllStop(); err != nil {
		e.failInitialization(err)
		return
	}
	var selected *thread
	for _, t := range e.sortedThreads() {
		if t.process == e.primary && t.state == target.StateStopped && !t.exiting {
			if selected == nil || t.tid == e.primary.tgid {
				selected = t
			}
		}
	}
	if selected == nil {
		e.failInitialization(target.ErrExited)
		return
	}
	if e.primary.profile == nil {
		if err := e.loadImage(e.primary, selected.tid, true); err != nil {
			e.failInitialization(err)
			return
		}
	}
	stop := selected.stop
	if e.life.launch != nil {
		stop.Reason = target.StopExec
	} else if stop.Reason == target.StopInterrupt {
		stop.Reason = target.StopAttach
	}
	var err error
	stop, err = e.capturePC(stop)
	if err != nil {
		e.failInitialization(err)
		return
	}
	selected.stop = copyStop(stop)
	e.life.initializing, e.life.attaching = false, false
	e.s.architecture = e.primary.profile.Architecture
	e.emit(target.EventAllStopped, selected, 0, stop)
	e.publish(stop)
	e.life.ready <- response[*Session]{value: e.s}
	e.life.ready = nil
}

func (e *engine) failInitialization(err error) {
	e.life.startError = errors.Join(e.life.startError, err)
	e.unsupported = errors.Join(e.unsupported, err)
	e.life.initializing = false
	e.beginShutdown("close", nil)
}

func (e *engine) registerBirth(parent *thread, cause int) error {
	child, err := unix.PtraceGetEventMsg(parent.tid)
	if err != nil {
		return err
	}
	tid := int(child)
	if tid <= 0 {
		return fmt.Errorf("invalid child TID: %w", target.ErrUnknown)
	}
	b := e.life.births[tid]
	if b == nil {
		b = &birth{}
		e.life.births[tid] = b
	}
	b.parent, b.creator, b.cause, b.message = parent.process, parent, cause, true
	if old := e.life.missing[tid]; old != nil && e.threads[tid] == old {
		delete(e.threads, tid)
	}
	t := e.newThread(nil, tid, parent.seized)
	if cause == unix.PTRACE_EVENT_CLONE {
		if _, stepped := e.life.syscallSteps[parent]; stepped {
			if e.life.cloneChildren == nil {
				e.life.cloneChildren = make(map[*thread]*thread)
			}
			e.life.cloneChildren[parent] = t
		}
	}
	if err := e.resolveBirth(t, b); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
		b.fault = err
		return err
	}
	if t.state == target.StateStopped {
		b.stopped = true
	}
	return nil
}

func sameAddressSpace(a, b int) (bool, error) {
	result, _, errno := unix.Syscall6(unix.SYS_KCMP, uintptr(a), uintptr(b), 1, 0, 0, 0)
	if errno != 0 {
		return false, errno
	}
	return result == 0, nil
}

func (e *engine) resolveBirth(t *thread, b *birth) error {
	status, err := readTaskStatus(t.tid)
	if err != nil {
		return err
	}
	if status.tracer != e.life.tracer {
		return fmt.Errorf("child tracer identity changed: %w", target.ErrStale)
	}
	p := e.processes[status.tgid]
	if p == nil {
		fd, err := unix.PidfdOpen(status.tgid, 0)
		if err != nil {
			return err
		}
		p = e.newProcess(status.tgid, fd, b.parent != nil && b.parent.owned)
		if b.parent != nil {
			p.profile = b.parent.profile
			shared, relationErr := sameAddressSpace(b.parent.tgid, t.tid)
			if relationErr != nil {
				p.space.unknown = true
				p.space.fault = fmt.Errorf("cannot determine child address-space relation: %w", relationErr)
			} else if shared {
				p.space = b.parent.space
			} else if err := e.copyBreakpoints(b.parent.space, p.space); err != nil {
				p.space.fault = err
			}
		}
		e.unsupported = errors.Join(e.unsupported, fmt.Errorf("cross-process tracing is not supported: %w", target.ErrUnsupported))
	}
	t.process, t.name = p, status.name
	return nil
}

func (e *engine) finishBirth(t *thread, b *birth) {
	if !b.message || !b.decoded || !b.stopped || t.process == nil || b.announced {
		return
	}
	b.announced = true
	delete(e.life.births, t.tid)
	e.onThreadCreated(t)
}

func (e *engine) handleExec(t *thread, w waitResult) (*thread, error) {
	old, err := unix.PtraceGetEventMsg(w.pid)
	if err != nil {
		return t, err
	}
	if old != 0 && int(old) != w.pid {
		execer := e.life.missing[int(old)]
		if execer == nil {
			execer = e.threads[int(old)]
		}
		if execer == nil || execer.process == nil {
			return t, fmt.Errorf("exec former TID %d is not owned: %w", old, target.ErrUnknown)
		}
		if t != nil && t != execer {
			delete(e.life.detachedExits, t)
			t.state, t.exiting, t.exitComplete = target.StateExited, false, true
			t.watchpoints = nil
			e.emit(target.EventThreadExited, t, 0, target.Stop{})
		}
		delete(e.life.aliases, w.pid)
		if e.threads[int(old)] == execer {
			delete(e.threads, int(old))
			delete(e.life.lost, int(old))
			delete(e.life.births, int(old))
		}
		delete(e.life.missing, int(old))
		execer.tid = w.pid
		e.threads[w.pid] = execer
		t = execer
	}
	if t == nil || t.process == nil {
		return t, fmt.Errorf("exec has no process identity: %w", target.ErrUnknown)
	}
	t.state, t.listening = target.StateStopped, false
	p := t.process
	p.space = e.newSpace()
	for tid, peer := range e.threads {
		if peer.process != p {
			continue
		}
		if err := e.abandonBreakpointStep(peer); err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
		}
		peer.hit = nil
		e.forgetSyscallStep(peer)
		peer.pendingSignal = 0
		peer.registerRevision++
		if peer != t {
			peer.state, peer.exiting, peer.exitComplete = target.StateExited, false, true
			peer.watchpoints = nil
			delete(e.life.births, tid)
			delete(e.life.lost, tid)
			delete(e.life.missing, tid)
		}
	}
	t.exiting, t.exitComplete, t.listening, t.groupStopped = false, false, false, false
	t.needsUserBoundary = true
	if err := e.resetExecWatchpoints(t); err != nil {
		return t, err
	}
	if err := e.loadImage(p, t.tid, e.life.initializing); err != nil {
		return t, err
	}
	if e.life.initializing && e.life.launch != nil {
		if err := e.life.launch.execError(); err != nil {
			return t, err
		}
		e.life.launchExec = true
	}
	return t, nil
}

func terminalStop(w waitResult) target.Stop {
	stop := rawStop(w)
	stop.Signal = target.Signal{}
	if w.status.Exited() {
		code := w.status.ExitStatus()
		stop.Reason, stop.ExitCode = target.StopExited, &code
	} else {
		stop.Reason = target.StopSignaled
		stop.Signal = target.Signal{Domain: target.SignalLinux, Number: uint32(w.status.Signal())}
	}
	return stop
}

func (e *engine) handleWait(w waitResult) {
	t := e.threads[w.pid]
	if w.err != nil {
		e.unsupported = errors.Join(e.unsupported, w.err)
		e.failRun(w.err)
		return
	}
	cause := int(uint32(w.status) >> 16)
	if w.status.Stopped() && cause == unix.PTRACE_EVENT_EXEC {
		var err error
		t, err = e.handleExec(t, w)
		if err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
			if e.life.initializing {
				e.failInitialization(err)
			}
		}
	}
	if t == nil {
		e.unsupported = errors.Join(e.unsupported, fmt.Errorf("wait for unregistered TID %d: %w", w.pid, target.ErrUnknown))
		e.failRun(e.unsupported)
		return
	}
	if w.status.Exited() || w.status.Signaled() {
		stop := terminalStop(w)
		e.forgetSyscallStep(t)
		t.state, t.exiting, t.exitComplete, t.listening = target.StateExited, false, true, false
		t.watchpoints = nil
		delete(e.life.births, t.tid)
		delete(e.life.lost, t.tid)
		if e.life.missing[t.tid] == t {
			delete(e.life.missing, t.tid)
		}
		e.observeProcessExit()
		e.onThreadExit(t, stop)
		delete(e.life.exitStops, t)
		if e.allExited() && e.life.shutdownKind != "" && !e.life.initializing {
			e.publish(stop)
			if e.run != nil {
				e.beginBarrier(t, stop, nil)
			}
		}
		if e.life.initializing {
			err := target.ErrExited
			if e.life.launch != nil {
				err = errors.Join(err, e.life.launch.execError())
			}
			e.failInitialization(fmt.Errorf("target exited before initial stop: %w", err))
		}
		return
	}
	if !w.status.Stopped() {
		e.unsupported = errors.Join(e.unsupported, fmt.Errorf("unexpected wait status %x: %w", uint32(w.status), target.ErrUnknown))
		e.failRun(e.unsupported)
		return
	}
	wasListening := t.listening
	t.state, t.listening = target.StateStopped, false
	if wasListening && cause == unix.PTRACE_EVENT_STOP && w.status.StopSignal() == unix.SIGTRAP && !t.interruptRequested && e.life.shutdownKind == "" {
		t.groupStopped = false
		if err := e.prepareWatchpointResume(t); err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
			e.failRun(err)
			return
		}
		if err := unix.PtraceCont(t.tid, 0); err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
			e.failRun(err)
			return
		}
		t.state = target.StateRunning
		return
	}
	if e.life.launch != nil && e.life.initializing && !e.life.launchReleased {
		if cause != unix.PTRACE_EVENT_STOP || w.status.StopSignal() != unix.SIGTRAP {
			e.failInitialization(fmt.Errorf("unexpected launch gate stop: %w", target.ErrUnknown))
			return
		}
		if err := e.life.launch.release(); err != nil {
			e.failInitialization(err)
			return
		}
		e.life.launchReleased = true
		if err := unix.PtraceCont(t.tid, 0); err != nil {
			e.failInitialization(err)
			return
		}
		t.state, t.interruptRequested = target.StateRunning, false
		return
	}
	if cause == unix.PTRACE_EVENT_CLONE || cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK {
		if err := e.registerBirth(t, cause); err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
		}
	}
	if b := e.life.births[t.tid]; b != nil {
		b.stopped = true
		t.needsUserBoundary = true
		if err := e.resolveBirth(t, b); err != nil {
			b.fault = err
			e.unsupported = errors.Join(e.unsupported, err)
		}
	}
	if cause == unix.PTRACE_EVENT_EXIT {
		if code, err := unix.PtraceGetEventMsg(t.tid); err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
		} else {
			if e.life.exitStops == nil {
				e.life.exitStops = make(map[*thread]target.Stop)
			}
			e.life.exitStops[t] = terminalStop(waitResult{pid: t.tid, status: unix.WaitStatus(code)})
		}
		t.exiting, t.exitComplete = true, false
		if detached, err := e.detachExitingLeader(t); detached {
			return
		} else if err != nil && !errors.Is(err, unix.ESRCH) {
			e.unsupported = errors.Join(e.unsupported, err)
		}
		if err := unix.PtraceCont(t.tid, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			e.unsupported = errors.Join(e.unsupported, err)
			e.failRun(err)
			return
		}
		t.state = target.StateRunning
		return
	}
	if t.process == nil {
		e.unsupported = errors.Join(e.unsupported, target.ErrUnavailable)
		e.failRun(e.unsupported)
		return
	}
	if t.process.profile == nil {
		if err := e.loadImage(t.process, t.tid, e.life.initializing); err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
			if e.life.initializing {
				e.failInitialization(err)
				return
			}
		}
	}
	if t.watchpoints == nil {
		var err error
		if e.life.births[t.tid] != nil {
			err = e.resetNewbornWatchpoints(t)
		} else {
			err = e.initializeWatchpoints(t)
		}
		if err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
			if e.life.initializing {
				e.failInitialization(err)
				return
			}
		}
	}
	stepping := e.threadStepping(t)
	stop, err := e.classify(t, w, stepping)
	if err != nil {
		e.unsupported = errors.Join(e.unsupported, err)
		if e.life.initializing {
			e.failInitialization(err)
			return
		}
	}
	e.onThreadStop(t, stop)
	for tid, pending := range e.life.births {
		if pending.fault != nil {
			e.failRun(fmt.Errorf("unresolved child TID %d: %w", tid, pending.fault))
		}
	}
	if b := e.life.births[t.tid]; b != nil {
		e.finishBirth(t, b)
	}
	if cause == unix.PTRACE_EVENT_CLONE || cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK {
		for tid, b := range e.life.births {
			if b.creator == t {
				b.decoded = true
				if child := e.threads[tid]; child != nil {
					e.finishBirth(child, b)
				}
			}
		}
	}
}

func (e *engine) advanceExits() {
	wasWaiting := e.life.awaitProcessExit
	e.observeProcessExit()
	changed := wasWaiting && !e.life.awaitProcessExit
	for _, t := range e.threads {
		if !t.live() || !t.exiting || t.exitComplete || t.process == nil {
			continue
		}
		status, err := readTaskStatus(t.tid)
		dead := !t.seized && e.life.detachedExits[t] && processTerminated(t.process)
		if dead || err == nil && status.state == 'Z' && status.tgid == t.process.tgid && (status.tracer == e.life.tracer || !t.seized && status.tracer == 0 && e.life.detachedExits[t]) {
			t.exitComplete = true
			changed = true
			if !t.seized && e.life.detachedExits[t] {
				delete(e.life.detachedExits, t)
				t.state = target.StateExited
				t.watchpoints = nil
				e.observeProcessExit()
				e.onThreadExit(t, e.life.exitStops[t])
				delete(e.life.exitStops, t)
				continue
			}
			if e.run != nil && (e.run.step == t.ref || e.run.overThread == t || !e.runHasLiveActions()) && !e.life.initializing && e.life.shutdownKind == "" {
				e.beginBarrier(t, e.life.exitStops[t], nil)
			}
		}
	}
	if changed {
		e.advanceBarrier()
		e.updateState()
	}
}

func (e *engine) lifecycleError() error {
	if e.life.shutdownKind != "" || e.life.initializing {
		return target.ErrBusy
	}
	switch e.life.terminal {
	case target.StateClosed:
		return target.ErrClosed
	case target.StateDetached:
		return target.ErrDetached
	case target.StateExited:
		return target.ErrExited
	}
	if len(e.threads) != 0 && e.allExited() {
		return target.ErrExited
	}
	return nil
}

func (e *engine) beginShutdown(kind string, reply chan error) {
	if kind == "detach" && e.primary != nil && e.primary.owned {
		if reply != nil {
			reply <- fmt.Errorf("detaching launched children is not supported: %w", target.ErrUnsupported)
		}
		return
	}
	closeAfter := kind == "close"
	if closeAfter {
		kind = "detach"
		if e.primary != nil && e.primary.owned {
			kind = "kill"
		}
	}
	if e.life.shutdownKind != "" && e.life.shutdownKind != kind {
		if reply != nil {
			reply <- target.ErrBusy
		}
		return
	}
	e.life.shutdownKind = kind
	if kind == "kill" {
		e.life.awaitProcessExit = true
	}
	e.life.closeAfter = e.life.closeAfter || closeAfter
	if reply != nil {
		e.life.shutdownReply = append(e.life.shutdownReply, reply)
	}
	if e.life.killSent == nil {
		e.life.killSent = make(map[int]bool)
	}
	if kind == "detach" {
		if err := e.interruptAll(); err != nil {
			e.finishShutdown(err)
			return
		}
	}
	e.advanceShutdown()
}

func (e *engine) processLive(p *process) bool {
	for _, t := range e.threads {
		if t.process == p && t.live() {
			return true
		}
	}
	return false
}

func (e *engine) advanceShutdown() {
	if e.life.shutdownKind == "" {
		return
	}
	if e.allExited() {
		if e.life.shutdownKind == "kill" {
			for _, p := range e.processes {
				if !processTerminated(p) {
					e.life.awaitProcessExit = true
					e.setState(target.StateRunning)
					return
				}
			}
		}
		e.life.awaitProcessExit = false
		e.setState(target.StateExited)
		e.failRun(target.ErrExited)
		e.finishShutdown(nil)
		return
	}
	if len(e.life.missing) != 0 {
		e.finishShutdown(&target.PartialError{Op: "shutdown pending exec identity", Total: len(e.threads), Completed: e.detachedCount(), Err: target.ErrUnavailable})
		return
	}
	for tid, b := range e.life.births {
		if b.fault != nil {
			e.finishShutdown(&target.PartialError{Op: fmt.Sprintf("shutdown unresolved birth TID %d", tid), Total: len(e.threads), Completed: e.detachedCount(), Err: b.fault})
			return
		}
	}
	if len(e.life.lost) != 0 {
		var lost []error
		for tid, err := range e.life.lost {
			lost = append(lost, fmt.Errorf("TID %d wait ownership unresolved: %w", tid, err))
		}
		e.finishShutdown(&target.PartialError{Op: "shutdown unresolved ownership", Total: len(e.threads), Completed: e.detachedCount(), Err: errors.Join(lost...)})
		return
	}
	if e.life.shutdownKind == "kill" {
		var errs []error
		for _, p := range e.processes {
			if e.life.killSent[p.tgid] || !e.processLive(p) {
				continue
			}
			if p.pidfd < 0 {
				errs = append(errs, fmt.Errorf("missing process handle %d: %w", p.tgid, target.ErrUnavailable))
				continue
			}
			if err := unix.PidfdSendSignal(p.pidfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, err)
				continue
			}
			e.life.killSent[p.tgid] = true
		}
		if len(errs) != 0 {
			e.finishShutdown(errors.Join(errs...))
		}
		return
	}
	if !e.allStopped() || len(e.life.births) != 0 {
		return
	}
	for _, p := range e.processes {
		if p.space == nil || !p.space.unknown || !e.processLive(p) {
			continue
		}
		for _, other := range e.processes {
			if other.space != nil && len(other.space.breakpoints) != 0 {
				e.finishShutdown(fmt.Errorf("unresolved child address space retains breakpoint state: %w", target.ErrUnsupported))
				return
			}
		}
	}
	hasBreakpoints := false
	for _, p := range e.processes {
		hasBreakpoints = hasBreakpoints || p.space != nil && len(p.space.breakpoints) != 0
	}
	if hasBreakpoints {
		if err := e.validateAllStop(); err != nil {
			e.finishShutdown(err)
			return
		}
	}
	if err := e.restoreBreakpoints(); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return
		}
		e.finishShutdown(err)
		return
	}
	if err := e.restoreWatchpoints(); err != nil {
		e.finishShutdown(err)
		return
	}
	var errs []error
	for _, t := range e.sortedThreads() {
		if !t.live() {
			continue
		}
		if !t.seized && e.life.detachedExits[t] {
			delete(e.life.detachedExits, t)
			t.state = target.StateDetached
			continue
		}
		if t.exiting {
			othersRunning := false
			for _, peer := range e.threads {
				if peer != t && peer.process == t.process && peer.live() && !peer.exiting {
					othersRunning = true
				}
			}
			if !othersRunning {
				if w, ready := waitTask(t.tid); ready && w.err == nil {
					e.handleWait(w)
					e.advanceShutdown()
				}
				return
			}
			errs = append(errs, fmt.Errorf("TID %d exit remains wait-owned: %w", t.tid, target.ErrUnavailable))
			continue
		}
		if err := ptraceDetach(t.tid, t.pendingSignal); err != nil {
			errs = append(errs, fmt.Errorf("detach TID %d: %w", t.tid, err))
			continue
		}
		t.state, t.listening = target.StateDetached, false
		t.pendingSignal = 0
		delete(e.life.births, t.tid)
	}
	if len(errs) != 0 {
		e.finishShutdown(&target.PartialError{Op: "detach", Total: len(e.threads), Completed: e.detachedCount(), Err: errors.Join(errs...)})
		return
	}
	e.life.terminal = target.StateDetached
	e.setState(target.StateDetached)
	e.failRun(target.ErrDetached)
	e.finishShutdown(nil)
}

func (e *engine) detachedCount() int {
	count := 0
	for _, t := range e.threads {
		if t.state == target.StateDetached || t.state == target.StateExited {
			count++
		}
	}
	return count
}

func (e *engine) finishShutdown(err error) {
	if err != nil && e.life.shutdownKind == "detach" {
		e.invalidatePartialDetach()
	}
	if err != nil && !errors.Is(err, target.ErrPartial) {
		err = &target.PartialError{Op: fmt.Sprintf("shutdown %s: session remains open; remaining TIDs %v", e.life.shutdownKind, e.remainingTIDs()), Total: len(e.threads), Completed: e.detachedCount(), Err: err}
	}
	if err != nil {
		if !e.allExited() {
			e.life.awaitProcessExit = false
		}
		e.failRun(err)
		e.updateState()
	}
	replies := e.life.shutdownReply
	e.life.shutdownReply = nil
	if e.life.startError != nil && e.life.ready != nil {
		if err != nil {
			e.life.ready <- response[*Session]{value: e.s, err: &target.PartialError{Op: fmt.Sprintf("initialize cleanup: session remains open; remaining TIDs %v", e.remainingTIDs()), Total: len(e.threads), Completed: e.detachedCount(), Err: errors.Join(e.life.startError, err)}}
		} else {
			e.life.ready <- response[*Session]{err: e.life.startError}
			e.life.finished = true
		}
		e.life.ready = nil
	}
	if err == nil && (e.life.closeAfter || e.life.terminal == target.StateDetached) {
		if e.life.closeAfter {
			e.life.terminal = target.StateClosed
			e.setState(target.StateClosed)
		}
		e.emit(target.EventSessionClosed, nil, 0, e.last)
		e.life.finished = true
	}
	e.life.shutdownKind = ""
	e.life.killSent = nil
	e.life.closeAfter = false
	for _, reply := range replies {
		reply <- err
	}
}

func (e *engine) release() {
	if e.life.exitTicker != nil {
		e.life.exitTicker.Stop()
		e.life.exitTicker = nil
	}
	if e.life.launch != nil {
		e.life.launch.close()
		e.life.launch = nil
	}
	for _, p := range e.processes {
		if p.pidfd >= 0 {
			unix.Close(p.pidfd)
			p.pidfd = -1
		}
		if p.osProcess != nil {
			p.osProcess.Release()
			p.osProcess = nil
		}
	}
}

func (e *engine) validateAllStop() error {
	if len(e.life.births) != 0 || len(e.life.missing) != 0 || len(e.life.lost) != 0 {
		return fmt.Errorf("unresolved thread ownership: %w", target.ErrUnavailable)
	}
	for _, p := range e.processes {
		if !e.processLive(p) {
			continue
		}
		if p.space == nil || p.space.unknown {
			return fmt.Errorf("unknown address space for process %d: %w", p.tgid, target.ErrUnsupported)
		}
		var members []*thread
		for _, t := range e.threads {
			if t.process != p {
				continue
			}
			if t.live() || t.tid == p.tgid && e.life.aliases[t.tid] == p {
				members = append(members, t)
			}
		}
		if len(members) == 0 {
			continue
		}
		status, err := readTaskStatus(members[0].tid)
		if err == nil && (status.tgid != p.tgid || status.count != len(members)) {
			err = fmt.Errorf("process %d thread membership is incomplete (%d observed, %d kernel): %w", p.tgid, len(members), status.count, target.ErrUnsupported)
		}
		if err == nil {
			for _, t := range members {
				current, currentErr := readTaskStatus(t.tid)
				if currentErr != nil || current.tgid != p.tgid {
					err = errors.Join(target.ErrStale, currentErr)
					break
				}
				t.name = current.name
				if t.exitComplete && current.state == 'Z' {
					continue
				}
				if !t.seized || t.state != target.StateStopped || t.listening || current.tracer != e.life.tracer {
					err = target.ErrUnavailable
					break
				}
				if _, err = readSignalInfo(t.tid); err != nil {
					break
				}
			}
		}
		if err != nil {
			p.space.fault = fmt.Errorf("all-stop process %d: %w", p.tgid, err)
			return p.space.fault
		}
	}
	return nil
}

func processTerminated(p *process) bool {
	if p == nil || p.pidfd < 0 {
		return false
	}
	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 0)
	return err == nil && fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0
}

func (e *engine) detachExitingLeader(t *thread) (bool, error) {
	p := t.process
	if p == nil || p.owned || t.tid != p.tgid || e.life.shutdownKind == "kill" {
		return false, nil
	}
	hasPeer := false
	for _, peer := range e.threads {
		hasPeer = hasPeer || peer != t && peer.process == p && peer.live()
	}
	if !hasPeer {
		return false, nil
	}
	if err := e.restoreThreadWatchpoints(t); err != nil {
		return false, err
	}
	if err := ptraceDetach(t.tid, 0); err != nil {
		return false, err
	}
	if e.life.detachedExits == nil {
		e.life.detachedExits = make(map[*thread]bool)
	}
	if e.life.aliases == nil {
		e.life.aliases = make(map[int]*process)
	}
	e.life.detachedExits[t] = true
	e.life.aliases[t.tid] = p
	t.seized = false
	t.state = target.StateRunning
	return true, nil
}

func (e *engine) exitTicks() <-chan time.Time {
	if len(e.life.detachedExits) == 0 && e.life.shutdownKind != "kill" && !e.life.awaitProcessExit {
		if e.life.exitTicker != nil {
			e.life.exitTicker.Stop()
			e.life.exitTicker = nil
		}
		return nil
	}
	if e.life.exitTicker == nil {
		e.life.exitTicker = time.NewTicker(5 * time.Millisecond)
	}
	return e.life.exitTicker.C
}

func (e *engine) remainingTIDs() []int {
	var tids []int
	for tid, t := range e.threads {
		if t.live() {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	return tids
}

func (e *engine) observeProcessExit() {
	if !e.allExited() {
		return
	}
	e.life.awaitProcessExit = false
	for _, p := range e.processes {
		if p.pidfd >= 0 && !processTerminated(p) {
			e.life.awaitProcessExit = true
			return
		}
	}
}

func (e *engine) invalidatePartialDetach() {
	detached := make(map[*addressSpace]bool)
	for _, t := range e.threads {
		if t.state == target.StateDetached && t.process != nil && t.process.space != nil {
			detached[t.process.space] = true
		}
	}
	for _, t := range e.threads {
		if !t.live() || !t.seized || t.process == nil || !detached[t.process.space] {
			continue
		}
		space := t.process.space
		space.fault = errors.Join(space.fault, fmt.Errorf("detached peers may still access this address space: %w", target.ErrUnavailable))
		e.memoryChanged(space)
		delete(detached, space)
	}
}
