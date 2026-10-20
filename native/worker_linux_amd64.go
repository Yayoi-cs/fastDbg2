package native

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type task struct {
	pid     int
	tgid    int
	stopped bool
	exited  bool
	waiting bool
}

type waitResult struct {
	pid    int
	status unix.WaitStatus
	err    error
}

type runOperation struct {
	step  bool
	reply chan response[target.Stop]
	over  *breakpoint
}

type engine struct {
	s             *Session
	ready         chan response[*Session]
	initializing  bool
	startError    error
	owned         bool
	seized        bool
	process       *os.Process
	exeInfo       os.FileInfo
	profile       *arch.Descriptor
	tasks         map[int]*task
	groups        map[int]int
	waits         chan waitResult
	waiters       sync.WaitGroup
	breakpoints   map[target.Address]*breakpoint
	last          target.Stop
	hit           *target.Address
	suspended     *breakpoint
	generation    uint64
	pendingSignal int
	interruptSent bool
	run           *runOperation
	unsupported   error
	deferredStop  *target.Stop
	shutdownKind  string
	shutdownReply []chan error
	closeAfter    bool
	killSent      bool
	finished      bool
}

type signalInfo struct {
	Signo int32
	Errno int32
	Code  int32
	Pad   int32
	Data  [112]byte
}

func (s *Session) worker(start func(*engine) error, ready chan response[*Session]) {
	runtime.LockOSThread()
	e := &engine{
		s: s, ready: ready, initializing: true,
		tasks: make(map[int]*task), groups: make(map[int]int),
		waits: make(chan waitResult, 16), breakpoints: make(map[target.Address]*breakpoint),
	}
	defer close(s.done)
	defer e.release()
	if err := start(e); err != nil {
		ready <- response[*Session]{err: err}
		return
	}
	for !e.finished {
		select {
		case req := <-s.requests:
			req(e)
		case w := <-e.waits:
			e.handleWait(w)
		}
	}
	e.waiters.Wait()
}

func (e *engine) launch(path string, args []string) error {
	resolved, err := exec.LookPath(path)
	if err != nil {
		return err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return err
	}
	defer f.Close()
	e.profile, err = profileForELF(f)
	if err != nil {
		return err
	}
	e.exeInfo, err = f.Stat()
	if err != nil {
		return err
	}
	cmd := exec.Command(resolved, args...)
	cmd.SysProcAttr = &unix.SysProcAttr{Ptrace: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	e.owned, e.process, e.s.pid = true, cmd.Process, cmd.Process.Pid
	fd, err := unix.PidfdOpen(e.s.pid, 0)
	if err != nil {
		killErr := cmd.Process.Kill()
		var waitErr error
		for {
			var ws unix.WaitStatus
			_, waitErr = unix.Wait4(e.s.pid, &ws, unix.WALL, nil)
			if errors.Is(waitErr, unix.EINTR) {
				continue
			}
			if waitErr != nil || ws.Exited() || ws.Signaled() {
				break
			}
		}
		return errors.Join(fmt.Errorf("pidfd_open: %w", err), killErr, waitErr)
	}
	e.groups[e.s.pid] = fd
	e.tasks[e.s.pid] = &task{pid: e.s.pid, tgid: e.s.pid}
	e.wait(e.tasks[e.s.pid])
	return nil
}

func (e *engine) attach(pid int) error {
	if err := unix.PtraceSeize(pid); err != nil {
		return fmt.Errorf("seize: %w", err)
	}
	e.s.pid, e.seized = pid, true
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return errors.Join(fmt.Errorf("pidfd_open after seize: %w", err), rollbackSeize(pid))
	}
	e.groups[pid] = fd
	e.tasks[pid] = &task{pid: pid, tgid: pid}
	if err := unix.PtraceInterrupt(pid); err != nil {
		return errors.Join(fmt.Errorf("initial interrupt: %w", err), rollbackSeize(pid))
	}
	e.wait(e.tasks[pid])
	return nil
}

func profileForELF(f *os.File) (*arch.Descriptor, error) {
	b, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("ELF: %w", err)
	}
	if b.Data == elf.ELFDATA2LSB {
		for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
			if b.Class == profile.ELFClass && b.Machine == profile.ELFMachine {
				return &profile, nil
			}
		}
	}
	return nil, fmt.Errorf("native requires little-endian ELF64 x86-64 or ELF32 i386: %w", target.ErrUnsupported)
}

func threadStatus(pid int) (int, int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	values := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "Pid:", "Tgid:", "Threads:":
			v, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, 0, err
			}
			values[fields[0]] = v
		}
	}
	if values["Pid:"] != pid || values["Tgid:"] <= 0 || values["Threads:"] <= 0 {
		return 0, 0, fmt.Errorf("invalid process thread identity: %w", target.ErrUnknown)
	}
	return values["Tgid:"], values["Threads:"], nil
}

func (e *engine) singleThread() error {
	tgid, count, err := threadStatus(e.s.pid)
	if err != nil {
		return err
	}
	if tgid != e.s.pid || count != 1 {
		return fmt.Errorf("native requires one thread and a thread-group leader (tgid=%d threads=%d): %w", tgid, count, target.ErrUnsupported)
	}
	return nil
}

func (e *engine) initialize(w waitResult) {
	if w.err != nil || !w.status.Stopped() {
		err := w.err
		if err == nil {
			err = fmt.Errorf("target exited before initial stop: %v", w.status)
		}
		e.startError = err
		e.initializing = false
		e.beginShutdown("close", nil)
		return
	}
	stop, _, err := e.classifySignal(w, false)
	if err == nil {
		err = e.singleThread()
	}
	if err == nil {
		var f *os.File
		f, err = os.Open(fmt.Sprintf("/proc/%d/exe", e.s.pid))
		if err == nil {
			var profile *arch.Descriptor
			profile, err = profileForELF(f)
			if err == nil && e.profile != nil && profile.Architecture != e.profile.Architecture {
				err = fmt.Errorf("executed ELF architecture changed during launch: %w", target.ErrStale)
			}
			if err == nil {
				e.profile = profile
			}
			if err == nil && e.exeInfo != nil {
				var actual os.FileInfo
				actual, err = f.Stat()
				if err == nil && !os.SameFile(e.exeInfo, actual) {
					err = fmt.Errorf("executed file changed during launch: %w", target.ErrStale)
				}
			}
			f.Close()
		}
	}
	if err == nil {
		stop, err = e.capturePC(stop)
	}
	if err == nil {
		options := unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACEEXEC
		if e.owned {
			options |= unix.PTRACE_O_EXITKILL
		}
		err = unix.PtraceSetOptions(e.s.pid, options)
	}
	e.initializing = false
	if err != nil {
		e.startError = err
		e.beginShutdown("close", nil)
		return
	}
	if e.owned {
		if w.status.StopSignal() != unix.SIGTRAP || w.status.TrapCause() != 0 {
			e.startError = fmt.Errorf("unexpected initial exec stop: %w", target.ErrUnknown)
			e.beginShutdown("close", nil)
			return
		}
		stop.Reason, e.pendingSignal = target.StopExec, 0
	} else if stop.Reason == target.StopInterrupt {
		stop.Reason = target.StopAttach
	}
	e.publish(stop)
	e.s.architecture = e.profile.Architecture
	e.ready <- response[*Session]{value: e.s}
	e.ready = nil
}

func (e *engine) wait(t *task) {
	if t.waiting || t.exited {
		return
	}
	t.waiting = true
	e.waiters.Add(1)
	go func(pid int) {
		defer e.waiters.Done()
		var ws unix.WaitStatus
		var err error
		for {
			_, err = unix.Wait4(pid, &ws, unix.WALL, nil)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		e.waits <- waitResult{pid, ws, err}
	}(t.pid)
}

func (e *engine) handleWait(w waitResult) {
	t := e.tasks[w.pid]
	t.waiting = false
	if w.err != nil {
		t.exited = errors.Is(w.err, unix.ECHILD) || errors.Is(w.err, unix.ESRCH)
	} else {
		t.stopped = w.status.Stopped()
		t.exited = w.status.Exited() || w.status.Signaled()
	}
	if e.initializing {
		e.initialize(w)
		return
	}
	if w.err != nil {
		e.unsupported = fmt.Errorf("wait PID %d: %w", w.pid, w.err)
		e.finishRun(e.last, e.unsupported)
		if e.shutdownKind != "" {
			e.advanceShutdown()
		} else {
			e.completeUnsupported()
		}
		return
	}
	if t.exited {
		if w.pid == e.s.pid {
			e.deferredStop = nil
			id := uint64(w.pid)
			stop := target.Stop{ThreadID: &id, Raw: fmt.Sprintf("wait_status=0x%x", uint32(w.status))}
			if w.status.Exited() {
				code := w.status.ExitStatus()
				stop.Reason, stop.ExitCode = target.StopExited, &code
			} else {
				stop.Reason = target.StopSignaled
				stop.Signal = target.Signal{Domain: target.SignalLinux, Number: uint32(w.status.Signal())}
			}
			e.publish(stop)
			e.setState(target.StateExited)
			if e.allExited() {
				e.breakpoints = make(map[target.Address]*breakpoint)
			}
			e.hit = nil
			if e.shutdownKind == "" {
				e.finishRun(e.last, nil)
			}
		}
		if e.shutdownKind != "" {
			e.advanceShutdown()
		} else {
			e.completeUnsupported()
		}
		return
	}
	if !t.stopped {
		e.unsupported = fmt.Errorf("unexpected wait status %v: %w", w.status, target.ErrUnknown)
		e.finishRun(e.last, e.unsupported)
		return
	}
	if w.pid != e.s.pid {
		tgid, _, err := threadStatus(w.pid)
		if err == nil {
			t.tgid = tgid
		}
		if err == nil && tgid == w.pid {
			var fd int
			fd, err = unix.PidfdOpen(w.pid, 0)
			if err == nil {
				e.groups[tgid] = fd
			}
		}
		if err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
		}
		if e.shutdownKind != "" {
			e.advanceShutdown()
		} else {
			e.completeUnsupported()
		}
		return
	}
	e.setState(target.StateStopped)
	cause := int(uint32(w.status) >> 16)
	newTask := cause == unix.PTRACE_EVENT_CLONE || cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK
	if newTask {
		child, childErr := unix.PtraceGetEventMsg(e.s.pid)
		e.unsupported = fmt.Errorf("additional task creation is not supported: %w", target.ErrUnsupported)
		if childErr != nil {
			e.unsupported = errors.Join(e.unsupported, childErr)
		} else {
			pid := int(child)
			if pid <= 0 {
				e.unsupported = errors.Join(e.unsupported, target.ErrUnknown)
			} else {
				e.tasks[pid] = &task{pid: pid}
				e.wait(e.tasks[pid])
			}
		}
	}
	if cause == unix.PTRACE_EVENT_EXEC {
		e.breakpoints = make(map[target.Address]*breakpoint)
		e.hit = nil
		e.suspended = nil
		e.unsupported = fmt.Errorf("exec changed the target address space: %w", target.ErrUnsupported)
	}
	stop, err := e.classify(w, e.run != nil && (e.run.step || e.run.over != nil))
	if err != nil {
		e.unsupported = errors.Join(e.unsupported, err)
	}
	if newTask {
		e.deferredStop = &stop
	}
	if e.unsupported == nil {
		if err := e.singleThread(); err != nil {
			e.unsupported = err
		}
	}
	if e.run != nil && e.run.over != nil && cause != unix.PTRACE_EVENT_EXEC {
		if stop.Reason == target.StopStep && e.unsupported == nil {
			if armErr := e.arm(e.run.over); armErr != nil {
				e.unsupported = errors.Join(e.unsupported, armErr)
			}
		} else {
			e.suspended = e.run.over
		}
		e.run.over = nil
		if e.unsupported == nil && stop.Reason == target.StopStep && !e.run.step && e.shutdownKind == "" {
			if err := unix.PtraceCont(e.s.pid, 0); err != nil {
				e.finishRun(stop, err)
				return
			}
			e.tasks[e.s.pid].stopped = false
			e.setState(target.StateRunning)
			e.wait(e.tasks[e.s.pid])
			return
		}
	}
	e.publish(stop)
	if e.shutdownKind != "" {
		e.advanceShutdown()
		return
	}
	if e.deferredStop != nil {
		e.completeUnsupported()
		return
	}
	e.finishRun(e.last, e.unsupported)
}

func (e *engine) classify(w waitResult, stepping bool) (target.Stop, error) {
	stop, info, err := e.classifySignal(w, stepping)
	if err != nil || stop.Reason == target.StopExec {
		return stop, err
	}
	stop, err = e.capturePC(stop)
	if err != nil {
		return stop, err
	}
	if stop.Reason == target.StopSignal && info != nil && w.status.StopSignal() == unix.SIGTRAP && (info.Code == 1 || info.Code == 128) && *stop.RawPC > 0 {
		addr := *stop.RawPC - 1
		if bp, ok := e.breakpoints[addr]; ok && bp.armed {
			value, err := e.readByte(w.pid, addr)
			if err != nil {
				return stop, err
			}
			if value == 0xcc {
				stop.Reason, stop.Breakpoint = target.StopBreakpoint, &addr
				e.hit, e.pendingSignal = &addr, 0
			}
		}
	}
	return stop, nil
}

func (e *engine) capturePC(stop target.Stop) (target.Stop, error) {
	if stop.ThreadID == nil {
		return stop, target.ErrUnknown
	}
	pc, err := e.readPC(int(*stop.ThreadID))
	if err != nil {
		return stop, err
	}
	stop.RawPC = &pc
	return stop, nil
}

func (e *engine) classifySignal(w waitResult, stepping bool) (target.Stop, *signalInfo, error) {
	id := uint64(w.pid)
	signal := w.status.StopSignal()
	stop := target.Stop{ThreadID: &id, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(signal)}, Raw: fmt.Sprintf("wait_status=0x%x", uint32(w.status))}
	e.pendingSignal, e.hit = 0, nil
	cause := int(uint32(w.status) >> 16)
	if cause == unix.PTRACE_EVENT_STOP && signal != unix.SIGTRAP {
		return stop, nil, fmt.Errorf("group-stop is not supported: %w", target.ErrUnsupported)
	}
	if signal == unix.SIGTRAP && cause > 0 {
		switch cause {
		case unix.PTRACE_EVENT_EXEC:
			stop.Reason = target.StopExec
		case unix.PTRACE_EVENT_CLONE:
			stop.Reason = target.StopClone
		case unix.PTRACE_EVENT_FORK:
			stop.Reason = target.StopFork
		case unix.PTRACE_EVENT_VFORK:
			stop.Reason = target.StopVFork
		case unix.PTRACE_EVENT_STOP:
			stop.Reason = target.StopInterrupt
		default:
			stop.Reason = target.StopUnknown
		}
		return stop, nil, nil
	}
	var info signalInfo
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GETSIGINFO, uintptr(w.pid), 0, uintptr(unsafe.Pointer(&info)), 0, 0)
	if errno != 0 {
		if errno == unix.EINVAL {
			return stop, nil, fmt.Errorf("group-stop is not supported: %w", target.ErrUnsupported)
		}
		return stop, nil, errno
	}
	stop.Raw += fmt.Sprintf(" si_code=%d", info.Code)
	if signal == unix.SIGSTOP && e.interruptSent && info.Code == 0 && int32(binary.LittleEndian.Uint32(info.Data[:4])) == int32(os.Getpid()) {
		e.interruptSent = false
		stop.Reason = target.StopInterrupt
		return stop, &info, nil
	}
	if signal == unix.SIGTRAP && info.Code == 2 && stepping {
		stop.Reason = target.StopStep
		return stop, &info, nil
	}
	stop.Reason = target.StopSignal
	e.pendingSignal = int(signal)
	return stop, &info, nil
}

func (e *engine) publish(stop target.Stop) {
	e.generation++
	stop.Generation = e.generation
	e.last = copyStop(stop)
	copy := copyStop(stop)
	e.s.last.Store(&copy)
	if stop.Reason != target.StopExited && stop.Reason != target.StopSignaled {
		e.setState(target.StateStopped)
	}
}

func (e *engine) setState(state target.State) { e.s.state.Store(uint32(state)) }

func (e *engine) requireStopped() error {
	if e.shutdownKind != "" {
		return target.ErrBusy
	}
	switch e.s.State() {
	case target.StateRunning:
		return target.ErrRunning
	case target.StateExited:
		return target.ErrExited
	case target.StateDetached:
		return target.ErrDetached
	case target.StateStopped:
		if e.unsupported != nil {
			return e.unsupported
		}
		if err := e.singleThread(); err != nil {
			e.unsupported = err
			return err
		}
		if _, err := e.readPC(e.s.pid); err != nil {
			e.unsupported = err
			return err
		}
		return nil
	default:
		return target.ErrInvalidState
	}
}

func (e *engine) completeUnsupported() {
	if e.deferredStop != nil && e.allStopped() {
		e.publish(*e.deferredStop)
		e.deferredStop = nil
		e.finishRun(e.last, e.unsupported)
	}
}

func (e *engine) allStopped() bool {
	for _, t := range e.tasks {
		if !t.exited && (!t.stopped || t.waiting) {
			return false
		}
	}
	return true
}

func (e *engine) allExited() bool {
	for _, t := range e.tasks {
		if !t.exited {
			return false
		}
	}
	return true
}

func (e *engine) release() {
	for pid, fd := range e.groups {
		unix.Close(fd)
		delete(e.groups, pid)
	}
	if e.process != nil {
		e.process.Release()
		e.process = nil
	}
}

func rollbackSeize(pid int) error {
	if err := unix.PtraceInterrupt(pid); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	for {
		var ws unix.WaitStatus
		_, err := unix.Wait4(pid, &ws, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) || errors.Is(err, unix.ESRCH) {
			return nil
		}
		if err != nil {
			return err
		}
		if ws.Exited() || ws.Signaled() {
			return nil
		}
		if !ws.Stopped() {
			continue
		}
		signal := 0
		if int(uint32(ws)>>16) != unix.PTRACE_EVENT_STOP {
			var info signalInfo
			_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GETSIGINFO, uintptr(pid), 0, uintptr(unsafe.Pointer(&info)), 0, 0)
			if errno == 0 {
				signal = int(ws.StopSignal())
			} else if errno != unix.EINVAL {
				return errno
			}
		}
		return ptraceDetach(pid, signal)
	}
}
