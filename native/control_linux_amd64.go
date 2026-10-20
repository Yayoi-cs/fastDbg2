package native

import (
	"errors"
	"fastdbg2/target"
	"fmt"

	"golang.org/x/sys/unix"
)

func signalNumber(signal target.Signal) (int, error) {
	if signal.Domain == target.SignalNone && signal.Number == 0 {
		return 0, nil
	}
	if signal.Domain != target.SignalLinux {
		return 0, fmt.Errorf("native requires Linux signals: %w", target.ErrUnsupported)
	}
	if signal.Number > 64 {
		return 0, target.ErrInvalidArgument
	}
	return int(signal.Number), nil
}

func (e *engine) beginRun(step bool, signal target.Signal, reply chan response[target.Stop]) {
	if err := e.requireStopped(); err != nil {
		reply <- response[target.Stop]{err: err}
		return
	}
	sig, err := signalNumber(signal)
	if err != nil {
		reply <- response[target.Stop]{err: err}
		return
	}
	if sig != 0 && e.pendingSignal == 0 {
		reply <- response[target.Stop]{err: fmt.Errorf("signal delivery requires a signal-delivery stop: %w", target.ErrInvalidState)}
		return
	}
	if e.run != nil {
		reply <- response[target.Stop]{err: target.ErrBusy}
		return
	}
	e.run = &runOperation{step: step, reply: reply}
	if bp := e.suspended; bp != nil {
		pc, err := e.readPC(e.s.pid)
		if err != nil {
			e.finishRun(e.last, err)
			return
		}
		if pc == bp.addr {
			if sig != 0 {
				e.finishRun(e.last, fmt.Errorf("remove the breakpoint before delivering a signal during interrupted step-over: %w", target.ErrUnsupported))
				return
			}
			value, err := e.readByte(e.s.pid, bp.addr)
			if err != nil || value != bp.original {
				if err == nil {
					err = fmt.Errorf("interrupted step instruction changed: %w", target.ErrStale)
				}
				e.unsupported = err
				e.finishRun(e.last, err)
				return
			}
			e.run.over = bp
			if err := ptraceStep(e.s.pid, 0); err != nil {
				e.finishRun(e.last, err)
				return
			}
			e.suspended = nil
			e.resumed()
			return
		}
		if err := e.arm(bp); err != nil {
			e.finishRun(e.last, err)
			return
		}
		e.suspended = nil
	}
	if e.hit != nil {
		if bp, ok := e.breakpoints[*e.hit]; ok {
			pc, err := e.readPC(e.s.pid)
			if err != nil {
				e.finishRun(e.last, err)
				return
			}
			if pc == bp.addr+1 {
				if err := e.disarm(bp); err != nil {
					e.finishRun(e.last, err)
					return
				}
				if err := e.writePC(e.s.pid, bp.addr); err != nil {
					e.finishRun(e.last, errors.Join(err, e.arm(bp)))
					return
				}
				e.run.over = bp
				if err := ptraceStep(e.s.pid, sig); err != nil {
					e.finishRun(e.last, errors.Join(err, e.writePC(e.s.pid, pc), e.arm(bp)))
					return
				}
				e.resumed()
				return
			}
		}
	}
	if step {
		err = ptraceStep(e.s.pid, sig)
	} else {
		err = unix.PtraceCont(e.s.pid, sig)
	}
	if err != nil {
		e.finishRun(e.last, err)
		return
	}
	e.resumed()
}

func ptraceStep(pid, signal int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SINGLESTEP, uintptr(pid), 0, uintptr(signal), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ptraceDetach(pid, signal int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(pid), 0, uintptr(signal), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (e *engine) resumed() {
	e.pendingSignal, e.hit = 0, nil
	e.tasks[e.s.pid].stopped = false
	e.setState(target.StateRunning)
	e.wait(e.tasks[e.s.pid])
}

func (e *engine) finishRun(stop target.Stop, err error) {
	if e.run == nil {
		return
	}
	e.run.reply <- response[target.Stop]{copyStop(stop), err}
	e.run = nil
}

func (e *engine) interrupt() error {
	if e.s.State() == target.StateExited {
		return target.ErrExited
	}
	if e.s.State() != target.StateRunning {
		return nil
	}
	if e.seized {
		return unix.PtraceInterrupt(e.s.pid)
	}
	if e.interruptSent {
		return nil
	}
	fd, ok := e.groups[e.s.pid]
	if !ok {
		return target.ErrInvalidState
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGSTOP, nil, 0); err != nil {
		return err
	}
	e.interruptSent = true
	return nil
}

func (e *engine) beginShutdown(kind string, reply chan error) {
	if kind == "detach" && e.owned {
		if reply != nil {
			reply <- fmt.Errorf("detaching launched children is not supported: %w", target.ErrUnsupported)
		}
		return
	}
	closeAfter := kind == "close"
	if kind == "close" {
		if e.owned {
			kind = "kill"
		} else {
			kind = "detach"
		}
	}
	if e.shutdownKind != "" && e.shutdownKind != kind {
		if reply != nil {
			reply <- target.ErrBusy
		}
		return
	}
	e.shutdownKind = kind
	e.closeAfter = e.closeAfter || closeAfter
	if reply != nil {
		e.shutdownReply = append(e.shutdownReply, reply)
	}
	if e.s.State() == target.StateRunning {
		if err := e.interrupt(); err != nil && !errors.Is(err, unix.ESRCH) {
			e.finishShutdown(err)
			return
		}
	}
	e.advanceShutdown()
}

func (e *engine) advanceShutdown() {
	if e.shutdownKind == "" {
		return
	}
	if e.allExited() {
		e.setState(target.StateExited)
		e.finishRun(e.last, nil)
		e.finishShutdown(nil)
		return
	}
	if e.shutdownKind == "kill" {
		if !e.killSent && !e.allStopped() {
			return
		}
		for _, t := range e.tasks {
			if t.exited {
				continue
			}
			if _, ok := e.groups[t.tgid]; !ok {
				e.finishShutdown(fmt.Errorf("no process handle for task %d: %w", t.pid, target.ErrUnavailable))
				return
			}
		}
		for pid, fd := range e.groups {
			if t := e.tasks[pid]; t != nil && !t.exited {
				if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					e.finishShutdown(err)
					return
				}
			}
		}
		e.killSent = true
		for _, t := range e.tasks {
			if !t.exited {
				t.stopped = false
				e.wait(t)
			}
		}
		return
	}
	if !e.allStopped() {
		return
	}
	if err := e.restoreBreakpoints(); err != nil {
		var failed *taskError
		if errors.Is(err, unix.ESRCH) && errors.As(err, &failed) {
			e.collectExit(failed.pid)
			return
		}
		e.unsupported = errors.Join(e.unsupported, err)
		e.finishShutdown(err)
		return
	}
	var errs []error
	waitingExit := false
	for pid, t := range e.tasks {
		if t.exited || pid == e.s.pid {
			continue
		}
		if err := ptraceDetach(pid, 0); err != nil {
			if errors.Is(err, unix.ESRCH) {
				e.collectExit(pid)
				waitingExit = true
			} else {
				errs = append(errs, err)
			}
		} else {
			t.exited = true
		}
	}
	if waitingExit && len(errs) == 0 {
		return
	}
	if len(errs) == 0 {
		if e.tasks[e.s.pid].exited {
			e.setState(target.StateDetached)
			e.finishRun(e.last, target.ErrDetached)
		} else if err := ptraceDetach(e.s.pid, e.pendingSignal); err != nil {
			if errors.Is(err, unix.ESRCH) {
				e.collectExit(e.s.pid)
				return
			}
			errs = append(errs, err)
		} else {
			e.tasks[e.s.pid].exited = true
			e.setState(target.StateDetached)
			e.finishRun(e.last, target.ErrDetached)
		}
	}
	e.finishShutdown(errors.Join(errs...))
}

func (e *engine) collectExit(pid int) {
	if t := e.tasks[pid]; t != nil && !t.exited {
		t.stopped = false
		e.wait(t)
	}
}

func (e *engine) finishShutdown(err error) {
	if err != nil && e.s.State() != target.StateRunning {
		e.finishRun(e.last, err)
	}
	for _, reply := range e.shutdownReply {
		reply <- err
	}
	e.shutdownReply = nil
	if e.startError != nil && e.ready != nil {
		e.ready <- response[*Session]{err: errors.Join(e.startError, err)}
		e.ready = nil
		e.finished = true
	}
	if err == nil && (e.closeAfter || e.s.State() == target.StateDetached) {
		e.release()
		if e.closeAfter {
			e.setState(target.StateClosed)
		}
		e.finished = true
	}
	e.shutdownKind, e.killSent = "", false
	e.closeAfter = false
}
