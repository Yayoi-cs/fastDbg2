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

func ptraceStep(tid, signal int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SINGLESTEP, uintptr(tid), 0, uintptr(signal), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ptraceDetach(tid, signal int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(tid), 0, uintptr(signal), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ptraceListen(tid int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_LISTEN, uintptr(tid), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (e *engine) resolveThreads(set target.ThreadSet) ([]*thread, error) {
	switch set.Scope {
	case target.ExactThreads:
		if set.Process != (target.ProcessRef{}) {
			return nil, target.ErrInvalidArgument
		}
		result := make([]*thread, 0, len(set.Threads))
		seen := make(map[target.ThreadRef]bool, len(set.Threads))
		for _, ref := range set.Threads {
			if seen[ref] {
				return nil, fmt.Errorf("duplicate thread: %w", target.ErrInvalidArgument)
			}
			t, err := e.findThread(ref)
			if err != nil {
				return nil, err
			}
			seen[ref] = true
			result = append(result, t)
		}
		return result, nil
	case target.ProcessThreads:
		if len(set.Threads) != 0 {
			return nil, target.ErrInvalidArgument
		}
		p, err := e.findProcess(set.Process)
		if err != nil {
			return nil, err
		}
		var result []*thread
		for _, t := range e.sortedThreads() {
			if t.process == p && t.live() && !t.exiting {
				result = append(result, t)
			}
		}
		return result, nil
	default:
		return nil, target.ErrInvalidArgument
	}
}

func (e *engine) startRun(request target.RunRequest) (*Run, error) {
	return e.startOperation(request.Threads, nil, request.Signals, false)
}

func (e *engine) startStep(request target.StepRequest) (*Run, error) {
	return e.startOperation(request.Continue, &request.Thread, request.Signals, false)
}

func (e *engine) startLegacyRun(step bool, signal target.Signal) (*Run, error) {
	t, err := e.singleStoppedThread()
	if err != nil {
		return nil, err
	}
	set := target.ThreadSet{Threads: []target.ThreadRef{t.ref}}
	signals := []target.ThreadSignal{{Thread: t.ref, Stop: t.stopEpoch, Signal: signal}}
	if step {
		return e.startOperation(target.ThreadSet{}, &t.ref, signals, true)
	}
	return e.startOperation(set, nil, signals, true)
}

func (e *engine) startOperation(set target.ThreadSet, step *target.ThreadRef, signals []target.ThreadSignal, legacy bool) (*Run, error) {
	if e.run != nil {
		return nil, target.ErrBusy
	}
	if err := e.requireAllStopped(); err != nil {
		return nil, err
	}
	threads, err := e.resolveThreads(set)
	if err != nil {
		return nil, err
	}
	op := &runOperation{
		actions: make(map[target.ThreadRef]*resumeAction),
		inherit: make(map[target.ProcessRef]bool), legacy: legacy,
	}
	for _, t := range threads {
		op.actions[t.ref] = &resumeAction{thread: t}
	}
	if set.Scope == target.ProcessThreads {
		op.inherit[set.Process] = true
	}
	if step != nil {
		t, err := e.findThread(*step)
		if err != nil {
			return nil, err
		}
		op.step = t.ref
		op.actions[t.ref] = &resumeAction{thread: t, step: true}
	}
	if len(op.actions) == 0 {
		return nil, fmt.Errorf("resume requires at least one thread: %w", target.ErrInvalidArgument)
	}
	for _, action := range op.actions {
		t := action.thread
		if _, pending := e.life.syscallSteps[t]; action.step && pending && e.life.cloneChildren[t] != nil {
			return nil, fmt.Errorf("an interrupted clone instruction remains pending: %w", target.ErrUnsupported)
		}
		if t.state != target.StateStopped || t.listening || t.exiting {
			return nil, target.ErrInvalidState
		}
		if t.fault != nil {
			return nil, t.fault
		}
		if watchpoints := t.watchpoints; watchpoints != nil {
			if watchpoints.fault != nil {
				return nil, watchpoints.fault
			}
			if watchpoints.pending != nil {
				return nil, target.ErrBusy
			}
		}
		if t.process == nil || t.process.profile == nil || t.process.space == nil {
			return nil, target.ErrUnavailable
		}
		space := t.process.space
		if space.unknown {
			return nil, target.ErrUnknown
		}
		if space.fault != nil {
			return nil, space.fault
		}
		if space.stepping != nil && op.actions[space.stepping.ref] == nil {
			return nil, fmt.Errorf("breakpoint step owner is not selected: %w", target.ErrInvalidState)
		}
		if t.groupStopped && action.step {
			return nil, fmt.Errorf("stepping a group-stopped thread: %w", target.ErrUnsupported)
		}
	}
	seen := make(map[target.ThreadRef]bool, len(signals))
	for _, delivery := range signals {
		action := op.actions[delivery.Thread]
		if action == nil || seen[delivery.Thread] {
			return nil, target.ErrInvalidArgument
		}
		t := action.thread
		if delivery.Stop == 0 || delivery.Stop != t.stopEpoch {
			return nil, target.ErrStale
		}
		signal, err := signalNumber(delivery.Signal)
		if err != nil {
			return nil, err
		}
		if signal != 0 && t.pendingSignal == 0 {
			return nil, fmt.Errorf("signal delivery requires a signal-delivery stop: %w", target.ErrInvalidState)
		}
		if signal != 0 && (t.hit != nil || t.suspended != nil) {
			return nil, fmt.Errorf("remove the suspended breakpoint before delivering a signal: %w", target.ErrUnsupported)
		}
		action.signal = signal
		seen[t.ref] = true
	}
	for ref, action := range op.actions {
		if action.thread.pendingSignal != 0 && !seen[ref] {
			return nil, fmt.Errorf("thread %d requires an explicit signal decision: %w", action.thread.tid, target.ErrInvalidArgument)
		}
		if action.step && action.thread.needsUserBoundary && action.signal != 0 {
			return nil, fmt.Errorf("instruction step across a kernel-return boundary cannot deliver a signal: %w", target.ErrUnsupported)
		}
	}
	e.nextRun++
	op.handle = newRun(e.nextRun)
	e.run = op
	e.advanceRun()
	return op.handle, nil
}

func (e *engine) threadStepping(t *thread) bool {
	if e.run == nil {
		return false
	}
	if e.run.entryThread == t {
		return false
	}
	if e.run.overThread == t {
		return true
	}
	action := e.run.actions[t.ref]
	return action != nil && action.step && action.started
}

func (e *engine) advanceRun() {
	if e.run == nil || e.barrier != nil || e.life.initializing || e.life.shutdownKind != "" || e.ownershipError() != nil {
		return
	}
	if e.unsupported != nil {
		e.beginBarrier(nil, e.last, e.unsupported)
		return
	}
	for _, t := range e.threads {
		if t.live() && t.state == target.StateUnknown {
			return
		}
	}
	if e.run.entryThread != nil {
		return
	}
	if e.run.overThread != nil {
		if e.run.overPaused {
			t := e.run.overThread
			action := e.run.actions[t.ref]
			if action == nil || !action.cloneStep || action.started {
				e.beginBarrier(t, t.stop, target.ErrInvalidState)
				return
			}
			if err := e.resumeThread(action, true); err != nil {
				e.beginBarrier(t, t.stop, err)
			}
		}
		return
	}
	for _, t := range e.sortedThreads() {
		action := e.run.actions[t.ref]
		if action == nil || action.started || !action.step || !t.needsUserBoundary {
			continue
		}
		pc, err := e.readPC(t.tid)
		if err != nil {
			e.beginBarrier(t, t.stop, err)
			return
		}
		bp, err := e.installExecBoundary(t, pc)
		if err != nil {
			e.beginBarrier(t, t.stop, err)
			return
		}
		e.run.entryThread, e.run.entry, e.run.entryHit = t, bp, false
		if err := e.resumeThread(action, false); err != nil {
			e.beginBarrier(t, t.stop, err)
		}
		return
	}
	for _, t := range e.sortedThreads() {
		action := e.run.actions[t.ref]
		if action == nil || action.started || t.state != target.StateStopped || t.exiting {
			continue
		}
		if t.hit == nil && t.suspended == nil {
			continue
		}
		bp, err := e.prepareBreakpointStep(t)
		if err != nil {
			e.beginBarrier(t, t.stop, err)
			return
		}
		if bp == nil {
			continue
		}
		e.run.overThread, e.run.over = t, bp
		if err := e.resumeThread(action, true); err != nil {
			e.run.overThread, e.run.over = nil, nil
			e.beginBarrier(t, t.stop, err)
		}
		return
	}
	for _, t := range e.sortedThreads() {
		action := e.run.actions[t.ref]
		if action == nil || action.started || !t.live() || t.exiting {
			continue
		}
		if err := e.resumeThread(action, action.step); err != nil {
			err = &target.PartialError{Op: "resume threads", Completed: e.run.resumeCount, Total: len(e.run.actions), Err: err}
			e.beginBarrier(t, t.stop, err)
			return
		}
	}
}

func (e *engine) resumeThread(action *resumeAction, step bool) error {
	t := action.thread
	if t.state != target.StateStopped || t.listening || t.exiting || t.process == nil || t.process.space == nil {
		return target.ErrInvalidState
	}
	space := t.process.space
	if space.stepping != nil && space.stepping != t {
		return fmt.Errorf("address space has an unfinished breakpoint step: %w", target.ErrBusy)
	}
	var commit func()
	var err error
	if action.cloneStep {
		if !step || action.signal != 0 || t.stop.Reason != target.StopClone {
			return target.ErrInvalidState
		}
		err = e.validateCloneStep(t)
		if err == nil && space.stepping != nil {
			err = e.validateAllStop()
		}
	} else {
		commit, err = e.prepareSyscallStep(t, action, step)
	}
	if err != nil {
		return err
	}
	if err := e.prepareWatchpointResume(t); err != nil {
		return err
	}
	listening := t.groupStopped && !step
	if listening {
		if !t.seized || action.signal != 0 {
			return target.ErrUnsupported
		}
		err = ptraceListen(t.tid)
	} else if step {
		err = ptraceStep(t.tid, action.signal)
	} else {
		err = unix.PtraceCont(t.tid, action.signal)
	}
	if err != nil {
		return err
	}
	if commit != nil {
		commit()
	}
	t.state, t.listening = target.StateRunning, listening
	t.pendingSignal = 0
	t.interruptRequested = false
	action.signal, action.started = 0, true
	action.cloneStep = false
	if e.run.overThread == t {
		e.run.overPaused = false
	}
	e.registersChanged(t)
	e.memoryChanged(space)
	if !action.resumed {
		action.resumed = true
		e.run.resumeCount++
	}
	e.updateState()
	e.emit(target.EventThreadResumed, t, e.run.handle.ID(), target.Stop{})
	return nil
}

func (e *engine) onThreadCreated(t *thread) {
	e.emit(target.EventThreadCreated, t, e.runID(), target.Stop{})
	if e.run == nil || e.life.initializing || e.life.shutdownKind != "" {
		return
	}
	if e.run.legacy {
		e.beginBarrier(nil, target.Stop{Reason: target.StopClone}, target.ErrAmbiguous)
		return
	}
	if t.process != nil && e.run.inherit[t.process.ref] {
		e.run.actions[t.ref] = &resumeAction{thread: t}
	}
	if e.barrier != nil {
		e.advanceBarrier()
		return
	}
	e.advanceRun()
}

func (e *engine) onThreadStop(t *thread, stop target.Stop) {
	first := t.stopEpoch == 0
	internalStep := t.internalStepTrap
	t.internalStepTrap = false
	t.state, t.listening = target.StateStopped, false
	t.interruptRequested = false
	entryComplete := false
	var entryError error
	if e.run != nil && e.run.entryThread == t && e.run.entry != nil && stop.Reason == target.StopBreakpoint && t.hit != nil && t.hit.bp == e.run.entry {
		e.run.entryHit = true
		stop.Reason, stop.Breakpoint, stop.StepCompleted = target.StopUnknown, nil, false
		if e.barrier == nil && !e.life.initializing && e.life.shutdownKind == "" {
			entryError = e.consumeExecBoundary(t, e.run.entry)
			if entryError == nil {
				t.needsUserBoundary = false
				e.run.entryThread, e.run.entry, e.run.entryHit = nil, nil, false
				entryComplete = true
			} else {
				e.unsupported = errors.Join(e.unsupported, entryError)
			}
		}
	}
	t.stopEpoch++
	e.registersChanged(t)
	t.stop = copyStop(stop)
	e.updateState()
	e.emit(target.EventThreadStopped, t, e.runID(), stop)
	if stop.Reason == target.StopExec {
		e.emit(target.EventProcessExec, t, e.runID(), stop)
	}
	if e.life.initializing || e.life.shutdownKind != "" {
		e.advanceBarrier()
		return
	}
	if entryError != nil {
		e.beginBarrier(t, stop, entryError)
		return
	}
	if entryComplete && e.run != nil {
		if action := e.run.actions[t.ref]; action != nil {
			action.started = false
			e.advanceRun()
			return
		}
	}
	if internalStep && stop.StepCompleted && stop.Reason == target.StopStep && len(stop.Watchpoints) == 0 {
		if e.barrier != nil {
			e.advanceBarrier()
			return
		}
		if e.run != nil {
			if action := e.run.actions[t.ref]; action != nil && !action.step {
				action.started = false
				e.advanceRun()
				return
			}
		}
	}
	if e.run != nil && e.run.overThread == t && stop.Reason == target.StopExec {
		e.run.overThread, e.run.over, e.run.overPaused = nil, nil, false
	}
	if e.run != nil && e.barrier == nil && e.unsupported == nil && stop.Reason == target.StopClone {
		action := e.run.actions[t.ref]
		if action != nil && (action.step || e.run.overThread == t) {
			action.started, action.cloneStep = false, true
			if e.run.overThread == t {
				e.run.overPaused = true
			}
			e.advanceRun()
			return
		}
	}
	if e.run != nil && e.run.overThread == t {
		completed := stop.StepCompleted
		err := e.finishBreakpointStep(t, e.run.over, completed)
		e.run.overThread, e.run.over = nil, nil
		if err != nil {
			e.unsupported = errors.Join(e.unsupported, err)
		}
		if !completed && (stop.Reason == target.StopClone || stop.Reason == target.StopFork || stop.Reason == target.StopVFork) {
			err = errors.Join(err, fmt.Errorf("task creation during breakpoint step: %w", target.ErrUnsupported))
		}
		if completed && stop.Reason == target.StopStep && len(stop.Watchpoints) == 0 && err == nil && e.barrier == nil && e.run.step != t.ref {
			if action := e.run.actions[t.ref]; action != nil {
				action.started = false
			}
			e.advanceRun()
			return
		}
		if e.barrier == nil {
			e.beginBarrier(t, stop, errors.Join(e.unsupported, err))
			return
		}
		e.barrier.err = errors.Join(e.barrier.err, err)
	}
	if e.barrier != nil {
		if e.barrier.thread == nil {
			e.barrier.thread = t
			if e.barrier.stop.Reason == target.StopUnknown || e.barrier.stop.Reason == target.StopInterrupt {
				e.barrier.stop = copyStop(stop)
			}
		}
		e.advanceBarrier()
		return
	}
	if e.unsupported != nil {
		e.beginBarrier(t, stop, e.unsupported)
		return
	}
	if e.run != nil && first && stop.Reason == target.StopInterrupt {
		e.advanceRun()
		return
	}
	if e.run != nil && (stop.Reason == target.StopClone || stop.Reason == target.StopFork || stop.Reason == target.StopVFork) {
		action := e.run.actions[t.ref]
		if action != nil && action.step {
			e.beginBarrier(t, stop, fmt.Errorf("task creation during instruction step: %w", target.ErrUnsupported))
			return
		}
		if action != nil {
			action.started = false
		}
		e.advanceRun()
		return
	}
	e.beginBarrier(t, stop, nil)
}

func (e *engine) onThreadExit(t *thread, stop target.Stop) {
	t.state, t.listening = target.StateExited, false
	t.exiting, t.exitComplete = false, true
	t.groupStopped, t.internalStepTrap = false, false
	t.hit = nil
	t.pendingSignal, t.interruptRequested = 0, false
	t.stopEpoch++
	e.registersChanged(t)
	t.stop = copyStop(stop)
	e.updateState()
	e.emit(target.EventThreadExited, t, e.runID(), stop)
	if e.barrier != nil && e.allExited() {
		e.barrier.thread, e.barrier.stop = t, copyStop(stop)
	}
	if e.life.initializing || e.life.shutdownKind != "" {
		e.advanceBarrier()
		return
	}
	if e.barrier != nil {
		e.advanceBarrier()
		return
	}
	if e.run == nil {
		if e.allExited() {
			e.publish(stop)
		}
		return
	}
	if e.run.overThread == t || e.run.step == t.ref || e.allExited() || !e.runHasLiveActions() {
		e.beginBarrier(t, stop, nil)
		return
	}
	e.advanceRun()
}

func (e *engine) runHasLiveActions() bool {
	if e.run == nil {
		return false
	}
	for _, action := range e.run.actions {
		if action.thread.live() && !action.thread.exiting {
			return true
		}
	}
	return false
}

func (e *engine) runID() uint64 {
	if e.run != nil {
		return e.run.handle.ID()
	}
	return 0
}

func (e *engine) beginBarrier(t *thread, stop target.Stop, err error) {
	if e.barrier == nil {
		e.barrier = &stopBarrier{thread: t, stop: copyStop(stop), err: err}
	} else {
		e.barrier.err = errors.Join(e.barrier.err, err)
	}
	if err := e.interruptAll(); err != nil {
		e.barrier.err = errors.Join(e.barrier.err, err)
		e.unsupported = errors.Join(e.unsupported, err)
		e.failRun(e.barrier.err)
	}
	e.updateState()
	e.advanceBarrier()
}

func (e *engine) advanceBarrier() {
	if e.barrier == nil || !e.allStopped() || e.life.initializing || e.life.awaitProcessExit || len(e.life.births) != 0 {
		return
	}
	barrier := e.barrier
	if (barrier.stop.Reason == target.StopExited || barrier.stop.Reason == target.StopSignaled) && !e.allExited() {
		live := false
		for _, t := range e.threads {
			live = live || t.live() && !t.exiting
		}
		if !live {
			return
		}
	}
	if err := e.validateAllStop(); err != nil {
		barrier.err = errors.Join(barrier.err, err)
		e.unsupported = errors.Join(e.unsupported, err)
		e.failRun(barrier.err)
		e.updateState()
		return
	}
	if err := e.cancelExecBoundaries(); err != nil {
		barrier.err = errors.Join(barrier.err, err)
		e.unsupported = errors.Join(e.unsupported, err)
		e.failRun(barrier.err)
		e.updateState()
		return
	}
	if e.run != nil {
		if e.run.entryThread != nil && e.run.entryHit {
			e.run.entryThread.needsUserBoundary = false
		}
		e.run.entryThread, e.run.entry, e.run.entryHit = nil, nil, false
	}
	e.completeBarrier()
}

func (e *engine) completeBarrier() {
	barrier := e.barrier
	if barrier == nil {
		return
	}
	for _, t := range e.threads {
		if t.suspended != nil && (!t.live() || t.exiting && t.exitComplete || t.process == nil || t.process.space != t.suspended.space) {
			if err := e.abandonBreakpointStep(t); err != nil {
				barrier.err = errors.Join(barrier.err, err)
				e.unsupported = errors.Join(e.unsupported, err)
			}
		}
	}
	op := e.run
	runID := e.runID()
	e.barrier, e.run = nil, nil
	e.updateState()
	seq := e.emit(target.EventAllStopped, barrier.thread, runID, barrier.stop)
	e.publish(barrier.stop)
	if op != nil {
		result := target.RunResult{Stop: copyStop(e.last), Sequence: seq}
		if barrier.thread != nil {
			result.Thread, result.Token = barrier.thread.ref, barrier.thread.token()
		}
		op.handle.complete(result, barrier.err)
	}
	e.updateState()
}

func (e *engine) interruptThread(t *thread) error {
	if e.life.missing[t.tid] != nil {
		return nil
	}
	if !t.live() || t.exiting || t.state == target.StateStopped || t.state == target.StateUnknown {
		return nil
	}
	if t.interruptRequested {
		return nil
	}
	if !t.seized {
		return fmt.Errorf("thread was not seized: %w", target.ErrUnsupported)
	}
	if err := unix.PtraceInterrupt(t.tid); err != nil {
		return err
	}
	t.interruptRequested = true
	return nil
}

func (e *engine) interruptAll() error {
	var errs []error
	for _, t := range e.sortedThreads() {
		if err := e.interruptThread(t); err != nil {
			errs = append(errs, fmt.Errorf("interrupt TID %d: %w", t.tid, err))
		}
	}
	return errors.Join(errs...)
}

func (e *engine) interrupt(set target.ThreadSet) error {
	if err := e.lifecycleError(); err != nil {
		return err
	}
	threads, err := e.resolveThreads(set)
	if err != nil {
		return err
	}
	active := false
	for _, t := range threads {
		if t.live() && !t.exiting && t.state == target.StateRunning {
			active = true
			if err := e.interruptThread(t); err != nil {
				return err
			}
		}
	}
	if active {
		e.beginBarrier(nil, target.Stop{Reason: target.StopInterrupt}, nil)
	}
	return nil
}

func (e *engine) interruptLegacy() error {
	if err := e.lifecycleError(); err != nil {
		return err
	}
	var selected *thread
	for _, t := range e.threads {
		if !t.live() || t.exiting {
			continue
		}
		if t.state == target.StateUnknown || t.process == nil {
			return target.ErrBusy
		}
		if selected != nil {
			return target.ErrAmbiguous
		}
		selected = t
	}
	if selected == nil {
		return target.ErrExited
	}
	return e.interrupt(target.ThreadSet{Threads: []target.ThreadRef{selected.ref}})
}

func (e *engine) failRun(err error) {
	if e.run == nil {
		return
	}
	result := target.RunResult{Stop: copyStop(e.last), Sequence: e.sequence}
	if e.barrier != nil {
		result.Stop = copyStop(e.barrier.stop)
		if e.barrier.thread != nil {
			result.Thread = e.barrier.thread.ref
		}
	}
	op := e.run
	e.run = nil
	e.updateState()
	op.handle.complete(result, err)
}
