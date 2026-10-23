package native

import (
	"context"
	"errors"
	"testing"
	"time"

	"fastdbg2/native/amd64"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func controlModel(threads int) (*engine, []*thread) {
	s := &Session{id: 901, done: make(chan struct{})}
	e := &engine{s: s}
	p := e.newProcess(41001, -1, false)
	profile := amd64.Descriptor()
	p.profile = &profile
	e.primary = p
	var result []*thread
	for i := 0; i < threads; i++ {
		thread := e.newThread(p, 41001+i, true)
		thread.state, thread.stopEpoch = target.StateStopped, 1
		result = append(result, thread)
	}
	e.updateState()
	return e, result
}

func TestModelThreadIdentitySurvivesTIDReuse(t *testing.T) {
	e, threads := controlModel(1)
	old := threads[0]
	old.state = target.StateExited
	next := e.newThread(e.primary, old.tid, true)
	if next.ref == old.ref || next.ref.Session != old.ref.Session || next.ref.ID <= old.ref.ID {
		t.Fatalf("old=%+v next=%+v", old.ref, next.ref)
	}
	if _, err := e.findThread(old.ref); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old ref: %v", err)
	}
	foreign := next.ref
	foreign.Session++
	if _, err := e.findThread(foreign); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign ref: %v", err)
	}
}

func TestModelThreadTokenInvalidatedByRegisterMutation(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	token := thread.token()
	if got, err := e.requireThread(token); err != nil || got != thread {
		t.Fatalf("initial thread=%p error=%v", got, err)
	}
	e.registersChanged(thread)
	if _, err := e.requireThread(token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old register revision: %v", err)
	}
	if _, err := e.requireThread(thread.token()); err != nil {
		t.Fatal(err)
	}
	thread.state = target.StateRunning
	if _, err := e.requireThread(thread.token()); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("running token: %v", err)
	}
}

func TestModelMemoryUsesSurvivingStoppedThread(t *testing.T) {
	e, threads := controlModel(2)
	threads[0].state = target.StateExited
	space := e.primary.space
	token := target.MemoryToken{Space: space.ref, Revision: space.revision}
	gotSpace, carrier, err := e.requireMemory(token)
	if err != nil || gotSpace != space || carrier != threads[1] {
		t.Fatalf("space=%p carrier=%p error=%v", gotSpace, carrier, err)
	}
	e.memoryChanged(space)
	if _, _, err := e.requireMemory(token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old memory revision: %v", err)
	}
	token.Revision = space.revision
	threads[1].state = target.StateRunning
	if _, _, err := e.requireMemory(token); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("running peer: %v", err)
	}
}

func TestModelRunningSnapshotDoesNotIssueMemoryToken(t *testing.T) {
	e, threads := controlModel(1)
	threads[0].state = target.StateRunning
	token := e.snapshot().Memory
	if token.Space != e.primary.space.ref || token.Revision != 0 {
		t.Fatalf("running memory token=%+v", token)
	}
	threads[0].state = target.StateStopped
	if _, _, err := e.requireMemory(token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("running token became valid after stop: %v", err)
	}
}

func TestModelExitStopIsNotCompletedExit(t *testing.T) {
	e, threads := controlModel(2)
	thread := threads[1]
	thread.state, thread.exiting = target.StateRunning, true
	if e.allStopped() || e.spaceStopped(e.primary.space) {
		t.Fatal("uncompleted exit was considered quiescent")
	}
	thread.exitComplete = true
	if !e.allStopped() || !e.spaceStopped(e.primary.space) {
		t.Fatal("confirmed completed exit blocked the stopped survivor")
	}
	if _, err := e.requireThread(thread.token()); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("completed exit is not a register window: %v", err)
	}
	threads[0].listening = true
	if e.allStopped() || e.spaceStopped(e.primary.space) {
		t.Fatal("listening tracee was considered inspectable")
	}
}

func TestModelUnresolvedThreadBlocksMemoryAndAllStop(t *testing.T) {
	e, _ := controlModel(1)
	unresolved := e.newThread(nil, 42001, true)
	if e.allStopped() || e.spaceStopped(e.primary.space) {
		t.Fatal("unresolved tracee was ignored")
	}
	if err := e.requireAllStopped(); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("unresolved state: %v", err)
	}
	unresolved.state = target.StateStopped
	if err := e.requireAllStopped(); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("unresolved membership: %v", err)
	}
}

func TestModelUnresolvedOwnershipBlocksInspection(t *testing.T) {
	for _, tc := range []struct {
		name string
		mark func(*engine, *thread)
		want error
	}{
		{"birth", func(e *engine, th *thread) { e.life.births = map[int]*birth{th.tid + 1: {}} }, target.ErrBusy},
		{"missing", func(e *engine, th *thread) { e.life.missing = map[int]*thread{th.tid: th} }, target.ErrBusy},
		{"lost", func(e *engine, th *thread) { e.life.lost = map[int]error{th.tid: target.ErrUnavailable} }, target.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, threads := controlModel(1)
			thread := threads[0]
			memory := e.snapshot().Memory
			tc.mark(e, thread)
			e.updateState()
			if _, err := e.requireThread(thread.token()); !errors.Is(err, tc.want) {
				t.Fatalf("thread read: %v", err)
			}
			if _, _, err := e.requireMemory(memory); !errors.Is(err, tc.want) {
				t.Fatalf("memory read: %v", err)
			}
			if err := e.requireAllStopped(); !errors.Is(err, tc.want) {
				t.Fatalf("all-stop operation: %v", err)
			}
			if e.allStopped() || e.spaceStopped(e.primary.space) || e.s.State() == target.StateStopped || e.snapshot().Memory.Revision != 0 {
				t.Fatal("unresolved ownership was published as a frozen snapshot")
			}
			thread.state = target.StateExited
			if e.allExited() {
				t.Fatal("unresolved ownership was published as process exit")
			}
		})
	}
}

func TestModelSnapshotCopiesStopValues(t *testing.T) {
	e, threads := controlModel(1)
	pc := target.Address(0x400010)
	tid := uint64(threads[0].tid)
	threads[0].stop = target.Stop{Reason: target.StopBreakpoint, ThreadID: &tid, RawPC: &pc}
	snapshot := e.snapshot()
	*snapshot.Threads[0].Stop.RawPC = 1
	*snapshot.Threads[0].Stop.ThreadID = 1
	if *threads[0].stop.RawPC != pc || *threads[0].stop.ThreadID != tid {
		t.Fatal("snapshot stop aliases owner state")
	}
	if snapshot.Architecture != target.AMD64 || snapshot.Process != e.primary.ref || snapshot.Memory.Space != e.primary.space.ref {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestModelAddressSpaceFaultInvalidatesAggregateState(t *testing.T) {
	e, _ := controlModel(1)
	e.primary.space.fault = target.ErrUnsupported
	e.updateState()
	snapshot := e.snapshot()
	if e.s.State() != target.StateUnknown || snapshot.State != target.StateUnknown || snapshot.Memory.Revision != 0 {
		t.Fatalf("public=%v snapshot=%+v", e.s.State(), snapshot)
	}
}

func TestModelProcessExitWaitIsNotTerminalState(t *testing.T) {
	e, threads := controlModel(1)
	threads[0].state = target.StateExited
	e.life.awaitProcessExit = true
	e.updateState()
	if e.s.State() != target.StateRunning || e.snapshot().State != target.StateRunning {
		t.Fatalf("process handle pending: state=%v snapshot=%+v", e.s.State(), e.snapshot())
	}
	e.life.awaitProcessExit = false
	e.updateState()
	if e.s.State() != target.StateExited {
		t.Fatalf("terminal process handle: %v", e.s.State())
	}
}

func TestControlResumeValidationDoesNotDiscardPendingSignal(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*thread) []target.ThreadSignal
		want error
	}{
		{"omitted", func(*thread) []target.ThreadSignal { return nil }, target.ErrInvalidArgument},
		{"zero-epoch", func(th *thread) []target.ThreadSignal {
			return []target.ThreadSignal{{Thread: th.ref}}
		}, target.ErrStale},
		{"old-epoch", func(th *thread) []target.ThreadSignal {
			return []target.ThreadSignal{{Thread: th.ref, Stop: th.stopEpoch + 1}}
		}, target.ErrStale},
		{"wrong-domain", func(th *thread) []target.ThreadSignal {
			return []target.ThreadSignal{{Thread: th.ref, Stop: th.stopEpoch, Signal: target.Signal{Domain: target.SignalGDB, Number: 10}}}
		}, target.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, threads := controlModel(1)
			thread := threads[0]
			thread.pendingSignal = int(unix.SIGUSR1)
			_, err := e.startRun(target.RunRequest{Threads: target.ThreadSet{Threads: []target.ThreadRef{thread.ref}}, Signals: tc.edit(thread)})
			if !errors.Is(err, tc.want) || thread.pendingSignal != int(unix.SIGUSR1) || e.run != nil || thread.state != target.StateStopped {
				t.Fatalf("error=%v pending=%d run=%+v state=%v", err, thread.pendingSignal, e.run, thread.state)
			}
		})
	}
}

func TestControlRejectsResumeWithoutBreakpointStepOwner(t *testing.T) {
	e, threads := controlModel(2)
	space := e.primary.space
	space.stepping = threads[0]
	threads[0].suspended = &breakpoint{space: space}
	_, err := e.startRun(target.RunRequest{Threads: target.ThreadSet{Threads: []target.ThreadRef{threads[1].ref}}})
	if !errors.Is(err, target.ErrInvalidState) || e.run != nil || threads[1].state != target.StateStopped {
		t.Fatalf("error=%v run=%+v peer=%v", err, e.run, threads[1].state)
	}
}

func TestControlRejectsGroupStoppedInstructionStep(t *testing.T) {
	e, threads := controlModel(1)
	threads[0].groupStopped = true
	_, err := e.startStep(target.StepRequest{Thread: threads[0].ref})
	if !errors.Is(err, target.ErrUnsupported) || e.run != nil {
		t.Fatalf("error=%v run=%+v", err, e.run)
	}
}

func TestControlLegacyRejectsAmbiguousThread(t *testing.T) {
	e, _ := controlModel(2)
	if _, err := e.startLegacyRun(false, target.Signal{}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("legacy run: %v", err)
	}
	if err := e.interruptLegacy(); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("legacy interrupt: %v", err)
	}
}

func TestControlSteppingClassificationIsThreadLocal(t *testing.T) {
	e, threads := controlModel(2)
	e.run = &runOperation{handle: newRun(1), actions: map[target.ThreadRef]*resumeAction{
		threads[0].ref: {thread: threads[0], step: true, started: true, mode: resumeStep},
		threads[1].ref: {thread: threads[1], started: true},
	}}
	if !e.threadStepping(threads[0]) || e.threadStepping(threads[1]) {
		t.Fatal("step expectation leaked between threads")
	}
	e.run.overThread = threads[1]
	e.run.actions[threads[1].ref].mode = resumeStep
	if !e.threadStepping(threads[1]) {
		t.Fatal("hidden step was not recognized")
	}
}

func TestControlCloneStopKeepsInstructionStepPending(t *testing.T) {
	e, threads := controlModel(2)
	parent, child := threads[0], threads[1]
	parent.state, child.state = target.StateRunning, target.StateUnknown
	e.life.births = map[int]*birth{child.tid: {}}
	action := &resumeAction{thread: parent, step: true, started: true, resumed: true}
	e.run = &runOperation{handle: newRun(1), step: parent.ref, actions: map[target.ThreadRef]*resumeAction{parent.ref: action}}
	e.onThreadStop(parent, target.Stop{Reason: target.StopClone})
	if e.run == nil || e.barrier != nil || action.started || !action.cloneStep || child.state != target.StateUnknown {
		t.Fatalf("run=%+v barrier=%+v action=%+v child=%v", e.run, e.barrier, action, child.state)
	}
	select {
	case <-e.run.handle.done:
		t.Fatal("clone event completed the original instruction step")
	default:
	}
}

func TestControlCloneStopKeepsBreakpointStepExclusive(t *testing.T) {
	e, threads := controlModel(2)
	parent, child := threads[0], threads[1]
	parent.state, child.state = target.StateRunning, target.StateUnknown
	e.life.births = map[int]*birth{child.tid: {}}
	space := e.primary.space
	bp := &breakpoint{addr: 0x400100, original: 0x0f, space: space, spaceRef: space.ref, generation: 1}
	space.breakpoints[bp.addr] = bp
	space.stepping, parent.suspended = parent, bp
	action := &resumeAction{thread: parent, started: true, resumed: true}
	e.run = &runOperation{handle: newRun(1), overThread: parent, over: bp, actions: map[target.ThreadRef]*resumeAction{parent.ref: action}}
	e.onThreadStop(parent, target.Stop{Reason: target.StopClone})
	if e.run == nil || !e.run.overPaused || e.run.overThread != parent || e.run.over != bp || bp.armed || parent.suspended != bp || space.stepping != parent || !action.cloneStep {
		t.Fatalf("run=%+v bp=%+v action=%+v", e.run, bp, action)
	}
	if e.barrier != nil || child.state != target.StateUnknown {
		t.Fatal("clone stop released the inline-step exclusion")
	}
}

func TestControlForkAndVForkDuringStepRemainUnsupported(t *testing.T) {
	for _, reason := range []target.StopReason{target.StopFork, target.StopVFork} {
		t.Run(reason.String(), func(t *testing.T) {
			e, threads := controlModel(2)
			parent, child := threads[0], threads[1]
			parent.state, child.state = target.StateRunning, target.StateUnknown
			e.life.births = map[int]*birth{child.tid: {}}
			action := &resumeAction{thread: parent, step: true, started: true}
			e.run = &runOperation{handle: newRun(1), step: parent.ref, actions: map[target.ThreadRef]*resumeAction{parent.ref: action}}
			e.onThreadStop(parent, target.Stop{Reason: reason})
			if e.barrier == nil || !errors.Is(e.barrier.err, target.ErrUnsupported) || action.cloneStep {
				t.Fatalf("barrier=%+v action=%+v", e.barrier, action)
			}
		})
	}
}

func TestControlNewStepDoesNotReplaceInterruptedCloneProof(t *testing.T) {
	e, threads := controlModel(2)
	parent, child := threads[0], threads[1]
	parent.stop.Reason = target.StopClone
	expected := syscallStep{space: e.primary.space.ref, pc: 0x400102, number: 56}
	e.life.syscallSteps = map[*thread]syscallStep{parent: expected}
	e.life.cloneChildren = map[*thread]*thread{parent: child}
	_, err := e.startStep(target.StepRequest{Thread: parent.ref})
	if !errors.Is(err, target.ErrUnsupported) || e.run != nil || e.life.syscallSteps[parent] != expected || e.life.cloneChildren[parent] != child {
		t.Fatalf("error=%v run=%+v proof=%+v child=%p", err, e.run, e.life.syscallSteps[parent], e.life.cloneChildren[parent])
	}
}

func TestControlBarrierRetainsEachThreadStop(t *testing.T) {
	e, threads := controlModel(2)
	first, second := threads[0], threads[1]
	first.state, second.state = target.StateUnknown, target.StateUnknown
	handle := newRun(1)
	e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{}}
	firstStop := target.Stop{Reason: target.StopBreakpoint}
	e.onThreadStop(first, firstStop)
	if e.barrier == nil || e.s.State() != target.StateRunning {
		t.Fatal("barrier completed before the second thread stopped")
	}
	second.pendingSignal = int(unix.SIGUSR1)
	secondStop := target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}}
	e.life.births = map[int]*birth{42001: {}}
	e.onThreadStop(second, secondStop)
	delete(e.life.births, 42001)
	e.completeBarrier()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := handle.Wait(ctx)
	if err != nil || result.Thread != first.ref || result.Stop.Reason != target.StopBreakpoint {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if second.stop.Reason != target.StopSignal || second.pendingSignal != int(unix.SIGUSR1) {
		t.Fatal("the second thread's signal stop was discarded")
	}
	if e.barrier != nil || e.run != nil || e.s.State() != target.StateStopped || result.Sequence != e.sequence || result.Sequence != e.last.Generation {
		t.Fatalf("barrier=%+v run=%+v state=%v result=%+v last=%+v", e.barrier, e.run, e.s.State(), result, e.last)
	}
}

func TestControlPendingBirthPreventsRunAndBarrierPublication(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	handle := newRun(1)
	e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{thread.ref: {thread: thread}}}
	e.life.births = map[int]*birth{42001: {}}
	e.advanceRun()
	if thread.state != target.StateStopped || e.sequence != 0 {
		t.Fatal("pending birth was resumed before decoding")
	}
	e.beginBarrier(thread, target.Stop{Reason: target.StopInterrupt}, nil)
	if e.barrier == nil || e.sequence != 0 {
		t.Fatal("pending birth was ignored by the barrier")
	}
	delete(e.life.births, 42001)
	e.completeBarrier()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := handle.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestControlOrdinaryThreadExitDoesNotCompletePeerRun(t *testing.T) {
	e, threads := controlModel(2)
	first, second := threads[0], threads[1]
	first.state, second.state = target.StateRunning, target.StateRunning
	e.run = &runOperation{handle: newRun(1), actions: map[target.ThreadRef]*resumeAction{
		first.ref:  {thread: first, started: true},
		second.ref: {thread: second, started: true},
	}}
	e.onThreadExit(first, target.Stop{Reason: target.StopExited})
	if e.run == nil || e.barrier != nil || second.state != target.StateRunning {
		t.Fatalf("run=%+v barrier=%+v peer=%v", e.run, e.barrier, second.state)
	}
}

func TestControlProcessExitWaitsForLeaderTerminalStatus(t *testing.T) {
	e, threads := controlModel(2)
	leader, peer := threads[0], threads[1]
	leader.state, leader.exiting, leader.exitComplete = target.StateRunning, true, true
	peer.state = target.StateRunning
	handle := newRun(1)
	e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{
		peer.ref: {thread: peer, started: true},
	}}
	e.onThreadExit(peer, target.Stop{Reason: target.StopExited})
	if e.barrier == nil || e.run == nil {
		t.Fatal("process exit published before leader terminal status")
	}
	e.onThreadExit(leader, target.Stop{Reason: target.StopExited})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result, err := handle.Wait(ctx); err != nil || result.Stop.Reason != target.StopExited || e.s.State() != target.StateExited {
		t.Fatalf("result=%+v error=%v state=%v", result, err, e.s.State())
	}
}

func TestControlWatchpointFaultPreventsPartialResume(t *testing.T) {
	e, threads := controlModel(2)
	fault := errors.New("debug-register rollback was not confirmed")
	threads[1].watchpoints = &watchpointState{fault: fault}
	_, err := e.startRun(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: e.primary.ref}})
	if !errors.Is(err, fault) || e.run != nil || e.sequence != 0 {
		t.Fatalf("error=%v run=%+v sequence=%d", err, e.run, e.sequence)
	}
	for _, thread := range threads {
		if thread.state != target.StateStopped {
			t.Fatalf("thread was resumed before watchpoint preflight: %+v", thread)
		}
	}
}

func TestModelWatchpointFaultDoesNotInvalidateMemory(t *testing.T) {
	e, threads := controlModel(2)
	memory := e.snapshot().Memory
	threads[1].watchpoints = &watchpointState{fault: target.ErrPartial}
	if _, _, err := e.requireMemory(memory); err != nil {
		t.Fatalf("hardware-only fault invalidated stopped memory: %v", err)
	}
	if e.snapshot().Memory != memory || e.actualState() != target.StateStopped {
		t.Fatalf("hardware-only fault changed memory or stop state: %+v", e.snapshot())
	}
	if _, err := e.requireThread(threads[1].token()); err != nil {
		t.Fatalf("hardware-only fault blocked register inspection: %v", err)
	}
}

func TestControlExtendedRegisterFaultPreventsPartialResume(t *testing.T) {
	e, threads := controlModel(2)
	fault := errors.New("extended register write was not confirmed")
	threads[1].extendedFault = fault
	memory := e.snapshot().Memory
	_, err := e.startRun(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: e.primary.ref}})
	if !errors.Is(err, fault) || e.run != nil || e.sequence != 0 {
		t.Fatalf("error=%v run=%+v sequence=%d", err, e.run, e.sequence)
	}
	for _, thread := range threads {
		if thread.state != target.StateStopped {
			t.Fatalf("thread resumed before extended register preflight: %+v", thread)
		}
		if _, err := e.requireThread(thread.token()); err != nil {
			t.Fatalf("extended fault blocked stopped register inspection: %v", err)
		}
	}
	if _, _, err := e.requireMemory(memory); err != nil {
		t.Fatalf("extended fault invalidated memory: %v", err)
	}
	if err := e.resumeThread(&resumeAction{thread: threads[1]}, false); !errors.Is(err, fault) {
		t.Fatalf("resume bypassed extended register fault: %v", err)
	}
}

func TestModelWatchpointOwnershipIsNotCopiedToNewborn(t *testing.T) {
	e, threads := controlModel(1)
	parent := threads[0]
	parent.watchpoints = &watchpointState{fault: target.ErrPartial}
	child := e.newThread(parent.process, parent.tid+1, true)
	if child.watchpoints != nil || child.ref == parent.ref {
		t.Fatalf("newborn inherited debugger watchpoint ownership: %+v", child)
	}
}

func TestControlStepWatchpointHitIsNeverConsumedInternally(t *testing.T) {
	for _, internal := range []bool{false, true} {
		t.Run(map[bool]string{false: "requested-step", true: "internal-step"}[internal], func(t *testing.T) {
			e, threads := controlModel(1)
			thread := threads[0]
			thread.state, thread.internalStepTrap = target.StateRunning, internal
			e.life.births = map[int]*birth{42001: {}}
			handle := newRun(1)
			action := &resumeAction{thread: thread, step: !internal, started: true}
			e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{thread.ref: action}}
			if !internal {
				e.run.step = thread.ref
			}
			dr6 := uint64(1 | 1<<14)
			hit := target.WatchpointHit{
				Ref:     target.WatchpointRef{Thread: thread.ref, Slot: 0, Generation: 1},
				Address: 0x404000, Size: 4, Access: target.WatchWrite,
			}
			stop := target.Stop{Reason: target.StopWatchpoint, Watchpoints: []target.WatchpointHit{hit}, StepCompleted: true, RawDR6: &dr6}
			e.onThreadStop(thread, stop)
			if e.barrier == nil || e.barrier.stop.Reason != target.StopWatchpoint || !action.started {
				t.Fatalf("watchpoint hit was consumed: barrier=%+v action=%+v", e.barrier, action)
			}
			stop.Watchpoints[0].Address = 1
			*stop.RawDR6 = 0
			delete(e.life.births, 42001)
			e.completeBarrier()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := handle.Wait(ctx)
			if err != nil || result.Stop.Reason != target.StopWatchpoint || !result.Stop.StepCompleted || len(result.Stop.Watchpoints) != 1 || result.Stop.Watchpoints[0] != hit || result.Stop.RawDR6 == nil || *result.Stop.RawDR6 != 1|1<<14 {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
}

func TestControlWatchpointPendingPreventsResume(t *testing.T) {
	e, threads := controlModel(1)
	threads[0].watchpoints = &watchpointState{pending: &debugTransaction{}}
	_, err := e.startRun(target.RunRequest{Threads: target.ThreadSet{Threads: []target.ThreadRef{threads[0].ref}}})
	if !errors.Is(err, target.ErrBusy) || e.run != nil || threads[0].state != target.StateStopped {
		t.Fatalf("error=%v run=%+v thread=%+v", err, e.run, threads[0])
	}
}

func TestControlHardwareBreakpointIsNeverConsumedInternally(t *testing.T) {
	for _, reason := range []target.StopReason{target.StopHardwareBreakpoint, target.StopStep} {
		e, threads := controlModel(1)
		thread := threads[0]
		thread.state, thread.internalStepTrap = target.StateRunning, true
		e.life.births = map[int]*birth{42001: {}}
		handle := newRun(1)
		action := &resumeAction{thread: thread, started: true}
		e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{thread.ref: action}}
		hit := target.HardwareBreakpointHit{
			Ref: target.HardwareBreakpointRef{Thread: thread.ref, Slot: 0, Generation: 1}, Address: 0x401000,
		}
		stop := target.Stop{Reason: reason, StepCompleted: reason == target.StopStep, HardwareBreakpoints: []target.HardwareBreakpointHit{hit}}
		e.onThreadStop(thread, stop)
		if e.barrier == nil || !action.started || len(e.barrier.stop.HardwareBreakpoints) != 1 {
			t.Fatalf("hardware execution fault was consumed: barrier=%+v action=%+v", e.barrier, action)
		}
		stop.HardwareBreakpoints[0].Address = 1
		delete(e.life.births, 42001)
		e.completeBarrier()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result, err := handle.Wait(ctx)
		cancel()
		if err != nil || len(result.Stop.HardwareBreakpoints) != 1 || result.Stop.HardwareBreakpoints[0] != hit {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	}
}

func TestControlBreakpointSyscallIsNotSingleStepping(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	e.run = &runOperation{handle: newRun(1), step: thread.ref, overThread: thread, actions: map[target.ThreadRef]*resumeAction{
		thread.ref: {thread: thread, step: true, mode: resumeSyscall, started: true},
	}}
	if e.threadStepping(thread) {
		t.Fatal("typed syscall tracing was treated as hardware single-step")
	}
	e.run.overThread = nil
	if e.threadStepping(thread) {
		t.Fatal("typed syscall exit obligation was treated as hardware single-step")
	}
}

func TestControlRestartedSyscallRejectsNewStep(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	pending := &breakpointSyscall{space: thread.process.space.ref, phase: syscallExit, needExit: true, restart: true}
	thread.syscall = pending
	_, err := e.startStep(target.StepRequest{Thread: thread.ref})
	if !errors.Is(err, target.ErrUnsupported) || e.run != nil || e.sequence != 0 || thread.syscall != pending || thread.state != target.StateStopped {
		t.Fatalf("error=%v run=%+v thread=%+v", err, e.run, thread)
	}
}

func TestControlTypedSyscallExitFacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		restart   bool
		interrupt bool
		reason    target.StopReason
		err       error
	}{
		{"completed", false, false, target.StopStep, nil},
		{"interrupt", true, true, target.StopInterrupt, nil},
		{"restart", true, false, target.StopUnknown, target.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, threads := controlModel(1)
			thread := threads[0]
			thread.state, thread.interruptRequested = target.StateRunning, tc.interrupt
			pending := &breakpointSyscall{space: thread.process.space.ref, phase: syscallExit, needExit: true, restart: tc.restart}
			thread.syscall = pending
			e.life.births = map[int]*birth{42001: {}}
			handle := newRun(1)
			e.run = &runOperation{handle: handle, step: thread.ref, actions: map[target.ThreadRef]*resumeAction{
				thread.ref: {thread: thread, step: true, mode: resumeSyscall, started: true},
			}}
			e.onThreadStop(thread, target.Stop{Reason: target.StopUnknown})
			if e.barrier == nil || e.barrier.stop.Reason != tc.reason || e.barrier.stop.StepCompleted == tc.restart || !thread.needsUserBoundary {
				t.Fatalf("barrier=%+v thread=%+v", e.barrier, thread)
			}
			if tc.restart && thread.syscall != pending || !tc.restart && thread.syscall != nil {
				t.Fatalf("syscall obligation=%+v restart=%v", thread.syscall, tc.restart)
			}
			delete(e.life.births, 42001)
			e.completeBarrier()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			result, err := handle.Wait(ctx)
			cancel()
			if !errors.Is(err, tc.err) || result.Stop.Reason != tc.reason || result.Stop.StepCompleted == tc.restart || result.Stop.RawDR6 != nil {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
}

func TestControlBreakpointSyscallEntryHoldsPeers(t *testing.T) {
	e, threads := controlModel(2)
	owner, peer := threads[0], threads[1]
	owner.state = target.StateRunning
	owner.syscall = &breakpointSyscall{phase: syscallEntering, space: owner.process.space.ref}
	e.run = &runOperation{handle: newRun(1), overThread: owner, actions: map[target.ThreadRef]*resumeAction{
		owner.ref: {thread: owner, mode: resumeSyscall, started: true},
		peer.ref:  {thread: peer},
	}}
	e.advanceRun()
	if peer.state != target.StateStopped || e.run.actions[peer.ref].started || e.sequence != 0 {
		t.Fatalf("peer resumed before syscall entry: peer=%+v run=%+v", peer, e.run)
	}
}

func TestControlDeferredInterruptRetainsCommittedModeAndProof(t *testing.T) {
	for _, mode := range []resumeMode{resumeContinue, resumeStep, resumeSyscall} {
		e, threads := controlModel(1)
		th := threads[0]
		th.state = target.StateRunning
		th.interruptDeferred, th.interruptResumed = true, true
		proof := syscallStep{space: th.process.space.ref, pc: 0x401002, number: 56}
		e.life.syscallSteps = map[*thread]syscallStep{th: proof}
		e.life.cloneChildren = map[*thread]*thread{th: {}}
		var pending *breakpointSyscall
		if mode == resumeSyscall {
			pending = &breakpointSyscall{space: th.process.space.ref, phase: syscallExecuting, needExit: true}
			th.syscall = pending
		}
		action := &resumeAction{thread: th, step: mode != resumeContinue, mode: mode, started: true}
		handle := newRun(1)
		e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{th.ref: action}}
		raw := "wait_status=0x80057f"
		e.onThreadStop(th, target.Stop{Reason: target.StopInterrupt, Raw: raw})
		if action.mode != mode || !errors.Is(action.resumeFailure, unix.ESRCH) || th.state != target.StateUnknown || e.barrier != nil {
			t.Fatalf("mode=%d action=%+v thread=%+v barrier=%+v", mode, action, th, e.barrier)
		}
		if e.life.syscallSteps[th] != proof || e.life.cloneChildren[th] == nil || th.syscall != pending || th.interruptDeferred || th.interruptResumed {
			t.Fatalf("deferred notification changed instruction proof: %+v", th)
		}
		if stop := e.snapshot().Threads[0].Stop; stop.Reason != target.StopUnknown || stop.StepCompleted || stop.Raw != raw {
			t.Fatalf("snapshot published an unsolicited interrupt: %+v", stop)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		event, err := e.s.NextEvent(ctx, 0)
		cancel()
		if err != nil || event.Kind != target.EventThreadStopped || event.Stop.Reason != target.StopUnknown || event.Stop.StepCompleted || event.Stop.Raw != raw {
			t.Fatalf("journal published an unsolicited interrupt: %+v error=%v", event, err)
		}
	}
}

func TestControlDeferredInterruptDoesNotConsumeAnotherStop(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reason    target.StopReason
		resumed   bool
		requested bool
	}{
		{"natural-breakpoint", target.StopBreakpoint, true, false},
		{"signal", target.StopSignal, true, false},
		{"group-stop", target.StopGroupStop, true, false},
		{"new-interrupt", target.StopInterrupt, true, true},
		{"new-request-natural", target.StopBreakpoint, true, true},
		{"no-resume", target.StopInterrupt, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, threads := controlModel(1)
			thread := threads[0]
			thread.state = target.StateRunning
			thread.interruptDeferred, thread.interruptResumed, thread.interruptRequested = true, tc.resumed, tc.requested
			action := &resumeAction{thread: thread, mode: resumeContinue, started: true}
			e.run = &runOperation{handle: newRun(1), actions: map[target.ThreadRef]*resumeAction{thread.ref: action}}
			e.onThreadStop(thread, target.Stop{Reason: tc.reason})
			if e.barrier == nil || e.barrier.stop.Reason != tc.reason || thread.stop.Reason != tc.reason || action.retry || !action.started || thread.interruptDeferred != tc.requested || thread.interruptResumed {
				t.Fatalf("barrier=%+v thread=%+v action=%+v", e.barrier, thread, action)
			}
		})
	}
}

func TestControlResumeESRCHWaitsForAuthoritativeExit(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	memory, token := e.snapshot().Memory, thread.token()
	handle := newRun(1)
	action := &resumeAction{thread: thread}
	e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{thread.ref: action}}
	e.resumeFailed(action, &ptraceResumeError{err: unix.ESRCH})
	if thread.state != target.StateUnknown || thread.exiting || thread.exitComplete || e.barrier != nil || action.started || action.mode != resumeNone || action.resumed || e.run.resumeCount != 0 {
		t.Fatalf("resume failure was committed as success or exit: thread=%+v action=%+v run=%+v", thread, action, e.run)
	}
	if e.snapshot().Memory.Revision != 0 || thread.token() == token || thread.process.space.revision == memory.Revision {
		t.Fatal("unknown resume outcome retained inspection tokens")
	}
	select {
	case <-handle.done:
		t.Fatal("ESRCH alone completed the run")
	default:
	}
	code := 0
	e.onThreadExit(thread, target.Stop{Reason: target.StopExited, ExitCode: &code})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := handle.Wait(ctx)
	if err != nil || result.Stop.Reason != target.StopExited || result.Stop.ExitCode == nil || *result.Stop.ExitCode != 0 || e.s.State() != target.StateExited {
		t.Fatalf("authoritative exit retained a provisional resume error: %+v error=%v", result, err)
	}
}

func TestControlResumeESRCHIsNotInferredFromBackendFailure(t *testing.T) {
	for _, actual := range []bool{false, true} {
		e, threads := controlModel(1)
		thread := threads[0]
		e.life.births = map[int]*birth{42001: {}}
		handle := newRun(1)
		action := &resumeAction{thread: thread}
		e.run = &runOperation{handle: handle, actions: map[target.ThreadRef]*resumeAction{thread.ref: action}}
		err := error(unix.ESRCH)
		if actual {
			err = &ptraceResumeError{err: err}
		}
		e.resumeFailed(action, err)
		if actual {
			e.onThreadStop(thread, target.Stop{Reason: target.StopSignal})
		}
		if e.barrier == nil || !errors.Is(e.barrier.err, target.ErrPartial) || !errors.Is(e.barrier.err, unix.ESRCH) || thread.state != target.StateStopped || thread.exiting || thread.exitComplete {
			t.Fatalf("unconfirmed failure was hidden: actual=%t barrier=%+v thread=%+v", actual, e.barrier, thread)
		}
		delete(e.life.births, 42001)
		e.completeBarrier()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result, err := handle.Wait(ctx)
		cancel()
		if !errors.Is(err, target.ErrPartial) || result.Stop.Reason == target.StopExited || result.Stop.Reason == target.StopSignaled {
			t.Fatalf("nonterminal failure became terminal success: %+v error=%v", result, err)
		}
	}
}

func TestControlUserBoundaryIsNotSingleStepping(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	e.run = &runOperation{handle: newRun(1), step: thread.ref, entryThread: thread, actions: map[target.ThreadRef]*resumeAction{
		thread.ref: {thread: thread, step: true, started: true},
	}}
	if e.threadStepping(thread) {
		t.Fatal("temporary boundary continue was treated as instruction stepping")
	}
	e.run.entryThread = nil
	e.run.actions[thread.ref].mode = resumeStep
	if !e.threadStepping(thread) {
		t.Fatal("the original instruction step was lost after the boundary")
	}
}

func TestControlUserBoundaryHoldsPeers(t *testing.T) {
	e, threads := controlModel(2)
	owner, peer := threads[0], threads[1]
	owner.state = target.StateRunning
	e.run = &runOperation{handle: newRun(1), step: owner.ref, entryThread: owner, actions: map[target.ThreadRef]*resumeAction{
		owner.ref: {thread: owner, step: true, started: true},
		peer.ref:  {thread: peer},
	}}
	e.advanceRun()
	if peer.state != target.StateStopped || e.run.actions[peer.ref].started || e.sequence != 0 {
		t.Fatalf("peer resumed during temporary patch: peer=%+v run=%+v", peer, e.run)
	}
}

func TestControlUserBoundaryRejectsSignalDelivery(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	thread.needsUserBoundary, thread.pendingSignal = true, int(unix.SIGUSR1)
	_, err := e.startStep(target.StepRequest{Thread: thread.ref, Signals: []target.ThreadSignal{
		{Thread: thread.ref, Stop: thread.stopEpoch, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}},
	}})
	if !errors.Is(err, target.ErrUnsupported) || e.run != nil || len(e.primary.space.breakpoints) != 0 || thread.pendingSignal != int(unix.SIGUSR1) {
		t.Fatalf("error=%v run=%+v thread=%+v", err, e.run, thread)
	}
}

func TestControlUserBoundaryPrivateHitPreservesInterruption(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	thread.state, thread.needsUserBoundary = target.StateRunning, true
	e.life.births = map[int]*birth{42001: {}}
	space := thread.process.space
	bp := &breakpoint{addr: 0x400100, original: 0x90, armed: true, space: space, spaceRef: space.ref, generation: 1, boundary: thread}
	space.breakpoints[bp.addr] = bp
	thread.hit = &breakpointHit{bp: bp, generation: bp.generation, rawPC: bp.addr + 1}
	action := &resumeAction{thread: thread, step: true, started: true}
	e.run = &runOperation{handle: newRun(1), entryThread: thread, entry: bp, actions: map[target.ThreadRef]*resumeAction{thread.ref: action}}
	e.barrier = &stopBarrier{thread: thread, stop: target.Stop{Reason: target.StopInterrupt}}
	pc, address := bp.addr+1, bp.addr
	e.onThreadStop(thread, target.Stop{Reason: target.StopBreakpoint, RawPC: &pc, Breakpoint: &address})
	if e.barrier == nil || e.barrier.stop.Reason != target.StopInterrupt || e.run == nil || e.run.entryThread != thread || e.run.entry != bp || !e.run.entryHit || !bp.armed || !thread.needsUserBoundary {
		t.Fatalf("barrier=%+v run=%+v site=%+v", e.barrier, e.run, bp)
	}
	if thread.stop.Reason != target.StopUnknown || thread.stop.Breakpoint != nil || thread.stop.StepCompleted {
		t.Fatalf("temporary breakpoint was published as a user stop: %+v", thread.stop)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	event, err := e.s.NextEvent(ctx, 0)
	if err != nil || event.Stop.Reason != target.StopUnknown || event.Stop.Breakpoint != nil || event.Stop.StepCompleted {
		t.Fatalf("temporary breakpoint event=%+v error=%v", event, err)
	}
	select {
	case <-e.run.handle.done:
		t.Fatal("boundary hit finished the pending interruption before cleanup")
	default:
	}
}

func TestControlUserBoundaryDoesNotHideAnotherSignal(t *testing.T) {
	e, threads := controlModel(1)
	thread := threads[0]
	thread.state, thread.needsUserBoundary = target.StateRunning, true
	thread.pendingSignal = int(unix.SIGUSR1)
	e.life.births = map[int]*birth{42001: {}}
	space := thread.process.space
	bp := &breakpoint{addr: 0x400100, original: 0x90, armed: true, space: space, spaceRef: space.ref, generation: 1, boundary: thread}
	space.breakpoints[bp.addr] = bp
	e.run = &runOperation{handle: newRun(1), entryThread: thread, entry: bp, actions: map[target.ThreadRef]*resumeAction{thread.ref: {thread: thread, step: true, started: true}}}
	stop := target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}}
	e.onThreadStop(thread, stop)
	if e.barrier == nil || e.barrier.stop.Reason != target.StopSignal || e.barrier.stop.Signal != stop.Signal || thread.pendingSignal != int(unix.SIGUSR1) || !thread.needsUserBoundary || !bp.armed {
		t.Fatalf("signal during boundary: barrier=%+v thread=%+v", e.barrier, thread)
	}
}
