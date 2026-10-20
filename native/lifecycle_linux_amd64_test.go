package native

import (
	"errors"
	"fastdbg2/native/amd64"
	"fastdbg2/target"
	"testing"
)

func TestLifecycleUnresolvedOwnershipRejectsShutdown(t *testing.T) {
	for _, missing := range []bool{false, true} {
		s := &Session{id: 1}
		e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
		p := e.newProcess(41, -1, true)
		e.primary = p
		tr := e.newThread(p, 41, true)
		tr.state = target.StateRunning
		if missing {
			e.life.missing = map[int]*thread{41: tr}
		} else {
			e.life.lost = map[int]error{41: target.ErrUnavailable}
		}
		reply := make(chan error, 1)
		e.life.shutdownKind = "kill"
		e.life.shutdownReply = []chan error{reply}
		e.life.closeAfter = true
		e.advanceShutdown()
		select {
		case err := <-reply:
			if !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrUnavailable) {
				t.Fatalf("shutdown error: %v", err)
			}
		default:
			t.Fatal("shutdown did not resolve its reply")
		}
		if e.life.finished || !tr.live() || e.life.shutdownKind != "" {
			t.Fatalf("unresolved ownership was discarded: finished=%t live=%t operation=%q", e.life.finished, tr.live(), e.life.shutdownKind)
		}
	}
}

func TestWaitTaskRejectsWildcardSelectors(t *testing.T) {
	for _, tid := range []int{-1, 0} {
		result, ready := waitTask(tid)
		if !ready || !errors.Is(result.err, target.ErrInvalidArgument) {
			t.Fatalf("wait selector %d: ready=%t result=%+v", tid, ready, result)
		}
	}
}

func TestLifecyclePendingBirthFailureRejectsShutdown(t *testing.T) {
	s := &Session{id: 1}
	e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
	task := e.newThread(nil, 41, true)
	task.state = target.StateStopped
	e.life.births = map[int]*birth{41: {fault: target.ErrUnavailable}}
	reply := make(chan error, 1)
	e.life.shutdownKind = "kill"
	e.life.shutdownReply = []chan error{reply}
	e.advanceShutdown()
	select {
	case err := <-reply:
		if !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrUnavailable) {
			t.Fatalf("shutdown error: %v", err)
		}
	default:
		t.Fatal("failed birth left shutdown waiting forever")
	}
	if e.life.finished || !task.live() {
		t.Fatal("failed birth was reported as terminal")
	}
}

func TestCloneStepRequiresFormalSameProcessChild(t *testing.T) {
	s := &Session{id: 1}
	e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
	p := e.newProcess(41, -1, true)
	profile := amd64.Descriptor()
	p.profile = &profile
	parent := e.newThread(p, 41, true)
	parent.state = target.StateStopped
	if err := e.validateCloneStep(parent); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("missing syscall proof: %v", err)
	}
	e.life.syscallSteps = map[*thread]syscallStep{parent: {space: p.space.ref, pc: 0x400002, number: 56}}
	if err := e.validateCloneStep(parent); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("missing birth proof: %v", err)
	}
	other := e.newProcess(42, -1, true)
	child := e.newThread(other, 42, true)
	child.state = target.StateStopped
	e.life.cloneChildren = map[*thread]*thread{parent: child}
	if err := e.validateCloneStep(parent); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("cross-process clone accepted: %v", err)
	}
	child.process = p
	child.state = target.StateUnknown
	if commit, err := e.prepareSyscallStep(parent, &resumeAction{thread: parent, step: true}, true); commit != nil || !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("new step discarded pending clone proof: commit=%t err=%v", commit != nil, err)
	}
	if len(e.life.syscallSteps) != 1 || len(e.life.cloneChildren) != 1 {
		t.Fatal("rejected new step consumed the in-flight clone proof")
	}
	if err := e.validateCloneStep(parent); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("unstopped child accepted: %v", err)
	}
	e.forgetSyscallStep(parent)
	if len(e.life.syscallSteps) != 0 || len(e.life.cloneChildren) != 0 {
		t.Fatal("syscall invalidation retained clone ownership proof")
	}
}

func TestLifecyclePartialDetachInvalidatesSharedSpace(t *testing.T) {
	s := &Session{id: 1}
	e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
	p := e.newProcess(41, -1, false)
	e.primary = p
	profile := amd64.Descriptor()
	p.profile = &profile
	detached := e.newThread(p, 41, true)
	detached.state = target.StateDetached
	owned := e.newThread(p, 42, true)
	owned.state = target.StateStopped
	owned.stopEpoch = 1
	e.updateState()
	token := target.MemoryToken{Space: p.space.ref, Revision: p.space.revision}
	reply := make(chan error, 1)
	e.life.shutdownKind = "detach"
	e.life.shutdownReply = []chan error{reply}
	e.finishShutdown(target.ErrUnavailable)
	if err := <-reply; !errors.Is(err, target.ErrPartial) {
		t.Fatalf("partial detach error: %v", err)
	}
	if p.space.fault == nil || s.State() == target.StateStopped || e.snapshot().State == target.StateStopped || e.snapshot().Memory.Revision != 0 {
		t.Fatalf("partial detach exposed a coherent space: fault=%v state=%v snapshot=%+v", p.space.fault, s.State(), e.snapshot())
	}
	if _, _, err := e.requireMemory(token); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("partial detach memory access: %v", err)
	}
	if run, err := e.startRun(target.RunRequest{Threads: target.ThreadSet{Threads: []target.ThreadRef{owned.ref}}}); run != nil || !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("partial detach resume accepted: run=%v error=%v", run, err)
	}
	if e.life.finished || !owned.live() {
		t.Fatal("partial detach discarded retained ownership")
	}
	if err := e.restoreBreakpoints(); err != nil {
		t.Fatalf("restored breakpoint state blocked cleanup retry: %v", err)
	}
	owned.state = target.StateDetached
	retry := make(chan error, 1)
	e.beginShutdown("close", retry)
	if err := <-retry; err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if !e.life.finished || s.State() != target.StateClosed {
		t.Fatalf("cleanup retry did not close: finished=%t state=%v", e.life.finished, s.State())
	}
}

func TestLifecyclePartialDetachDoesNotInvalidateIndependentSpace(t *testing.T) {
	s := &Session{id: 1}
	e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
	left := e.newProcess(41, -1, false)
	right := e.newProcess(42, -1, false)
	e.primary = right
	e.newThread(left, 41, true).state = target.StateDetached
	e.newThread(right, 42, true).state = target.StateStopped
	e.life.shutdownKind = "detach"
	e.finishShutdown(target.ErrUnavailable)
	if left.space.fault != nil || right.space.fault != nil {
		t.Fatal("independent address space was invalidated by an unrelated detach")
	}
}

func TestHardwareStopFactsRemainIndependent(t *testing.T) {
	hit := target.WatchpointHit{Ref: target.WatchpointRef{Thread: target.ThreadRef{Session: 1, ID: 2}, Slot: 0, Generation: 3}, Address: 0x400000, Size: 4, Access: target.WatchWrite}
	for _, test := range []struct {
		name      string
		code      int32
		hits      []target.WatchpointHit
		stepBit   bool
		dr6       uint64
		stepping  bool
		reason    target.StopReason
		completed bool
		signal    int
	}{
		{"watch", 4, []target.WatchpointHit{hit}, false, 1, false, target.StopWatchpoint, false, 0},
		{"watch_and_step", 2, []target.WatchpointHit{hit}, true, 0x4001, true, target.StopWatchpoint, true, 0},
		{"watch_without_step_fact", 4, []target.WatchpointHit{hit}, false, 1, true, target.StopWatchpoint, false, 0},
		{"watch_and_target_tf", 2, []target.WatchpointHit{hit}, true, 0x4001, false, target.StopWatchpoint, false, 5},
		{"step", 2, nil, true, 0x4000, true, target.StopStep, true, 0},
		{"foreign_watch_and_step", 2, nil, true, 0x4001, true, target.StopSignal, true, 5},
		{"foreign_watch", 4, nil, false, 1, false, target.StopSignal, false, 5},
		{"foreign_status_with_stale_bs", 4, nil, true, 0x4000, true, target.StopSignal, false, 5},
		{"unproved_trace", 2, nil, false, 0, true, target.StopSignal, false, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			stop, signal := applyWatchpointStop(target.Stop{}, test.code, test.hits, test.stepBit, test.dr6, test.stepping)
			if stop.Reason != test.reason || stop.StepCompleted != test.completed || signal != test.signal || len(stop.Watchpoints) != len(test.hits) {
				t.Fatalf("stop=%+v signal=%d", stop, signal)
			}
		})
	}
}

func TestUserBoundaryMarkerSurvivesRegisterProofInvalidation(t *testing.T) {
	task := &thread{needsUserBoundary: true}
	e := &engine{life: lifecycleState{
		syscallSteps:  map[*thread]syscallStep{task: {}},
		cloneChildren: map[*thread]*thread{task: {}},
	}}
	e.forgetSyscallStep(task)
	if !task.needsUserBoundary || len(e.life.syscallSteps) != 0 || len(e.life.cloneChildren) != 0 {
		t.Fatal("register proof invalidation discarded the kernel-return boundary requirement")
	}
}
