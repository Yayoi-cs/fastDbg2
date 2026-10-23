package native

import (
	"context"
	"errors"
	"sync"
	"testing"

	"fastdbg2/target"
)

func TestRunWaitCancellationDoesNotCompleteRun(t *testing.T) {
	run := newRun(7)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := run.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait: %v", err)
	}
	select {
	case <-run.done:
		t.Fatal("canceling a waiter completed the run")
	default:
	}
	run.complete(target.RunResult{Sequence: 19, Stop: target.Stop{Reason: target.StopInterrupt}}, nil)
	result, err := run.Wait(context.Background())
	if err != nil || result.Sequence != 19 || result.Stop.Reason != target.StopInterrupt || run.ID() != 7 {
		t.Fatalf("result=%+v id=%d err=%v", result, run.ID(), err)
	}
}

func TestRunCompletesOnceAndReturnsIndependentCopies(t *testing.T) {
	pc, tid := target.Address(0x401000), uint64(123)
	run := newRun(2)
	run.complete(target.RunResult{Stop: target.Stop{RawPC: &pc, ThreadID: &tid}}, target.ErrDetached)
	pc, tid = 0, 0
	run.complete(target.RunResult{}, target.ErrClosed)
	first, err := run.Wait(context.Background())
	if !errors.Is(err, target.ErrDetached) || *first.Stop.RawPC != 0x401000 || *first.Stop.ThreadID != 123 {
		t.Fatalf("result=%+v err=%v", first, err)
	}
	*first.Stop.RawPC, *first.Stop.ThreadID = 9, 9
	second, err := run.Wait(context.Background())
	if !errors.Is(err, target.ErrDetached) || *second.Stop.RawPC != 0x401000 || *second.Stop.ThreadID != 123 {
		t.Fatalf("aliased result=%+v err=%v", second, err)
	}
}

func TestRunWaitBroadcastsToEveryWaiter(t *testing.T) {
	run := newRun(8)
	const count = 16
	results := make(chan response[target.RunResult], count)
	var ready sync.WaitGroup
	ready.Add(count)
	for range count {
		go func() {
			ready.Done()
			value, err := run.Wait(context.Background())
			results <- response[target.RunResult]{value: value, err: err}
		}()
	}
	ready.Wait()
	run.complete(target.RunResult{Sequence: 42}, nil)
	for range count {
		result := <-results
		if result.err != nil || result.value.Sequence != 42 {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestRunWaitRejectsInvalidArguments(t *testing.T) {
	if _, err := newRun(1).Wait(nil); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context: %v", err)
	}
	var run *Run
	if _, err := run.Wait(context.Background()); !errors.Is(err, target.ErrInvalidArgument) || run.ID() != 0 {
		t.Fatalf("nil run: id=%d err=%v", run.ID(), err)
	}
}

func TestRunCompletionDoesNotConsumeEvents(t *testing.T) {
	session := &Session{done: make(chan struct{})}
	run := newRun(3)
	sequence := session.publishEvent(target.Event{Kind: target.EventAllStopped, RunID: run.ID()})
	run.complete(target.RunResult{Sequence: sequence}, nil)
	result, err := run.Wait(context.Background())
	if err != nil || result.Sequence != sequence {
		t.Fatalf("completion=%+v err=%v", result, err)
	}
	event, err := session.NextEvent(context.Background(), 0)
	if err != nil || event.Sequence != sequence || event.RunID != run.ID() {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	result, err = run.Wait(context.Background())
	if err != nil || result.Sequence != sequence {
		t.Fatalf("completion after event=%+v err=%v", result, err)
	}
}

func TestWatchpointRunWaitersOwnReturnedBuffers(t *testing.T) {
	dr6 := uint64(1)
	run := newRun(9)
	run.complete(target.RunResult{Stop: target.Stop{
		Reason: target.StopWatchpoint, RawDR6: &dr6,
		Watchpoints: []target.WatchpointHit{{Address: 0x1000, Size: 8, Access: target.WatchWrite}},
	}}, nil)
	const count = 16
	results := make(chan bool, count)
	for range count {
		go func() {
			value, err := run.Wait(context.Background())
			valid := err == nil && value.Stop.RawDR6 != nil && *value.Stop.RawDR6 == 1 && len(value.Stop.Watchpoints) == 1 && value.Stop.Watchpoints[0].Address == 0x1000
			if valid {
				*value.Stop.RawDR6 = 0
				value.Stop.Watchpoints[0].Address = 0
			}
			results <- valid
		}()
	}
	for range count {
		if !<-results {
			t.Fatal("a waiter observed another consumer's watchpoint mutation")
		}
	}
}

func TestHardwareBreakpointRunWaitersOwnReturnedBuffers(t *testing.T) {
	pc := target.Address(0x401000)
	run := newRun(10)
	run.complete(target.RunResult{Stop: target.Stop{
		Reason: target.StopHardwareBreakpoint, RawPC: &pc,
		HardwareBreakpoints: []target.HardwareBreakpointHit{{Address: pc}},
	}}, nil)
	const count = 16
	results := make(chan bool, count)
	for range count {
		go func() {
			value, err := run.Wait(context.Background())
			valid := err == nil && value.Stop.RawPC != nil && *value.Stop.RawPC == 0x401000 && len(value.Stop.HardwareBreakpoints) == 1 && value.Stop.HardwareBreakpoints[0].Address == 0x401000
			if valid {
				*value.Stop.RawPC = 0
				value.Stop.HardwareBreakpoints[0].Address = 0
			}
			results <- valid
		}()
	}
	for range count {
		if !<-results {
			t.Fatal("a waiter observed another consumer's hardware breakpoint mutation")
		}
	}
}
