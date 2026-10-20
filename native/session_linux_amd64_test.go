package native

import (
	"context"
	"errors"
	"testing"
	"time"

	"fastdbg2/target"
)

func TestShutdownDoesNotInventAnUnacknowledgedSuccess(t *testing.T) {
	for _, kind := range []string{"close", "kill", "detach"} {
		t.Run(kind, func(t *testing.T) {
			session := &Session{requests: make(chan func(*engine)), done: make(chan struct{})}
			go func() {
				<-session.requests
				close(session.done)
			}()
			if err := session.shutdown(kind); !errors.Is(err, target.ErrClosed) {
				t.Fatalf("shutdown without a reply: %v", err)
			}
		})
	}
}

func TestClosedSessionRejectsCommandsAndKeepsCloseIdempotent(t *testing.T) {
	session := &Session{requests: make(chan func(*engine)), done: make(chan struct{})}
	session.state.Store(uint32(target.StateClosed))
	close(session.done)
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := session.Snapshot(); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := session.Run(target.RunRequest{}); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("run: %v", err)
	}
	if err := session.Interrupt(target.InterruptRequest{}, target.InterruptRequest{}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("multiple interrupt requests: %v", err)
	}
	if _, err := session.SetWatchpoint(target.ThreadToken{}, target.WatchpointRequest{}); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("set watchpoint: %v", err)
	}
	if _, err := session.ClearWatchpoint(target.ThreadToken{}, target.WatchpointRef{}); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("clear watchpoint: %v", err)
	}
}

func TestPartialInitializationReturnsRecoverableSessionBeforeCleanup(t *testing.T) {
	session := &Session{done: make(chan struct{})}
	defer close(session.done)
	partial := &target.PartialError{Op: "initialize: session retains one task", Completed: 0, Total: 1, Err: target.ErrUnavailable}
	ready := make(chan response[*Session], 1)
	ready <- response[*Session]{value: session, err: partial}
	returned := make(chan response[*Session], 1)
	go func() {
		value, err := awaitSession(session, ready)
		returned <- response[*Session]{value: value, err: err}
	}()
	select {
	case result := <-returned:
		if result.value != session || !errors.Is(result.err, target.ErrPartial) {
			t.Fatalf("partial initialization=%+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("partial initialization hid the recovery handle behind cleanup")
	}
}

func TestInitializationFailureWithoutSessionWaitsForCleanup(t *testing.T) {
	session := &Session{done: make(chan struct{})}
	ready := make(chan response[*Session])
	returned := make(chan response[*Session], 1)
	go func() {
		value, err := awaitSession(session, ready)
		returned <- response[*Session]{value: value, err: err}
	}()
	ready <- response[*Session]{err: target.ErrUnsupported}
	select {
	case result := <-returned:
		t.Fatalf("initialization returned before cleanup: %+v", result)
	default:
	}
	close(session.done)
	result := <-returned
	if result.value != nil || !errors.Is(result.err, target.ErrUnsupported) {
		t.Fatalf("initialization failure=%+v", result)
	}
}

func TestWatchpointStopCopiesAcrossPublicBoundaries(t *testing.T) {
	dr6 := uint64(1<<14 | 3)
	ref := target.ThreadRef{Session: 3, ID: 4}
	stop := target.Stop{
		Reason: target.StopWatchpoint, StepCompleted: true, RawDR6: &dr6,
		Watchpoints: []target.WatchpointHit{
			{Ref: target.WatchpointRef{Thread: ref, Slot: 0, Generation: 1}, Address: 0x1000, Size: 8, Access: target.WatchReadWrite},
			{Ref: target.WatchpointRef{Thread: ref, Slot: 1, Generation: 2}, Address: 0x1000, Size: 4, Access: target.WatchWrite},
		},
	}
	session := &Session{id: ref.Session, requests: make(chan func(*engine)), done: make(chan struct{})}
	p := &process{ref: target.ProcessRef{Session: ref.Session, ID: 1}}
	e := &engine{
		s: session, primary: p,
		threads: map[int]*thread{12: {ref: ref, tid: 12, process: p, state: target.StateStopped, stop: copyStop(stop)}},
	}
	stored := copyStop(stop)
	session.last.Store(&stored)
	e.sequence = session.publishEvent(target.Event{Kind: target.EventAllStopped, Thread: ref, Stop: stop})
	run := newRun(1)
	run.complete(target.RunResult{Thread: ref, Stop: stop}, nil)
	stop.Watchpoints[0].Address, dr6 = 0, 0
	quit := make(chan struct{})
	go func() {
		defer close(session.done)
		for {
			select {
			case request := <-session.requests:
				request(e)
			case <-quit:
				return
			}
		}
	}()
	t.Cleanup(func() { close(quit); <-session.done })
	check := func(value target.Stop) {
		t.Helper()
		if !value.StepCompleted || value.RawDR6 == nil || *value.RawDR6 != 1<<14|3 || len(value.Watchpoints) != 2 || value.Watchpoints[0].Address != 0x1000 || value.Watchpoints[1].Ref.Generation != 2 {
			t.Fatalf("shared or incomplete watchpoint stop: %+v", value)
		}
		value.Watchpoints[0].Address = 0
		value.Watchpoints[1].Ref.Generation = 0
		*value.RawDR6 = 0
	}
	for range 2 {
		result, err := run.Wait(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		check(result.Stop)
		event, err := session.NextEvent(context.Background(), 0)
		if err != nil {
			t.Fatal(err)
		}
		check(event.Stop)
		snapshot, err := session.Snapshot()
		if err != nil || len(snapshot.Threads) != 1 {
			t.Fatalf("snapshot=%+v err=%v", snapshot, err)
		}
		check(snapshot.Threads[0].Stop)
		threads, err := session.Threads()
		if err != nil || len(threads) != 1 {
			t.Fatalf("threads=%+v err=%v", threads, err)
		}
		check(threads[0].Stop)
		check(session.LastStop())
	}
}
