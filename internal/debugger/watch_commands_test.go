package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"fastdbg2/target"
)

func (s *mutationTestSession) SetWatchpoint(token target.ThreadToken, request target.WatchpointRequest) (target.WatchpointResult, error) {
	s.watchTokens = append(s.watchTokens, token)
	s.watchRequests = append(s.watchRequests, request)
	s.generation++
	updated := s.advanceRegisterToken(token.Thread)
	if s.afterWrite != nil {
		s.afterWrite()
	}
	if s.watchErr != nil {
		return target.WatchpointResult{}, s.watchErr
	}
	result := target.WatchpointResult{Ref: target.WatchpointRef{Thread: token.Thread, Slot: request.Slot, Generation: s.generation}, Token: updated}
	if s.editWatchResult != nil {
		s.editWatchResult(&result)
	}
	return result, nil
}

func (s *mutationTestSession) ClearWatchpoint(token target.ThreadToken, ref target.WatchpointRef) (target.ThreadToken, error) {
	s.clearTokens = append(s.clearTokens, token)
	s.watchClears = append(s.watchClears, ref)
	updated := s.advanceRegisterToken(token.Thread)
	if s.afterWrite != nil {
		s.afterWrite()
	}
	return updated, s.clearErr
}

func TestWatchpointDefaultsAndExplicitOptions(t *testing.T) {
	for _, test := range []struct {
		args   string
		size   int
		access target.WatchAccess
	}{
		{"0x1000", 1, target.WatchReadWrite},
		{`"$rax + 8" --size 8 --access write`, 8, target.WatchWrite},
		{"--access read-write --size 4 0x1000", 4, target.WatchReadWrite},
	} {
		var output bytes.Buffer
		c, s := mutationController(t, &output)
		before := s.snapshot.Threads[0].Token
		s.snapshot.Threads[0].Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 12}}
		if err := c.commandWatch(context.Background(), test.args); err != nil {
			t.Fatal(err)
		}
		if len(s.watchRequests) != 1 || s.watchTokens[0] != before || s.watchRequests[0].Slot != 0 || s.watchRequests[0].Size != test.size || s.watchRequests[0].Access != test.access || s.snapshots != 2 {
			t.Fatalf("args=%q requests=%+v tokens=%+v snapshots=%d", test.args, s.watchRequests, s.watchTokens, s.snapshots)
		}
		point := c.watchpoints[0]
		if !point.installed || !point.attempted || point.ref.Generation != 1 || point.ref.Thread != before.Thread || point.space != s.snapshot.Memory.Space || point.err != nil || s.snapshot.Threads[0].Stop.Signal.Number != 12 || s.runCalls+s.stepCalls != 0 {
			t.Fatalf("point=%+v", point)
		}
	}
}

func TestWatchpointInvalidArgumentsNeverAttemptInstallation(t *testing.T) {
	for _, args := range []string{"", "list extra", "d", "d 4", "d -1", "d +1", "d 0 extra", "0x1000 --size 3", "0x1000 --access read", "0x1000 --access exec", "0x1000 --size", "0x1000 --size 1 --size 2", "0x1000 --access write --access read-write", "0x1000 --slot 1", "0x1000 0x2000", "0x1001 --size 8", "0xffffffffffffffff --size 8"} {
		c, s := mutationController(t, io.Discard)
		if err := c.commandWatch(context.Background(), args); err == nil || len(s.watchRequests)+len(s.watchClears) != 0 || len(c.watchpoints) != 0 {
			t.Fatalf("args=%q err=%v requests=%+v points=%+v", args, err, s.watchRequests, c.watchpoints)
		}
	}
}

func TestWatchpointSlotsAreThreadLocalAndDeletionUsesExactGeneration(t *testing.T) {
	c, s := mutationController(t, io.Discard)
	leader := c.selected
	peer := controllerPeer(s.controllerTestSession, 2)
	for slot := 0; slot < 4; slot++ {
		if err := c.commandWatch(context.Background(), "0x1000"); err != nil {
			t.Fatal(err)
		}
		if s.watchRequests[slot].Slot != slot {
			t.Fatalf("slots=%+v", s.watchRequests)
		}
	}
	if err := c.commandWatch(context.Background(), "0x2000"); !errors.Is(err, target.ErrBusy) || len(s.watchRequests) != 4 {
		t.Fatalf("fifth slot err=%v requests=%+v", err, s.watchRequests)
	}
	c.selected = peer.Ref
	if err := c.commandWatch(context.Background(), "d 0"); !errors.Is(err, target.ErrNotFound) || len(s.watchClears) != 0 {
		t.Fatalf("another thread's slot was deleted: %v", err)
	}
	if err := c.commandWatch(context.Background(), "0x2000"); err != nil {
		t.Fatal(err)
	}
	peerRef := c.watchpoints[4].ref
	if peerRef.Thread != peer.Ref || peerRef.Slot != 0 || len(c.watchpoints) != 5 {
		t.Fatalf("peer slot=%+v points=%+v", peerRef, c.watchpoints)
	}
	if err := c.commandWatch(context.Background(), "d 0"); err != nil || len(s.watchClears) != 1 || s.watchClears[0] != peerRef || len(c.watchpoints) != 4 {
		t.Fatalf("peer deletion err=%v clears=%+v points=%+v", err, s.watchClears, c.watchpoints)
	}
	c.selected = leader
	leaderRef := c.watchpoints[0].ref
	if err := c.commandWatch(context.Background(), "d 0x0"); err != nil || s.watchClears[1] != leaderRef {
		t.Fatalf("leader deletion err=%v clears=%+v", err, s.watchClears)
	}
}

func TestWatchpointFailedAttemptIsRetainedWithoutRetryOrGuessedCleanup(t *testing.T) {
	var output bytes.Buffer
	c, s := mutationController(t, &output)
	want := &target.PartialError{Op: "debug register write", Total: 1, Err: target.ErrUnavailable}
	s.watchErr = want
	if err := c.commandWatch(context.Background(), "0x1000"); !errors.Is(err, target.ErrPartial) || len(c.watchpoints) != 1 || s.snapshots != 2 || output.Len() != 0 {
		t.Fatalf("err=%v points=%+v snapshots=%d output=%q", err, c.watchpoints, s.snapshots, output.String())
	}
	point := c.watchpoints[0]
	if !point.attempted || point.installed || point.ref.Generation != 0 || !errors.Is(point.err, want) {
		t.Fatalf("failed attempt forgotten: %+v", point)
	}
	if err := c.commandWatch(context.Background(), "0x2000"); !errors.Is(err, target.ErrUnavailable) || len(s.watchRequests) != 1 {
		t.Fatalf("blind slot retry err=%v requests=%+v", err, s.watchRequests)
	}
	if err := c.commandWatch(context.Background(), "d 0"); !errors.Is(err, target.ErrUnavailable) || len(s.watchClears) != 0 {
		t.Fatalf("guessed handle cleanup err=%v clears=%+v", err, s.watchClears)
	}
	if err := c.commandWatch(context.Background(), "list"); err != nil || !uiWatchpointRowMatches(output.String(), point.thread.ID, point.request.Slot, point.request.Access.String(), point.request.Size, point.request.Address, "unconfirmed", 0) {
		t.Fatalf("list err=%v output=%q", err, output.String())
	}
	s.closeError = target.ErrPartial
	if err := c.Close(); !errors.Is(err, target.ErrPartial) || c.session != s || len(c.watchpoints) != 1 {
		t.Fatalf("failed close lost ownership: err=%v session=%v", err, c.session)
	}
}

func TestWatchpointDeleteFailureRetainsExactHandleForExplicitRetry(t *testing.T) {
	c, s := mutationController(t, io.Discard)
	if err := c.commandWatch(context.Background(), "0x1000"); err != nil {
		t.Fatal(err)
	}
	ref := c.watchpoints[0].ref
	s.clearErr = &target.PartialError{Op: "clear debug registers", Total: 1, Err: target.ErrUnavailable}
	if err := c.commandWatch(context.Background(), "d 0"); !errors.Is(err, target.ErrPartial) || len(c.watchpoints) != 1 || c.watchpoints[0].ref != ref || c.watchpoints[0].err == nil {
		t.Fatalf("err=%v points=%+v", err, c.watchpoints)
	}
	if err := c.commandWatch(context.Background(), "0x2000"); !errors.Is(err, target.ErrUnavailable) || len(s.watchRequests) != 1 {
		t.Fatalf("uncertain clear allowed another install: %v", err)
	}
	s.clearErr = nil
	if err := c.commandWatch(context.Background(), "d 0"); err != nil || len(c.watchpoints) != 0 || len(s.watchClears) != 2 || s.watchClears[0] != ref || s.watchClears[1] != ref || s.clearTokens[0] == s.clearTokens[1] {
		t.Fatalf("err=%v clears=%+v tokens=%+v points=%+v", err, s.watchClears, s.clearTokens, c.watchpoints)
	}
}

func TestWatchpointRejectsInconsistentReturnedIdentity(t *testing.T) {
	for _, edit := range []func(*target.WatchpointResult){
		func(result *target.WatchpointResult) { result.Ref.Generation = 0 },
		func(result *target.WatchpointResult) { result.Ref.Thread.Session++ },
		func(result *target.WatchpointResult) { result.Ref.Slot++ },
		func(result *target.WatchpointResult) { result.Token.Stop++ },
	} {
		c, s := mutationController(t, io.Discard)
		s.editWatchResult = edit
		if err := c.commandWatch(context.Background(), "0x1000"); !errors.Is(err, target.ErrUnknown) || len(c.watchpoints) != 1 || c.watchpoints[0].installed || s.snapshots != 2 {
			t.Fatalf("err=%v points=%+v snapshots=%d", err, c.watchpoints, s.snapshots)
		}
	}
}

func TestWatchpointExecAndThreadIncarnationInvalidateWithoutReinstall(t *testing.T) {
	for _, change := range []string{"exec", "new-session", "tid-reuse", "exit"} {
		t.Run(change, func(t *testing.T) {
			var output bytes.Buffer
			c, s := mutationController(t, &output)
			if err := c.commandWatch(context.Background(), "0x1000"); err != nil {
				t.Fatal(err)
			}
			old := c.watchpoints[0].ref
			switch change {
			case "exec":
				s.snapshot.Memory.Space.ID++
			case "new-session":
				s.snapshot.Memory.Space.Session++
				s.snapshot.Process.Session++
				s.snapshot.Threads[0].Process = s.snapshot.Process
				s.snapshot.Threads[0].Ref.Session++
				s.snapshot.Threads[0].Token.Thread = s.snapshot.Threads[0].Ref
				c.selected = s.snapshot.Threads[0].Ref
			case "tid-reuse":
				s.snapshot.Threads[0].Ref.ID++
				s.snapshot.Threads[0].Token.Thread = s.snapshot.Threads[0].Ref
				c.selected = s.snapshot.Threads[0].Ref
			case "exit":
				s.snapshot.State = target.StateExited
				s.snapshot.Threads[0].State = target.StateExited
			}
			if err := c.commandWatch(context.Background(), "list"); err != nil || !c.watchpoints[0].expired || c.watchpoints[0].ref != old || len(s.watchRequests) != 1 || !uiWatchpointRowMatches(output.String(), old.Thread.ID, old.Slot, "read-write", 1, 0x1000, "invalidated", old.Generation) {
				t.Fatalf("err=%v points=%+v output=%q", err, c.watchpoints, output.String())
			}
			if err := c.commandWatch(context.Background(), "d 0"); err == nil || len(s.watchClears) != 0 {
				t.Fatalf("old generation cleared in new image: %v", err)
			}
		})
	}
}

func TestWatchpointNewbornIsNotConfigured(t *testing.T) {
	c, s := mutationController(t, io.Discard)
	if err := c.commandWatch(context.Background(), "0x1000"); err != nil {
		t.Fatal(err)
	}
	peer := controllerPeer(s.controllerTestSession, 2)
	c.selected = peer.Ref
	if err := c.commandWatch(context.Background(), "list"); err != nil || len(s.watchRequests) != 1 || len(c.watchpoints) != 1 {
		t.Fatalf("newborn inherited configuration: %v", err)
	}
	if err := c.commandWatch(context.Background(), "d 0"); !errors.Is(err, target.ErrNotFound) || len(s.watchClears) != 0 {
		t.Fatalf("newborn inherited cleanup handle: %v", err)
	}
}

func TestWatchpointOutputAndSnapshotFailuresPreserveInstallation(t *testing.T) {
	want := errors.New("output failed")
	c, s := mutationController(t, controllerTestWriter(func([]byte) (int, error) { return 0, want }))
	err := c.commandWatch(context.Background(), "0x1000")
	var outputErr *OutputError
	if !errors.Is(err, want) || !errors.As(err, &outputErr) || len(c.watchpoints) != 1 || !c.watchpoints[0].installed || len(s.watchRequests) != 1 || c.session != s {
		t.Fatalf("err=%v points=%+v session=%v", err, c.watchpoints, c.session)
	}
	c, s = mutationController(t, io.Discard)
	snapshotErr := errors.New("snapshot failed")
	s.afterWrite = func() { s.snapshotError = snapshotErr }
	err = c.commandWatch(context.Background(), "0x1000")
	if !errors.Is(err, snapshotErr) || len(c.watchpoints) != 1 || !c.watchpoints[0].installed || c.watchpoints[0].ref.Generation == 0 {
		t.Fatalf("snapshot failure lost confirmed handle: err=%v points=%+v", err, c.watchpoints)
	}
}

func TestWatchpointListAfterCloseIsExpiredAndCapabilityIsOptional(t *testing.T) {
	var output bytes.Buffer
	c, _ := mutationController(t, &output)
	if err := c.commandWatch(context.Background(), "0x1000"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	point := c.watchpoints[0]
	if err := c.commandWatch(context.Background(), "list"); err != nil || !point.expired || !uiWatchpointRowMatches(output.String(), point.thread.ID, point.request.Slot, point.request.Access.String(), point.request.Size, point.request.Address, "invalidated", point.ref.Generation) {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
	c, _ = runningController(t, io.Discard)
	if err := c.commandWatch(context.Background(), "0x1000"); !errors.Is(err, target.ErrUnsupported) || len(c.watchpoints) != 0 {
		t.Fatalf("missing capability err=%v points=%+v", err, c.watchpoints)
	}
}

func TestWatchpointUnsettledSnapshotDoesNotForgetOwnership(t *testing.T) {
	c, s := mutationController(t, io.Discard)
	if err := c.commandWatch(context.Background(), "0x1000"); err != nil {
		t.Fatal(err)
	}
	before := s.snapshot
	s.snapshot.State = target.StateUnknown
	s.snapshot.Memory = target.MemoryToken{}
	s.snapshot.Threads = nil
	if err := c.commandWatch(context.Background(), "list"); err != nil || c.watchpoints[0].expired {
		t.Fatalf("unsettled snapshot forgot known handle: err=%v point=%+v", err, c.watchpoints[0])
	}
	s.snapshot = before
	if err := c.commandWatch(context.Background(), "d 0"); err != nil || len(s.watchClears) != 1 {
		t.Fatalf("retained handle could not be cleaned up: err=%v clears=%+v", err, s.watchClears)
	}
}

func TestMutationThreadApplyRejectsAllWriteFormsExceptWatchpointListing(t *testing.T) {
	for _, test := range []struct{ command, args string }{
		{"set", "rax 1"}, {"set8", "0x1000 1"}, {"set16", "0x1000 1"}, {"set32", "0x1000 1"},
		{"xor", "0x1000 1"}, {"wp", "0x1000"}, {"wp", "d 0"}, {"wp", "list extra"},
	} {
		if err := threadApplyReadOnly(test.command, test.args); err == nil {
			t.Fatalf("thread apply permitted %s %s", test.command, test.args)
		}
	}
	if err := threadApplyReadOnly("wp", "list"); err != nil {
		t.Fatalf("read-only watchpoint listing rejected: %v", err)
	}
}

func TestWatchpointStopDisplaysOnlyExactHitAndIndependentStepFacts(t *testing.T) {
	var output bytes.Buffer
	c, s := mutationController(t, &output)
	c.contextDisabled = true
	peer := controllerPeer(s.controllerTestSession, 2)
	stop := target.Stop{
		Reason: target.StopWatchpoint, StepCompleted: true,
		Watchpoints: []target.WatchpointHit{
			{Ref: target.WatchpointRef{Thread: peer.Ref, Slot: 3, Generation: 17}, Address: 0x405010, Size: 4, Access: target.WatchWrite},
			{Ref: target.WatchpointRef{Thread: peer.Ref, Slot: 1, Generation: 19}, Address: 0x405011, Size: 1, Access: target.WatchReadWrite},
		},
		HardwareBreakpoints: []target.HardwareBreakpointHit{
			{Ref: target.HardwareBreakpointRef{Thread: peer.Ref, Slot: 2, Generation: 23}, Address: 0x401000},
		},
	}
	if err := c.showStop(context.Background(), stop, peer.Ref); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		fmt.Sprintf("Thread #2 (TID %d) stopped (hardware watchpoint).", peer.TID),
		"  Instruction step completed.",
		"  Watchpoint: thread #2, slot 3, generation 17; write 4 byte(s) at 0x0000000000405010 (session 1).",
		"  Watchpoint: thread #2, slot 1, generation 19; read-write 1 byte(s) at 0x0000000000405011 (session 1).",
		"  Hardware breakpoint: thread #2, slot 2, generation 23; execution at 0x0000000000401000 (session 1).",
	} {
		if !uiOutputHasLine(output.String(), expected) {
			t.Fatalf("missing %q in %q", expected, output.String())
		}
	}
	if c.selected != peer.Ref || len(c.watchpoints) != 0 || len(s.watchRequests) != 0 {
		t.Fatal("stop display inferred or modified watchpoint ownership")
	}
}
