package target_test

import (
	"testing"

	"fastdbg2/target"
)

func TestWatchAccessStrings(t *testing.T) {
	for _, test := range []struct {
		access target.WatchAccess
		want   string
	}{
		{target.WatchUnknown, "unknown"},
		{target.WatchWrite, "write"},
		{target.WatchReadWrite, "read-write"},
		{target.WatchAccess(255), "unknown"},
	} {
		if got := test.access.String(); got != test.want {
			t.Fatalf("access %d: got %q, want %q", test.access, got, test.want)
		}
	}
	if target.StopWatchpoint.String() != "watchpoint" {
		t.Fatal("watchpoint stops must remain distinct")
	}
}

func TestWatchpointReferencesSeparateThreadSlotAndGeneration(t *testing.T) {
	ref := target.WatchpointRef{Thread: target.ThreadRef{Session: 3, ID: 4}, Slot: 1, Generation: 9}
	nextSession, nextThread, nextSlot, nextGeneration := ref, ref, ref, ref
	nextSession.Thread.Session++
	nextThread.Thread.ID++
	nextSlot.Slot++
	nextGeneration.Generation++
	for _, other := range []target.WatchpointRef{nextSession, nextThread, nextSlot, nextGeneration} {
		if ref == other {
			t.Fatalf("watchpoint identity collided: %+v", other)
		}
	}
}

func TestWatchpointAndStepFactsAreIndependent(t *testing.T) {
	var stop target.Stop
	if stop.RawDR6 != nil || stop.Watchpoints != nil || stop.StepCompleted {
		t.Fatal("zero stop must not invent debug-register observations")
	}
	dr6 := uint64(1<<14 | 3)
	thread := target.ThreadRef{Session: 1, ID: 2}
	stop = target.Stop{
		Reason: target.StopWatchpoint, StepCompleted: true, RawDR6: &dr6,
		Watchpoints: []target.WatchpointHit{
			{Ref: target.WatchpointRef{Thread: thread, Slot: 0, Generation: 1}, Address: 0x1000, Size: 8, Access: target.WatchReadWrite},
			{Ref: target.WatchpointRef{Thread: thread, Slot: 1, Generation: 2}, Address: 0x1000, Size: 4, Access: target.WatchWrite},
		},
	}
	if stop.Reason != target.StopWatchpoint || !stop.StepCompleted || len(stop.Watchpoints) != 2 || *stop.RawDR6 != dr6 {
		t.Fatal("one debug exception must retain every confirmed cause")
	}
}
