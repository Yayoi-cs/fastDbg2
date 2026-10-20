package target_test

import (
	"errors"
	"testing"

	"fastdbg2/target"
)

func TestThreadReferencesIncludeSessionAndIncarnation(t *testing.T) {
	first := target.ThreadRef{Session: 4, ID: 7}
	if first == (target.ThreadRef{Session: 5, ID: 7}) {
		t.Fatal("thread identities crossed sessions")
	}
	if first == (target.ThreadRef{Session: 4, ID: 8}) {
		t.Fatal("thread identities reused an incarnation")
	}
	token := target.ThreadToken{Thread: first, Stop: 2, Registers: 3}
	nextStop, nextRegisters := token, token
	nextStop.Stop++
	nextRegisters.Registers++
	if token == nextStop || token == nextRegisters {
		t.Fatal("stopped intervals and register revisions must be distinguishable")
	}
}

func TestMemoryTokenSeparatesAddressSpacesAndRevisions(t *testing.T) {
	token := target.MemoryToken{Space: target.SpaceRef{Session: 4, ID: 2}, Revision: 8}
	nextSpace, nextRevision := token, token
	nextSpace.Space.ID++
	nextRevision.Revision++
	if token == nextSpace || token == nextRevision {
		t.Fatal("memory identities and revisions must be distinguishable")
	}
}

func TestThreadSnapshotsDoNotInventObservations(t *testing.T) {
	var snapshot target.Snapshot
	var event target.Event
	var capabilities target.Capabilities
	if snapshot.Sequence != 0 || snapshot.State != target.StateUnknown || snapshot.Threads != nil {
		t.Fatal("zero snapshot must not invent observed state")
	}
	if event.Kind != target.EventUnknown || event.Thread != (target.ThreadRef{}) {
		t.Fatal("zero event must not identify a real thread or event")
	}
	if len(capabilities.Modes) != 0 || capabilities.ThreadControl || capabilities.HardwareWatchpoints {
		t.Fatal("zero capabilities must not claim support")
	}
}

func TestEventKinds(t *testing.T) {
	for _, test := range []struct {
		kind target.EventKind
		want string
	}{
		{target.EventUnknown, "unknown"},
		{target.EventThreadCreated, "thread-created"},
		{target.EventThreadExited, "thread-exited"},
		{target.EventThreadStopped, "thread-stopped"},
		{target.EventThreadResumed, "thread-resumed"},
		{target.EventProcessExec, "process-exec"},
		{target.EventAllStopped, "all-stopped"},
		{target.EventSessionClosed, "session-closed"},
		{target.EventKind(255), "unknown"},
	} {
		if got := test.kind.String(); got != test.want {
			t.Errorf("kind %d: got %q, want %q", test.kind, got, test.want)
		}
	}
	if target.StopGroupStop.String() != "group-stop" {
		t.Fatal("group stop must remain distinct from signal delivery")
	}
}

func TestEventGapIsExplicitAndStale(t *testing.T) {
	err := &target.EventGapError{After: 3, First: 8, Last: 12}
	if !errors.Is(err, target.ErrEventGap) || !errors.Is(err, target.ErrStale) || errors.Is(err, target.ErrClosed) {
		t.Fatalf("unexpected error classification: %v", err)
	}
	if got, want := err.Error(), "events after 3 are unavailable; retained 8 through 12: event history gap"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
