package native

import (
	"context"
	"errors"
	"slices"
	"testing"

	"fastdbg2/target"
)

func TestEventJournalBoundsAndReportsGap(t *testing.T) {
	journal := eventJournal{limit: 2}
	for sequence := uint64(1); sequence <= 4; sequence++ {
		if got := journal.append(target.Event{Sequence: 1000, Kind: target.EventThreadStopped}); got != sequence {
			t.Fatalf("sequence=%d, want %d", got, sequence)
		}
	}
	_, err := journal.next(context.Background(), nil, 0)
	var gap *target.EventGapError
	if !errors.As(err, &gap) || gap.After != 0 || gap.First != 3 || gap.Last != 4 {
		t.Fatalf("gap=%+v err=%v", gap, err)
	}
	for after := uint64(2); after < 4; after++ {
		event, err := journal.next(context.Background(), nil, after)
		if err != nil || event.Sequence != after+1 {
			t.Fatalf("after=%d event=%+v err=%v", after, event, err)
		}
	}
	if len(journal.entries) != 2 || journal.count != 2 {
		t.Fatalf("retained %d of %d", journal.count, len(journal.entries))
	}
	if _, err := journal.next(context.Background(), nil, 5); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("future cursor: %v", err)
	}
}

func TestEventJournalCopiesPublishedAndReturnedValues(t *testing.T) {
	var journal eventJournal
	pc := target.Address(0x1234)
	journal.append(target.Event{Kind: target.EventThreadStopped, Stop: target.Stop{RawPC: &pc}})
	pc = 0
	first, err := journal.next(context.Background(), nil, 0)
	if err != nil || *first.Stop.RawPC != 0x1234 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	*first.Stop.RawPC = 1
	second, err := journal.next(context.Background(), nil, 0)
	if err != nil || *second.Stop.RawPC != 0x1234 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
}

func TestEventJournalWaitersDoNotConsumeEachOthersEvents(t *testing.T) {
	var journal eventJournal
	const count = 8
	results := make(chan response[target.Event], count)
	for range count {
		go func() {
			event, err := journal.next(context.Background(), nil, 0)
			results <- response[target.Event]{value: event, err: err}
		}()
	}
	journal.append(target.Event{Kind: target.EventAllStopped, RunID: 3})
	for range count {
		result := <-results
		if result.err != nil || result.value.Sequence != 1 || result.value.RunID != 3 {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestEventJournalCancellationAndClose(t *testing.T) {
	var journal eventJournal
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := journal.next(ctx, nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	done := make(chan struct{})
	journal.append(target.Event{Kind: target.EventSessionClosed})
	close(done)
	event, err := journal.next(context.Background(), done, 0)
	if err != nil || event.Kind != target.EventSessionClosed {
		t.Fatalf("terminal event=%+v err=%v", event, err)
	}
	if _, err := journal.next(context.Background(), done, 1); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
	if _, err := journal.next(nil, done, 1); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context: %v", err)
	}
}

func TestEventJournalDoesNotBlockOnSlowConsumers(t *testing.T) {
	journal := eventJournal{limit: 4}
	for range 10000 {
		journal.append(target.Event{Kind: target.EventThreadResumed})
	}
	if journal.sequence != 10000 || journal.count != 4 {
		t.Fatalf("sequence=%d retained=%d", journal.sequence, journal.count)
	}
	if _, err := journal.next(context.Background(), nil, 0); !errors.Is(err, target.ErrEventGap) {
		t.Fatalf("slow consumer: %v", err)
	}
}

func TestRequestsAndSnapshotsCopyCallerSlices(t *testing.T) {
	thread := target.ThreadRef{Session: 3, ID: 4}
	request := target.RunRequest{
		Threads: target.ThreadSet{Threads: []target.ThreadRef{thread}},
		Signals: []target.ThreadSignal{{Thread: thread, Stop: 8}},
	}
	cloned := copyRunRequest(request)
	request.Threads.Threads[0].ID++
	request.Signals[0].Stop++
	if cloned.Threads.Threads[0] != thread || cloned.Signals[0].Stop != 8 {
		t.Fatal("run request retained caller-owned slices")
	}
	step := target.StepRequest{Thread: thread, Continue: cloned.Threads, Signals: cloned.Signals}
	clonedStep := copyStepRequest(step)
	step.Continue.Threads[0].ID++
	step.Signals[0].Stop++
	if clonedStep.Continue.Threads[0] != thread || clonedStep.Signals[0].Stop != 8 {
		t.Fatal("step request retained caller-owned slices")
	}
	pc := target.Address(0x1234)
	snapshot := target.Snapshot{Threads: []target.ThreadInfo{{Ref: thread, Stop: target.Stop{RawPC: &pc}}}}
	clonedSnapshot := copySnapshot(snapshot)
	snapshot.Threads[0].Ref.ID++
	pc++
	if clonedSnapshot.Threads[0].Ref != thread || *clonedSnapshot.Threads[0].Stop.RawPC != 0x1234 {
		t.Fatal("snapshot retained mutable owner state")
	}
}

func TestNativeCapabilitiesOnlyAdvertiseImplementedExecution(t *testing.T) {
	session := &Session{}
	capabilities := session.Capabilities()
	if len(capabilities.Modes) != 1 || capabilities.Modes[0] != target.AllStop || !capabilities.ThreadControl || !capabilities.HardwareWatchpoints {
		t.Fatalf("capabilities=%+v", capabilities)
	}
	if capabilities.WatchpointSlotsPerThread != 4 || !slices.Equal(capabilities.WatchpointSizes, []int{1, 2, 4, 8}) {
		t.Fatalf("watchpoint geometry=%+v", capabilities)
	}
	if !capabilities.HardwareBreakpoints || capabilities.HardwareSlotsPerThread != 4 || capabilities.HardwareSlotsPerThread != capabilities.WatchpointSlotsPerThread {
		t.Fatalf("hardware execution and data breakpoints must share four slots: %+v", capabilities)
	}
	formats := []target.ExtendedRegisterFormat{target.ExtendedFormatXSave, target.ExtendedFormatFXSave}
	if !capabilities.ExtendedRegisters || !slices.Equal(capabilities.ExtendedRegisterFormats, formats) {
		t.Fatalf("extended register formats=%+v", capabilities)
	}
	capabilities.Modes[0] = target.NonStop
	capabilities.WatchpointSizes[0] = 16
	capabilities.ExtendedRegisterFormats[0] = target.ExtendedFormatUnknown
	if session.Capabilities().Modes[0] != target.AllStop {
		t.Fatal("capabilities retained caller-owned mode slice")
	}
	if !slices.Equal(session.Capabilities().WatchpointSizes, []int{1, 2, 4, 8}) {
		t.Fatal("capabilities retained caller-owned watchpoint geometry")
	}
	if !slices.Equal(session.Capabilities().ExtendedRegisterFormats, formats) {
		t.Fatal("capabilities retained caller-owned extended register formats")
	}
}
