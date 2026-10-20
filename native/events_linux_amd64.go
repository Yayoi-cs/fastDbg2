package native

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"fastdbg2/target"
)

const eventJournalCapacity = 256

type eventJournal struct {
	mu       sync.Mutex
	limit    int
	entries  []target.Event
	head     int
	count    int
	sequence uint64
	changed  chan struct{}
}

func (journal *eventJournal) initializeLocked() {
	if journal.changed == nil {
		journal.changed = make(chan struct{})
	}
	if journal.entries == nil {
		if journal.limit <= 0 {
			journal.limit = eventJournalCapacity
		}
		journal.entries = make([]target.Event, journal.limit)
	}
}

func (journal *eventJournal) append(event target.Event) uint64 {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.initializeLocked()
	journal.sequence++
	event.Sequence = journal.sequence
	event = copyEvent(event)
	if journal.count < len(journal.entries) {
		journal.entries[(journal.head+journal.count)%len(journal.entries)] = event
		journal.count++
	} else {
		journal.entries[journal.head] = event
		journal.head = (journal.head + 1) % len(journal.entries)
	}
	close(journal.changed)
	journal.changed = make(chan struct{})
	return event.Sequence
}

func (journal *eventJournal) nextLocked(after uint64) (target.Event, bool, error) {
	if after > journal.sequence {
		return target.Event{}, false, fmt.Errorf("event cursor %d exceeds sequence %d: %w", after, journal.sequence, target.ErrInvalidArgument)
	}
	if journal.count == 0 {
		return target.Event{}, false, nil
	}
	first := journal.sequence - uint64(journal.count) + 1
	if after < first-1 {
		return target.Event{}, false, &target.EventGapError{After: after, First: first, Last: journal.sequence}
	}
	if after == journal.sequence {
		return target.Event{}, false, nil
	}
	index := (journal.head + int(after+1-first)) % len(journal.entries)
	return copyEvent(journal.entries[index]), true, nil
}

func (journal *eventJournal) next(ctx context.Context, done <-chan struct{}, after uint64) (target.Event, error) {
	if ctx == nil {
		return target.Event{}, target.ErrInvalidArgument
	}
	for {
		journal.mu.Lock()
		journal.initializeLocked()
		event, found, err := journal.nextLocked(after)
		changed := journal.changed
		journal.mu.Unlock()
		if err != nil || found {
			return event, err
		}
		select {
		case <-ctx.Done():
			return target.Event{}, ctx.Err()
		case <-changed:
		case <-done:
			journal.mu.Lock()
			event, found, err = journal.nextLocked(after)
			journal.mu.Unlock()
			if err != nil || found {
				return event, err
			}
			return target.Event{}, target.ErrClosed
		}
	}
}

func (s *Session) NextEvent(ctx context.Context, after uint64) (target.Event, error) {
	return s.events.next(ctx, s.done, after)
}

func (s *Session) publishEvent(event target.Event) uint64 {
	return s.events.append(event)
}

func copyEvent(event target.Event) target.Event {
	event.Stop = copyStop(event.Stop)
	return event
}

func copySnapshot(snapshot target.Snapshot) target.Snapshot {
	snapshot.Threads = slices.Clone(snapshot.Threads)
	for index := range snapshot.Threads {
		snapshot.Threads[index].Stop = copyStop(snapshot.Threads[index].Stop)
	}
	return snapshot
}

func copyThreadSet(set target.ThreadSet) target.ThreadSet {
	set.Threads = slices.Clone(set.Threads)
	return set
}

func copyRunRequest(request target.RunRequest) target.RunRequest {
	request.Threads = copyThreadSet(request.Threads)
	request.Signals = slices.Clone(request.Signals)
	return request
}

func copyStepRequest(request target.StepRequest) target.StepRequest {
	request.Continue = copyThreadSet(request.Continue)
	request.Signals = slices.Clone(request.Signals)
	return request
}
