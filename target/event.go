package target

import (
	"errors"
	"fmt"
)

type EventKind uint8

const (
	EventUnknown EventKind = iota
	EventThreadCreated
	EventThreadExited
	EventThreadStopped
	EventThreadResumed
	EventProcessExec
	EventAllStopped
	EventSessionClosed
)

func (kind EventKind) String() string {
	switch kind {
	case EventThreadCreated:
		return "thread-created"
	case EventThreadExited:
		return "thread-exited"
	case EventThreadStopped:
		return "thread-stopped"
	case EventThreadResumed:
		return "thread-resumed"
	case EventProcessExec:
		return "process-exec"
	case EventAllStopped:
		return "all-stopped"
	case EventSessionClosed:
		return "session-closed"
	default:
		return "unknown"
	}
}

type Event struct {
	Sequence uint64
	Kind     EventKind
	Thread   ThreadRef
	RunID    uint64
	Stop     Stop
}

var ErrEventGap = errors.New("event history gap")

type EventGapError struct {
	After uint64
	First uint64
	Last  uint64
}

func (err *EventGapError) Error() string {
	return fmt.Sprintf("events after %d are unavailable; retained %d through %d: %v", err.After, err.First, err.Last, ErrEventGap)
}

func (err *EventGapError) Is(target error) bool {
	return target == ErrEventGap || target == ErrStale
}
