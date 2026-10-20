package target

import (
	"errors"
	"fmt"
)

var (
	ErrUnsupported     = errors.New("unsupported")
	ErrUnknown         = errors.New("unknown")
	ErrUnavailable     = errors.New("unavailable")
	ErrAmbiguous       = errors.New("ambiguous")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrInvalidState    = errors.New("invalid state")
	ErrNotFound        = errors.New("not found")
	ErrOverflow        = errors.New("overflow")
	ErrClosed          = errors.New("session closed")
	ErrRunning         = errors.New("target running")
	ErrBusy            = errors.New("operation in progress")
	ErrExited          = errors.New("target exited")
	ErrDetached        = errors.New("target detached")
	ErrStale           = errors.New("stale state")
	ErrPartial         = errors.New("partial operation")
)

type PartialError struct {
	Op        string
	Completed int
	Total     int
	Err       error
}

func (e *PartialError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %d of %d confirmed: %v", e.Op, e.Completed, e.Total, ErrPartial)
	}
	return fmt.Sprintf("%s: %d of %d confirmed: %v", e.Op, e.Completed, e.Total, e.Err)
}

func (e *PartialError) Is(err error) bool {
	return err == ErrPartial
}

func (e *PartialError) Unwrap() error {
	return e.Err
}
