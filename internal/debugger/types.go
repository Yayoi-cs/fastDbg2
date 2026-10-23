package debugger

import (
	"context"
	"fmt"
	"io"

	"fastdbg2/display"
	"fastdbg2/native"
	"fastdbg2/target"
)

type operation interface {
	Wait(context.Context) (target.RunResult, error)
}

type session interface {
	PID() int
	State() target.State
	Snapshot() (target.Snapshot, error)
	LastStop() target.Stop
	Run(target.RunRequest) (operation, error)
	StepInstruction(target.StepRequest) (operation, error)
	Interrupt(target.InterruptRequest) error
	ReadThreadRegisters(target.ThreadToken) ([]target.Register, error)
	ReadSpaceMemory(target.MemoryToken, target.Address, []byte) (int, error)
	ReadCodeLocation(target.ThreadToken) (native.CodeLocation, error)
	ReadCodeMemory(target.MemoryToken, target.Address, []byte) (int, error)
	AddBreakpoint(target.Address) error
	RemoveBreakpoint(target.Address) error
	Kill() error
	Detach() error
	Close() error
}

type breakpoint struct {
	id         uint64
	expression string
	kind       breakpointKind
	enabled    bool
	address    target.Address
	space      target.SpaceRef
	installed  bool
	attempted  bool
	err        error
}

type Controller struct {
	session          session
	snapshot         target.Snapshot
	selected         target.ThreadRef
	path             string
	args             []string
	owned            bool
	out              io.Writer
	pager            *commandPager
	renderer         display.Renderer
	image            imageState
	active           operation
	schedulerLocking string
	contextDisabled  bool
	contextScreen    bool
	registerHistory  map[uiRegisterIdentity]uiRegisterHistory
	breakpoints      []*breakpoint
	loaderBreakpoint *loaderBreakpointState
	watchpoints      []*watchRecord
	nextBreakpoint   uint64
	launch           func(string, []string) (session, error)
	attach           func(int) (session, error)
}

type OutputError struct {
	Err error
}

func (e *OutputError) Error() string { return fmt.Sprintf("debugger output: %v", e.Err) }

func (e *OutputError) Unwrap() error { return e.Err }

func (c *Controller) writef(format string, args ...any) error {
	if c.out == nil {
		return &OutputError{Err: fmt.Errorf("output writer is required: %w", target.ErrInvalidArgument)}
	}
	text := fmt.Sprintf(format, args...)
	n, err := io.WriteString(c.out, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &OutputError{Err: err}
	}
	return nil
}
