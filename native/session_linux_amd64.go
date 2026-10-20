package native

import (
	"context"
	"fastdbg2/target"
	"fmt"
	"slices"
	"sync/atomic"
)

type Session struct {
	id           uint64
	requests     chan func(*engine)
	done         chan struct{}
	pid          int
	architecture target.Architecture
	state        atomic.Uint32
	last         atomic.Pointer[target.Stop]
	events       eventJournal
}

var sessionSequence atomic.Uint64

type response[T any] struct {
	value T
	err   error
}

func Launch(path string, args ...string) (*Session, error) {
	return openSession(func(e *engine) error { return e.launch(path, args) })
}

func Attach(pid int) (*Session, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("attach PID %d: %w", pid, target.ErrInvalidArgument)
	}
	return openSession(func(e *engine) error { return e.attach(pid) })
}

func openSession(start func(*engine) error) (*Session, error) {
	s := &Session{id: sessionSequence.Add(1), requests: make(chan func(*engine)), done: make(chan struct{})}
	ready := make(chan response[*Session], 1)
	go s.worker(start, ready)
	return awaitSession(s, ready)
}

func awaitSession(s *Session, ready <-chan response[*Session]) (*Session, error) {
	r := <-ready
	if r.err != nil && r.value == nil {
		<-s.done
	}
	return r.value, r.err
}

func call[T any](s *Session, f func(*engine) (T, error)) (T, error) {
	r := make(chan response[T], 1)
	select {
	case s.requests <- func(e *engine) {
		v, err := f(e)
		r <- response[T]{v, err}
	}:
	case <-s.done:
		var zero T
		return zero, target.ErrClosed
	}
	select {
	case result := <-r:
		return result.value, result.err
	case <-s.done:
		select {
		case result := <-r:
			return result.value, result.err
		default:
			var zero T
			return zero, target.ErrClosed
		}
	}
}

func command(s *Session, f func(*engine) error) error {
	_, err := call(s, func(e *engine) (struct{}, error) { return struct{}{}, f(e) })
	return err
}

func (s *Session) PID() int { return s.pid }

func (s *Session) Architecture() target.Architecture {
	architecture, err := call(s, func(e *engine) (target.Architecture, error) {
		return e.snapshot().Architecture, nil
	})
	if err != nil {
		return s.architecture
	}
	return architecture
}

func (s *Session) State() target.State { return target.State(s.state.Load()) }

func (s *Session) LastStop() target.Stop {
	if stop := s.last.Load(); stop != nil {
		return copyStop(*stop)
	}
	return target.Stop{}
}

func (s *Session) Capabilities() target.Capabilities {
	return target.Capabilities{
		Modes:                    []target.ExecutionMode{target.AllStop},
		ThreadControl:            true,
		InstructionStep:          true,
		SoftwareBreakpoints:      true,
		HardwareWatchpoints:      true,
		WatchpointSlotsPerThread: 4,
		WatchpointSizes:          []int{1, 2, 4, 8},
	}
}

func (s *Session) SetWatchpoint(token target.ThreadToken, request target.WatchpointRequest) (target.WatchpointResult, error) {
	return call(s, func(e *engine) (target.WatchpointResult, error) {
		return e.setWatchpoint(token, request)
	})
}

func (s *Session) ClearWatchpoint(token target.ThreadToken, ref target.WatchpointRef) (target.ThreadToken, error) {
	return call(s, func(e *engine) (target.ThreadToken, error) {
		return e.clearWatchpoint(token, ref)
	})
}

func (s *Session) Snapshot() (target.Snapshot, error) {
	return call(s, func(e *engine) (target.Snapshot, error) {
		return copySnapshot(e.snapshot()), nil
	})
}

func (s *Session) Threads() ([]target.ThreadInfo, error) {
	snapshot, err := s.Snapshot()
	return snapshot.Threads, err
}

func (s *Session) Run(request target.RunRequest) (*Run, error) {
	request = copyRunRequest(request)
	return call(s, func(e *engine) (*Run, error) { return e.startRun(request) })
}

func (s *Session) StepInstruction(request target.StepRequest) (*Run, error) {
	request = copyStepRequest(request)
	return call(s, func(e *engine) (*Run, error) { return e.startStep(request) })
}

func (s *Session) Continue(signal target.Signal) (target.Stop, error) {
	return s.run(false, signal)
}

func (s *Session) Step(signal target.Signal) (target.Stop, error) {
	return s.run(true, signal)
}

func (s *Session) run(step bool, signal target.Signal) (target.Stop, error) {
	run, err := call(s, func(e *engine) (*Run, error) { return e.startLegacyRun(step, signal) })
	if err != nil {
		return target.Stop{}, err
	}
	result, err := run.Wait(context.Background())
	return result.Stop, err
}

func (s *Session) Interrupt(requests ...target.InterruptRequest) error {
	if len(requests) > 1 {
		return target.ErrInvalidArgument
	}
	if len(requests) == 0 {
		return command(s, func(e *engine) error { return e.interruptLegacy() })
	}
	set := copyThreadSet(requests[0].Threads)
	return command(s, func(e *engine) error { return e.interrupt(set) })
}

func (s *Session) Close() error { return s.shutdown("close") }

func (s *Session) Kill() error { return s.shutdown("kill") }

func (s *Session) Detach() error { return s.shutdown("detach") }

func (s *Session) shutdown(kind string) error {
	r := make(chan error, 1)
	select {
	case s.requests <- func(e *engine) { e.beginShutdown(kind, r) }:
	case <-s.done:
		if kind == "close" {
			return nil
		}
		return target.ErrClosed
	}
	select {
	case err := <-r:
		if kind == "close" && err == nil {
			<-s.done
		}
		return err
	case <-s.done:
		select {
		case err := <-r:
			return err
		default:
			if kind == "close" && s.State() == target.StateClosed {
				return nil
			}
			return target.ErrClosed
		}
	}
}

func copyStop(s target.Stop) target.Stop {
	s.Watchpoints = slices.Clone(s.Watchpoints)
	if s.RawDR6 != nil {
		value := *s.RawDR6
		s.RawDR6 = &value
	}
	if s.ThreadID != nil {
		v := *s.ThreadID
		s.ThreadID = &v
	}
	if s.RawPC != nil {
		v := *s.RawPC
		s.RawPC = &v
	}
	if s.ExitCode != nil {
		v := *s.ExitCode
		s.ExitCode = &v
	}
	if s.Breakpoint != nil {
		v := *s.Breakpoint
		s.Breakpoint = &v
	}
	return s
}
