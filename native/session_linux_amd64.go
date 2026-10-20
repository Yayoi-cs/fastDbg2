package native

import (
	"fastdbg2/target"
	"fmt"
	"sync/atomic"
)

type Session struct {
	requests     chan func(*engine)
	done         chan struct{}
	pid          int
	architecture target.Architecture
	state        atomic.Uint32
	last         atomic.Pointer[target.Stop]
}

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
	s := &Session{requests: make(chan func(*engine)), done: make(chan struct{})}
	ready := make(chan response[*Session], 1)
	go s.worker(start, ready)
	r := <-ready
	if r.err != nil {
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

func (s *Session) Architecture() target.Architecture { return s.architecture }

func (s *Session) State() target.State { return target.State(s.state.Load()) }

func (s *Session) LastStop() target.Stop {
	if stop := s.last.Load(); stop != nil {
		return copyStop(*stop)
	}
	return target.Stop{}
}

func (s *Session) Continue(signal target.Signal) (target.Stop, error) {
	return s.run(false, signal)
}

func (s *Session) Step(signal target.Signal) (target.Stop, error) {
	return s.run(true, signal)
}

func (s *Session) run(step bool, signal target.Signal) (target.Stop, error) {
	r := make(chan response[target.Stop], 1)
	select {
	case s.requests <- func(e *engine) { e.beginRun(step, signal, r) }:
	case <-s.done:
		return target.Stop{}, target.ErrClosed
	}
	select {
	case result := <-r:
		return result.value, result.err
	case <-s.done:
		select {
		case result := <-r:
			return result.value, result.err
		default:
			return s.LastStop(), target.ErrClosed
		}
	}
}

func (s *Session) Interrupt() error {
	return command(s, func(e *engine) error { return e.interrupt() })
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
			return nil
		}
	}
}

func copyStop(s target.Stop) target.Stop {
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
