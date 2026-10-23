package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type commandCancellation struct {
	cancel context.CancelFunc
}

type consoleSignals struct {
	ctx     context.Context
	cancel  context.CancelFunc
	signals chan os.Signal
	done    chan struct{}
	stopped chan struct{}
	mu      sync.Mutex
	command *commandCancellation
	once    sync.Once
}

func newConsoleSignals(parent context.Context) *consoleSignals {
	ctx, cancel := context.WithCancel(parent)
	s := &consoleSignals{
		ctx:     ctx,
		cancel:  cancel,
		signals: make(chan os.Signal, 8),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	signal.Notify(s.signals, os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE)
	go func() {
		defer close(s.stopped)
		for {
			select {
			case received := <-s.signals:
				s.route(received)
			case <-s.done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return s
}

func (s *consoleSignals) route(received os.Signal) {
	switch received {
	case os.Interrupt:
		s.mu.Lock()
		if s.command != nil {
			s.command.cancel()
		}
		s.mu.Unlock()
	case syscall.SIGTERM:
		s.cancel()
	}
}

func (s *consoleSignals) beginCommand() (context.Context, func()) {
	ctx, cancel := context.WithCancel(s.ctx)
	command := &commandCancellation{cancel: cancel}
	s.mu.Lock()
	s.command = command
	s.mu.Unlock()
	return ctx, sync.OnceFunc(func() {
		s.mu.Lock()
		if s.command == command {
			s.command = nil
		}
		s.mu.Unlock()
		cancel()
	})
}

func (s *consoleSignals) Close() {
	s.once.Do(func() {
		signal.Stop(s.signals)
		close(s.done)
		<-s.stopped
		s.cancel()
	})
}
