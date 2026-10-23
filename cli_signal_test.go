package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestConsoleSignalsIdleInterrupt(t *testing.T) {
	s := newConsoleSignals(context.Background())
	defer s.Close()
	s.route(os.Interrupt)
	s.route(syscall.SIGHUP)
	if err := s.ctx.Err(); err != nil {
		t.Fatalf("idle interrupt canceled the console: %v", err)
	}
	ctx, end := s.beginCommand()
	end()
	s.route(os.Interrupt)
	if !errors.Is(ctx.Err(), context.Canceled) || s.ctx.Err() != nil {
		t.Fatalf("late interrupt changed console lifetime: command=%v console=%v", ctx.Err(), s.ctx.Err())
	}
}

func TestConsoleSignalsInterruptOnlyCurrentCommand(t *testing.T) {
	s := newConsoleSignals(context.Background())
	defer s.Close()
	first, endFirst := s.beginCommand()
	s.route(os.Interrupt)
	if !errors.Is(first.Err(), context.Canceled) || s.ctx.Err() != nil {
		t.Fatalf("interrupt cancellation: command=%v console=%v", first.Err(), s.ctx.Err())
	}
	endFirst()
	next, endNext := s.beginCommand()
	defer endNext()
	endFirst()
	if next.Err() != nil {
		t.Fatalf("old command end canceled new command: %v", next.Err())
	}
	s.route(os.Interrupt)
	if !errors.Is(next.Err(), context.Canceled) || s.ctx.Err() != nil {
		t.Fatalf("next command cancellation: command=%v console=%v", next.Err(), s.ctx.Err())
	}
}

func TestConsoleSignalsPipeDoesNotCancelContexts(t *testing.T) {
	s := newConsoleSignals(context.Background())
	defer s.Close()
	s.route(syscall.SIGPIPE)
	ctx, end := s.beginCommand()
	defer end()
	s.route(syscall.SIGPIPE)
	if err := s.ctx.Err(); err != nil {
		t.Fatalf("SIGPIPE canceled the console: %v", err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("SIGPIPE canceled the current command: %v", err)
	}
	s.route(os.Interrupt)
	if !errors.Is(ctx.Err(), context.Canceled) || s.ctx.Err() != nil {
		t.Fatalf("SIGPIPE changed interrupt behavior: command=%v console=%v", ctx.Err(), s.ctx.Err())
	}
}

func TestConsoleSignalsBrokenStdoutReturnsError(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		output.Close()
		t.Fatal(err)
	}
	defer output.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestConsoleSignalsBrokenStdoutProcess$")
	command.Env = append(os.Environ(), "FASTDBG2_SIGNAL_BROKEN_STDOUT_PROCESS=1")
	command.Stdout = output
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	if err := command.Run(); err != nil {
		t.Fatalf("broken stdout terminated process before cleanup: %v; %s", err, diagnostics.String())
	}
	if diagnostics.String() != "BROKEN_STDOUT_RETURNED\n" {
		t.Fatalf("broken stdout did not return EPIPE: %q", diagnostics.String())
	}
}

func TestConsoleSignalsBrokenStdoutProcess(t *testing.T) {
	if os.Getenv("FASTDBG2_SIGNAL_BROKEN_STDOUT_PROCESS") != "1" {
		return
	}
	signals := newConsoleSignals(context.Background())
	_, err := os.Stdout.Write([]byte("closed-pipe output\n"))
	if !errors.Is(err, syscall.EPIPE) || signals.ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "unexpected broken stdout result: write=%v context=%v\n", err, signals.ctx.Err())
		signals.Close()
		os.Exit(2)
	}
	signals.Close()
	fmt.Fprintln(os.Stderr, "BROKEN_STDOUT_RETURNED")
	os.Exit(0)
}

func TestConsoleSignalsTerminate(t *testing.T) {
	s := newConsoleSignals(context.Background())
	defer s.Close()
	ctx, end := s.beginCommand()
	defer end()
	s.route(syscall.SIGTERM)
	if !errors.Is(ctx.Err(), context.Canceled) || !errors.Is(s.ctx.Err(), context.Canceled) {
		t.Fatalf("termination did not cancel both contexts: command=%v console=%v", ctx.Err(), s.ctx.Err())
	}
}

func TestConsoleSignalsParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	s := newConsoleSignals(parent)
	defer s.Close()
	ctx, end := s.beginCommand()
	defer end()
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) || !errors.Is(s.ctx.Err(), context.Canceled) {
		t.Fatalf("parent cancellation did not propagate: command=%v console=%v", ctx.Err(), s.ctx.Err())
	}
}

func TestConsoleSignalsReceiveInterrupt(t *testing.T) {
	s := newConsoleSignals(context.Background())
	defer s.Close()
	ctx, end := s.beginCommand()
	defer end()
	s.signals <- os.Interrupt
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("signal receiver did not cancel command")
	}
	if s.ctx.Err() != nil {
		t.Fatalf("signal receiver canceled console: %v", s.ctx.Err())
	}
}

func TestConsoleSignalsReceiveTermination(t *testing.T) {
	s := newConsoleSignals(context.Background())
	defer s.Close()
	s.signals <- syscall.SIGTERM
	select {
	case <-s.stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("signal receiver did not terminate")
	}
	if !errors.Is(s.ctx.Err(), context.Canceled) {
		t.Fatalf("signal receiver did not cancel console: %v", s.ctx.Err())
	}
}

func TestConsoleSignalsConcurrentRoutingAndClose(t *testing.T) {
	s := newConsoleSignals(context.Background())
	var group sync.WaitGroup
	group.Go(func() {
		for range 1000 {
			_, end := s.beginCommand()
			end()
		}
	})
	group.Go(func() {
		for range 1000 {
			s.route(os.Interrupt)
		}
	})
	for range 4 {
		group.Go(s.Close)
	}
	group.Wait()
	if !errors.Is(s.ctx.Err(), context.Canceled) {
		t.Fatalf("close did not cancel console: %v", s.ctx.Err())
	}
}
