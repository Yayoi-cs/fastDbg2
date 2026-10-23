package debugger

import (
	"context"
	"errors"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/native"
	"fastdbg2/target"
)

type promptSession struct {
	*controllerTestSession
	location native.CodeLocation
	err      error
	read     func(target.ThreadToken)
}

func (s *promptSession) ReadCodeLocation(token target.ThreadToken) (native.CodeLocation, error) {
	if s.read != nil {
		s.read(token)
	}
	return s.location, s.err
}

func promptController() (*Controller, *promptSession) {
	base := controllerSession(73)
	session := &promptSession{controllerTestSession: base, location: native.CodeLocation{RawPC: 0x401001, InstructionPC: 0x401000}}
	return &Controller{session: session, selected: base.snapshot.Threads[0].Ref}, session
}

func TestPromptUsesOnlyConfirmedInstructionPC(t *testing.T) {
	c, s := promptController()
	s.read = func(token target.ThreadToken) {
		if token != s.snapshot.Threads[0].Token {
			t.Fatalf("wrong prompt token: %+v", token)
		}
	}
	if got := c.Prompt(); got != "[fastDbg2:0x401000]$ " {
		t.Fatalf("prompt used raw or guessed PC: %q", got)
	}
	s.location.InstructionPC = 0
	if got := c.Prompt(); got != "[fastDbg2:0x0]$ " {
		t.Fatalf("valid zero instruction PC was hidden: %q", got)
	}
}

func TestPromptDoesNotClaimUnavailableOrStalePC(t *testing.T) {
	tests := map[string]func(*Controller, *promptSession){
		"no session": func(c *Controller, _ *promptSession) { c.session = nil },
		"active": func(c *Controller, _ *promptSession) {
			c.active = controllerTestOperation(func(context.Context) (target.RunResult, error) { return target.RunResult{}, nil })
		},
		"snapshot error": func(_ *Controller, s *promptSession) { s.snapshotError = errors.New("snapshot unavailable") },
		"running":        func(_ *Controller, s *promptSession) { s.snapshot.State = target.StateRunning },
		"exited":         func(_ *Controller, s *promptSession) { s.snapshot.State = target.StateExited },
		"unselected":     func(c *Controller, _ *promptSession) { c.selected = target.ThreadRef{} },
		"exiting":        func(_ *Controller, s *promptSession) { s.snapshot.Threads[0].Exiting = true },
		"listening":      func(_ *Controller, s *promptSession) { s.snapshot.Threads[0].Listening = true },
		"core unavailable": func(_ *Controller, s *promptSession) {
			s.err = target.ErrUnavailable
		},
		"sequence changed": func(_ *Controller, s *promptSession) {
			s.read = func(target.ThreadToken) { s.snapshot.Sequence++ }
		},
		"register token changed": func(_ *Controller, s *promptSession) {
			s.read = func(target.ThreadToken) { s.snapshot.Threads[0].Token.Registers++ }
		},
		"memory changed": func(_ *Controller, s *promptSession) {
			s.read = func(target.ThreadToken) { s.snapshot.Memory.Revision++ }
		},
		"second snapshot error": func(_ *Controller, s *promptSession) {
			s.read = func(target.ThreadToken) { s.snapshotError = target.ErrStale }
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c, s := promptController()
			change(c, s)
			if got := c.Prompt(); got != "[fastDbg2]$ " {
				t.Fatalf("unconfirmed PC displayed: %q", got)
			}
		})
	}
}

func TestPromptUsesSelectedThreadAndColorPolicy(t *testing.T) {
	c, s := promptController()
	thread := s.snapshot.Threads[0]
	thread.Ref.ID++
	thread.Token.Thread = thread.Ref
	thread.TID++
	s.snapshot.Threads = append(s.snapshot.Threads, thread)
	c.selected = thread.Ref
	s.read = func(token target.ThreadToken) {
		if token != thread.Token {
			t.Fatal("prompt read an unselected thread")
		}
	}
	c.renderer, _ = display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if got := c.Prompt(); !strings.Contains(got, "\x1b[36mfastDbg2\x1b[0m") || !strings.Contains(got, "\x1b[36m0x401000\x1b[0m") {
		t.Fatalf("colored legacy prompt: %q", got)
	}
	c.renderer, _ = display.NewRenderer(display.Options{Mode: display.ColorAuto, IsTerminal: true, NoColor: "1"})
	if got := c.Prompt(); got != "[fastDbg2:0x401000]$ " {
		t.Fatalf("NO_COLOR prompt: %q", got)
	}
}
