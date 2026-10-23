package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

type breakpointCommandSession struct {
	*controllerTestSession
	afterAdd    func(target.Address) error
	afterRemove func(target.Address) error
}

func (s *breakpointCommandSession) AddBreakpoint(address target.Address) error {
	if err := s.controllerTestSession.AddBreakpoint(address); err != nil {
		return err
	}
	if s.afterAdd != nil {
		return s.afterAdd(address)
	}
	return nil
}

func (s *breakpointCommandSession) RemoveBreakpoint(address target.Address) error {
	if err := s.controllerTestSession.RemoveBreakpoint(address); err != nil {
		return err
	}
	if s.afterRemove != nil {
		return s.afterRemove(address)
	}
	return nil
}

func breakpointCommandController(t *testing.T, out io.Writer) (*Controller, *breakpointCommandSession) {
	t.Helper()
	c, base := runningController(t, out)
	s := &breakpointCommandSession{controllerTestSession: base}
	c.session = s
	return c, s
}

func TestBreakpointCommandsDisabledPendingSurvivesRestart(t *testing.T) {
	c := configuredController(t, io.Discard)
	var sessions []*controllerTestSession
	c.launch = func(string, []string) (session, error) {
		s := controllerSession(uint64(len(sessions) + 1))
		sessions = append(sessions, s)
		return s, nil
	}
	executeController(t, c, "break", "$rip + 4")
	executeController(t, c, "break", "1 +")
	executeController(t, c, "disable", "2")
	executeController(t, c, "start", "")
	if len(sessions[0].added) != 1 || !c.breakpoints[0].enabled || c.breakpoints[1].enabled || c.breakpoints[1].err != nil {
		t.Fatalf("added=%v breakpoints=%+v", sessions[0].added, c.breakpoints)
	}
	executeController(t, c, "disable", "1")
	executeController(t, c, "run", "")
	if len(sessions[1].added) != 0 || sessions[1].runCalls != 1 {
		t.Fatalf("disabled breakpoints were installed: %+v", sessions[1])
	}
	for _, bp := range c.breakpoints {
		if bp.enabled || bp.attempted || bp.installed || bp.err != nil {
			t.Fatalf("disabled breakpoint after restart: %+v", bp)
		}
	}
	executeController(t, c, "enable", "1")
	executeController(t, c, "start", "")
	want := []target.Address{target.Address(sessions[2].pc + 4)}
	if !reflect.DeepEqual(sessions[2].added, want) || c.breakpoints[1].enabled {
		t.Fatalf("added=%v want=%v breakpoints=%+v", sessions[2].added, want, c.breakpoints)
	}
}

func TestBreakpointCommandsDisableEnableReevaluatesExpression(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	executeController(t, c, "break", "$rip + 7")
	old := c.breakpoints[0].address
	executeController(t, c, "disable", "1")
	bp := c.breakpoints[0]
	if bp.enabled || bp.installed || bp.attempted || bp.space != (target.SpaceRef{}) || bp.address != 0 {
		t.Fatalf("disabled breakpoint=%+v", bp)
	}
	s.pc += 0x2000
	executeController(t, c, "enable", "1")
	if !bp.enabled || !bp.installed || !bp.attempted || bp.address != target.Address(s.pc+7) || bp.address == old {
		t.Fatalf("reenabled breakpoint=%+v", bp)
	}
	executeController(t, c, "enable", "1")
	if len(s.added) != 2 || !reflect.DeepEqual(s.removed, []target.Address{old}) {
		t.Fatalf("added=%v removed=%v", s.added, s.removed)
	}
	executeController(t, c, "disable", "1")
	executeController(t, c, "disable", "1")
	if len(s.removed) != 2 {
		t.Fatalf("repeated disable removed again: %v", s.removed)
	}
}

func TestBreakpointCommandsValidateAllIDsBeforeMutation(t *testing.T) {
	for _, command := range []string{"enable", "disable", "delete"} {
		for _, args := range []string{"", "1 99", "1 1", "1 01", "1 0", "1 -2", "1 +2", "1 0x2", "1 18446744073709551616", "1 all", "all 1", "1 \"2\"", "1\x1b[31m"} {
			t.Run(command+"/"+args, func(t *testing.T) {
				c, s := breakpointCommandController(t, io.Discard)
				executeController(t, c, "break", "0x401000")
				executeController(t, c, "break", "0x402000")
				before := *c.breakpoints[0]
				_, err := c.Execute(context.Background(), command, args)
				if err == nil || len(s.removed) != 0 || len(s.added) != 2 || len(c.breakpoints) != 2 || *c.breakpoints[0] != before {
					t.Fatalf("err=%v removed=%v added=%v breakpoints=%+v", err, s.removed, s.added, c.breakpoints)
				}
				if strings.ContainsRune(err.Error(), '\x1b') {
					t.Fatalf("unescaped invalid ID: %q", err)
				}
			})
		}
	}
	for _, command := range []string{"enable", "disable"} {
		c := New(io.Discard, display.Renderer{})
		executeController(t, c, "break", "0x401000")
		if _, err := c.Execute(context.Background(), command, "all"); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%s all: %v", command, err)
		}
	}
}

func TestBreakpointCommandsAcceptUint64ID(t *testing.T) {
	c := New(io.Discard, display.Renderer{})
	c.nextBreakpoint = math.MaxUint64 - 1
	executeController(t, c, "break", "0x401000")
	id := strconv.FormatUint(math.MaxUint64, 10)
	executeController(t, c, "disable", id)
	executeController(t, c, "enable", id)
	executeController(t, c, "delete", id)
	if len(c.breakpoints) != 0 {
		t.Fatalf("remaining breakpoints=%v", c.breakpoints)
	}
	if _, err := c.Execute(context.Background(), "break", "0x401000"); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("exhausted IDs: %v", err)
	}
}

func TestBreakpointCommandsDisablePartialPreservesFailedAndUnprocessed(t *testing.T) {
	var output bytes.Buffer
	c, s := breakpointCommandController(t, &output)
	for _, address := range []string{"0x401000", "0x402000", "0x403000"} {
		executeController(t, c, "break", address)
	}
	output.Reset()
	s.afterRemove = func(address target.Address) error {
		if address == 0x401000 {
			return target.ErrPartial
		}
		return nil
	}
	_, err := c.Execute(context.Background(), "disable", "2 1 3")
	var partial *target.PartialError
	if !errors.As(err, &partial) || partial.Completed != 1 || partial.Total != 3 {
		t.Fatalf("partial result=%v", err)
	}
	if !reflect.DeepEqual(s.removed, []target.Address{0x402000, 0x401000}) || c.breakpoints[1].enabled || c.breakpoints[1].attempted {
		t.Fatalf("removed=%v second=%+v", s.removed, c.breakpoints[1])
	}
	for _, index := range []int{0, 2} {
		bp := c.breakpoints[index]
		if !bp.enabled || !bp.installed || !bp.attempted {
			t.Fatalf("lost failed/unprocessed breakpoint=%+v", bp)
		}
	}
	if output.String() != "Breakpoint 2 enabled=false\n" {
		t.Fatalf("output=%q", output.String())
	}
	s.afterRemove = nil
	executeController(t, c, "disable", "1 3")
	for _, bp := range c.breakpoints {
		if bp.enabled || bp.attempted || bp.installed || bp.err != nil {
			t.Fatalf("retry did not clear breakpoint=%+v", bp)
		}
	}
}

func TestBreakpointCommandsDeleteAllPartialAndRetry(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	for _, address := range []string{"0x401000", "0x402000", "0x403000"} {
		executeController(t, c, "break", address)
	}
	s.afterRemove = func(address target.Address) error {
		if address == 0x402000 {
			return target.ErrPartial
		}
		return nil
	}
	_, err := c.Execute(context.Background(), "delete", "all")
	var partial *target.PartialError
	if !errors.As(err, &partial) || partial.Completed != 1 || partial.Total != 3 || len(c.breakpoints) != 2 || c.breakpoints[0].id != 2 || c.breakpoints[1].id != 3 {
		t.Fatalf("err=%v breakpoints=%+v", err, c.breakpoints)
	}
	if !c.breakpoints[0].attempted || !c.breakpoints[0].installed || !c.breakpoints[1].installed || len(s.removed) != 2 {
		t.Fatalf("removed=%v breakpoints=%+v", s.removed, c.breakpoints)
	}
	s.afterRemove = nil
	executeController(t, c, "delete", "all")
	executeController(t, c, "delete", "all")
	if len(c.breakpoints) != 0 || !reflect.DeepEqual(s.removed, []target.Address{0x401000, 0x402000, 0x402000, 0x403000}) {
		t.Fatalf("removed=%v breakpoints=%v", s.removed, c.breakpoints)
	}
}

func TestBreakpointCommandsEnablePartialHasTruthfulState(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	for _, address := range []string{"0x401000", "0x402000", "0x403000"} {
		executeController(t, c, "break", address)
	}
	executeController(t, c, "disable", "1 2 3")
	s.afterAdd = func(address target.Address) error {
		if address == 0x402000 {
			return target.ErrPartial
		}
		return nil
	}
	_, err := c.Execute(context.Background(), "enable", "1 2 3")
	var partial *target.PartialError
	if !errors.As(err, &partial) || partial.Completed != 1 || partial.Total != 3 || len(s.added) != 5 {
		t.Fatalf("err=%v added=%v", err, s.added)
	}
	if !c.breakpoints[0].enabled || !c.breakpoints[0].installed || !c.breakpoints[1].enabled || c.breakpoints[1].installed || !c.breakpoints[1].attempted || c.breakpoints[2].enabled || c.breakpoints[2].attempted {
		t.Fatalf("breakpoints=%+v %+v %+v", c.breakpoints[0], c.breakpoints[1], c.breakpoints[2])
	}
	s.afterAdd = nil
	s.removeError = target.ErrNotFound
	executeController(t, c, "enable", "2 3")
	for _, bp := range c.breakpoints {
		if !bp.enabled || !bp.installed || !bp.attempted || bp.err != nil {
			t.Fatalf("retry did not install breakpoint=%+v", bp)
		}
	}
}

func TestBreakpointCommandsRetryFailedAddCleansOldAddressFirst(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	s.addError = target.ErrPartial
	_, err := c.Execute(context.Background(), "break", "$rip + 3")
	if !errors.Is(err, target.ErrPartial) || len(c.breakpoints) != 1 {
		t.Fatalf("add err=%v breakpoints=%v", err, c.breakpoints)
	}
	bp := c.breakpoints[0]
	old := bp.address
	s.pc += 0x5000
	s.addError, s.removeError = nil, target.ErrPartial
	_, err = c.Execute(context.Background(), "enable", "1")
	if !errors.Is(err, target.ErrPartial) || !bp.attempted || bp.installed || bp.address != old || len(s.added) != 1 {
		t.Fatalf("cleanup err=%v bp=%+v added=%v", err, bp, s.added)
	}
	s.removeError = target.ErrNotFound
	executeController(t, c, "enable", "1")
	if !bp.installed || bp.address != target.Address(s.pc+3) || !reflect.DeepEqual(s.removed, []target.Address{old, old}) {
		t.Fatalf("bp=%+v removed=%v", bp, s.removed)
	}
	_, err = c.Execute(context.Background(), "disable", "1")
	if !errors.Is(err, target.ErrNotFound) || !bp.enabled || !bp.installed || !bp.attempted {
		t.Fatalf("confirmed installation incorrectly discarded: err=%v bp=%+v", err, bp)
	}
}

func TestBreakpointCommandsAmbiguousNotFoundPreservesAttemptedInstallation(t *testing.T) {
	for _, failure := range []error{
		errors.Join(target.ErrNotFound, target.ErrPartial),
		errors.Join(target.ErrNotFound, target.ErrStale),
		fmt.Errorf("removal could not be confirmed: %w", target.ErrNotFound),
	} {
		for _, command := range []string{"disable", "delete", "enable"} {
			t.Run(command+"/"+failure.Error(), func(t *testing.T) {
				var output bytes.Buffer
				c, s := breakpointCommandController(t, &output)
				s.addError = target.ErrPartial
				if _, err := c.Execute(context.Background(), "break", "0x401000"); !errors.Is(err, target.ErrPartial) {
					t.Fatalf("expected failed initial add: %v", err)
				}
				bp := c.breakpoints[0]
				s.addError, s.removeError = nil, failure
				_, err := c.Execute(context.Background(), command, "1")
				if !errors.Is(err, failure) || len(c.breakpoints) != 1 || !bp.enabled || !bp.attempted || bp.installed || bp.address != 0x401000 || len(s.added) != 1 {
					t.Fatalf("err=%v bp=%+v added=%v breakpoints=%v", err, bp, s.added, c.breakpoints)
				}
				output.Reset()
				executeController(t, c, "info", "breakpoints")
				if !uiBreakpointRowMatches(output.String(), 1, true, "0x0000000000401000", "unconfirmed", "0x401000", false) {
					t.Fatalf("unconfirmed native ownership was hidden: %q", output.String())
				}
			})
		}
	}
}

func TestBreakpointCommandsDuplicateEnableDoesNotClaimInstallation(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	executeController(t, c, "break", "0x401000")
	executeController(t, c, "disable", "1")
	executeController(t, c, "break", "0x401000")
	_, err := c.Execute(context.Background(), "enable", "1")
	first, second := c.breakpoints[0], c.breakpoints[1]
	if !errors.Is(err, target.ErrInvalidArgument) || !first.enabled || first.installed || first.attempted || first.err == nil || !second.installed || len(s.added) != 2 {
		t.Fatalf("err=%v first=%+v second=%+v added=%v", err, first, second, s.added)
	}
	executeController(t, c, "disable", "2")
	executeController(t, c, "enable", "1")
	if !first.installed || first.err != nil || len(s.added) != 3 {
		t.Fatalf("first=%+v added=%v", first, s.added)
	}
}

func TestBreakpointCommandsRemoveSuccessSurvivesSnapshotFailure(t *testing.T) {
	for _, command := range []string{"disable", "delete"} {
		t.Run(command, func(t *testing.T) {
			c, s := breakpointCommandController(t, io.Discard)
			executeController(t, c, "break", "0x401000")
			executeController(t, c, "break", "0x402000")
			first, second := c.breakpoints[0], c.breakpoints[1]
			want := errors.New("refresh unavailable")
			s.afterRemove = func(target.Address) error {
				s.snapshotError = want
				return nil
			}
			_, err := c.Execute(context.Background(), command, "1 2")
			var partial *target.PartialError
			if !errors.Is(err, want) || !errors.As(err, &partial) || partial.Completed != 1 || partial.Total != 2 || first.installed || first.attempted || first.address != 0 || !second.installed || len(s.removed) != 1 {
				t.Fatalf("err=%v first=%+v second=%+v removed=%v", err, first, second, s.removed)
			}
			if command == "disable" && first.enabled || command == "delete" && (len(c.breakpoints) != 1 || c.breakpoints[0] != second) {
				t.Fatalf("logical state did not record confirmed removal: command=%s first=%+v breakpoints=%v", command, first, c.breakpoints)
			}
			s.snapshotError, s.afterRemove = nil, nil
			if command == "disable" {
				executeController(t, c, "disable", "1 2")
			} else {
				executeController(t, c, "delete", "all")
			}
			if !reflect.DeepEqual(s.removed, []target.Address{0x401000, 0x402000}) {
				t.Fatalf("successful removal was retried: %v", s.removed)
			}
		})
	}
}

func TestBreakpointCommandsAddSuccessSnapshotFailureRetainsOwnership(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	want := errors.New("refresh unavailable")
	s.afterAdd = func(target.Address) error {
		s.snapshotError = want
		return nil
	}
	_, err := c.Execute(context.Background(), "break", "0x401000")
	bp := c.breakpoints[0]
	if !errors.Is(err, want) || !bp.installed || !bp.attempted || !bp.enabled || bp.address != 0x401000 {
		t.Fatalf("err=%v bp=%+v", err, bp)
	}
	s.snapshotError, s.afterAdd = nil, nil
	executeController(t, c, "disable", "1")
	if bp.installed || bp.attempted || bp.enabled || !reflect.DeepEqual(s.removed, []target.Address{0x401000}) {
		t.Fatalf("bp=%+v removed=%v", bp, s.removed)
	}
}

func TestBreakpointCommandsImageChangeKeepsFlagsWithoutAddressRebasing(t *testing.T) {
	c, s := breakpointCommandController(t, io.Discard)
	executeController(t, c, "break", "$rip")
	executeController(t, c, "disable", "1")
	executeController(t, c, "break", "$rip + 1")
	s.snapshot.Memory.Space.ID++
	s.pc += 0x10000
	executeController(t, c, "info", "breakpoints")
	if c.breakpoints[0].enabled || !c.breakpoints[1].enabled {
		t.Fatalf("logical flags lost on image change: %v", c.breakpoints)
	}
	for _, bp := range c.breakpoints {
		if bp.attempted || bp.installed || bp.address != 0 || bp.space != (target.SpaceRef{}) {
			t.Fatalf("old installation survived image change: %+v", bp)
		}
	}
	executeController(t, c, "enable", "2")
	if c.breakpoints[1].address != target.Address(s.pc+1) || len(s.removed) != 1 || len(s.added) != 3 {
		t.Fatalf("bp=%+v removed=%v added=%v", c.breakpoints[1], s.removed, s.added)
	}
}

func TestBreakpointCommandsListFlagsErrorsAndEscaping(t *testing.T) {
	var output bytes.Buffer
	c, s := breakpointCommandController(t, &output)
	executeController(t, c, "break", "0x401000")
	executeController(t, c, "break", "0x402000")
	executeController(t, c, "disable", "2")
	s.addError = errors.New("native\x1b[31m\nerror")
	if _, err := c.Execute(context.Background(), "break", "0x403000"); err == nil {
		t.Fatal("expected native add failure")
	}
	c.breakpoints[1].expression = "expr\x1b[32m\nname"
	output.Reset()
	executeController(t, c, "info", "breakpoints")
	text := output.String()
	if !uiBreakpointRowMatches(text, 1, true, "0x0000000000401000", "installed", "0x401000", false) ||
		!uiBreakpointRowMatches(text, 2, false, "<pending>", "pending", "expr\x1b[32m\nname", false) ||
		!uiBreakpointRowMatches(text, 3, true, "0x0000000000403000", "unconfirmed", "0x403000", false) ||
		!uiOutputHasLine(text, `     Error: "native\x1b[31m\nerror"`) {
		t.Fatalf("breakpoint rows lost enable/address/certainty/escaped facts: %q", text)
	}
	if strings.ContainsRune(text, '\x1b') || strings.Count(text, "\n") != 6 {
		t.Fatalf("unescaped listing: %q", text)
	}
	output.Reset()
	executeController(t, c, "break", "list")
	if output.String() != text {
		t.Fatalf("info/list mismatch: %q vs %q", text, output.String())
	}
}

func TestBreakpointCommandsCanceledAndActiveRequestsDoNotMutate(t *testing.T) {
	for _, command := range []string{"enable", "disable", "delete"} {
		t.Run(command, func(t *testing.T) {
			c, s := breakpointCommandController(t, io.Discard)
			executeController(t, c, "break", "0x401000")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := c.Execute(ctx, command, "1"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled command: %v", err)
			}
			c.active = controllerTestOperation(func(context.Context) (target.RunResult, error) {
				t.Fatal("active operation was waited")
				return target.RunResult{}, nil
			})
			if _, err := c.Execute(context.Background(), command, "1"); !errors.Is(err, target.ErrBusy) || len(s.added) != 1 || len(s.removed) != 0 || len(c.breakpoints) != 1 || !c.breakpoints[0].enabled {
				t.Fatalf("active command: err=%v added=%v removed=%v breakpoints=%v", err, s.added, s.removed, c.breakpoints)
			}
		})
	}
}

func TestBreakpointCommandsBatchOutputFailureRecordsConfirmedMutation(t *testing.T) {
	for _, command := range []string{"disable", "delete"} {
		t.Run(command, func(t *testing.T) {
			c, s := breakpointCommandController(t, io.Discard)
			executeController(t, c, "break", "0x401000")
			executeController(t, c, "break", "0x402000")
			first, second := c.breakpoints[0], c.breakpoints[1]
			want := errors.New("output failed")
			c.out = controllerTestWriter(func([]byte) (int, error) { return 0, want })
			_, err := c.Execute(context.Background(), command, "1 2")
			var outputError *OutputError
			var partial *target.PartialError
			if !errors.Is(err, want) || !errors.As(err, &outputError) || !errors.As(err, &partial) || partial.Completed != 1 || partial.Total != 2 || first.installed || first.attempted || !second.installed || len(s.removed) != 1 {
				t.Fatalf("err=%v first=%+v second=%+v removed=%v", err, first, second, s.removed)
			}
		})
	}
}
