package debugger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestContextPanesRenderInCanonicalOrder(t *testing.T) {
	fixture, _, thread := newContextFixture()
	peer := fixture.snapshot.Threads[0]
	peer.Ref.ID, peer.Token.Thread.ID, peer.TID = 3, 3, 5678
	peer.Stop = target.Stop{Reason: target.StopInterrupt}
	fixture.snapshot.Threads = append(fixture.snapshot.Threads, peer)
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := c.showContext(context.Background(), "threads code stack regs"); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	previous := -1
	for _, heading := range []string{"[registers]", "[stack]", "[code]", "[threads]"} {
		index := strings.Index(text, heading)
		if index <= previous {
			t.Fatalf("context order %q:\n%s", heading, text)
		}
		previous = index
	}
	flat := strings.Join(strings.Fields(text), " ")
	if !strings.Contains(flat, "3 5678 1 \"test\" stopped interrupt") ||
		strings.Contains(flat, "3 5678 1 \"test\" stopped breakpoint") {
		t.Fatalf("peer stop reason was inferred from the selected thread:\n%s", text)
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || len(fixture.locationTokens) != 1 {
		t.Fatalf("context did not use a single snapshot/read set: %+v", fixture)
	}
}

func TestContextSelectedPanesReadOnlyRequiredState(t *testing.T) {
	for _, test := range []struct {
		pane                       string
		registers, location, stack int
	}{
		{"regs", 1, 0, 0},
		{"registers", 1, 0, 0},
		{"stack", 1, 0, 1},
		{"code", 1, 1, 0},
		{"threads", 0, 0, 0},
	} {
		t.Run(test.pane, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			if err := c.showContext(context.Background(), test.pane); err != nil {
				t.Fatal(err)
			}
			if len(fixture.registerTokens) != test.registers || len(fixture.locationTokens) != test.location ||
				len(fixture.stackCalls) != test.stack || fixture.snapshotReads != 1 {
				t.Fatalf("unexpected reads for %s: %+v", test.pane, fixture)
			}
			want := test.pane
			if want == "regs" {
				want = "registers"
			}
			for _, name := range []string{"registers", "stack", "code", "threads"} {
				if strings.Contains(output.String(), "["+name+"]") != (name == want) {
					t.Fatalf("unexpected pane %s for %s:\n%s", name, test.pane, output.String())
				}
			}
		})
	}
}

func TestContextThreadPaneDoesNotNeedInspectableSelection(t *testing.T) {
	for _, state := range []target.State{target.StateStopped, target.StateRunning, target.StateExited} {
		t.Run(state.String(), func(t *testing.T) {
			fixture, _, _ := newContextFixture()
			fixture.snapshot.State = state
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: target.ThreadRef{Session: 4, ID: 999}, out: &output}
			if err := c.showContext(context.Background(), "threads"); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(output.String(), contextPlainHeading("threads")) || len(fixture.registerTokens) != 0 || c.selected.ID != 999 {
				t.Fatalf("thread pane altered selection or inspected registers: %s %+v", output.String(), fixture)
			}
		})
	}
}

func TestContextInvalidPaneArgumentsHaveNoSideEffects(t *testing.T) {
	for _, args := range []string{"unknown", "regs unknown", "regs regs", "regs registers", "on regs", "off stack", "on off", "regs\x00"} {
		t.Run(args, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			err := c.showContext(context.Background(), args)
			if !errors.Is(err, target.ErrInvalidArgument) || output.Len() != 0 || fixture.snapshotReads != 0 || c.contextDisabled {
				t.Fatalf("invalid pane changed state: %v output=%q %+v", err, output.String(), fixture)
			}
		})
	}
}

func TestContextAutomaticDisplayTogglePreservesManualDisplay(t *testing.T) {
	var output bytes.Buffer
	c, s := runningController(t, &output)
	if c.contextDisabled {
		t.Fatal("automatic context is disabled by default")
	}
	executeController(t, c, "ctx", "off")
	output.Reset()
	if err := c.showStop(context.Background(), s.LastStop(), c.selected); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Thread #") || strings.Contains(output.String(), "[registers]") || len(s.registerReads) != 0 {
		t.Fatalf("automatic context off was ignored: %s", output.String())
	}
	output.Reset()
	executeController(t, c, "context", "regs")
	if output.Len() != 0 || !c.contextDisabled {
		t.Fatalf("hidden manual context produced output or changed the setting: %s", output.String())
	}
	executeController(t, c, "context", "on")
	output.Reset()
	executeController(t, c, "context", "regs")
	if !strings.Contains(output.String(), "[registers]") || c.contextDisabled {
		t.Fatalf("manual context did not return after enabling: %s", output.String())
	}
	output.Reset()
	if err := c.showStop(context.Background(), s.LastStop(), c.selected); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Thread #") || !strings.Contains(output.String(), "[threads]") {
		t.Fatalf("automatic context on was ignored: %s", output.String())
	}
}

func TestContextAutomaticSettingDoesNotRequireTarget(t *testing.T) {
	var output bytes.Buffer
	c := New(&output, display.Renderer{})
	executeController(t, c, "context", "off")
	if !c.contextDisabled || output.String() != "Context is off.\n" {
		t.Fatalf("toggle without target: %t %q", c.contextDisabled, output.String())
	}
	executeController(t, c, "ctx", "on")
	if c.contextDisabled {
		t.Fatal("context on did not restore the default")
	}
}

func TestRegisterArgumentsValidateBeforeReading(t *testing.T) {
	for _, args := range []string{"bogus", "rip bogus", "$", "$$rip", "-s -s", "--simple --simple", "--unknown", "rip -s", "rip $rip", "rip\x1b[31m"} {
		t.Run(args, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			err := c.showRegisters(context.Background(), args)
			if err == nil || output.Len() != 0 || fixture.snapshotReads != 0 || len(fixture.registerTokens) != 0 {
				t.Fatalf("invalid register arguments were read or output: %v %q %+v", err, output.String(), fixture)
			}
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Fatalf("terminal control in error: %q", err)
			}
		})
	}
}

func TestRegisterSelectionPreservesOrderAndRawRIP(t *testing.T) {
	for _, args := range []string{"rip rax", "-s $rip $rax", "--simple rip $rax"} {
		t.Run(args, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			if err := c.showRegisters(context.Background(), args); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !strings.Contains(text, "$rip   : 0x0000000000401001") ||
				strings.Index(text, "rip") > strings.Index(text, "rax") || strings.Contains(text, "rsp") ||
				len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != thread.Token || len(fixture.locationTokens) != 0 {
				t.Fatalf("wrong selected register rendering: %s %+v", text, fixture)
			}
		})
	}
}

func TestRegisterSelectionRejectsAbsentAndAmbiguousValues(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		fixture, _, thread := newContextFixture()
		want := target.ErrNotFound
		if duplicate {
			fixture.registers = append(fixture.registers, fixture.registers[1])
			want = target.ErrAmbiguous
		} else {
			fixture.registers = fixture.registers[:1]
		}
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		err := c.showRegisters(context.Background(), "rax rip")
		if !errors.Is(err, want) || output.Len() != 0 || len(fixture.registerTokens) != 1 {
			t.Fatalf("invalid register set was partly displayed: duplicate=%t err=%v %q", duplicate, err, output.String())
		}
	}
}

func TestRegisterAliasesAndInfoUseTheSameSelection(t *testing.T) {
	var expected string
	for _, command := range []struct{ name, args string }{
		{"regs", "rip rsp"}, {"registers", "-s rip rsp"}, {"info", "registers rip rsp"}, {"i", "registers --simple rip rsp"},
	} {
		fixture, _, thread := newContextFixture()
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		executeController(t, c, command.name, command.args)
		if expected == "" {
			expected = output.String()
		}
		if output.String() != expected || c.selected != thread.Ref || len(fixture.registerTokens) != 1 {
			t.Fatalf("alias mismatch %s %s: %q", command.name, command.args, output.String())
		}
	}
}

func TestRegisterArgumentResultsAreIndependent(t *testing.T) {
	names, err := registerArguments("--simple $rip rsp")
	if err != nil || !reflect.DeepEqual(names, []string{"rip", "rsp"}) {
		t.Fatalf("register names: %q %v", names, err)
	}
	registers := []target.Register{contextTestRegister("rip", 1), contextTestRegister("rsp", 2)}
	selected, err := selectRegisters(registers, []string{"rsp", "rip"})
	if err != nil || selected[0].Name != "rsp" || selected[1].Name != "rip" || registers[0].Name != "rip" {
		t.Fatalf("register order: %v %v", selected, err)
	}
}

func TestRegistersCancellationAfterReadStopsOutput(t *testing.T) {
	fixture, _, thread := newContextFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.onReadRegisters = cancel
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := c.showRegisters(ctx, "rip"); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("canceled registers printed output: %v %q", err, output.String())
	}
}

func TestContextArgumentHelpersRejectExtraInternalArguments(t *testing.T) {
	c := New(io.Discard, display.Renderer{})
	if err := c.showContext(context.Background(), "regs", "stack"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("extra context arguments: %v", err)
	}
	if err := c.showRegisters(context.Background(), "rip", "rsp"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("extra registers arguments: %v", err)
	}
}

func TestMemoryCommandReturnsReadErrorsAndOnlyConfirmedPrefixes(t *testing.T) {
	for _, stale := range []bool{false, true} {
		fixture, _, thread := newContextFixture()
		fixture.stack = []byte{0xde, 0xad}
		fixture.stackErr = io.ErrUnexpectedEOF
		want := target.ErrPartial
		if stale {
			fixture.stackErr, want = target.ErrStale, target.ErrStale
		}
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		err := c.showMemory(context.Background(), "--count 4 $rsp")
		if !errors.Is(err, want) || !strings.Contains(output.String(), "unavailable:") ||
			strings.Contains(output.String(), "de ad") == stale || len(fixture.stackCalls) != 1 {
			t.Fatalf("stale=%t err=%v output=%q calls=%+v", stale, err, output.String(), fixture.stackCalls)
		}
	}
}

func TestContextStaleStackDiscardsUnprintedCode(t *testing.T) {
	fixture, _, thread := newContextFixture()
	fixture.stackErr = target.ErrStale
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	err := c.showContext(context.Background())
	if !errors.Is(err, target.ErrStale) || strings.Contains(output.String(), "  nop\n") ||
		strings.Contains(output.String(), "00 01 02 03") || output.Len() != 0 ||
		len(fixture.codeCalls) != 1 || len(fixture.stackCalls) != 1 || len(fixture.registerTokens) != 1 {
		t.Fatalf("stale stack was reused or retried: %v\n%s\n%+v", err, output.String(), fixture)
	}
}

func TestContextReadAndOutputErrorsAreBothPreserved(t *testing.T) {
	fixture, _, thread := newContextFixture()
	fixture.locationErr = target.ErrUnavailable
	want := errors.New("stack output failed")
	c := &Controller{session: fixture, selected: thread.Ref, out: controllerTestWriter(func(data []byte) (int, error) {
		if strings.Contains(string(data), "[stack]") {
			return 0, want
		}
		return len(data), nil
	})}
	err := (contextOutput{writef: c.writef, renderer: c.renderer}).context(context.Background(), fixture, fixture.snapshot, thread)
	var outputErr *OutputError
	if !errors.Is(err, want) || !errors.Is(err, target.ErrUnavailable) || !errors.As(err, &outputErr) || len(fixture.stackCalls) != 0 {
		t.Fatalf("read/output error was lost or reading continued: %v %+v", err, fixture)
	}
}

func TestRegistersReadFailureIsReturnedAfterUnavailableDisplay(t *testing.T) {
	fixture, _, thread := newContextFixture()
	fixture.registerErr = target.ErrUnavailable
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	err := c.showRegisters(context.Background(), "rip")
	if !errors.Is(err, target.ErrUnavailable) || !strings.Contains(output.String(), contextPlainHeading("registers")+"  unavailable:") ||
		strings.Contains(output.String(), "0x0000000000401001") || len(fixture.registerTokens) != 1 {
		t.Fatalf("register read error was masked: %v %q %+v", err, output.String(), fixture)
	}
}
