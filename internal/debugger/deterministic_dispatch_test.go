package debugger

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestDeterministicUnwindAliasesAndReadOnlyApply(t *testing.T) {
	for alias, canonical := range map[string]string{
		"backtrace": "backtrace", "bt": "backtrace", "BT": "backtrace", "BACKTRACE": "backtrace",
		"stackframe": "stackframe", "stkf": "stackframe", "STACKFRAME": "stackframe", "STKF": "stackframe",
	} {
		command, ok := canonicalCommand(alias)
		if !ok || command.name != canonical {
			t.Fatalf("unwind alias %q: %+v %t", alias, command, ok)
		}
		if err := threadApplyReadOnly(alias, ""); err != nil {
			t.Fatalf("read-only unwind alias %q: %v", alias, err)
		}
		var output bytes.Buffer
		c := New(&output, display.Renderer{})
		quit, err := c.Execute(context.Background(), alias, "")
		if quit || !errors.Is(err, target.ErrInvalidState) || output.Len() != 0 {
			t.Fatalf("unwind without a target %q: quit=%t err=%v output=%q", alias, quit, err, output.String())
		}
		for _, arguments := range []string{"--abi strict", "--abi sysv"} {
			quit, err := c.Execute(context.Background(), alias, arguments)
			if quit || !errors.Is(err, target.ErrInvalidState) || output.Len() != 0 {
				t.Fatalf("explicit ABI without a target %q %s: quit=%t err=%v output=%q", alias, arguments, quit, err, output.String())
			}
		}
	}
	for _, name := range []string{"Backtrace", "StackFrame", "BTrace", "btExtra"} {
		if _, ok := canonicalCommand(name); ok {
			t.Fatalf("undeclared alias accepted: %q", name)
		}
	}
}

func TestDeterministicUnwindArgumentsFailBeforeTargetReads(t *testing.T) {
	for _, command := range []struct{ name, args string }{
		{"bt", "0"}, {"backtrace", "257"}, {"BT", "-1"}, {"BACKTRACE", "+1"}, {"bt", "0x10"}, {"bt", "1 2"},
		{"stackframe", "256"}, {"stkf", "-1"}, {"STKF", "+1"}, {"STACKFRAME", "0x0"}, {"stkf", "0 1"},
		{"bt", "--abi"}, {"bt", "--abi unknown"}, {"bt", "--abi strict 0"}, {"bt", "--abi sysv --abi strict"},
		{"stkf", "--abi sysv 256"}, {"stkf", "0 --abi sysv"}, {"stkf", "--abi SYSV"},
	} {
		fixture, _, thread := newContextFixture()
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		quit, err := c.Execute(context.Background(), command.name, command.args)
		if quit || !errors.Is(err, target.ErrInvalidArgument) || output.Len() != 0 || fixture.snapshotReads != 0 || len(fixture.registerTokens) != 0 {
			t.Fatalf("invalid unwind arguments %s %s: quit=%t err=%v output=%q fixture=%+v", command.name, command.args, quit, err, output.String(), fixture)
		}
	}
}

func TestDeterministicUnwindHelpReportsMetadataAndBounds(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
	}{
		{"bt", []string{"default 32", "maximum 256", "Native Linux AMD64 defaults to the SysV AMD64 ABI", "--abi strict|sysv", "labeled SysV", "exact registers", "InstructionPC", "No RBP-chain or stack-scan fallback", "confirmed frames", "zero return PC is not a confirmed bottom"}},
		{"stkf", []string{"default 0", "maximum 255", "Native Linux AMD64 defaults to SysV AMD64 ABI rules", "labeled SysV", "CFA", "saved-register rules", "not a raw stack-word count", "missing/unsupported metadata"}},
	} {
		var output bytes.Buffer
		c := New(&output, display.Renderer{})
		executeController(t, c, "help", test.command)
		for _, wanted := range test.want {
			if !strings.Contains(output.String(), wanted) {
				t.Fatalf("help %s missing %q: %s", test.command, wanted, output.String())
			}
		}
	}
}

func TestDeterministicHeapAliasesRequireExplicitMetadata(t *testing.T) {
	for alias, canonical := range map[string]string{
		"arena": "arena", "arenas": "arena", "ARENA": "arena", "ARENAS": "arena",
		"bins": "bins", "BINS": "bins",
	} {
		command, ok := canonicalCommand(alias)
		if !ok || command.name != canonical {
			t.Fatalf("heap alias %q: %+v %t", alias, command, ok)
		}
		if err := threadApplyReadOnly(alias, ""); err != nil {
			t.Fatalf("read-only heap alias %q: %v", alias, err)
		}
		t.Run(alias+"/automatic-metadata-proof", func(t *testing.T) {
			fixture, snapshot, thread := newContextFixture()
			probeErr := errors.New("injected allocator provenance validation failure")
			fixture.registerErr = probeErr
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			quit, err := c.Execute(context.Background(), alias, "")
			var proofErr *heapGraphProofError
			if quit || !errors.Is(err, probeErr) || !errors.As(err, &proofErr) || errors.Is(err, target.ErrInvalidArgument) ||
				fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != thread.Token ||
				len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0 || len(fixture.stackCalls) != 0 ||
				c.selected != thread.Ref || fixture.snapshot.Memory != snapshot.Memory || output.Len() != 0 {
				t.Fatalf("automatic heap metadata proof for %q: quit=%t err=%v output=%q fixture=%+v", alias, quit, err, output.String(), fixture)
			}
		})
		t.Run(alias+"/stale-snapshot", func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			fixture.snapshotErr = target.ErrStale
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			quit, err := c.Execute(context.Background(), alias, "")
			if quit || !errors.Is(err, target.ErrStale) || fixture.snapshotReads != 1 || len(fixture.registerTokens) != 0 ||
				len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0 || len(fixture.stackCalls) != 0 ||
				c.selected != thread.Ref || output.Len() != 0 {
				t.Fatalf("stale automatic heap request for %q: quit=%t err=%v output=%q fixture=%+v", alias, quit, err, output.String(), fixture)
			}
		})
		t.Run(alias+"/not-started", func(t *testing.T) {
			var output bytes.Buffer
			c := New(&output, display.Renderer{})
			quit, err := c.Execute(context.Background(), alias, "")
			if quit || !errors.Is(err, target.ErrInvalidState) || errors.Is(err, target.ErrInvalidArgument) ||
				!strings.Contains(err.Error(), "no target") || c.session != nil || c.selected != (target.ThreadRef{}) || output.Len() != 0 {
				t.Fatalf("heap request without a target %q: quit=%t err=%v output=%q", alias, quit, err, output.String())
			}
		})
		for _, arguments := range []string{"--module main", "--layout-file missing"} {
			t.Run(alias+"/explicit-arguments/"+arguments, func(t *testing.T) {
				fixture, _, thread := newContextFixture()
				var output bytes.Buffer
				c := &Controller{session: fixture, selected: thread.Ref, out: &output}
				quit, err := c.Execute(context.Background(), alias, arguments)
				if quit || !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || len(fixture.registerTokens) != 0 ||
					len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0 || len(fixture.stackCalls) != 0 ||
					c.selected != thread.Ref || output.Len() != 0 {
					t.Fatalf("incomplete explicit heap metadata %q %s: quit=%t err=%v output=%q fixture=%+v", alias, arguments, quit, err, output.String(), fixture)
				}
			})
		}
	}
	for _, name := range []string{"Arena", "Arenas", "Bins", "bin"} {
		if _, ok := canonicalCommand(name); ok {
			t.Fatalf("undeclared heap alias accepted: %q", name)
		}
	}
}

func TestDeterministicHeapInvalidOptionsFailBeforeReads(t *testing.T) {
	for _, command := range []struct{ name, args string }{
		{"arena", "--layout-file missing"}, {"arena", "--module main"},
		{"arena", "--module main --fast-link unknown"}, {"arena", "--all --all --module main --fast-link plain"},
		{"arena", "--layout-file missing --fast-link plain 0"}, {"arena", "--layout-file missing --module main 0"},
		{"bins", "--all --module main --fast-link plain"}, {"bins", "--debug-file missing 0"},
		{"bins", "--module main --fast-link plain 0 1"}, {"bins", "--layout-file missing --debug-file other 0"},
	} {
		fixture, _, thread := newContextFixture()
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		quit, err := c.Execute(context.Background(), command.name, command.args)
		if quit || !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || len(fixture.registerTokens) != 0 || output.Len() != 0 {
			t.Fatalf("invalid heap arguments %s %s: quit=%t err=%v output=%q fixture=%+v", command.name, command.args, quit, err, output.String(), fixture)
		}
	}
}

func TestDeterministicHeapHelpSeparatesDeclaredLayoutAndProof(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
	}{
		{"ARENAS", []string{"--layout-file FILE", "--module EXACT", "--fast-link plain|safe-link-12", "With no arguments", "--all", "-a EXPR", "-n"}},
		{"BINS", []string{"selected thread's tcache", "--all", "-v", "-n", "--layout-file"}},
	} {
		var output bytes.Buffer
		c := New(&output, display.Renderer{})
		executeController(t, c, "help", test.command)
		for _, wanted := range test.want {
			if !strings.Contains(output.String(), wanted) {
				t.Fatalf("help %s missing %q: %s", test.command, wanted, output.String())
			}
		}
	}
}

func TestDeterministicMetadataHelpDistinguishesIdentityAndAssociation(t *testing.T) {
	for _, name := range []string{"sym", "got", "checksec", "stdio", "disassemble"} {
		var output bytes.Buffer
		c := New(&output, display.Renderer{})
		executeController(t, c, "help", name)
		for _, wanted := range []string{
			"scope and metadata are verified", "proc-exe+auxv", "strict mapped-file identity",
			"kernel-vma-build-id-metadata", "does not prove the same backing file or all contents",
			"DT_DEBUG/link_map", "AT_SYSINFO_EHDR", "unavailable/partial errors", "stale/cancel discards results",
		} {
			if !strings.Contains(output.String(), wanted) {
				t.Fatalf("help %s missing metadata contract %q: %s", name, wanted, output.String())
			}
		}
	}
}

func TestDeterministicGeneralHelpDoesNotClaimTheFourCommandsAreDeferred(t *testing.T) {
	var output bytes.Buffer
	c := New(&output, display.Renderer{})
	executeController(t, c, "help", "")
	text := output.String()
	if strings.Contains(text, "are not implemented") || strings.Contains(text, "pending deterministic") {
		t.Fatalf("obsolete deferred claim: %s", text)
	}
	for _, wanted := range []string{"backtrace", "stackframe", "arena", "bins", "require supported, proven CFI metadata", "no automatic allocator or tcache discovery"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("missing conditional implementation contract %q: %s", wanted, text)
		}
	}
}
