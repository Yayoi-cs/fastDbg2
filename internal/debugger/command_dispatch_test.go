package debugger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

func TestExpandedCommandAliasesAreExplicit(t *testing.T) {
	for alias, want := range map[string]string{
		"r": "run", "R": "run", "s": "start", "S": "start", "c": "continue", "cont": "continue", "si": "step", "stepi": "step", "b": "break",
		"ctx": "context", "registers": "regs", "p": "print", "p/x": "print", "print/d": "print",
		"disass": "disassemble", "disasm": "disassemble", "stk": "stack", "hd": "hexdump", "t": "thread", "i": "info",
		"x/8xb": "x", "x/3gx": "x", "exit": "quit",
	} {
		command, ok := canonicalCommand(alias)
		if !ok || command.name != want {
			t.Fatalf("alias %s: command=%s ok=%t", alias, command.name, ok)
		}
	}
	for _, name := range []string{"n", "ni", "next", "nexti", "finish", "con", "threading", "p/", "p/xx", "p/z", "x/", "regs/x", "print/x/y"} {
		if command, ok := canonicalCommand(name); ok {
			t.Fatalf("unsupported alias %q accepted as %s", name, command.name)
		}
	}
}

func TestExpandedCommandNamesCompleteAndHaveHelp(t *testing.T) {
	names := CommandNames()
	seen := make(map[string]bool)
	completer, err := cli.NewCompleter(names)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate command completion %q", name)
		}
		seen[name] = true
		var output bytes.Buffer
		c := New(&output, display.Renderer{})
		executeController(t, c, "help", name)
		if !strings.HasPrefix(output.String(), "Usage: ") {
			t.Fatalf("missing individual help for %s: %q", name, output.String())
		}
		candidates, _ := completer.Do([]rune(name), len([]rune(name)))
		if !slices.ContainsFunc(candidates, func(candidate []rune) bool { return string(candidate) == " " }) {
			t.Fatalf("command not completable %q: %q", name, candidates)
		}
	}
}

func TestCommandHelpDocumentsIntentionalDifferences(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
	}{
		{"start", []string{"after exec", "not at main"}},
		{"stepi", []string{"machine instruction", "not GDB source-line step", "peer"}},
		{"set scheduler-locking", []string{"replay is the default", "recording/replay execution is unsupported"}},
		{"thread apply", []string{"logical ThreadRef.ID", "never a TID fallback", "-ascending", "-c", "Selection is restored"}},
		{"context", []string{"registers, raw stack values with bounded chains, current code and threads", "default on", "automatic and manual context", "standalone regs", "snapshot validation", "named panes append"}},
		{"p/d", []string{"unsigned 64-bit", "int64", "not GDB C-type"}},
		{"x/8xb", []string{"EXPR", "4096 bytes", "256 instructions", "byte units only", "not reused"}},
		{"disass", []string{"maximum 256", "InstructionPC", "raw RIP"}},
		{"stack", []string{"maximum 512", "actual selected thread RSP"}},
		{"hexdump", []string{"64, 32, 16 and 8", "4096 bytes", "counts units"}},
		{"delete", []string{"No arguments is an error", "All IDs are validated"}},
		{"info registers", []string{"info registers", "Only these explicit subcommands"}},
	} {
		t.Run(test.command, func(t *testing.T) {
			var output bytes.Buffer
			c := New(&output, display.Renderer{})
			executeController(t, c, "help", test.command)
			for _, want := range test.want {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("help %s missing %q:\n%s", test.command, want, output.String())
				}
			}
		})
	}
}

func TestCommandHelpRejectsInvalidRequestsBeforeOutput(t *testing.T) {
	for _, args := range []string{"unknown", "info unknown", "info threads extra", "set unknown", "show unknown", "thread unknown", "regs rip", "next", "p/z", "unknown\x1b[31m"} {
		t.Run(args, func(t *testing.T) {
			var output bytes.Buffer
			c := New(&output, display.Renderer{})
			_, err := c.Execute(context.Background(), "help", args)
			if !errors.Is(err, target.ErrInvalidArgument) || output.Len() != 0 || strings.ContainsRune(err.Error(), '\x1b') {
				t.Fatalf("invalid help: %v %q", err, output.String())
			}
		})
	}
}

func TestInfoAndSettingsDispatchRejectUnsupportedArguments(t *testing.T) {
	for _, command := range []struct{ name, args string }{
		{"info", ""}, {"info", "threads extra"}, {"i", "breakpoints extra"}, {"info", "program"},
		{"set", ""}, {"set", "scheduler-locking"}, {"set", "non-stop"}, {"show", "scheduler-locking extra"}, {"show", "non-stop"},
		{"interrupt", "extra"}, {"threads", "extra"}, {"help", "show scheduler-locking extra"},
	} {
		c := New(io.Discard, display.Renderer{})
		if quit, err := c.Execute(context.Background(), command.name, command.args); quit || !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%s %s: quit=%t err=%v", command.name, command.args, quit, err)
		}
	}
}

func TestInfoThreadsDoesNotSelectOrInspect(t *testing.T) {
	fixture, _, thread := newContextFixture()
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	executeController(t, c, "info", "threads")
	want := output.String()
	output.Reset()
	executeController(t, c, "threads", "")
	if output.String() != want || c.selected != thread.Ref || len(fixture.registerTokens) != 0 {
		t.Fatalf("info threads diverged from threads: %q %q %+v", want, output.String(), fixture)
	}
}

func TestFormattedPrintAndExamineDispatch(t *testing.T) {
	var output bytes.Buffer
	c := New(&output, display.Renderer{})
	executeController(t, c, "p/x", "255")
	if output.String() != "0xff\n" {
		t.Fatalf("formatted print dispatch: %q", output.String())
	}
	fixture, _, thread := newContextFixture()
	c.session, c.selected = fixture, thread.Ref
	output.Reset()
	executeController(t, c, "x/2xb", "$rsp")
	if len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 2 || len(fixture.codeCalls) != 0 {
		t.Fatalf("examine suffix not dispatched: %q %+v", output.String(), fixture)
	}
}
