package debugger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestLegacyAliasesAreRegisteredWithoutCaseGuessing(t *testing.T) {
	for alias, name := range map[string]string{
		"s": "start", "S": "start", "START": "start", "r": "run", "R": "run", "RUN": "run",
		"B": "break", "BREAK": "break", "P": "print", "PRINT": "print",
		"C": "continue", "CONTINUE": "continue", "CONT": "continue", "STEP": "step",
		"CONTEXT": "context", "COLOR": "color", "STACK": "stack", "STK": "stack", "VMMAP": "vmmap",
		"symbol": "sym", "SYM": "sym", "SYMBOL": "sym", "GOT": "got", "CHUNK": "chunk",
		"stdio-dump": "stdio", "STDIO": "stdio", "STDIO-DUMP": "stdio", "procinfo": "proc-info",
		"proc.info": "proc-info", "PROC-INFO": "proc-info", "PROCINFO": "proc-info",
		"fds": "fd", "FD": "fd", "FDS": "fd", "CHECKSEC": "checksec", "fs": "fs_base",
		"vis": "visual-heap", "VIS": "visual-heap", "VISUAL-HEAP": "visual-heap", "tel": "telescope",
		"SIMD": "simd", "XMM": "xmm", "YMM": "ymm", "q": "quit", "xxd": "xxd", "!": "!",
		"arenas": "arena", "ARENA": "arena", "ARENAS": "arena", "BINS": "bins",
		"bt": "backtrace", "BT": "backtrace", "BACKTRACE": "backtrace", "stkf": "stackframe", "STACKFRAME": "stackframe", "STKF": "stackframe",
	} {
		command, ok := canonicalCommand(alias)
		if !ok || command.name != name {
			t.Fatalf("legacy alias %q: got %+v %t, want %s", alias, command, ok, name)
		}
	}
	for _, name := range []string{"Run", "Start", "Vmmap", "pRINT", "REGS", "SET", "DD", "Proc.Info", "n", "ni", "finish", "stepover", "bin"} {
		if command, ok := canonicalCommand(name); ok {
			t.Fatalf("unimplemented or guessed alias %q became %s", name, command.name)
		}
	}
}

func TestLegacyDumpPositionalCountsHaveAnExplicitGrammar(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"0x400000 16", "--count 16 0x400000"},
		{"0x400000 010", "--count 8 0x400000"},
		{"4194304 0x10", "--count 16 4194304"},
		{"0 1", "--count 1 0"},
		{"0x400000 +8", "0x400000 +8"},
		{"$rsp +8", "$rsp +8"},
		{"$rsp 8", "$rsp 8"},
		{"+ 8", "+ 8"},
		{"~ 1", "~ 1"},
		{"--count 8 $rsp + 8", "--count 8 $rsp + 8"},
		{"`symbol with spaces` + 8", "`symbol with spaces` + 8"},
	} {
		got, err := legacyDumpArguments(test.input)
		if err != nil || got != test.want {
			t.Fatalf("legacy dump %q: %q %v, want %q", test.input, got, err, test.want)
		}
	}
	if _, err := legacyDumpArguments("0 0x10000000000000000"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("overflowing legacy count: %v", err)
	}
}

func TestLegacyXXDCompoundUnitsAndLiteralArguments(t *testing.T) {
	for _, test := range []struct{ input, unit, want string }{
		{"0x400000", "byte", "0x400000"},
		{"dword 0x400000 010", "dword", "--count 8 0x400000"},
		{"qword $rsp 2", "qword", "--count 2 $rsp"},
		{"qword '$rsp + 8' 2", "qword", "--count 2 $rsp + 8"},
		{"dword --count 4 $rsp + 8", "dword", "--count 4 $rsp + 8"},
		{"--count 2 `symbol with spaces`", "byte", "--count 2 `symbol with spaces`"},
	} {
		unit, expression, err := legacyXXDArguments(test.input)
		if err != nil || unit != test.unit || expression != test.want {
			t.Fatalf("xxd %q: %q %q %v, want %q %q", test.input, unit, expression, err, test.unit, test.want)
		}
	}
	for _, input := range []string{"", "dword", "qword", "qword 0x400000 +8", "0 1 2", "0 0x10000000000000000", "''", "'unfinished"} {
		if _, _, err := legacyXXDArguments(input); err == nil {
			t.Fatalf("invalid xxd syntax accepted: %q", input)
		}
	}
}

func TestLegacyDumpDispatchPreservesRawMemoryAndCounts(t *testing.T) {
	for _, command := range []struct {
		name, arguments string
		address         target.Address
		bytes           int
	}{
		{"db", "0x70000000 8", 0x70000000, 8},
		{"dd", "0x70000000 2", 0x70000000, 8},
		{"dq", "0x70000000 2", 0x70000000, 16},
		{"xxd", "qword '$rsp + 8' 2", 0x70000008, 16},
		{"xxd", "dword --count 2 $rsp", 0x70000000, 8},
		{"db", "--count 8 $rsp + 8", 0x70000008, 8},
	} {
		t.Run(command.name+command.arguments, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			var output bytes.Buffer
			c := &Controller{session: fixture, selected: thread.Ref, out: &output}
			executeController(t, c, command.name, command.arguments)
			if len(fixture.stackCalls) != 1 || fixture.stackCalls[0].address != command.address || fixture.stackCalls[0].size != command.bytes || len(fixture.codeCalls) != 0 {
				t.Fatalf("wrong raw dump access: %s %+v", output.String(), fixture)
			}
		})
	}
}

func TestLegacyDumpInvalidCountsDoNotReadTarget(t *testing.T) {
	for _, command := range []struct{ name, arguments string }{
		{"db", "0x400000 0"}, {"dd", "0x400000 1025"}, {"dq", "0x400000 513"},
		{"xxd", "qword $rsp 0"}, {"xxd", "qword $rsp 513"}, {"xxd", "dword 0x400000 -1"},
	} {
		fixture, _, thread := newContextFixture()
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		_, err := c.Execute(context.Background(), command.name, command.arguments)
		if !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || output.Len() != 0 {
			t.Fatalf("invalid dump %s %s: err=%v output=%q %+v", command.name, command.arguments, err, output.String(), fixture)
		}
	}
}

func TestLegacyColorLegendUsesExistingRendererPolicy(t *testing.T) {
	for _, test := range []struct {
		options display.Options
		color   bool
	}{
		{display.Options{Mode: display.ColorNever}, false},
		{display.Options{Mode: display.ColorAuto, IsTerminal: true, Term: "xterm", NoColor: "1"}, false},
		{display.Options{Mode: display.ColorAlways}, true},
	} {
		renderer, err := display.NewRenderer(test.options)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		c := New(&output, renderer)
		executeController(t, c, "COLOR", "")
		text := output.String()
		if strings.ContainsRune(text, '\x1b') != test.color || strings.Contains(text, "not inferred") || !strings.Contains(text, "rwx") || c.session != nil {
			t.Fatalf("legend changed policy or inferred permissions: %q", text)
		}
	}
	c := New(io.Discard, display.Renderer{})
	if _, err := c.Execute(context.Background(), "color", "on"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("color unexpectedly accepted a toggle: %v", err)
	}
}

func TestLegacyHelpExplainsExactScopeAndCompatibility(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
	}{
		{"s", []string{"Legacy s/S aliases mean start", "not GDB"}},
		{"B pie", []string{"ET_EXEC has bias zero", "not automatically unbased"}},
		{"xxd dword", []string{"COUNT counts", "4096 bytes", "quote"}},
		{"wp list", []string{"thread-local", "generation", "newborn"}},
		{"SIMD", []string{"XSAVE", "initial state", "malformed"}},
		{"XMM", []string{"full SIMD", "0..15"}},
		{"CHECKSEC", []string{"symbol evidence", "does not prove runtime"}},
		{"GOT", []string{"No index-times-16", "unreadable-as-zero"}},
		{"STDIO-DUMP", []string{"matching libc DWARF", "wide vtables", "rather than guessed", "pager"}},
		{"fs", []string{"128 raw bytes", "No automatic canary"}},
		{"tel", []string{"--depth", "cycles", "NUL-terminated", "unicode.IsPrint"}},
		{"findruction", []string{"do not prove instruction boundaries", "not asserted runtime"}},
		{"asm", []string{"never a shell", "unresolved .text relocations", "all its descendants"}},
		{"cyclic", []string{"first exact match", "shorter than 4 bytes may be nonunique"}},
		{"sym", []string{"scope and metadata are verified", "kernel-vma-build-id-metadata", "does not prove the same backing file", "partial errors"}},
		{"disass func", []string{"[--module EXACT]", "verified loaded symbol scope", "independently limits the function-extent source", "No automatic cross-module fallback"}},
		{"VIS", []string{"START END", "With no arguments"}},
		{"CHUNK", []string{"--layout glibc-amd64", "No allocator"}},
		{"!", []string{"entire remainder", "remain literal", "owned shell process group", "Only TTY stdin", "Non-TTY", "<FILE", "NO_NEW_PRIVS restriction is added", "ownership is retained", "incomplete cleanup is not reported as success"}},
	} {
		t.Run(test.command, func(t *testing.T) {
			var output bytes.Buffer
			c := New(&output, display.Renderer{})
			executeController(t, c, "help", test.command)
			for _, wanted := range test.want {
				if !strings.Contains(output.String(), wanted) {
					t.Fatalf("help %s missing %q: %s", test.command, wanted, output.String())
				}
			}
		})
	}
}
