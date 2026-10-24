package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/internal/debugger"
)

func TestRunCLIHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"-h"}, {"--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			if err := runCLI(args, &output); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fastDbg2", "Usage:", "--interactive", "-f FILE", "-p PID", "Linux/amd64 host", "native x86 (32-bit) and amd64 targets"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("help does not contain %q: %q", want, output.String())
				}
			}
		})
	}
}

func TestRunCLIRejectsCommands(t *testing.T) {
	for _, args := range [][]string{{"run", "/bin/true"}, {"--unknown"}, {"-h", "run"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			if err := runCLI(args, &output); err == nil {
				t.Fatal("expected an unsupported argument error")
			}
			if output.Len() != 0 {
				t.Fatalf("unexpected output: %q", output.String())
			}
		})
	}
}

func TestRunCLIReturnsWriterError(t *testing.T) {
	want := errors.New("write failed")
	err := runCLI(nil, writerFunc(func([]byte) (int, error) { return 0, want }))
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func TestRunCLIHelpShortWrite(t *testing.T) {
	err := runCLI(nil, writerFunc(func(p []byte) (int, error) { return len(p) - 1, nil }))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want short write", err)
	}
}

func TestRunCLIErrorIsSafeAndPreservesCause(t *testing.T) {
	want := errors.New("failure \x1b[31m\x07\n日本語\xff")
	err := runCLI(nil, writerFunc(func([]byte) (int, error) { return 0, want }))
	if !errors.Is(err, want) {
		t.Fatalf("lost error cause: %v", err)
	}
	for _, value := range []byte{0x1b, 0x07, '\n', 0xff} {
		if strings.IndexByte(err.Error(), value) >= 0 {
			t.Fatalf("unsafe byte %#x in public error %q", value, err.Error())
		}
	}
	if !strings.Contains(err.Error(), "日本語") || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("safe error lost readable information: %q", err.Error())
	}
}

func TestRunCLIStartupPathErrorIsSafe(t *testing.T) {
	path := t.TempDir() + "/missing-\x1b[31mPWN\x07\nNEXT"
	var output bytes.Buffer
	err := runCLI([]string{"-f", path}, &output)
	if err == nil {
		t.Fatal("missing startup path succeeded")
	}
	if strings.ContainsAny(err.Error(), "\x1b\x07\n") {
		t.Fatalf("startup path error contains raw controls: %q", err.Error())
	}
	if output.Len() != 0 {
		t.Fatalf("startup path error wrote output: %q", output.String())
	}
}

func TestParseCLIOptions(t *testing.T) {
	for _, test := range []struct {
		args []string
		want cliOptions
	}{
		{[]string{"--interactive"}, cliOptions{}},
		{[]string{"-f", "program"}, cliOptions{file: "program"}},
		{[]string{"-f", "two words", "--", "", "a b", "$HOME", "`pwd`", "-p", "1"}, cliOptions{file: "two words", args: []string{"", "a b", "$HOME", "`pwd`", "-p", "1"}}},
		{[]string{"-f", "program", "--"}, cliOptions{file: "program", args: []string{}}},
		{[]string{"-p", "1234"}, cliOptions{pid: 1234}},
		{[]string{"-p", "0001234"}, cliOptions{pid: 1234}},
		{[]string{"--interactive", "-f", "program"}, cliOptions{file: "program"}},
		{[]string{"-f", "program", "--interactive"}, cliOptions{file: "program"}},
		{[]string{"--interactive", "-p", "1234"}, cliOptions{pid: 1234}},
		{[]string{"-p", "1234", "--interactive"}, cliOptions{pid: 1234}},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			before := slices.Clone(test.args)
			got, err := parseCLIOptions(test.args)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %+v, %v; want %+v", got, err, test.want)
			}
			if !slices.Equal(test.args, before) {
				t.Fatal("option parsing mutated caller arguments")
			}
		})
	}
}

func TestParseCLIOptionsOwnsTargetArgs(t *testing.T) {
	args := []string{"-f", "program", "--", "one"}
	got, err := parseCLIOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	args[3] = "changed"
	if got.args[0] != "one" {
		t.Fatalf("target arguments alias caller memory: %q", got.args)
	}
}

func TestRunCLIRejectsOptionsBeforeSideEffects(t *testing.T) {
	for _, args := range [][]string{
		{"--interactive", "extra"}, {"--interactive", "--interactive"}, {"--interactive", "--help"},
		{"-f"}, {"-f", ""}, {"-p"}, {"-p", ""}, {"-p", "0"}, {"-p", "-1"}, {"-p", "+1"},
		{"-p", "0x10"}, {"-p", " 1"}, {"-p", "1 "}, {"-p", "１"}, {"-p", "18446744073709551616"},
		{"-p", strconv.FormatUint(uint64(^uint(0)>>1)+1, 10)}, {"-f", "a", "-f", "b"},
		{"-f", "a", "-p", "1"}, {"-p", "1", "-f", "a"}, {"-p", "1", "-p", "2"},
		{"-f", "a", "extra"}, {"-f", "a", "--unknown"}, {"-p", "1", "--"}, {"--interactive", "--"},
		{"--", "a"}, {"-f=a"}, {"-p=1"}, {"-h", "extra"}, {"\x1b"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			input := &integrationReader{err: errors.New("invalid options must not read")}
			var output bytes.Buffer
			err := runCLIInput(args, input, &output)
			if err == nil {
				t.Fatalf("accepted invalid options: %q", args)
			}
			if input.reads != 0 || input.closes != 0 || output.Len() != 0 {
				t.Fatalf("invalid options had side effects: reads=%d closes=%d output=%q", input.reads, input.closes, output.String())
			}
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Fatalf("unsafe option error: %q", err.Error())
			}
		})
	}
}

func TestParseCLIOptionsRequiresMode(t *testing.T) {
	if _, err := parseCLIOptions(nil); err == nil {
		t.Fatal("accepted missing interactive mode")
	}
}

func TestRunConsoleInterrupt(t *testing.T) {
	var reads int
	input := lineReaderFunc(func() (string, error) {
		reads++
		if reads == 1 {
			return "discarded", cli.ErrInterrupt
		}
		return "exit", nil
	})
	var output bytes.Buffer
	if err := runConsole(context.Background(), input, &output, display.Renderer{}); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || output.Len() != 0 {
		t.Fatalf("got %d reads, %q output", reads, output.String())
	}
}

func TestRunConsoleDoesNotHideJoinedErrors(t *testing.T) {
	want := errors.New("restore failed")
	for _, inputErr := range []error{errors.Join(cli.ErrInterrupt, want), errors.Join(io.EOF, want)} {
		input := lineReaderFunc(func() (string, error) { return "", inputErr })
		err := runConsole(context.Background(), input, io.Discard, display.Renderer{})
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want restore failure", err)
		}
	}
}

func TestRunConsoleContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	input := lineReaderFunc(func() (string, error) {
		t.Fatal("read after cancellation")
		return "", nil
	})
	if err := runConsole(ctx, input, io.Discard, display.Renderer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestRunConsoleContextAndReadError(t *testing.T) {
	want := errors.New("read failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := lineReaderFunc(func() (string, error) {
		cancel()
		return "", want
	})
	err := runConsole(ctx, input, io.Discard, display.Renderer{})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, want) {
		t.Fatalf("got %v, want cancellation and read failure", err)
	}
}

func TestRunConsolePreservesRawCommandArguments(t *testing.T) {
	input := &integrationLines{lines: []integrationLine{
		{line: " \tbreak `name ' \" \\  space` + $rip  "},
		{line: "run \"\" 'two words' a\\ b"},
		{line: "quit"},
	}}
	var calls [][2]string
	controller := &testConsoleController{execute: func(ctx context.Context, name, args string) (bool, error) {
		calls = append(calls, [2]string{name, args})
		return name == "quit", nil
	}}
	if err := runConsoleController(context.Background(), input, io.Discard, display.Renderer{}, controller, nil); err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{"break", "`name ' \" \\  space` + $rip  "}, {"run", "\"\" 'two words' a\\ b"}, {"quit", ""}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("got command calls %q, want %q", calls, want)
	}
}

func TestRunConsoleWaitsForCanceledCommandToFinish(t *testing.T) {
	signals := newConsoleSignals(context.Background())
	defer signals.Close()
	var finished bool
	var reads int
	input := lineReaderFunc(func() (string, error) {
		reads++
		if reads == 1 {
			return "continue", nil
		}
		if !finished {
			t.Fatal("read input before interrupted command finished")
		}
		return "quit", nil
	})
	controller := &testConsoleController{execute: func(ctx context.Context, name, args string) (bool, error) {
		if name == "quit" {
			return true, nil
		}
		signals.route(os.Interrupt)
		if !errors.Is(ctx.Err(), context.Canceled) || signals.ctx.Err() != nil {
			t.Fatalf("wrong interrupt scope: command=%v console=%v", ctx.Err(), signals.ctx.Err())
		}
		finished = true
		return false, nil
	}}
	if err := runConsoleController(signals.ctx, input, io.Discard, display.Renderer{}, controller, signals); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatalf("got %d reads, want 2", reads)
	}
}

func TestRunConsoleRecoversFromCommandAndQuitErrors(t *testing.T) {
	for _, first := range []string{"break invalid", "quit"} {
		input := &integrationLines{lines: []integrationLine{{line: first}, {line: "quit"}}}
		var output bytes.Buffer
		var calls int
		controller := &testConsoleController{execute: func(context.Context, string, string) (bool, error) {
			calls++
			if calls == 1 {
				return false, errors.New("failure \x1b[31m")
			}
			return true, nil
		}}
		if err := runConsoleController(context.Background(), input, &output, display.Renderer{}, controller, nil); err != nil {
			t.Fatal(err)
		}
		if calls != 2 || input.reads != 2 || !strings.Contains(output.String(), "error:") || strings.ContainsRune(output.String(), '\x1b') {
			t.Fatalf("error did not recover safely: calls=%d reads=%d output=%q", calls, input.reads, output.String())
		}
	}
}

func TestRunConsoleContextAndCommandError(t *testing.T) {
	want := errors.New("command failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controller := &testConsoleController{execute: func(context.Context, string, string) (bool, error) {
		cancel()
		return false, want
	}}
	input := &integrationLines{lines: []integrationLine{{line: "continue"}, {line: "must-not-read"}}}
	err := runConsoleController(ctx, input, io.Discard, display.Renderer{}, controller, nil)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, want) || input.reads != 1 {
		t.Fatalf("lost cancellation/command failure or read more input: %v, reads=%d", err, input.reads)
	}
}

func TestRunConsoleErrorShortWrite(t *testing.T) {
	controller := &testConsoleController{execute: func(context.Context, string, string) (bool, error) {
		return false, errors.New("command failed")
	}}
	input := &integrationLines{lines: []integrationLine{{line: "break invalid"}}}
	err := runConsoleController(context.Background(), input, writerFunc(func(p []byte) (int, error) {
		return len(p) - 1, nil
	}), display.Renderer{}, controller, nil)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want short write", err)
	}
}

func TestRunConsoleOutputErrorStopsDispatch(t *testing.T) {
	want := errors.New("output failed")
	controller := &testConsoleController{execute: func(context.Context, string, string) (bool, error) {
		return false, &debugger.OutputError{Err: want}
	}}
	input := &integrationLines{lines: []integrationLine{{line: "help"}, {line: "must-not-read"}}}
	var output bytes.Buffer
	err := runConsoleController(context.Background(), input, &output, display.Renderer{}, controller, nil)
	if !errors.Is(err, want) || input.reads != 1 || output.Len() != 0 {
		t.Fatalf("output error did not terminate dispatch: %v reads=%d output=%q", err, input.reads, output.String())
	}
}

func TestRegisteredCommandsCompleteWithoutArgumentCompletion(t *testing.T) {
	names := debugger.CommandNames()
	completer, err := cli.NewCompleter(names)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		candidates, _ := completer.Do([]rune(name), len([]rune(name)))
		found := false
		for _, candidate := range candidates {
			found = found || string(candidate) == " "
		}
		if !found {
			t.Fatalf("registered command %q is not completed: %q", name, candidates)
		}
		for _, suffix := range []string{" ", " test", " 'unfinished", " `symbol"} {
			line := []rune(name + suffix)
			got, offset := completer.Do(line, len(line))
			if len(got) != 0 || offset != 0 {
				t.Fatalf("unexpected argument completion for %q: %q, %d", line, got, offset)
			}
		}
	}
}

type testConsoleController struct {
	execute func(context.Context, string, string) (bool, error)
}

func (c *testConsoleController) Execute(ctx context.Context, name, args string) (bool, error) {
	return c.execute(ctx, name, args)
}

func (c *testConsoleController) Close() error {
	return nil
}

type lineReaderFunc func() (string, error)

func (f lineReaderFunc) ReadLine() (string, error) {
	return f()
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}
