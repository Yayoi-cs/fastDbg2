package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"golang.org/x/term"
)

func TestCLIIntegrationHelpDoesNotReadOrCloseInput(t *testing.T) {
	for _, args := range [][]string{nil, {"-h"}, {"--help"}} {
		input := &integrationReader{err: errors.New("help must not read input")}
		output := &integrationWriter{}
		if err := runCLIInput(args, input, output); err != nil {
			t.Fatal(err)
		}
		if input.reads != 0 || input.closes != 0 || output.closes != 0 {
			t.Fatalf("help touched caller streams: reads=%d input closes=%d output closes=%d", input.reads, input.closes, output.closes)
		}
		if !strings.Contains(output.String(), "Usage:") || strings.ContainsRune(output.String(), '\x1b') {
			t.Fatalf("help was not plain: %q", output.String())
		}
	}
}

func TestCLIIntegrationRejectsArgumentsBeforeReading(t *testing.T) {
	for _, args := range [][]string{{"--interactive", "help"}, {"--interactive", "--help"}, {"--unknown"}, {"run", "/bin/true"}} {
		input := &integrationReader{err: errors.New("invalid arguments must not read")}
		var output bytes.Buffer
		if err := runCLIInput(args, input, &output); err == nil {
			t.Fatalf("accepted unsupported arguments: %q", args)
		}
		if input.reads != 0 || input.closes != 0 || output.Len() != 0 {
			t.Fatalf("unsupported arguments had side effects: %q reads=%d closes=%d output=%q", args, input.reads, input.closes, output.String())
		}
	}
}

func TestCLIIntegrationStreamCommandBoundaries(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	for _, test := range []struct {
		name    string
		input   string
		helps   int
		unknown int
		errors  int
	}{
		{"eof", "", 0, 0, 0},
		{"spaces", "\n\r\n \t\n", 0, 0, 0},
		{"help at eof", "help", 1, 0, 0},
		{"crlf", "help\r\nexit\r\n", 1, 0, 0},
		{"exit stops dispatch", "exit\nhelp\n", 0, 0, 0},
		{"quit stops dispatch", "quit\nhelp\n", 0, 0, 0},
		{"trim command", " \thelp\t \nquit\n", 1, 0, 0},
		{"unknown is recoverable", "not-a-command\nhelp\nexit\n", 1, 1, 1},
		{"help arguments rejected", "help argument\nhelp\nexit\n", 1, 0, 1},
		{"no configured executable", "run /bin/true\nhelp\nexit\n", 1, 0, 1},
		{"case sensitive", "Help\nhelp\nexit\n", 1, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &integrationReader{source: strings.NewReader(test.input)}
			output := &integrationWriter{}
			if err := runCLIInput([]string{"--interactive"}, input, output); err != nil {
				t.Fatal(err)
			}
			got := output.String()
			if strings.Count(got, "Commands:") != test.helps || strings.Count(got, "unknown command:") != test.unknown || strings.Count(got, "error:") != test.errors {
				t.Fatalf("unexpected dispatch: %q", got)
			}
			if strings.ContainsRune(got, '\x1b') || strings.Contains(got, "fastDbg2> ") {
				t.Fatalf("stream output has terminal formatting: %q", got)
			}
			if input.closes != 0 || output.closes != 0 {
				t.Fatalf("caller streams closed: input=%d output=%d", input.closes, output.closes)
			}
		})
	}
}

func TestCLIIntegrationUnknownInputIsEscaped(t *testing.T) {
	var output bytes.Buffer
	if err := runCLIInput([]string{"--interactive"}, strings.NewReader("\x1b[31m日本語\nexit\n"), &output); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(output.String(), '\x1b') || !strings.Contains(output.String(), "日本語") || !strings.Contains(output.String(), `\x1b`) {
		t.Fatalf("untrusted command was not safely quoted: %q", output.String())
	}
}

func TestCLIIntegrationStreamReadFailures(t *testing.T) {
	failure := errors.New("independent reader failure")
	for _, data := range []string{"", "help\n", "help"} {
		t.Run(data, func(t *testing.T) {
			input := &integrationReader{source: strings.NewReader(data), err: failure}
			var output bytes.Buffer
			err := runCLIInput([]string{"--interactive"}, input, &output)
			if !errors.Is(err, failure) {
				t.Fatalf("lost read failure: %v", err)
			}
			if input.closes != 0 {
				t.Fatal("caller input closed after read failure")
			}
			want := 0
			if strings.HasSuffix(data, "\n") {
				want = 1
			}
			if strings.Count(output.String(), "Commands:") != want {
				t.Fatalf("incomplete input dispatched or complete line lost: %q", output.String())
			}
		})
	}
}

func TestCLIIntegrationStreamWriteFailures(t *testing.T) {
	failure := errors.New("independent writer failure")
	for _, data := range []string{"help\n", "unknown\n"} {
		input := &integrationReader{source: strings.NewReader(data)}
		output := &integrationWriter{err: failure}
		err := runCLIInput([]string{"--interactive"}, input, output)
		if !errors.Is(err, failure) {
			t.Fatalf("lost write failure for %q: %v", data, err)
		}
		if input.closes != 0 || output.closes != 0 {
			t.Fatalf("caller streams closed after write failure: input=%d output=%d", input.closes, output.closes)
		}
	}
}

func TestCLIIntegrationFileDescriptorsRemainOpen(t *testing.T) {
	dir := t.TempDir()
	input, err := os.Create(filepath.Join(dir, "input"))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.Create(filepath.Join(dir, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if _, err := io.WriteString(input, "help\nexit\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := runCLIInput([]string{"--interactive"}, input, output); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("caller input descriptor unavailable: %v", err)
	}
	if _, err := io.WriteString(output, "caller still owns output\n"); err != nil {
		t.Fatalf("caller output descriptor unavailable: %v", err)
	}
}

func TestCLIIntegrationConsoleInterruptAndCancellation(t *testing.T) {
	input := &integrationLines{lines: []integrationLine{{err: cli.ErrInterrupt}, {line: "help"}, {line: "exit"}, {line: "must-not-dispatch"}}}
	var output bytes.Buffer
	if err := runConsole(context.Background(), input, &output, display.Renderer{}); err != nil {
		t.Fatal(err)
	}
	if input.reads != 3 || strings.Count(output.String(), "Commands:") != 1 {
		t.Fatalf("interrupt or exit handling failed: reads=%d output=%q", input.reads, output.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	input = &integrationLines{}
	output.Reset()
	if err := runConsole(ctx, input, &output, display.Renderer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not returned: %v", err)
	}
	if input.reads != 0 || output.Len() != 0 {
		t.Fatalf("canceled console touched streams: reads=%d output=%q", input.reads, output.String())
	}
}

type integrationReader struct {
	source io.Reader
	err    error
	reads  int
	closes int
}

func (r *integrationReader) Read(data []byte) (int, error) {
	r.reads++
	if r.source != nil {
		n, err := r.source.Read(data)
		if !errors.Is(err, io.EOF) {
			return n, err
		}
		r.source = nil
		if r.err != nil {
			return n, r.err
		}
		return n, err
	}
	if r.err != nil {
		return 0, r.err
	}
	return 0, io.EOF
}

func (r *integrationReader) Close() error {
	r.closes++
	return nil
}

type integrationWriter struct {
	bytes.Buffer
	err    error
	closes int
}

func (w *integrationWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return w.Buffer.Write(data)
}

func (w *integrationWriter) WriteString(text string) (int, error) {
	return w.Write([]byte(text))
}

func (w *integrationWriter) Close() error {
	w.closes++
	return nil
}

type integrationLine struct {
	line string
	err  error
}

type integrationLines struct {
	lines []integrationLine
	reads int
}

func (r *integrationLines) ReadLine() (string, error) {
	r.reads++
	if len(r.lines) == 0 {
		return "", io.EOF
	}
	line := r.lines[0]
	r.lines = r.lines[1:]
	return line.line, line.err
}

func TestCLIIntegrationTTYCallerStreams(t *testing.T) {
	mode := os.Getenv("FASTDBG2_CLI_INTEGRATION_TTY")
	if mode == "" {
		return
	}
	before, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var input io.Reader = os.Stdin
	var output io.Writer = os.Stdout
	var injected *os.File
	if mode == "read-error" || mode == "write-error" {
		flags := os.O_WRONLY
		if mode == "write-error" {
			flags = os.O_RDONLY
		}
		file, err := os.OpenFile("/dev/tty", flags, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		injected = file
		if mode == "write-error" {
			output = file
		} else {
			input = file
		}
	}
	err = runCLIInput([]string{"--interactive"}, input, output)
	switch mode {
	case "signal":
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("signal error: %v", err)
		}
	case "read-error", "write-error":
		if err == nil {
			t.Fatal("terminal I/O error was not returned")
		}
	default:
		if err != nil {
			t.Fatal(err)
		}
	}
	after, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal not restored before returning: before=%+v after=%+v", before, after)
	}
	if injected != nil {
		if _, err := injected.Stat(); err != nil {
			t.Fatalf("injected caller stream closed: %v", err)
		}
	}
	if _, err := os.Stdin.Stat(); err != nil {
		t.Fatalf("caller stdin closed: %v", err)
	}
	if _, err := os.Stdout.Stat(); err != nil {
		t.Fatalf("caller stdout closed: %v", err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "CLI_READER_RETURNED"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	validProbe := line == "caller-input-probe\n"
	if mode == "read-error" {
		validProbe = regexp.MustCompile(`^\x1b\[[0-9]+;[0-9]+Rcaller-input-probe\n$`).MatchString(line)
	}
	if err != nil || !validProbe {
		t.Fatalf("caller stdin unavailable after console: %q %v", line, err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "CLI_CALLER_STREAMS_USABLE"); err != nil {
		t.Fatal(err)
	}
}
