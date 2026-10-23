package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
)

type promptLines struct {
	lines       []integrationLine
	prompts     []string
	interactive bool
}

func (r *promptLines) SetPrompt(prompt string) { r.prompts = append(r.prompts, prompt) }

func (r *promptLines) Interactive() bool { return r.interactive }

func (r *promptLines) ReadLine() (string, error) {
	if len(r.lines) == 0 {
		return "", io.EOF
	}
	line := r.lines[0]
	r.lines = r.lines[1:]
	return line.line, line.err
}

type promptConsole struct {
	prompt string
	reads  int
}

func (c *promptConsole) Prompt() string { c.reads++; return c.prompt }

func (c *promptConsole) Close() error { return nil }

func (c *promptConsole) Execute(_ context.Context, name, _ string) (bool, error) {
	if name == "advance" {
		c.prompt = "[fastDbg2:0x401000]$ "
	}
	if name == "bad" {
		return false, errors.New("bad command")
	}
	return name == "quit", nil
}

func TestConsoleRefreshesPromptBeforeEveryInteractiveRead(t *testing.T) {
	input := &promptLines{interactive: true, lines: []integrationLine{{err: cli.ErrInterrupt}, {}, {line: "bad"}, {line: "advance"}, {line: "quit"}}}
	controller := &promptConsole{prompt: "[fastDbg2]$ "}
	var output bytes.Buffer
	if err := runConsoleController(context.Background(), input, &output, display.Renderer{}, controller, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"[fastDbg2]$ ", "[fastDbg2]$ ", "[fastDbg2]$ ", "[fastDbg2]$ ", "[fastDbg2:0x401000]$ "}
	if !reflect.DeepEqual(input.prompts, want) || controller.reads != len(want) {
		t.Fatalf("prompt updates: %q, calls=%d", input.prompts, controller.reads)
	}
}

func TestConsoleStreamDoesNotRequestOrPrintPrompts(t *testing.T) {
	input := &promptLines{lines: []integrationLine{{line: "quit"}}}
	controller := &promptConsole{prompt: "[fastDbg2:0x401000]$ "}
	var output bytes.Buffer
	if err := runConsoleController(context.Background(), input, &output, display.Renderer{}, controller, nil); err != nil {
		t.Fatal(err)
	}
	if len(input.prompts) != 0 || controller.reads != 0 || output.Len() != 0 {
		t.Fatalf("stream prompt side effect: %q, calls=%d, output=%q", input.prompts, controller.reads, output.String())
	}
	if err := runCLIInput([]string{"--interactive"}, strings.NewReader("not_a_command\nquit\n"), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "[fastDbg2") || strings.ContainsRune(output.String(), '\x1b') {
		t.Fatalf("stream terminal formatting: %q", output.String())
	}
}
