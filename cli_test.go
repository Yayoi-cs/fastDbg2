package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunCLIHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"-h"}, {"--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			if err := runCLI(args, &output); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fastDbg2", "Usage:", "command interface is not implemented"} {
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
				t.Fatal("expected an unimplemented command error")
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

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}
