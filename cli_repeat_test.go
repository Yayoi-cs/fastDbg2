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

type repeatedCommand struct {
	name, arguments string
}

type repeatConsole struct {
	commands []repeatedCommand
}

func (c *repeatConsole) Close() error { return nil }

func (c *repeatConsole) Execute(_ context.Context, name, arguments string) (bool, error) {
	c.commands = append(c.commands, repeatedCommand{name, arguments})
	if name == "bad" || strings.TrimSpace(name) == "" {
		return false, errors.New("unknown command")
	}
	return name == "quit", nil
}

func TestConsoleInteractiveRepeatsPreviousRawCommand(t *testing.T) {
	for _, test := range []struct {
		name   string
		lines  []integrationLine
		want   []repeatedCommand
		errors int
	}{
		{"empty initially", []integrationLine{{}, {line: "quit"}}, []repeatedCommand{{"quit", ""}}, 0},
		{"arguments", []integrationLine{{line: "  p   '$rip + 1' "}, {}, {line: "quit"}}, []repeatedCommand{{"p", "'$rip + 1' "}, {"p", "'$rip + 1' "}, {"quit", ""}}, 0},
		{"explicit shell", []integrationLine{{line: "! printf '%s\\n' '$HOME'"}, {}, {line: "quit"}}, []repeatedCommand{{"!", " printf '%s\\n' '$HOME'"}, {"!", " printf '%s\\n' '$HOME'"}, {"quit", ""}}, 0},
		{"error retained", []integrationLine{{line: "bad"}, {}, {line: "quit"}}, []repeatedCommand{{"bad", ""}, {"bad", ""}, {"quit", ""}}, 2},
		{"spaces retained", []integrationLine{{line: "p 7"}, {line: "   "}, {}, {line: "quit"}}, []repeatedCommand{{"p", "7"}, {"   ", ""}, {"   ", ""}, {"quit", ""}}, 2},
		{"interrupt preserves previous", []integrationLine{{line: "p 9"}, {line: "cancelled input", err: cli.ErrInterrupt}, {}, {line: "quit"}}, []repeatedCommand{{"p", "9"}, {"p", "9"}, {"quit", ""}}, 0},
		{"eof never repeats", []integrationLine{{line: "p 11"}, {err: io.EOF}}, []repeatedCommand{{"p", "11"}}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &promptLines{interactive: true, lines: test.lines}
			controller := &repeatConsole{}
			var output bytes.Buffer
			if err := runConsoleController(context.Background(), input, &output, display.Renderer{}, controller, nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(controller.commands, test.want) || strings.Count(output.String(), "error:") != test.errors {
				t.Fatalf("repeat commands=%#v, want=%#v, output=%q", controller.commands, test.want, output.String())
			}
		})
	}
}

func TestConsoleScriptBlankLinesNeverRepeat(t *testing.T) {
	input := &promptLines{lines: []integrationLine{{line: "p 7"}, {}, {line: "  "}, {line: "\t"}, {line: "quit"}}}
	controller := &repeatConsole{}
	if err := runConsoleController(context.Background(), input, io.Discard, display.Renderer{}, controller, nil); err != nil {
		t.Fatal(err)
	}
	if want := []repeatedCommand{{"p", "7"}, {"quit", ""}}; !reflect.DeepEqual(controller.commands, want) {
		t.Fatalf("script repeated a command: %#v", controller.commands)
	}
}
