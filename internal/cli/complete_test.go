package cli

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCompleter(t *testing.T) {
	completer, err := NewCompleter([]string{"quit", "help", "exit", "help", "終了", "続行"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		line   string
		cursor int
		want   []string
		offset int
	}{
		{"empty", "", 0, []string{"exit ", "help ", "quit ", "終了 ", "続行 "}, 0},
		{"prefix", "he", 2, []string{"lp "}, 2},
		{"exact", "help", 4, []string{" "}, 4},
		{"leading space", "  he", 4, []string{"lp "}, 2},
		{"leading tab", "\the", 3, []string{"lp "}, 2},
		{"suffix", "he 世界", 2, []string{"lp"}, 2},
		{"unicode", "終", 1, []string{"了 "}, 1},
		{"case sensitive", "HE", 2, nil, 0},
		{"unknown", "run", 3, nil, 0},
		{"argument", "help e", 6, nil, 0},
		{"argument empty", "help ", 5, nil, 0},
		{"single quoted", "'he", 3, nil, 0},
		{"double quoted", "\"he", 3, nil, 0},
		{"backtick", "`he", 3, nil, 0},
		{"escaped", "\\he", 3, nil, 0},
		{"middle", "hepl", 2, nil, 0},
		{"before token", "help", 0, nil, 0},
		{"control", "\x1bhe", 3, nil, 0},
		{"newline", "\nhe", 3, nil, 0},
		{"negative", "he", -1, nil, 0},
		{"out of range", "he", 3, nil, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line := []rune(test.line)
			before := slices.Clone(line)
			candidates, offset := completer.Do(line, test.cursor)
			var got []string
			for _, candidate := range candidates {
				got = append(got, string(candidate))
			}
			if !reflect.DeepEqual(got, test.want) || offset != test.offset {
				t.Fatalf("got %q, %d; want %q, %d", got, offset, test.want, test.offset)
			}
			if !slices.Equal(line, before) {
				t.Fatal("completion mutated input")
			}
		})
	}
}

func TestCompleterCopiesNames(t *testing.T) {
	names := []string{"help", "exit"}
	completer, err := NewCompleter(names)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"help", "exit"}) {
		t.Fatal("constructor mutated names")
	}
	names[0] = "halt"
	got, _ := completer.Do([]rune("h"), 1)
	if len(got) != 1 || string(got[0]) != "elp " {
		t.Fatalf("constructor retained caller-owned names: %q", got)
	}
	got[0][0] = 'x'
	again, _ := completer.Do([]rune("h"), 1)
	if string(again[0]) != "elp " {
		t.Fatal("completion retained caller-owned result")
	}
}

func TestCompleterRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", "two words", "a\tb", "a\nb", "\x00", "\x1b[31m", "\u009b", "'quoted'", "\"quoted\"", "`quoted`", "es\\caped", strings.Repeat("\xff", 2)} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCompleter([]string{name}); err == nil {
				t.Fatal("expected invalid completion name error")
			}
		})
	}
}

func TestEmptyCompleter(t *testing.T) {
	var completer Completer
	got, offset := completer.Do(nil, 0)
	if got != nil || offset != 0 {
		t.Fatalf("got %q, %d", got, offset)
	}
}
