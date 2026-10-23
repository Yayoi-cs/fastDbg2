package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitCommand(t *testing.T) {
	for _, test := range []struct {
		name string
		line string
		head string
		tail string
	}{
		{"empty", "", "", ""},
		{"space", " \t\r\n", "", ""},
		{"name", "help", "help", ""},
		{"padded", " \thelp\t ", "help", ""},
		{"arguments", "start one two", "start", "one two"},
		{"expression", "break `symbol.name` + $rip  ", "break", "`symbol.name` + $rip  "},
		{"literal expression", "break `name ' \" \\  space`", "break", "`name ' \" \\  space`"},
		{"raw quoting", "run \"\" 'two words' a\\ b", "run", "\"\" 'two words' a\\ b"},
		{"unicode", "\u3000thread\t日本語", "thread", "日本語"},
		{"no command quoting", "'help'", "'help'", ""},
		{"invalid byte preserved", "break \xff", "break", "\xff"},
		{"control preserved", "\x1bhelp test", "\x1bhelp", "test"},
		{"explicit shell attached", "!printf 'hello world'", "!", "printf 'hello world'"},
		{"explicit shell whitespace", " \t!  printf '%s' a\\   b ", "!", "  printf '%s' a\\   b "},
		{"explicit shell newline", "!printf x\\\ny\nprintf z", "!", "printf x\\\ny\nprintf z"},
		{"explicit shell quoting", "!printf \"$HOME\" 'a\\b' `pwd` $(id)", "!", "printf \"$HOME\" 'a\\b' `pwd` $(id)"},
		{"explicit shell empty", "!", "!", ""},
		{"shell not implicit", "run !echo $HOME", "run", "!echo $HOME"},
	} {
		t.Run(test.name, func(t *testing.T) {
			head, tail := SplitCommand(test.line)
			if head != test.head || tail != test.tail {
				t.Fatalf("got %q, %q; want %q, %q", head, tail, test.head, test.tail)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"spaces", " \t\r\n\u3000", nil},
		{"plain", "a b\tc", []string{"a", "b", "c"}},
		{"single quoted", "'two words'", []string{"two words"}},
		{"double quoted", `"two words"`, []string{"two words"}},
		{"empty quoted", `"" ''`, []string{"", ""}},
		{"concatenation", `pre"two words"'post' ""suffix`, []string{"pretwo wordspost", "suffix"}},
		{"escaped", `a\ b c\\d \"quoted\"`, []string{"a b", `c\d`, `"quoted"`}},
		{"quoted escape", `"a\"b\\c\ d"`, []string{`a"b\c d`}},
		{"single literal", `'a\b"c'`, []string{`a\b"c`}},
		{"quoted quote", `"a'b" 'a"b'`, []string{"a'b", `a"b`}},
		{"unicode", `日本語 "🌐 文" λ\ μ`, []string{"日本語", "🌐 文", "λ μ"}},
		{"no variable expansion", `$HOME "$HOME" '${HOME}'`, []string{"$HOME", "$HOME", "${HOME}"}},
		{"no glob expansion", "~ ~/foo *.go ?", []string{"~", "~/foo", "*.go", "?"}},
		{"no shell syntax", "`pwd` $(id) ; | & > < #", []string{"`pwd`", "$(id)", ";", "|", "&", ">", "<", "#"}},
		{"backticks literal", "`two words`", []string{"`two", "words`"}},
		{"backslash is not C escape", `\n "\t"`, []string{"n", "t"}},
		{"leading dash", "-- --file -x", []string{"--", "--file", "-x"}},
		{"quoted whitespace", "' \t\r\n '", []string{" \t\r\n "}},
		{"escaped newline", "a\\\nb", []string{"a\nb"}},
		{"control literal", "'\x1b[31m'", []string{"\x1b[31m"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseArgs(test.input)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestParseArgsRejectsIncompleteOrInvalidInput(t *testing.T) {
	for _, input := range []string{
		"\\", "prefix \\", "'", "\"", "'unterminated", "\"unfinished\\", "\"unfinished\\\"",
		"\x00", "'\x00'", "\"\x00\"", "a\\\x00", "\xff", "valid '\xff'",
	} {
		t.Run(input, func(t *testing.T) {
			args, err := ParseArgs(input)
			if err == nil || args != nil {
				t.Fatalf("got %q, %v; want no arguments and an error", args, err)
			}
			if strings.ContainsRune(err.Error(), '\x1b') || strings.ContainsRune(err.Error(), '\x00') {
				t.Fatalf("unsafe error output: %q", err)
			}
		})
	}
}
