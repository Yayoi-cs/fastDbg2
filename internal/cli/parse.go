package cli

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func SplitCommand(line string) (string, string) {
	line = strings.TrimLeftFunc(line, unicode.IsSpace)
	if strings.HasPrefix(line, "!") {
		return "!", line[1:]
	}
	end := strings.IndexFunc(line, unicode.IsSpace)
	if end < 0 {
		return line, ""
	}
	return line[:end], strings.TrimLeftFunc(line[end:], unicode.IsSpace)
}

func ParseArgs(input string) ([]string, error) {
	if !utf8.ValidString(input) {
		return nil, errors.New("arguments contain invalid UTF-8")
	}
	var args []string
	var value strings.Builder
	var quote rune
	var escaped, started bool
	for _, r := range input {
		if r == 0 {
			return nil, errors.New("arguments contain a NUL byte")
		}
		switch {
		case quote == '\'':
			if r == quote {
				quote = 0
			} else {
				value.WriteRune(r)
			}
		case escaped:
			value.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped, started = true, true
		case quote == '"':
			if r == quote {
				quote = 0
			} else {
				value.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, started = r, true
		case unicode.IsSpace(r):
			if started {
				args = append(args, value.String())
				value.Reset()
				started = false
			}
		default:
			value.WriteRune(r)
			started = true
		}
	}
	if escaped {
		return nil, errors.New("arguments end with an unfinished escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("arguments contain an unterminated %c quote", quote)
	}
	if started {
		args = append(args, value.String())
	}
	return args, nil
}
