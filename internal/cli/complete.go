package cli

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Completer struct {
	names []string
}

func NewCompleter(names []string) (*Completer, error) {
	names = slices.Clone(names)
	for _, name := range names {
		if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "'\"`\\") {
			return nil, fmt.Errorf("invalid completion name: %q", name)
		}
		for _, r := range name {
			if unicode.IsSpace(r) || unicode.IsControl(r) {
				return nil, fmt.Errorf("invalid completion name: %q", name)
			}
		}
	}
	slices.Sort(names)
	return &Completer{names: slices.Compact(names)}, nil
}

func (c *Completer) Do(line []rune, cursor int) ([][]rune, int) {
	if cursor < 0 || cursor > len(line) {
		return nil, 0
	}
	start := 0
	for start < cursor && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	for _, r := range line[start:cursor] {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("'\"`\\", r) {
			return nil, 0
		}
	}
	if cursor < len(line) && line[cursor] != ' ' && line[cursor] != '\t' {
		return nil, 0
	}
	prefix := string(line[start:cursor])
	var candidates [][]rune
	for _, name := range c.names {
		if strings.HasPrefix(name, prefix) {
			suffix := []rune(strings.TrimPrefix(name, prefix))
			if cursor == len(line) {
				suffix = append(suffix, ' ')
			}
			candidates = append(candidates, suffix)
		}
	}
	if len(candidates) == 0 {
		return nil, 0
	}
	return candidates, cursor - start
}
