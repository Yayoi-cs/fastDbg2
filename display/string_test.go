package display_test

import (
	"strings"
	"testing"

	"fastdbg2/display"
)

func TestVisibleStringColorRespectsRendererPolicy(t *testing.T) {
	for _, options := range []display.Options{{Mode: display.ColorAlways}, {Mode: display.ColorNever}, {IsTerminal: true, Term: "xterm", NoColor: "1"}} {
		renderer, err := display.NewRenderer(options)
		if err != nil {
			t.Fatal(err)
		}
		text := renderer.Text(display.StyleString, "'SHELL=/bin/bash'")
		want := "'SHELL=/bin/bash'"
		if options.Mode == display.ColorAlways {
			want = "\x1b[33m" + want + "\x1b[0m"
		}
		if text != want {
			t.Fatalf("string color=%q want=%q", text, want)
		}
	}
}

func TestVisibleStringWrapKeepsEscapesAndEllipsisTogether(t *testing.T) {
	for _, annotation := range []string{`'hello world'`, `'quote\' and slash\\ end'...`, "'日本語 and text'..."} {
		for _, color := range []bool{false, true} {
			text := annotation
			if color {
				text = "\x1b[33m" + text + "\x1b[0m"
			}
			wrapped := display.Wrap(strings.Repeat("x", 75)+" "+text+"\n", 80, 4)
			if !strings.Contains(wrapped, "\n    "+text) || strings.Contains(wrapped, "\\\n") || strings.Contains(wrapped, "\n    ...") {
				t.Fatalf("quoted annotation split: %q", wrapped)
			}
		}
	}
}
