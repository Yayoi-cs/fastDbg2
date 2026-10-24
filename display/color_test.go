package display_test

import (
	"errors"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestRendererColorPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		options display.Options
		color   bool
	}{
		{"default", display.Options{}, false},
		{"auto terminal", display.Options{IsTerminal: true, Term: "xterm-256color"}, true},
		{"auto redirected", display.Options{Term: "xterm-256color"}, false},
		{"auto dumb", display.Options{IsTerminal: true, Term: "dumb"}, false},
		{"auto no color", display.Options{IsTerminal: true, NoColor: "1"}, false},
		{"auto no color zero", display.Options{IsTerminal: true, NoColor: "0"}, false},
		{"auto no color whitespace", display.Options{IsTerminal: true, NoColor: " "}, false},
		{"auto empty term", display.Options{IsTerminal: true}, true},
		{"auto empty no color", display.Options{IsTerminal: true, NoColor: ""}, true},
		{"never terminal", display.Options{Mode: display.ColorNever, IsTerminal: true}, false},
		{"never redirected", display.Options{Mode: display.ColorNever}, false},
		{"always terminal", display.Options{Mode: display.ColorAlways, IsTerminal: true}, true},
		{"always redirected", display.Options{Mode: display.ColorAlways}, true},
		{"always dumb", display.Options{Mode: display.ColorAlways, IsTerminal: true, Term: "dumb"}, true},
		{"always no color", display.Options{Mode: display.ColorAlways, NoColor: "1"}, true},
		{"always all disabled", display.Options{Mode: display.ColorAlways, Term: "dumb", NoColor: "1"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			renderer, err := display.NewRenderer(test.options)
			if err != nil {
				t.Fatal(err)
			}
			want := "error"
			if test.color {
				want = "\x1b[31merror\x1b[0m"
			}
			if got := renderer.Text(display.StyleError, "error"); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestRendererRejectsUnknownColorMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []display.ColorMode{3, 255} {
		renderer, err := display.NewRenderer(display.Options{Mode: mode, IsTerminal: true})
		if !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("mode %d: %v", mode, err)
		}
		if got := renderer.Text(display.StyleError, "error"); got != "error" {
			t.Fatalf("failed constructor returned a colored renderer: %q", got)
		}
	}
}

func TestRendererTextStyles(t *testing.T) {
	t.Parallel()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		style display.Style
		want  string
	}{
		{display.StylePlain, "text"},
		{display.StyleHeading, "text"},
		{display.StyleError, "\x1b[31mtext\x1b[0m"},
		{display.StyleMuted, "text"},
		{display.Style(255), "text"},
	} {
		if got := renderer.Text(test.style, "text"); got != test.want {
			t.Fatalf("style %d: got %q, want %q", test.style, got, test.want)
		}
		if got := renderer.Text(test.style, ""); got != "" {
			t.Fatalf("style %d: empty text produced %q", test.style, got)
		}
	}
}

func TestZeroRendererIsPlain(t *testing.T) {
	t.Parallel()
	var renderer display.Renderer
	for _, style := range []display.Style{display.StylePlain, display.StyleHeading, display.StyleError, display.StyleMuted, 255} {
		if got := renderer.Text(style, "text"); got != "text" {
			t.Fatalf("style %d: got %q", style, got)
		}
	}
}

func TestRendererTextPreservesTrustedInput(t *testing.T) {
	t.Parallel()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	input := "日本語 e\u0301\t\x00\r\n\x1b[36mtext\x1b[0m"
	if got := renderer.Text(display.StylePlain, input); got != input {
		t.Fatalf("plain text changed: %q", got)
	}
	if got := renderer.Text(display.StyleHeading, input); got != input {
		t.Fatalf("styled text changed: %q", got)
	}
	var plain display.Renderer
	if got := plain.Text(display.StyleError, input); got != input {
		t.Fatalf("disabled color changed text: %q", got)
	}
}
