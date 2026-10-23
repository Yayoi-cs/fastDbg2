package display_test

import (
	"io"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestSectionWidthsAndEscaping(t *testing.T) {
	var renderer display.Renderer
	for _, width := range []int{0, 1, 8, 80, 100, 140, 1000000} {
		line := renderer.Section("registers", width)
		want := width
		if want <= 0 {
			want = 100
		}
		want = max(11, min(want, 512))
		if len(line) != want || !strings.Contains(line, "[registers]") || strings.ContainsRune(line, '\x1b') {
			t.Fatalf("section width %d: %q", width, line)
		}
	}
	line := renderer.Section("unsafe\x1b[31m\n\u202e", 100)
	if strings.ContainsAny(line, "\x1b\n\u202e") || !strings.Contains(line, `\x1b`) {
		t.Fatalf("unescaped section: %q", line)
	}
	if got := display.OutputWidth(io.Discard); got != 100 {
		t.Fatalf("nonterminal width: %d", got)
	}
	if text := renderer.Section("レジスタ", 40); display.VisibleWidth(text) != 40 {
		t.Fatalf("wide section label: %q", text)
	}
}

func TestPermissionColorsUseOnlyExplicitPermissionBits(t *testing.T) {
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		read, write, execute bool
		code                 string
	}{
		{true, true, true, "33"}, {true, false, true, "31"}, {false, false, true, "31"},
		{true, true, false, "36"}, {true, false, false, "34"}, {false, true, false, "32"}, {false, false, false, "90"},
	} {
		for _, address := range []target.Address{0, 0x401000, 0x7ffffffff000} {
			var plain display.Renderer
			text, err := plain.AddressPermissions(target.AMD64, address, test.read, test.write, test.execute)
			if err != nil || strings.ContainsRune(text, '\x1b') {
				t.Fatalf("plain permission address: %q %v", text, err)
			}
			got, err := renderer.AddressPermissions(target.AMD64, address, test.read, test.write, test.execute)
			want := "\x1b[" + test.code + "m" + text + "\x1b[0m"
			if err != nil || got != want {
				t.Fatalf("explicit permissions %+v: %q %v, want %q", test, got, err, want)
			}
		}
	}
	explicit, err := renderer.Address(target.AMD64, 0x401000, display.AddressCode)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := renderer.AddressPermissions(target.AMD64, 0x401000, true, false, true)
	if err != nil || explicit != verified {
		t.Fatalf("code theme differs between explicit role and verified mapping: %q %q %v", explicit, verified, err)
	}
}

func TestWrapPreservesANSIAndAddressWords(t *testing.T) {
	line := "$rax   : \x1b[36m0x0000000000500000\x1b[0m -> 0x0000000000600000 -> 0x0000000000700000 -> 0x0000000000800000\n"
	wrapped := display.Wrap(line, 80, 9)
	if !strings.Contains(wrapped, "\n         ") || !strings.Contains(wrapped, "\x1b[36m0x0000000000500000\x1b[0m") {
		t.Fatalf("word/ANSI wrapping: %q", wrapped)
	}
	for _, row := range strings.Split(strings.TrimSuffix(wrapped, "\n"), "\n") {
		if display.VisibleWidth(row) > 80 {
			t.Fatalf("wrapped row too wide: %q", row)
		}
	}
	if got := display.VisibleWidth("\x1b[1m日本\x1b[0me\u0301"); got != 5 {
		t.Fatalf("Unicode/ANSI column count: %d", got)
	}
	grouped := display.Wrap(strings.Repeat("x", 65)+" -> \x1b[2m[loop detected]\x1b[0m\n", 80, 4)
	if !strings.Contains(grouped, "[loop detected]") || strings.Contains(grouped, "[loop\n") {
		t.Fatalf("terminal state label split: %q", grouped)
	}
	if got := display.Pad("日本", 8); display.VisibleWidth(got) != 8 {
		t.Fatalf("display-cell padding: %q", got)
	}
}
