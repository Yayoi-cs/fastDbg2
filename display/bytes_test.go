package display_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"fastdbg2/display"
)

func TestFormatBytes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input []byte
		want  string
	}{
		{nil, ""},
		{[]byte{}, ""},
		{[]byte{0}, "00"},
		{[]byte{0x0a}, "0a"},
		{[]byte{0xff}, "ff"},
		{[]byte{0, 0x01, 0x0a, 0x10, 0xab, 0xff}, "00 01 0a 10 ab ff"},
		{[]byte{0x1b, '[', '0', 'm'}, "1b 5b 30 6d"},
	} {
		before := bytes.Clone(test.input)
		if got := display.FormatBytes(test.input); got != test.want {
			t.Fatalf("input %x: got %q, want %q", test.input, got, test.want)
		}
		if !bytes.Equal(test.input, before) {
			t.Fatalf("input mutated: %x became %x", before, test.input)
		}
	}
}

func TestFormatAllBytes(t *testing.T) {
	t.Parallel()
	input := make([]byte, 256)
	want := make([]string, len(input))
	for i := range input {
		input[i] = byte(i)
		want[i] = fmt.Sprintf("%02x", i)
	}
	got := display.FormatBytes(input)
	if got != strings.Join(want, " ") || len(got) != 3*len(input)-1 {
		t.Fatalf("unexpected byte formatting: %q", got)
	}
	input[0] = 0xff
	if !strings.HasPrefix(got, "00 01 ") {
		t.Fatalf("formatted text aliases input: %q", got)
	}
}
