package display_test

import (
	"errors"
	"math"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestAddressWidths(t *testing.T) {
	t.Parallel()
	var renderer display.Renderer
	for _, test := range []struct {
		arch    target.Architecture
		address target.Address
		want    string
	}{
		{target.X86, 0, "0x00000000"},
		{target.X86, 0x123abc, "0x00123abc"},
		{target.X86, math.MaxUint32, "0xffffffff"},
		{target.AMD64, 0, "0x0000000000000000"},
		{target.AMD64, 0x123abc, "0x0000000000123abc"},
		{target.AMD64, math.MaxUint64, "0xffffffffffffffff"},
		{target.AArch64, 0, "0x0000000000000000"},
		{target.AArch64, 0x123abc, "0x0000000000123abc"},
		{target.AArch64, math.MaxUint64, "0xffffffffffffffff"},
	} {
		got, err := renderer.Address(test.arch, test.address, display.AddressUnknown)
		if err != nil || got != test.want {
			t.Fatalf("%s %#x: got %q, %v, want %q", test.arch, test.address, got, err, test.want)
		}
	}
}

func TestAddressUsesOnlyExplicitKind(t *testing.T) {
	t.Parallel()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []target.Architecture{target.X86, target.AMD64, target.AArch64} {
		for _, address := range []target.Address{0, 0x401000, 0x7fff1234, math.MaxUint32} {
			var plain display.Renderer
			text, err := plain.Address(arch, address, display.AddressUnknown)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				kind display.AddressKind
				code string
			}{
				{display.AddressUnknown, ""},
				{display.AddressCode, "35"},
				{display.AddressData, "36"},
				{display.AddressStack, "36"},
				{display.AddressHeap, "36"},
			} {
				want := text
				if test.code != "" {
					want = "\x1b[" + test.code + "m" + text + "\x1b[0m"
				}
				got, err := renderer.Address(arch, address, test.kind)
				if err != nil || got != want {
					t.Fatalf("%s %#x kind %d: got %q, %v, want %q", arch, address, test.kind, got, err, want)
				}
				got, err = plain.Address(arch, address, test.kind)
				if err != nil || got != text {
					t.Fatalf("plain %s %#x kind %d: got %q, %v, want %q", arch, address, test.kind, got, err, text)
				}
			}
		}
	}
}

func TestAddressRejectsUnsupportedAndInvalidArguments(t *testing.T) {
	t.Parallel()
	for _, mode := range []display.ColorMode{display.ColorNever, display.ColorAlways} {
		renderer, err := display.NewRenderer(display.Options{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			arch    target.Architecture
			address target.Address
			kind    display.AddressKind
			want    error
		}{
			{target.X86, 1 << 32, display.AddressUnknown, target.ErrOverflow},
			{target.X86, math.MaxUint64, display.AddressCode, target.ErrOverflow},
			{"", 0, display.AddressUnknown, target.ErrUnsupported},
			{"arm64", 0, display.AddressCode, target.ErrUnsupported},
			{"riscv64", 0, display.AddressUnknown, target.ErrUnsupported},
			{target.AMD64, 0, 5, target.ErrInvalidArgument},
			{target.AArch64, 0, 255, target.ErrInvalidArgument},
			{target.X86, math.MaxUint32, 255, target.ErrInvalidArgument},
		} {
			got, err := renderer.Address(test.arch, test.address, test.kind)
			if got != "" || !errors.Is(err, test.want) {
				t.Fatalf("mode %d case %+v: got %q, %v", mode, test, got, err)
			}
		}
	}
}
