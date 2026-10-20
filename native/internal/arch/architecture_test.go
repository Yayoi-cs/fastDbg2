package arch_test

import (
	"errors"
	"math"
	"testing"

	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
)

func TestAddressRanges(t *testing.T) {
	for _, bits := range []int{32, 64} {
		profile := arch.Descriptor{AddressBits: bits}
		maximum, err := profile.MaxAddress()
		if err != nil {
			t.Fatal(err)
		}
		want := target.Address(math.MaxUint64)
		if bits == 32 {
			want = target.Address(math.MaxUint32)
		}
		if maximum != want {
			t.Fatalf("width=%d maximum=%#x", bits, maximum)
		}
		for _, test := range []struct {
			address target.Address
			size    int
			want    error
		}{
			{0, 0, nil},
			{maximum, 0, nil},
			{maximum, 1, nil},
			{maximum - 1, 2, nil},
			{maximum, 2, target.ErrOverflow},
			{maximum - 1, 3, target.ErrOverflow},
			{0, -1, target.ErrInvalidArgument},
		} {
			if err := profile.ValidateRange(test.address, test.size); !errors.Is(err, test.want) {
				t.Fatalf("width=%d case=%+v err=%v", bits, test, err)
			}
		}
		if bits == 32 {
			for _, size := range []int{0, 1} {
				if err := profile.ValidateRange(1<<32, size); !errors.Is(err, target.ErrOverflow) {
					t.Fatalf("out-of-width start with size %d: %v", size, err)
				}
			}
		}
	}
	for _, bits := range []int{0, 16, 128} {
		profile := arch.Descriptor{AddressBits: bits}
		if _, err := profile.MaxAddress(); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("unknown width %d: %v", bits, err)
		}
	}
}

func TestRegisterLookupIsExact(t *testing.T) {
	profile := arch.Descriptor{Registers: []arch.Register{{Name: "eip", Bits: 32, Offset: 48}}}
	if register, ok := profile.Register("eip"); !ok || register.Bits != 32 || register.Offset != 48 {
		t.Fatalf("register=%+v found=%v", register, ok)
	}
	for _, name := range []string{"EIP", "rip", "ip", ""} {
		if _, ok := profile.Register(name); ok {
			t.Fatalf("unexpected register alias %q", name)
		}
	}
}
