package amd64_test

import (
	"errors"
	"reflect"
	"testing"

	"fastdbg2/qemu/amd64"
	"fastdbg2/qemu/internal/arch"
	"fastdbg2/target"
)

func TestDescriptor(t *testing.T) {
	profile := amd64.Descriptor()
	if profile.Architecture != target.AMD64 || profile.XMLArchitecture != "i386:x86-64" || profile.IsProgramCounter == nil || profile.BreakpointKind != 1 || profile.BreakpointAlignment != 1 || profile.FixedRegisterByteOrder != target.LittleEndian || profile.ValidateRegisters == nil {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	profile.XMLArchitecture = "changed"
	if amd64.Descriptor().XMLArchitecture != "i386:x86-64" {
		t.Fatal("profile constructors share mutable state")
	}
}

func TestProgramCounterKeepsExactAMD64Name(t *testing.T) {
	profile := amd64.Descriptor()
	for _, test := range []struct {
		register arch.Register
		want     bool
	}{
		{arch.Register{Name: "rip", Bits: 64}, true},
		{arch.Register{Name: "rip", Bits: 64, Feature: "custom"}, true},
		{arch.Register{Name: "RIP", Bits: 64}, false},
		{arch.Register{Name: "Rip", Bits: 64}, false},
		{arch.Register{Name: "rip", Bits: 32}, false},
		{arch.Register{Name: "pc", Bits: 64}, false},
	} {
		if got := profile.IsProgramCounter(test.register); got != test.want {
			t.Fatalf("register=%+v got=%v want=%v", test.register, got, test.want)
		}
	}
}

func TestMinimalXMLCompatibility(t *testing.T) {
	profile := amd64.Descriptor()
	for _, registers := range [][]arch.Register{
		nil,
		{{Name: "rax", Bits: 64, Feature: "custom"}},
		{{Name: "rip", Bits: 64, Feature: "custom"}},
		{{Name: "RIP", Bits: 64, Feature: "custom"}},
		{{Name: "rax", Bits: 64, Feature: "custom"}, {Name: "rip", Bits: 64, Feature: "custom"}, {Name: "vendor", Bits: 256, Feature: "vendor.raw"}},
	} {
		if err := profile.ValidateRegisters(registers); err != nil {
			t.Fatalf("registers=%+v err=%v", registers, err)
		}
	}
}

func TestContradictoryOrAmbiguousLayout(t *testing.T) {
	profile := amd64.Descriptor()
	for _, width := range []int{0, 32, 128} {
		if err := profile.ValidateRegisters([]arch.Register{{Name: "rip", Bits: width}}); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("PC width %d: %v", width, err)
		}
	}
	for _, registers := range [][]arch.Register{
		{{Name: "rip", Bits: 64}, {Name: "rip", Bits: 64}},
		{{Name: "rax", Bits: 64}, {Name: "rax", Bits: 64}},
		{{Name: "vendor", Bits: 32}, {Name: "vendor", Bits: 32}},
	} {
		if err := profile.ValidateRegisters(registers); !errors.Is(err, target.ErrAmbiguous) {
			t.Fatalf("registers=%+v err=%v", registers, err)
		}
	}
}

func TestValidationPreservesRawNames(t *testing.T) {
	registers := []arch.Register{
		{Name: "rip", Bits: 64, Feature: "custom"},
		{Name: "RIP", Bits: 32, Feature: "vendor.raw"},
		{Name: "vendor", Bits: 256, Feature: "vendor.raw"},
		{Name: "VENDOR", Bits: 64, Feature: "vendor.other"},
	}
	before := append([]arch.Register(nil), registers...)
	if err := amd64.Descriptor().ValidateRegisters(registers); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(registers, before) {
		t.Fatalf("validator mutated the input: %+v", registers)
	}
}
