package aarch64_test

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/qemu/aarch64"
	"fastdbg2/qemu/internal/arch"
	"fastdbg2/target"
)

func TestDescriptor(t *testing.T) {
	profile := aarch64.Descriptor()
	if profile.Architecture != target.AArch64 || profile.XMLArchitecture != "aarch64" || profile.IsProgramCounter == nil || profile.BreakpointKind != 4 || profile.BreakpointAlignment != 4 || profile.FixedRegisterByteOrder != target.ByteOrderUnknown || profile.ValidateRegisters == nil {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	profile.XMLArchitecture = "changed"
	if aarch64.Descriptor().XMLArchitecture != "aarch64" {
		t.Fatal("profile constructors share mutable state")
	}
}

func TestProgramCounterRequiresCoreFeatureAndWidth(t *testing.T) {
	profile := aarch64.Descriptor()
	for _, test := range []struct {
		register arch.Register
		want     bool
	}{
		{arch.Register{Name: "pc", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"}, true},
		{arch.Register{Name: "PC", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"}, true},
		{arch.Register{Name: "pc", Bits: 32, Feature: "org.gnu.gdb.aarch64.core"}, false},
		{arch.Register{Name: "pc", Bits: 64, Feature: "vendor.raw"}, false},
		{arch.Register{Name: "PC", Bits: 64, Feature: "vendor.raw"}, false},
		{arch.Register{Name: "pc", Bits: 64, Feature: "ORG.GNU.GDB.AARCH64.CORE"}, false},
		{arch.Register{Name: "pc", Bits: 64}, false},
		{arch.Register{Name: "rip", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"}, false},
	} {
		if got := profile.IsProgramCounter(test.register); got != test.want {
			t.Fatalf("register=%+v got=%v want=%v", test.register, got, test.want)
		}
	}
}

func TestCoreRegistersRequired(t *testing.T) {
	profile := aarch64.Descriptor()
	registers := coreRegisters()
	if err := profile.ValidateRegisters(registers); err != nil {
		t.Fatal(err)
	}
	for i, register := range registers {
		t.Run(register.Name, func(t *testing.T) {
			missing := append([]arch.Register(nil), registers[:i]...)
			missing = append(missing, registers[i+1:]...)
			if err := profile.ValidateRegisters(missing); !errors.Is(err, target.ErrUnknown) {
				t.Fatalf("missing %s: %v", register.Name, err)
			}
		})
	}
	if err := profile.ValidateRegisters(nil); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing core layout: %v", err)
	}
}

func TestCoreRegisterWidths(t *testing.T) {
	profile := aarch64.Descriptor()
	for i, register := range coreRegisters() {
		t.Run(register.Name, func(t *testing.T) {
			registers := coreRegisters()
			registers[i].Bits += 8
			if err := profile.ValidateRegisters(registers); !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("invalid width for %s: %v", register.Name, err)
			}
		})
	}
}

func TestCoreFeatureNameIsExact(t *testing.T) {
	profile := aarch64.Descriptor()
	for _, feature := range []string{"", "org.gnu.gdb.arm.core", "ORG.GNU.GDB.AARCH64.CORE", "vendor.core"} {
		registers := coreRegisters()
		registers[0].Feature = feature
		if err := profile.ValidateRegisters(registers); !errors.Is(err, target.ErrUnknown) {
			t.Fatalf("feature=%q err=%v", feature, err)
		}
	}
}

func TestRegisterNamesAreCaseInsensitiveAndPreserved(t *testing.T) {
	registers := coreRegisters()
	for i := range registers {
		registers[i].Name = strings.ToUpper(registers[i].Name)
	}
	before := append([]arch.Register(nil), registers...)
	if err := aarch64.Descriptor().ValidateRegisters(registers); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, registers) {
		t.Fatal("validator rewrote raw XML names")
	}
}

func TestAmbiguousSemanticNamesWithinCoreFeature(t *testing.T) {
	for _, duplicate := range []arch.Register{
		{Name: "pc", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"},
		{Name: "PC", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"},
		{Name: "X0", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"},
		{Name: "CPSR", Bits: 32, Feature: "org.gnu.gdb.aarch64.core"},
	} {
		registers := append(coreRegisters(), duplicate)
		if err := aarch64.Descriptor().ValidateRegisters(registers); !errors.Is(err, target.ErrAmbiguous) {
			t.Fatalf("duplicate=%+v err=%v", duplicate, err)
		}
	}
	registers := append(coreRegisters(), arch.Register{Name: "vendor", Bits: 32}, arch.Register{Name: "vendor", Bits: 64, Feature: "other.vendor"})
	if err := aarch64.Descriptor().ValidateRegisters(registers); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("duplicate exact names: %v", err)
	}
}

func TestOptionalRegistersKeepExactNamesAndWidths(t *testing.T) {
	registers := append(coreRegisters(),
		arch.Register{Name: "fpsr", Bits: 32, Feature: "org.gnu.gdb.aarch64.fpu"},
		arch.Register{Name: "fpcr", Bits: 32, Feature: "org.gnu.gdb.aarch64.fpu"},
		arch.Register{Name: "FPSR", Bits: 64, Feature: "org.qemu.gdb.arm.sys.regs"},
		arch.Register{Name: "FPCR", Bits: 64, Feature: "org.qemu.gdb.arm.sys.regs"},
		arch.Register{Name: "PC", Bits: 64, Feature: "vendor.raw"},
		arch.Register{Name: "X0", Bits: 32, Feature: "vendor.raw"},
		arch.Register{Name: "CPSR", Bits: 64, Feature: "vendor.raw"},
		arch.Register{Name: "vendor", Bits: 24, Feature: "vendor.raw"},
		arch.Register{Name: "VENDOR", Bits: 64, Feature: "vendor.other"},
		arch.Register{Name: "extra", Bits: 32, Feature: "org.gnu.gdb.aarch64.core"},
		arch.Register{Name: "EXTRA", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"},
	)
	before := append([]arch.Register(nil), registers...)
	if err := aarch64.Descriptor().ValidateRegisters(registers); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, registers) {
		t.Fatal("case-distinct optional registers were merged or rewritten")
	}
}

func TestOptionalRegistersRemainOpaque(t *testing.T) {
	registers := append(coreRegisters(),
		arch.Register{Name: "z0", Bits: 1024, Feature: "org.gnu.gdb.aarch64.sve"},
		arch.Register{Name: "p0", Bits: 128, Feature: "org.gnu.gdb.aarch64.sve"},
		arch.Register{Name: "vg", Bits: 64, Feature: "org.gnu.gdb.aarch64.sve"},
		arch.Register{Name: "za", Bits: 8192, Feature: "org.gnu.gdb.aarch64.sme"},
		arch.Register{Name: "vendor", Bits: 24, Feature: "vendor.raw"},
	)
	before := append([]arch.Register(nil), registers...)
	if err := aarch64.Descriptor().ValidateRegisters(registers); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, registers) {
		t.Fatal("optional register layout was rewritten")
	}
}

func coreRegisters() []arch.Register {
	registers := make([]arch.Register, 0, 34)
	for i := 0; i <= 30; i++ {
		registers = append(registers, arch.Register{Name: "x" + strconv.Itoa(i), Bits: 64, Feature: "org.gnu.gdb.aarch64.core"})
	}
	return append(registers,
		arch.Register{Name: "sp", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"},
		arch.Register{Name: "pc", Bits: 64, Feature: "org.gnu.gdb.aarch64.core"},
		arch.Register{Name: "cpsr", Bits: 32, Feature: "org.gnu.gdb.aarch64.core"},
	)
}
