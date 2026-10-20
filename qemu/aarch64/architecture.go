package aarch64

import (
	"fmt"
	"strconv"
	"strings"

	"fastdbg2/qemu/internal/arch"
	"fastdbg2/target"
)

const coreFeature = "org.gnu.gdb.aarch64.core"

func Descriptor() arch.Descriptor {
	return arch.Descriptor{
		Architecture:           target.AArch64,
		XMLArchitecture:        "aarch64",
		IsProgramCounter:       isProgramCounter,
		BreakpointKind:         4,
		BreakpointAlignment:    4,
		FixedRegisterByteOrder: target.ByteOrderUnknown,
		ValidateRegisters:      validateRegisters,
	}
}

func isProgramCounter(register arch.Register) bool {
	return register.Feature == coreFeature && strings.EqualFold(register.Name, "pc") && register.Bits == 64
}

func validateRegisters(registers []arch.Register) error {
	names := make(map[string]struct{}, len(registers))
	for _, register := range registers {
		if _, exists := names[register.Name]; exists {
			return fmt.Errorf("register name %q: %w", register.Name, target.ErrAmbiguous)
		}
		names[register.Name] = struct{}{}
	}
	for i := 0; i <= 30; i++ {
		if err := requireRegister(registers, "x"+strconv.Itoa(i), 64); err != nil {
			return err
		}
	}
	for _, name := range []string{"sp", "pc"} {
		if err := requireRegister(registers, name, 64); err != nil {
			return err
		}
	}
	return requireRegister(registers, "cpsr", 32)
}

func requireRegister(registers []arch.Register, name string, bits int) error {
	var found *arch.Register
	for i := range registers {
		register := &registers[i]
		if register.Feature != coreFeature || !strings.EqualFold(register.Name, name) {
			continue
		}
		if found != nil {
			return fmt.Errorf("AArch64 %s register %q: %w", coreFeature, name, target.ErrAmbiguous)
		}
		found = register
	}
	if found == nil {
		return fmt.Errorf("AArch64 %s register %q is missing: %w", coreFeature, name, target.ErrUnknown)
	}
	if found.Bits != bits {
		return fmt.Errorf("AArch64 %s has width %d, expected %d: %w", name, found.Bits, bits, target.ErrUnsupported)
	}
	return nil
}
