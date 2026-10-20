package amd64

import (
	"fmt"

	"fastdbg2/qemu/internal/arch"
	"fastdbg2/target"
)

func Descriptor() arch.Descriptor {
	return arch.Descriptor{
		Architecture:           target.AMD64,
		XMLArchitecture:        "i386:x86-64",
		IsProgramCounter:       isProgramCounter,
		BreakpointKind:         1,
		BreakpointAlignment:    1,
		FixedRegisterByteOrder: target.LittleEndian,
		ValidateRegisters:      validateRegisters,
	}
}

func isProgramCounter(register arch.Register) bool {
	return register.Name == "rip" && register.Bits == 64
}

func validateRegisters(registers []arch.Register) error {
	names := make(map[string]arch.Register, len(registers))
	for _, register := range registers {
		if _, exists := names[register.Name]; exists {
			return fmt.Errorf("register name %q: %w", register.Name, target.ErrAmbiguous)
		}
		names[register.Name] = register
	}
	if pc, exists := names["rip"]; exists && pc.Bits != 64 {
		return fmt.Errorf("AMD64 rip has width %d, expected 64: %w", pc.Bits, target.ErrUnsupported)
	}
	return nil
}
