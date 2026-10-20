package x86

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
)

func Descriptor() arch.Descriptor {
	names := []string{"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss"}
	registers := make([]arch.Register, len(names))
	for i, name := range names {
		registers[i] = arch.Register{Name: name, Bits: 32, Offset: i * 4}
	}
	return arch.Descriptor{
		Architecture:      target.X86,
		ELFClass:          elf.ELFCLASS32,
		ELFMachine:        elf.EM_386,
		AddressBits:       32,
		RegisterSetSize:   68,
		PCName:            "eip",
		Registers:         registers,
		ValidateRegisters: validateRegisters,
	}
}

func validateRegisters(data []byte) error {
	if len(data) != 68 {
		return fmt.Errorf("i386 register set size %d, expected 68: %w", len(data), target.ErrUnsupported)
	}
	if cs := binary.LittleEndian.Uint32(data[52:56]); cs != 0x23 {
		return fmt.Errorf("i386 code segment %#x is outside the flat user32 profile: %w", cs, target.ErrUnsupported)
	}
	return nil
}
