package amd64

import (
	"debug/elf"

	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
)

func Descriptor() arch.Descriptor {
	return arch.Descriptor{
		Architecture:    target.AMD64,
		ELFClass:        elf.ELFCLASS64,
		ELFMachine:      elf.EM_X86_64,
		AddressBits:     64,
		RegisterSetSize: 216,
		PCName:          "rip",
		Registers: []arch.Register{
			{Name: "rax", Bits: 64, Offset: 80},
			{Name: "rbx", Bits: 64, Offset: 40},
			{Name: "rcx", Bits: 64, Offset: 88},
			{Name: "rdx", Bits: 64, Offset: 96},
			{Name: "rsi", Bits: 64, Offset: 104},
			{Name: "rdi", Bits: 64, Offset: 112},
			{Name: "rbp", Bits: 64, Offset: 32},
			{Name: "rsp", Bits: 64, Offset: 152},
			{Name: "r8", Bits: 64, Offset: 72},
			{Name: "r9", Bits: 64, Offset: 64},
			{Name: "r10", Bits: 64, Offset: 56},
			{Name: "r11", Bits: 64, Offset: 48},
			{Name: "r12", Bits: 64, Offset: 24},
			{Name: "r13", Bits: 64, Offset: 16},
			{Name: "r14", Bits: 64, Offset: 8},
			{Name: "r15", Bits: 64, Offset: 0},
			{Name: "rip", Bits: 64, Offset: 128},
			{Name: "eflags", Bits: 64, Offset: 144},
			{Name: "orig_rax", Bits: 64, Offset: 120},
			{Name: "cs", Bits: 64, Offset: 136},
			{Name: "ss", Bits: 64, Offset: 160},
			{Name: "ds", Bits: 64, Offset: 184},
			{Name: "es", Bits: 64, Offset: 192},
			{Name: "fs", Bits: 64, Offset: 200},
			{Name: "gs", Bits: 64, Offset: 208},
			{Name: "fs_base", Bits: 64, Offset: 168},
			{Name: "gs_base", Bits: 64, Offset: 176},
		},
	}
}
