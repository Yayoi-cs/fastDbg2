package amd64_test

import (
	"debug/elf"
	"reflect"
	"testing"

	"fastdbg2/native/amd64"
	"fastdbg2/target"
)

func TestDescriptor(t *testing.T) {
	profile := amd64.Descriptor()
	if profile.Architecture != target.AMD64 || profile.ELFClass != elf.ELFCLASS64 || profile.ELFMachine != elf.EM_X86_64 || profile.AddressBits != 64 || profile.RegisterSetSize != 216 || profile.PCName != "rip" || len(profile.Registers) != 27 {
		t.Fatalf("profile=%+v", profile)
	}
	want := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "orig_rax", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base"}
	var names []string
	used := make(map[int]bool)
	for _, register := range profile.Registers {
		if register.Bits != 64 || register.Offset < 0 || register.Offset%8 != 0 || register.Offset+8 > 216 || used[register.Offset] {
			t.Fatalf("invalid register slot: %+v", register)
		}
		used[register.Offset] = true
		names = append(names, register.Name)
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("public register order changed: %v", names)
	}
	pc, _ := profile.Register("rip")
	cs, _ := profile.Register("cs")
	if pc.Offset != 128 || cs.Offset != 136 {
		t.Fatalf("PC=%+v CS=%+v", pc, cs)
	}
	profile.Registers[0].Name = "changed"
	if amd64.Descriptor().Registers[0].Name != "rax" {
		t.Fatal("descriptor shares mutable schema")
	}
}
