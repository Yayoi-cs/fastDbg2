package x86_test

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"fastdbg2/native/x86"
	"fastdbg2/target"
)

func TestDescriptor(t *testing.T) {
	profile := x86.Descriptor()
	if profile.Architecture != target.X86 || profile.ELFClass != elf.ELFCLASS32 || profile.ELFMachine != elf.EM_386 || profile.AddressBits != 32 || profile.RegisterSetSize != 68 || profile.PCName != "eip" || len(profile.Registers) != 17 || profile.ValidateRegisters == nil {
		t.Fatalf("profile=%+v", profile)
	}
	want := []string{"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss"}
	var names []string
	for i, register := range profile.Registers {
		if register.Bits != 32 || register.Offset != i*4 {
			t.Fatalf("invalid i386 slot: %+v", register)
		}
		names = append(names, register.Name)
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("register schema=%v", names)
	}
	for _, name := range []string{"rax", "rip", "fs_base", "gs_base", "cs_base"} {
		if _, ok := profile.Register(name); ok {
			t.Fatalf("i386 profile invented %q", name)
		}
	}
	profile.Registers[0].Name = "changed"
	if x86.Descriptor().Registers[0].Name != "ebx" {
		t.Fatal("descriptor shares mutable schema")
	}
}

func TestFlatCodeSegmentAndExactSize(t *testing.T) {
	profile := x86.Descriptor()
	data := make([]byte, 68)
	binary.LittleEndian.PutUint32(data[52:56], 0x23)
	if err := profile.ValidateRegisters(data); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 64, 67, 69, 216, 224} {
		if err := profile.ValidateRegisters(make([]byte, size)); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("size=%d err=%v", size, err)
		}
	}
	for _, cs := range []uint32{0, 0x1b, 0x27, 0x33, 0x10023} {
		binary.LittleEndian.PutUint32(data[52:56], cs)
		if err := profile.ValidateRegisters(data); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("CS=%#x err=%v", cs, err)
		}
	}
	binary.LittleEndian.PutUint32(data[52:56], 0x23)
	for _, offset := range []int{28, 32, 36, 40, 64} {
		binary.LittleEndian.PutUint32(data[offset:offset+4], 0x67)
	}
	if err := profile.ValidateRegisters(data); err != nil {
		t.Fatalf("raw data selectors are not linear address guesses: %v", err)
	}
}
