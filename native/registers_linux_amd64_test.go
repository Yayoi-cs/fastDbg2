package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func TestNativeRegisterSchemaAndEncoding(t *testing.T) {
	regs := unix.PtraceRegs{
		Rax: 1, Rbx: 2, Rcx: 3, Rdx: 4, Rsi: 5, Rdi: 6, Rbp: 7, Rsp: 8,
		R8: 9, R9: 10, R10: 11, R11: 12, R12: 13, R13: 14, R14: 15, R15: 16,
		Rip: 0x401001, Eflags: 0x202, Orig_rax: 19, Cs: 0x33, Ss: 0x2b,
		Ds: 22, Es: 23, Fs: 24, Gs: 25, Fs_base: 26, Gs_base: 27,
	}
	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, regs); err != nil {
		t.Fatal(err)
	}
	profile := amd64.Descriptor()
	result, err := encodeRegisters(&profile, raw.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "orig_rax", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base"}
	wantValues := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x401001, 0x202, 19, 0x33, 0x2b, 22, 23, 24, 25, 26, 27}
	if len(result) != len(wantNames) {
		t.Fatalf("register count=%d", len(result))
	}
	for i, register := range result {
		if register.Name != wantNames[i] || register.Bits != 64 || len(register.Data) != 8 || !register.Available || binary.LittleEndian.Uint64(register.Data) != wantValues[i] {
			t.Fatalf("register %d: %+v bytes=%x", i, register, register.Data)
		}
	}
}

func TestNativeRegisterX86SchemaAndEncoding(t *testing.T) {
	profile := x86.Descriptor()
	data := make([]byte, 68)
	values := []uint32{1, 2, 3, 4, 5, 6, 7, 0x2b, 0x2b, 0x63, 0x6b, 12, 0xf0000001, 0x23, 0x202, 0xff000100, 0x2b}
	names := []string{"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss"}
	for i, value := range values {
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], value)
	}
	result, err := encodeRegisters(&profile, data)
	if err != nil || len(result) != len(names) {
		t.Fatalf("registers=%v err=%v", result, err)
	}
	for i, register := range result {
		if register.Name != names[i] || register.Bits != 32 || len(register.Data) != 4 || !register.Available || binary.LittleEndian.Uint32(register.Data) != values[i] {
			t.Fatalf("register %d: %+v bytes=%x", i, register, register.Data)
		}
	}
	if uint64(binary.LittleEndian.Uint32(result[12].Data)) != 0xf0000001 {
		t.Fatal("high EIP was sign-extended or adjusted")
	}
}

func TestNativeRegisterBytesDoNotAlias(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		data := nativeRegisterTestData(profile)
		first, err := encodeRegisters(&profile, data)
		if err != nil {
			t.Fatal(err)
		}
		second, err := encodeRegisters(&profile, data)
		if err != nil {
			t.Fatal(err)
		}
		before := append([]byte(nil), first[0].Data...)
		other := append([]byte(nil), first[1].Data...)
		data[profile.Registers[0].Offset] ^= 0xff
		if !bytes.Equal(first[0].Data, before) {
			t.Fatal("register bytes alias the source buffer")
		}
		first[0].Data[0] ^= 0xff
		if !bytes.Equal(first[1].Data, other) || !bytes.Equal(second[0].Data, before) {
			t.Fatal("register results alias each other")
		}
	}
}

func TestNativeRegisterWriteValidation(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		t.Run(string(profile.Architecture), func(t *testing.T) {
			first, second := profile.Registers[0], profile.Registers[1]
			valid := target.Register{Name: first.Name, Bits: first.Bits, Data: make([]byte, first.Bits/8), Available: true}
			for _, registers := range [][]target.Register{nil, {}, {valid}} {
				if err := validateRegisterWrites(&profile, registers); err != nil {
					t.Fatalf("valid batch %v: %v", registers, err)
				}
			}
			cases := []struct {
				name   string
				modify func(*target.Register)
			}{
				{"unknown", func(r *target.Register) { r.Name = "unknown" }},
				{"empty-name", func(r *target.Register) { r.Name = "" }},
				{"uppercase", func(r *target.Register) { r.Name = strings.ToUpper(r.Name) }},
				{"width", func(r *target.Register) { r.Bits += 8 }},
				{"negative-width", func(r *target.Register) { r.Bits = -1 }},
				{"short", func(r *target.Register) { r.Data = make([]byte, second.Bits/8-1) }},
				{"long", func(r *target.Register) { r.Data = make([]byte, second.Bits/8+1) }},
				{"nil-data", func(r *target.Register) { r.Data = nil }},
				{"unavailable", func(r *target.Register) { r.Available = false }},
				{"duplicate", func(r *target.Register) { r.Name = first.Name }},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					invalid := target.Register{Name: second.Name, Bits: second.Bits, Data: make([]byte, second.Bits/8), Available: true}
					test.modify(&invalid)
					batch := []target.Register{valid, invalid}
					if err := validateRegisterWrites(&profile, batch); !errors.Is(err, target.ErrInvalidArgument) {
						t.Fatalf("expected prevalidation rejection: %v", err)
					}
					if valid.Data[0] != 0 || batch[0].Name != first.Name {
						t.Fatal("validation modified the batch")
					}
				})
			}
		})
	}
}

func TestNativeRegisterPCWriteRejectsSuspendedBreakpoint(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		e := &engine{profile: &profile, suspended: &breakpoint{addr: 0x1000, original: 0x90}}
		other := profile.Registers[0]
		general := target.Register{Name: other.Name, Bits: other.Bits, Data: make([]byte, other.Bits/8), Available: true}
		pc := target.Register{Name: profile.PCName, Bits: profile.AddressBits, Data: make([]byte, profile.AddressBits/8), Available: true}
		if err := e.checkRegisterWrites([]target.Register{general, pc}); !errors.Is(err, target.ErrInvalidState) {
			t.Fatalf("PC change during suspended step-over: %v", err)
		}
		if err := e.checkRegisterWrites([]target.Register{general}); err != nil {
			t.Fatalf("other registers remain writable: %v", err)
		}
		if err := e.checkRegisterWrites(nil); err != nil {
			t.Fatalf("empty batch: %v", err)
		}
		e.suspended = nil
		if err := e.checkRegisterWrites([]target.Register{pc}); err != nil {
			t.Fatalf("PC change without suspended step-over: %v", err)
		}
	}
}

func TestNativeRegisterSetMustMatchProfile(t *testing.T) {
	if generalRegisterBufferSize <= 216 || generalRegisterBufferSize%8 != 0 {
		t.Fatal("GETREGSET must detect a larger view without violating either slot alignment")
	}
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		for _, size := range []int{0, 64, 68, 72, 208, 216, 224} {
			if size == profile.RegisterSetSize {
				continue
			}
			if err := validateRegisterSet(&profile, make([]byte, size)); !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("architecture=%s size=%d err=%v", profile.Architecture, size, err)
			}
		}
		if err := validateRegisterSet(&profile, nativeRegisterTestData(profile)); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateRegisterSet(nil, nil); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing profile: %v", err)
	}
	if _, err := encodeRegisters(nil, nil); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing decode profile: %v", err)
	}
	if err := validateRegisterWrites(nil, nil); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing write profile: %v", err)
	}
}

func TestNativeRegisterPCWidthAndCSRejectedBeforeSyscall(t *testing.T) {
	profile := x86.Descriptor()
	address := target.Address(0x1000)
	e := &engine{profile: &profile, hit: &address}
	if err := e.writePC(-1, 1<<32); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("wide PC must not reach ptrace: %v", err)
	}
	for _, cs := range []uint32{0, 0x27, 0x33} {
		data := nativeRegisterTestData(profile)
		binary.LittleEndian.PutUint32(data[52:56], cs)
		if err := e.writeRegisterSet(-1, data, 1); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("CS %#x must not reach ptrace: %v", cs, err)
		}
		if e.unsupported != nil || e.hit == nil || *e.hit != address {
			t.Fatal("prevalidation changed debugger state")
		}
	}
}

func TestNativeRegistersRequireStoppedEvenForEmptyWrites(t *testing.T) {
	for _, test := range []struct {
		state target.State
		want  error
	}{
		{target.StateRunning, target.ErrRunning},
		{target.StateExited, target.ErrExited},
		{target.StateDetached, target.ErrDetached},
		{target.StateUnknown, target.ErrInvalidState},
	} {
		session := memoryTestSession(t, test.state)
		if registers, err := session.ReadRegisters(); len(registers) != 0 || !errors.Is(err, test.want) {
			t.Fatalf("read state=%v registers=%v err=%v", test.state, registers, err)
		}
		if err := session.WriteRegisters(nil); !errors.Is(err, test.want) {
			t.Fatalf("write state=%v err=%v", test.state, err)
		}
	}
}

func nativeRegisterTestData(profile arch.Descriptor) []byte {
	data := make([]byte, profile.RegisterSetSize)
	for i := range data {
		data[i] = byte(i)
	}
	if profile.Architecture == target.X86 {
		binary.LittleEndian.PutUint32(data[52:56], 0x23)
	}
	return data
}
