package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
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
		e, th, _ := nativeDataTestEngine(profile)
		th.suspended = &breakpoint{addr: 0x1000, original: 0x90}
		other := profile.Registers[0]
		general := target.Register{Name: other.Name, Bits: other.Bits, Data: make([]byte, other.Bits/8), Available: true}
		pc := target.Register{Name: profile.PCName, Bits: profile.AddressBits, Data: make([]byte, profile.AddressBits/8), Available: true}
		if err := e.checkRegisterWrites(th, []target.Register{general, pc}); !errors.Is(err, target.ErrInvalidState) {
			t.Fatalf("PC change during suspended step-over: %v", err)
		}
		if err := e.checkRegisterWrites(th, []target.Register{general}); err != nil {
			t.Fatalf("other registers remain writable: %v", err)
		}
		if err := e.checkRegisterWrites(th, nil); err != nil {
			t.Fatalf("empty batch: %v", err)
		}
		th.suspended = nil
		if err := e.checkRegisterWrites(th, []target.Register{pc}); err != nil {
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
	e, th, _ := nativeDataTestEngine(profile)
	hit := &breakpointHit{}
	th.hit = hit
	expected := syscallStep{pc: 0x1002, number: 1}
	e.life.syscallSteps = map[*thread]syscallStep{th: expected}
	if err := e.writePC(-1, 1<<32); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("wide PC must not reach ptrace: %v", err)
	}
	for _, cs := range []uint32{0, 0x27, 0x33} {
		data := nativeRegisterTestData(profile)
		binary.LittleEndian.PutUint32(data[52:56], cs)
		if err := e.writeRegisterSet(-1, data, 1); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("CS %#x must not reach ptrace: %v", cs, err)
		}
		if e.unsupported != nil || th.hit != hit || th.registerRevision != 0 || e.life.syscallSteps[th] != expected {
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
		{target.StateUnknown, target.ErrBusy},
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

func TestNativeRegisterWriteBatchDoesNotAlias(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	registers := []target.Register{
		{Name: "rax", Bits: 64, Data: data, Available: true},
		{Name: "rbx", Bits: 64, Data: data, Available: true},
	}
	copy := cloneRegisters(registers)
	registers[0].Name = "changed"
	data[0] = 9
	if copy[0].Name != "rax" || copy[0].Data[0] != 1 || copy[1].Data[0] != 1 {
		t.Fatal("write batch aliases its input")
	}
	copy[0].Data[0] = 10
	if copy[1].Data[0] != 1 || data[0] != 9 {
		t.Fatal("write batch values alias")
	}
}

func TestNativeRegisterValidationUsesSelectedThread(t *testing.T) {
	profile := amd64.Descriptor()
	e, selected, space := nativeDataTestEngine(profile)
	x86Profile := x86.Descriptor()
	other := &thread{tid: -2, state: target.StateStopped, process: &process{profile: &x86Profile, space: space}}
	other.suspended = &breakpoint{addr: 0x1000}
	e.threads[other.tid] = other
	pc := target.Register{Name: "rip", Bits: 64, Data: make([]byte, 8), Available: true}
	if err := e.checkRegisterWrites(selected, []target.Register{pc}); err != nil {
		t.Fatal(err)
	}
	if err := e.checkRegisterWrites(other, []target.Register{pc}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("selected thread profile not enforced: %v", err)
	}
	if err := e.writePC(other.tid, 1<<32); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("selected thread PC width not enforced: %v", err)
	}
	if _, err := e.readPC(-3); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("missing TID not rejected: %v", err)
	}
}

func TestNativeRegisterSetWriteFailureInvalidatesOnlySelectedThread(t *testing.T) {
	profile := amd64.Descriptor()
	e, selected, space := nativeDataTestEngine(profile)
	other := &thread{tid: -2, state: target.StateStopped, process: &process{profile: &profile, space: space}, registerRevision: 7}
	e.threads[other.tid] = other
	selected.hit = &breakpointHit{}
	otherHit := &breakpointHit{}
	other.hit = otherHit
	expected := syscallStep{pc: 0x1002, number: 1}
	e.life.syscallSteps = map[*thread]syscallStep{selected: expected, other: expected}
	err := e.writeRegisterSet(selected.tid, nativeRegisterTestData(profile), 1)
	var partial *target.PartialError
	if !errors.As(err, &partial) || partial.Completed != 0 || partial.Total != 1 {
		t.Fatalf("unconfirmed SETREGSET must fail closed: %v", err)
	}
	if selected.registerRevision != 1 || selected.hit != nil || e.unsupported != err {
		t.Fatal("selected thread revision or fail-closed state not updated")
	}
	if _, ok := e.life.syscallSteps[selected]; ok {
		t.Fatal("unconfirmed SETREGSET retained syscall-step provenance")
	}
	if other.registerRevision != 7 || other.hit != otherHit || e.life.syscallSteps[other] != expected {
		t.Fatal("unrelated thread register state was modified")
	}
}

func TestNativeRawDataAccessRequiresExactStoppedThread(t *testing.T) {
	profile := amd64.Descriptor()
	e, th, _ := nativeDataTestEngine(profile)
	for _, test := range []struct {
		state target.State
		want  error
	}{
		{target.StateRunning, target.ErrRunning},
		{target.StateExited, target.ErrExited},
		{target.StateDetached, target.ErrDetached},
		{target.StateUnknown, target.ErrInvalidState},
	} {
		th.state = test.state
		if _, err := e.readRegisterSet(th.tid); !errors.Is(err, test.want) {
			t.Fatalf("register read state=%v err=%v", test.state, err)
		}
		if err := e.writeRegisterSet(th.tid, nativeRegisterTestData(profile), 1); !errors.Is(err, test.want) {
			t.Fatalf("register write state=%v err=%v", test.state, err)
		}
		if _, err := e.readByte(th.tid, 0); !errors.Is(err, test.want) {
			t.Fatalf("byte read state=%v err=%v", test.state, err)
		}
		if err := e.writeByte(th.tid, 0, 0); !errors.Is(err, test.want) {
			t.Fatalf("byte write state=%v err=%v", test.state, err)
		}
	}
	th.state = target.StateStopped
	th.process.profile = nil
	if _, err := e.readRegisterSet(th.tid); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing process image profile: %v", err)
	}
	if th.registerRevision != 0 || th.process.space.revision != 0 || e.unsupported != nil {
		t.Fatal("rejected raw access changed owner state")
	}
}

func nativeDataSession(t *testing.T) *Session {
	t.Helper()
	s, err := Launch(coreFixture(t), "exit")
	if errors.Is(err, unix.EPERM) {
		t.Skipf("ptrace unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func nativeDataSnapshot(t *testing.T, s *Session) target.Snapshot {
	t.Helper()
	snapshot, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Threads) != 1 || snapshot.Threads[0].State != target.StateStopped {
		t.Fatalf("single stopped thread required: %+v", snapshot)
	}
	return snapshot
}

func TestNativeThreadRegisterTokensAndIsolation(t *testing.T) {
	s := nativeDataSession(t)
	snapshot := nativeDataSnapshot(t, s)
	token := snapshot.Threads[0].Token
	registers, err := s.ReadThreadRegisters(token)
	if err != nil || len(registers) == 0 {
		t.Fatalf("read selected registers=%v err=%v", registers, err)
	}
	original := slices.Clone(registers[0].Data)
	registers[0].Data[0] ^= 0xff
	again, err := s.ReadThreadRegisters(token)
	if err != nil || !bytes.Equal(again[0].Data, original) {
		t.Fatalf("register output aliases tracee state: %v", err)
	}
	foreign := token
	foreign.Thread.Session ^= uint64(1) << 63
	if _, err := s.ReadThreadRegisters(foreign); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign register token: %v", err)
	}
	if err := s.WriteThreadRegisters(foreign, nil); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign empty register write: %v", err)
	}
	if err := s.WriteThreadRegisters(token, []target.Register{again[0]}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadThreadRegisters(token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("pre-write register token remained valid: %v", err)
	}
	if err := s.WriteThreadRegisters(token, nil); !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale empty register write: %v", err)
	}
	after := nativeDataSnapshot(t, s)
	if after.Threads[0].Token.Stop != token.Stop || after.Threads[0].Token.Registers == token.Registers {
		t.Fatalf("register write token transition old=%+v new=%+v", token, after.Threads[0].Token)
	}
	if after.Memory != snapshot.Memory {
		t.Fatal("register-only write changed the memory revision")
	}
	if err := s.WriteThreadRegisters(after.Threads[0].Token, nil); err != nil {
		t.Fatal(err)
	}
	if current := nativeDataSnapshot(t, s); current.Threads[0].Token != after.Threads[0].Token {
		t.Fatal("empty register write changed the token")
	}
}

func nativeDataTokenEngine() (*engine, *thread) {
	s := &Session{id: 1}
	s.state.Store(uint32(target.StateStopped))
	e := &engine{s: s}
	p := e.newProcess(101, -1, false)
	profile := amd64.Descriptor()
	p.profile = &profile
	e.primary = p
	th := e.newThread(p, 101, true)
	th.state, th.stopEpoch = target.StateStopped, 1
	return e, th
}

func TestNativeThreadRegisterTokenRejectsStaleStopAndIncarnation(t *testing.T) {
	e, th := nativeDataTokenEngine()
	current := th.token()
	for _, token := range []target.ThreadToken{
		{Thread: current.Thread, Stop: current.Stop + 1, Registers: current.Registers},
		{Thread: current.Thread, Stop: current.Stop, Registers: current.Registers + 1},
		{Thread: current.Thread, Stop: 0, Registers: current.Registers},
	} {
		if _, err := e.requireThread(token); !errors.Is(err, target.ErrStale) {
			t.Fatalf("stale thread token accepted %+v: %v", token, err)
		}
	}
	if got, err := e.requireThread(current); err != nil || got != th {
		t.Fatalf("current thread token rejected: %v", err)
	}
	th.state = target.StateExited
	replacement := e.newThread(th.process, th.tid, true)
	replacement.state, replacement.stopEpoch = target.StateStopped, 1
	if replacement.ref == current.Thread {
		t.Fatal("kernel TID reuse retained the old thread incarnation")
	}
	if _, err := e.requireThread(current); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old incarnation remained valid after TID reuse: %v", err)
	}
}

func TestNativeDataTokensInvalidateOnResume(t *testing.T) {
	s := nativeDataSession(t)
	before := nativeDataSnapshot(t, s)
	if _, err := s.Step(target.Signal{}); err != nil {
		t.Fatal(err)
	}
	after := nativeDataSnapshot(t, s)
	if before.Threads[0].Token.Stop == after.Threads[0].Token.Stop {
		t.Fatal("resumption retained the old thread stop epoch")
	}
	if before.Memory == after.Memory {
		t.Fatal("resumption retained the old memory token")
	}
	if _, err := s.ReadThreadRegisters(before.Threads[0].Token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("register token survived resumption: %v", err)
	}
	if _, err := s.ReadSpaceMemory(before.Memory, 0, nil); !errors.Is(err, target.ErrStale) {
		t.Fatalf("memory token survived resumption: %v", err)
	}
	if _, err := s.ReadThreadRegisters(after.Threads[0].Token); err != nil {
		t.Fatalf("new register token rejected: %v", err)
	}
}

func TestNativeRegisterWritesForgetSyscallStep(t *testing.T) {
	s := nativeDataSession(t)
	for _, name := range []string{"rip", "orig_rax"} {
		snapshot := nativeDataSnapshot(t, s)
		token := snapshot.Threads[0].Token
		registers, err := s.ReadThreadRegisters(token)
		if err != nil {
			t.Fatal(err)
		}
		var value target.Register
		for _, register := range registers {
			if register.Name == name {
				value = register
			}
		}
		if value.Name == "" {
			t.Fatalf("register %s missing", name)
		}
		if err := command(s, func(e *engine) error {
			th, err := e.requireThread(token)
			if err != nil {
				return err
			}
			e.life.syscallSteps = map[*thread]syscallStep{th: {pc: 0x1002, number: 1}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.WriteThreadRegisters(token, []target.Register{value}); err != nil {
			t.Fatal(err)
		}
		retained, err := call(s, func(e *engine) (bool, error) {
			th, err := e.findThread(token.Thread)
			if err != nil {
				return false, err
			}
			_, ok := e.life.syscallSteps[th]
			return ok, nil
		})
		if err != nil || retained {
			t.Fatalf("%s write retained syscall-step provenance: retained=%v err=%v", name, retained, err)
		}
	}
}
