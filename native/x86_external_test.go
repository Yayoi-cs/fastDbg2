package native_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"
)

func x86Fixture(t *testing.T, source string, high bool) (string, map[string]target.Address) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("IA32 native fixtures require a linux/amd64 tracer host")
	}
	tmp, err := filepath.Abs(filepath.Join("..", ".cache", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path+".S", []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "as", "--32", "-o", path+".o", path+".S").CombinedOutput(); err != nil {
		t.Fatalf("assemble IA32 fixture: %v\n%s", err, output)
	}
	args := []string{"-m", "elf_i386", "--build-id=none", "-z", "noexecstack", "-o", path, path + ".o"}
	if high {
		args = append(args, "-Ttext=0xf0000000")
	}
	if output, err := exec.CommandContext(ctx, "ld", args...).CombinedOutput(); err != nil {
		t.Fatalf("link IA32 fixture: %v\n%s", err, output)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS32 || f.Machine != elf.EM_386 || f.Data != elf.ELFDATA2LSB {
		t.Fatalf("unexpected fixture ELF: class=%s machine=%s data=%s", f.Class, f.Machine, f.Data)
	}
	if high && f.Entry != 0xf0000000 {
		t.Fatalf("high IA32 entry: %#x", f.Entry)
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	addresses := make(map[string]target.Address, len(symbols))
	for _, symbol := range symbols {
		addresses[symbol.Name] = target.Address(symbol.Value)
	}
	return path, addresses
}

func x86Launch(t *testing.T, path string) *native.Session {
	t.Helper()
	s, err := native.Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	nativeSessionCleanup(t, s, true)
	if s.Architecture() != target.X86 {
		t.Fatalf("IA32 architecture: %s", s.Architecture())
	}
	return s
}

func x86Registers(t *testing.T, s *native.Session) map[string]uint32 {
	t.Helper()
	registers, err := s.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss"}
	if len(registers) != len(names) {
		t.Fatalf("IA32 register count: got %d, want %d", len(registers), len(names))
	}
	values := make(map[string]uint32, len(registers))
	for _, register := range registers {
		if !register.Available || register.Bits != 32 || len(register.Data) != 4 {
			t.Fatalf("invalid IA32 register: %+v", register)
		}
		if _, exists := values[register.Name]; exists {
			t.Fatalf("duplicate IA32 register: %q", register.Name)
		}
		values[register.Name] = binary.LittleEndian.Uint32(register.Data)
	}
	for _, name := range names {
		if _, ok := values[name]; !ok {
			t.Fatalf("missing IA32 register %q", name)
		}
	}
	return values
}

func x86Register(name string, value uint32) target.Register {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	return target.Register{Name: name, Bits: 32, Data: data, Available: true}
}

func x86BreakpointStop(t *testing.T, s *native.Session, stop target.Stop, address target.Address) {
	t.Helper()
	if stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != address {
		t.Fatalf("IA32 breakpoint at %#x: %+v", address, stop)
	}
	if stop.ThreadID == nil || *stop.ThreadID != uint64(s.PID()) {
		t.Fatalf("IA32 breakpoint thread identity: %+v", stop)
	}
	if stop.RawPC == nil || *stop.RawPC != address+1 {
		t.Fatalf("raw IA32 breakpoint EIP must be %#x: %+v", address+1, stop)
	}
	if pc := target.Address(x86Registers(t, s)["eip"]); pc != address+1 {
		t.Fatalf("IA32 EIP was corrected or sign-extended: got %#x, want %#x", pc, address+1)
	}
}

func x86Exit(t *testing.T, stop target.Stop, code int) {
	t.Helper()
	if stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != code {
		t.Fatalf("expected IA32 exit(%d): %+v", code, stop)
	}
}

func TestNativeX86RejectsELF32MachineX86_64(t *testing.T) {
	path, _ := x86Fixture(t, `
.text
.global _start
_start:
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
`, false)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(data[18:20], uint16(elf.EM_X86_64))
	path += ".machine-x86-64"
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := native.Launch(path)
	if s != nil {
		nativeSessionCleanup(t, s, true)
	}
	if !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("ELF32+EM_X86_64 must not be classified as i386: %v", err)
	}
}

func TestNativeX86ArchitectureAndRegisters(t *testing.T) {
	path, symbols := x86Fixture(t, `
.text
.global _start, breakpoint_set
_start:
    clc
breakpoint_set:
    stc
    mov $0, %ebx
    setc %bl
    mov $1, %eax
    int $0x80
`, true)
	s := x86Launch(t, path)
	initial := s.LastStop()
	if initial.RawPC == nil || *initial.RawPC != symbols["_start"] || *initial.RawPC != 0xf0000000 {
		t.Fatalf("initial high IA32 PC: %+v", initial)
	}
	if got := x86Registers(t, s)["eip"]; got != 0xf0000000 {
		t.Fatalf("initial high EIP: %#x", got)
	}
	if err := s.WriteRegisters([]target.Register{x86Register("eax", 0x87654321), x86Register("ebx", 0xfedcba98)}); err != nil {
		t.Fatal(err)
	}
	before := x86Registers(t, s)
	if before["eax"] != 0x87654321 || before["ebx"] != 0xfedcba98 {
		t.Fatalf("IA32 writes lost high bits: eax=%#x ebx=%#x", before["eax"], before["ebx"])
	}
	invalid := []struct {
		register target.Register
		err      error
	}{
		{x86Register("rax", 0), target.ErrInvalidArgument},
		{x86Register("rip", 0), target.ErrInvalidArgument},
		{x86Register("fs_base", 0), target.ErrInvalidArgument},
		{x86Register("eax", 2), target.ErrInvalidArgument},
		{target.Register{Name: "ebx", Bits: 64, Data: make([]byte, 8), Available: true}, target.ErrInvalidArgument},
		{target.Register{Name: "ebx", Bits: 32, Data: make([]byte, 3), Available: true}, target.ErrInvalidArgument},
		{target.Register{Name: "ebx", Bits: 32, Data: make([]byte, 4)}, target.ErrInvalidArgument},
		{x86Register("cs", 0), target.ErrUnsupported},
	}
	for i, bad := range invalid {
		err := s.WriteRegisters([]target.Register{x86Register("eax", 1), bad.register})
		if !errors.Is(err, bad.err) {
			t.Fatalf("invalid IA32 batch %d: got %v, want %v", i, err, bad.err)
		}
		after := x86Registers(t, s)
		for name, want := range before {
			if after[name] != want {
				t.Fatalf("invalid IA32 batch %d modified %s: got %#x want %#x", i, name, after[name], want)
			}
		}
	}
	address := symbols["breakpoint_set"]
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	stop := nativeStop(t, s, target.Signal{}, false)
	x86BreakpointStop(t, s, stop, address)
	if err := s.WriteRegisters([]target.Register{x86Register("eip", uint32(*stop.RawPC))}); err != nil {
		t.Fatal(err)
	}
	x86Exit(t, nativeStop(t, s, target.Signal{}, false), 0)
}

func TestNativeX86RegisterViewMismatchFailsClosed(t *testing.T) {
	path, _ := nativeFixture(t, `
.text
.global _start
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
`)
	s, err := native.Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	nativeSessionCleanup(t, s, true)
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, 0x23)
	err = s.WriteRegisters([]target.Register{{Name: "cs", Bits: 64, Data: data, Available: true}})
	if !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("changed register ABI was not rejected after SET: %v", err)
	}
	t.Logf("observed post-SET register-view mismatch: %v", err)
	var partial *target.PartialError
	if !errors.As(err, &partial) || partial.Completed != 0 || partial.Total != 1 {
		t.Fatalf("register ABI change confirmation: %v", err)
	}
	if s.Architecture() != target.AMD64 {
		t.Fatalf("session silently changed architecture: %s", s.Architecture())
	}
	if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrPartial) {
		t.Fatalf("register ABI mismatch did not fail closed: %v", err)
	}
	result := nativeWait(t, nativeResume(s, target.Signal{}, false))
	if !errors.Is(result.err, target.ErrPartial) {
		t.Fatalf("resume after register ABI mismatch: %+v, %v", result.stop, result.err)
	}
	nativeCommand(t, s.Close)
	if s.State() != target.StateClosed {
		t.Fatalf("ABI-mismatched session close: %s", s.State())
	}
	if pid, err := syscall.Wait4(s.PID(), nil, syscall.WNOHANG, nil); pid != -1 || !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("ABI-mismatched child was not reaped: pid=%d err=%v", pid, err)
	}
}

func TestNativeX86RuntimeModeChangeFailsClosed(t *testing.T) {
	path, _ := x86Fixture(t, `
.text
.code32
.global _start
_start:
    ljmp $0x33, $long_mode
.code64
long_mode:
    int3
spin:
    pause
    jmp spin
`, true)
	s := x86Launch(t, path)
	result := nativeWait(t, nativeResume(s, target.Signal{}, false))
	if !errors.Is(result.err, target.ErrUnsupported) {
		t.Fatalf("runtime long-mode switch accepted as IA32: %+v, %v", result.stop, result.err)
	}
	t.Logf("observed runtime register-view mismatch: %v", result.err)
	if result.stop.RawPC != nil {
		t.Fatalf("incompatible runtime register view produced an IA32 PC: %+v", result.stop)
	}
	if s.Architecture() != target.X86 {
		t.Fatalf("ELF32 session silently changed architecture: %s", s.Architecture())
	}
	if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("runtime mode mismatch did not fail closed: %v", err)
	}
	result = nativeWait(t, nativeResume(s, target.Signal{}, false))
	if !errors.Is(result.err, target.ErrUnsupported) {
		t.Fatalf("resume after runtime mode mismatch: %+v, %v", result.stop, result.err)
	}
	nativeCommand(t, s.Close)
	if s.State() != target.StateClosed {
		t.Fatalf("runtime-mode-mismatched close state: %s", s.State())
	}
	if pid, err := syscall.Wait4(s.PID(), nil, syscall.WNOHANG, nil); pid != -1 || !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("runtime-mode-mismatched child was not reaped: pid=%d err=%v", pid, err)
	}
}

func TestNativeX86BreakpointsMemoryAndStep(t *testing.T) {
	path, symbols := x86Fixture(t, `
.text
.global _start, breakpoint_a, breakpoint_b
_start:
    nop
breakpoint_a:
    nop
breakpoint_b:
    clc
    mov $0, %ebx
    setc %bl
    mov $1, %eax
    int $0x80
`, true)
	s := x86Launch(t, path)
	a, b := symbols["breakpoint_a"], symbols["breakpoint_b"]
	if a <= math.MaxInt32 || b != a+1 {
		t.Fatalf("fixture BP positions: %#x, %#x", a, b)
	}
	for _, span := range []struct {
		address target.Address
		size    int
	}{
		{1 << 32, 0}, {1 << 32, 1}, {math.MaxUint32, 2}, {math.MaxUint32 - 1, 3}, {math.MaxUint64, 1},
	} {
		dst := bytes.Repeat([]byte{0xa5}, span.size)
		if n, err := s.ReadMemory(span.address, dst); n != 0 || !errors.Is(err, target.ErrOverflow) {
			t.Fatalf("IA32 read span %#x+%d: n=%d err=%v", span.address, span.size, n, err)
		}
		if !bytes.Equal(dst, bytes.Repeat([]byte{0xa5}, span.size)) {
			t.Fatal("rejected IA32 read modified destination")
		}
		if n, err := s.WriteMemory(span.address, dst); n != 0 || !errors.Is(err, target.ErrOverflow) {
			t.Fatalf("IA32 write span %#x+%d: n=%d err=%v", span.address, span.size, n, err)
		}
	}
	if n, err := s.ReadMemory(math.MaxUint32, nil); n != 0 || err != nil {
		t.Fatalf("empty IA32 read at maximum valid address: n=%d err=%v", n, err)
	}
	if n, err := s.WriteMemory(math.MaxUint32, nil); n != 0 || err != nil {
		t.Fatalf("empty IA32 write at maximum valid address: n=%d err=%v", n, err)
	}
	if _, err := s.ReadMemory(math.MaxUint32, make([]byte, 1)); errors.Is(err, target.ErrOverflow) {
		t.Fatalf("single-byte IA32 maximum-address span was incorrectly rejected: %v", err)
	}
	for _, address := range []target.Address{math.MaxUint32, 1 << 32} {
		if err := s.AddBreakpoint(address); !errors.Is(err, target.ErrOverflow) {
			t.Fatalf("IA32 breakpoint address %#x: %v", address, err)
		}
	}
	for _, address := range []target.Address{a, b} {
		if err := s.AddBreakpoint(address); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want []byte) {
		t.Helper()
		got := make([]byte, len(want))
		if n, err := s.ReadMemory(a-1, got); n != len(got) || err != nil {
			t.Fatalf("read high IA32 memory: n=%d err=%v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("high IA32 memory: got %x want %x", got, want)
		}
	}
	read([]byte{0x90, 0xcc, 0xcc})
	if n, err := s.WriteMemory(a-1, []byte{0xf8, 0xf9, 0xf8}); n != 0 || !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("write crossing IA32 BP: n=%d err=%v", n, err)
	}
	read([]byte{0x90, 0xcc, 0xcc})
	if err := s.RemoveBreakpoint(a); err != nil {
		t.Fatal(err)
	}
	read([]byte{0x90, 0x90, 0xcc})
	if n, err := s.WriteMemory(a, []byte{0xf9}); n != 1 || err != nil {
		t.Fatalf("write high IA32 instruction: n=%d err=%v", n, err)
	}
	if err := s.AddBreakpoint(a); err != nil {
		t.Fatal(err)
	}
	x86BreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), a)
	stop := nativeStop(t, s, target.Signal{}, true)
	if stop.Reason != target.StopStep || stop.RawPC == nil || *stop.RawPC != b {
		t.Fatalf("IA32 step over adjacent BP: %+v", stop)
	}
	x86BreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), b)
	for _, address := range []target.Address{a, b} {
		if err := s.RemoveBreakpoint(address); err != nil {
			t.Fatal(err)
		}
	}
	read([]byte{0x90, 0xf9, 0xf8})
	x86Exit(t, nativeStop(t, s, target.Signal{}, false), 0)
}

func TestNativeX86SignalDelivery(t *testing.T) {
	path, _ := x86Fixture(t, `
.text
.global _start
_start:
    mov $20, %eax
    int $0x80
    mov %eax, %ebx
    mov $10, %ecx
    mov $37, %eax
    int $0x80
    mov $1, %eax
    mov $37, %ebx
    int $0x80
`, false)
	for _, deliver := range []bool{false, true} {
		name := "suppress"
		if deliver {
			name = "deliver"
		}
		t.Run(name, func(t *testing.T) {
			s := x86Launch(t, path)
			stop := nativeStop(t, s, target.Signal{}, false)
			if stop.Reason != target.StopSignal || stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(syscall.SIGUSR1) {
				t.Fatalf("IA32 SIGUSR1 stop: %+v", stop)
			}
			signal := target.Signal{}
			if deliver {
				signal = target.Signal{Domain: target.SignalLinux, Number: uint32(syscall.SIGUSR1)}
			}
			stop = nativeStop(t, s, signal, false)
			if deliver {
				if stop.Reason != target.StopSignaled || stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(syscall.SIGUSR1) {
					t.Fatalf("IA32 SIGUSR1 termination: %+v", stop)
				}
			} else {
				x86Exit(t, stop, 37)
			}
		})
	}
}

func TestNativeX86SignalDuringBreakpointStep(t *testing.T) {
	path, symbols := x86Fixture(t, `
.text
.global _start, breakpoint_loop
_start:
    mov $0, %eax
breakpoint_loop:
    inc %eax
    cmp $2, %eax
    jne breakpoint_loop
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
`, true)
	s := x86Launch(t, path)
	address := symbols["breakpoint_loop"]
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	x86BreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), address)
	if err := syscall.Kill(s.PID(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	stop := nativeStop(t, s, target.Signal{}, false)
	if stop.Reason != target.StopSignal || stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(syscall.SIGUSR1) || stop.RawPC == nil || *stop.RawPC != address {
		t.Fatalf("IA32 signal interrupted step stop: %+v", stop)
	}
	if x86Registers(t, s)["eax"] != 0 {
		t.Fatal("IA32 breakpoint instruction ran before the queued signal")
	}
	if err := s.WriteRegisters([]target.Register{x86Register("eip", uint32(address))}); !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("IA32 EIP write during suspended step: %v", err)
	}
	x86BreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), address)
	if got := x86Registers(t, s)["eax"]; got != 1 {
		t.Fatalf("IA32 interrupted instruction did not run exactly once: eax=%d", got)
	}
	if err := s.RemoveBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	x86Exit(t, nativeStop(t, s, target.Signal{}, false), 0)
}

func TestNativeX86MixedSessionsInterruptAndClose(t *testing.T) {
	x86Path, _ := x86Fixture(t, `
.text
.global _start
_start:
    pause
    jmp _start
`, true)
	amd64Path, _ := nativeFixture(t, `
.text
.global _start
_start:
    pause
    jmp _start
`)
	a := x86Launch(t, x86Path)
	b, err := native.Launch(amd64Path)
	if err != nil {
		t.Fatal(err)
	}
	nativeSessionCleanup(t, b, true)
	if b.Architecture() != target.AMD64 {
		t.Fatalf("AMD64 session architecture: %s", b.Architecture())
	}
	aDone, bDone := nativeResume(a, target.Signal{}, false), nativeResume(b, target.Signal{}, false)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for a.State() != target.StateRunning || b.State() != target.StateRunning {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("mixed-architecture sessions did not start")
		}
	}
	nativeCommand(t, a.Interrupt)
	result := nativeWait(t, aDone)
	if result.err != nil || result.stop.Reason != target.StopInterrupt || result.stop.RawPC == nil || *result.stop.RawPC < 0xf0000000 || *result.stop.RawPC > math.MaxUint32 {
		t.Fatalf("IA32 interrupt in mixed sessions: %+v, %v", result.stop, result.err)
	}
	if result.stop.ThreadID == nil || *result.stop.ThreadID != uint64(a.PID()) {
		t.Fatalf("mixed session interrupt thread: %+v", result.stop)
	}
	if target.Address(x86Registers(t, a)["eip"]) != *result.stop.RawPC || b.State() != target.StateRunning {
		t.Fatal("mixed sessions exchanged stop state or register view")
	}
	nativeCommand(t, b.Close)
	result = nativeWait(t, bDone)
	if result.err != nil && !errors.Is(result.err, target.ErrClosed) {
		t.Fatalf("AMD64 continue after close: %v", result.err)
	}
	if result.err == nil && (result.stop.Reason != target.StopSignaled || result.stop.Signal.Number != uint32(syscall.SIGKILL) || result.stop.ThreadID == nil || *result.stop.ThreadID != uint64(b.PID())) {
		t.Fatalf("AMD64 close returned another session's stop: %+v", result.stop)
	}
	if b.State() != target.StateClosed || a.State() != target.StateStopped {
		t.Fatalf("mixed close state: x86=%s amd64=%s", a.State(), b.State())
	}
	aDone = nativeResume(a, target.Signal{}, false)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for a.State() != target.StateRunning {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("IA32 session did not resume")
		}
	}
	nativeCommand(t, a.Close)
	result = nativeWait(t, aDone)
	if result.err != nil && !errors.Is(result.err, target.ErrClosed) {
		t.Fatalf("IA32 continue after close: %v", result.err)
	}
	if result.err == nil && (result.stop.Reason != target.StopSignaled || result.stop.Signal.Number != uint32(syscall.SIGKILL) || result.stop.ThreadID == nil || *result.stop.ThreadID != uint64(a.PID())) {
		t.Fatalf("IA32 close returned another session's stop: %+v", result.stop)
	}
	if a.State() != target.StateClosed {
		t.Fatalf("IA32 closed state: %s", a.State())
	}
	for _, s := range []*native.Session{a, b} {
		if pid, err := syscall.Wait4(s.PID(), nil, syscall.WNOHANG, nil); pid != -1 || !errors.Is(err, syscall.ECHILD) {
			t.Fatalf("mixed session close did not reap PID %d: pid=%d err=%v", s.PID(), pid, err)
		}
	}
}

func TestNativeX86AttachDetach(t *testing.T) {
	path, _ := x86Fixture(t, `
.section .rodata
ready: .byte 82
ack: .byte 65
.section .bss
buffer: .skip 1
.text
.global _start
_start:
    mov $4, %eax
    mov $1, %ebx
    mov $ready, %ecx
    mov $1, %edx
    int $0x80
    mov $3, %eax
    xor %ebx, %ebx
    mov $buffer, %ecx
    mov $1, %edx
    int $0x80
    cmp $1, %eax
    jne failure
    mov $4, %eax
    mov $1, %ebx
    mov $ack, %ecx
    mov $1, %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
failure:
    mov $1, %eax
    mov $42, %ebx
    int $0x80
`, true)
	p := nativeStartProcess(t, path)
	s, err := native.Attach(p.command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	nativeSessionCleanup(t, s, false)
	if s.Architecture() != target.X86 || s.State() != target.StateStopped || s.LastStop().Reason != target.StopAttach {
		t.Fatalf("IA32 attach: architecture=%s state=%s stop=%+v", s.Architecture(), s.State(), s.LastStop())
	}
	if pc := x86Registers(t, s)["eip"]; pc < 0xf0000000 {
		t.Fatalf("attached IA32 EIP lost high bits: %#x", pc)
	}
	done := nativeResume(s, target.Signal{}, false)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for s.State() != target.StateRunning {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("attached IA32 process did not resume")
		}
	}
	nativeCommand(t, s.Interrupt)
	result := nativeWait(t, done)
	if result.err != nil || result.stop.Reason != target.StopInterrupt || result.stop.RawPC == nil || target.Address(x86Registers(t, s)["eip"]) != *result.stop.RawPC {
		t.Fatalf("attached IA32 interrupt: %+v, %v", result.stop, result.err)
	}
	nativeCommand(t, s.Detach)
	if s.State() != target.StateDetached {
		t.Fatalf("IA32 detached state: %s", s.State())
	}
	p.finish(t)
}
