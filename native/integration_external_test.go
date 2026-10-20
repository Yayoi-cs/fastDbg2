package native_test

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

type nativeResumeResult struct {
	stop target.Stop
	err  error
}

func nativeFixture(t *testing.T, source string) (string, map[string]target.Address) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native integration fixtures require linux/amd64")
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
	input := path + ".S"
	if err := os.WriteFile(input, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cc", "-nostdlib", "-no-pie", "-Wl,--build-id=none", "-o", path, input)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, output)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
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

func nativeLaunch(t *testing.T, path string) *native.Session {
	t.Helper()
	s, err := native.Launch(path)
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("ptrace denied by this environment: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	nativeSessionCleanup(t, s, true)
	return s
}

func nativeSessionCleanup(t *testing.T, s *native.Session, owned bool) {
	t.Helper()
	pidfd := -1
	if owned {
		if fd, err := unix.PidfdOpen(s.PID(), 0); err == nil {
			pidfd = fd
		}
	}
	t.Cleanup(func() {
		if pidfd >= 0 {
			defer unix.Close(pidfd)
		}
		done := make(chan error, 1)
		go func() { done <- s.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("close session: %v", err)
			}
		case <-time.After(5 * time.Second):
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			t.Error("session close exceeded 5 seconds")
		}
	})
}

func nativeResume(s *native.Session, signal target.Signal, step bool) <-chan nativeResumeResult {
	done := make(chan nativeResumeResult, 1)
	go func() {
		if step {
			stop, err := s.Step(signal)
			done <- nativeResumeResult{stop, err}
			return
		}
		stop, err := s.Continue(signal)
		done <- nativeResumeResult{stop, err}
	}()
	return done
}

func nativeWait(t *testing.T, done <-chan nativeResumeResult) nativeResumeResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("resume did not finish within 5 seconds")
		return nativeResumeResult{}
	}
}

func nativeStop(t *testing.T, s *native.Session, signal target.Signal, step bool) target.Stop {
	t.Helper()
	result := nativeWait(t, nativeResume(s, signal, step))
	if result.err != nil {
		t.Fatal(result.err)
	}
	return result.stop
}

func nativePC(t *testing.T, s *native.Session) target.Address {
	t.Helper()
	return target.Address(nativeRegister(t, s, "rip"))
}

func nativeRegister(t *testing.T, s *native.Session, name string) uint64 {
	t.Helper()
	registers, err := s.ReadRegisters()
	if err != nil {
		t.Fatal(err)
	}
	for _, register := range registers {
		if register.Name == name {
			if !register.Available || register.Bits != 64 || len(register.Data) != 8 {
				t.Fatalf("invalid %s register: %+v", name, register)
			}
			return binary.LittleEndian.Uint64(register.Data)
		}
	}
	t.Fatalf("%s register missing", name)
	return 0
}

func nativeBreakpointStop(t *testing.T, s *native.Session, stop target.Stop, address target.Address) {
	t.Helper()
	if stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != address {
		t.Fatalf("stop at %#x: %+v", address, stop)
	}
	if stop.RawPC == nil || *stop.RawPC != address+1 {
		t.Fatalf("raw breakpoint PC must be %#x: %+v", address+1, stop)
	}
	if pc := nativePC(t, s); pc != address+1 {
		t.Fatalf("register PC was corrected: got %#x, want %#x", pc, address+1)
	}
}

func TestNativeIntegrationAdjacentBreakpointsMemoryAndStep(t *testing.T) {
	path, symbols := nativeFixture(t, `
.text
.global _start, breakpoint_a, breakpoint_b
_start:
    nop
breakpoint_a:
    nop
breakpoint_b:
    clc
    mov $0, %edi
    setc %dil
    mov $60, %eax
    syscall
`)
	a, b := symbols["breakpoint_a"], symbols["breakpoint_b"]
	if a == 0 || b != a+1 {
		t.Fatalf("fixture breakpoints are not adjacent: %#x, %#x", a, b)
	}
	s := nativeLaunch(t, path)
	for _, address := range []target.Address{a, b} {
		if err := s.AddBreakpoint(address); err != nil {
			t.Fatal(err)
		}
	}
	raw := make([]byte, 3)
	if n, err := s.ReadMemory(a-1, raw); err != nil || n != len(raw) {
		t.Fatalf("read armed instructions: %d, %v", n, err)
	}
	if raw[0] != 0x90 || raw[1] != 0xcc || raw[2] != 0xcc {
		t.Fatalf("memory must expose raw breakpoint bytes: %x", raw)
	}
	if n, err := s.WriteMemory(a-1, []byte{0xf8, 0xf9, 0xf8}); n != 0 || !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("write across armed breakpoint: %d, %v", n, err)
	}
	if n, err := s.ReadMemory(a-1, raw); err != nil || n != len(raw) {
		t.Fatalf("read after rejected write: %d, %v", n, err)
	}
	if raw[0] != 0x90 || raw[1] != 0xcc || raw[2] != 0xcc {
		t.Fatalf("rejected write modified memory: %x", raw)
	}
	if err := s.RemoveBreakpoint(a); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ReadMemory(a-1, raw); err != nil || n != len(raw) {
		t.Fatalf("read after removing adjacent breakpoint: %d, %v", n, err)
	}
	if raw[0] != 0x90 || raw[1] != 0x90 || raw[2] != 0xcc {
		t.Fatalf("removing one breakpoint corrupted its neighbor: %x", raw)
	}
	if n, err := s.WriteMemory(a, []byte{0xf9}); err != nil || n != 1 {
		t.Fatalf("write after removing breakpoint: %d, %v", n, err)
	}
	if err := s.AddBreakpoint(a); err != nil {
		t.Fatal(err)
	}
	nativeBreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), a)
	stop := nativeStop(t, s, target.Signal{}, true)
	if stop.Reason != target.StopStep || stop.RawPC == nil || *stop.RawPC != b {
		t.Fatalf("step over first breakpoint: %+v", stop)
	}
	nativeBreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), b)
	for _, address := range []target.Address{a, b} {
		if err := s.RemoveBreakpoint(address); err != nil {
			t.Fatal(err)
		}
	}
	bytes := make([]byte, 2)
	if n, err := s.ReadMemory(a, bytes); err != nil || n != len(bytes) {
		t.Fatalf("read restored instructions: %d, %v", n, err)
	}
	if bytes[0] != 0xf9 || bytes[1] != 0xf8 {
		t.Fatalf("adjacent breakpoint restoration corrupted instructions: %x", bytes)
	}
	stop = nativeStop(t, s, target.Signal{}, false)
	if stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 0 {
		t.Fatalf("final stop: %+v", stop)
	}
}

func TestNativeIntegrationSignalDelivery(t *testing.T) {
	path, _ := nativeFixture(t, `
.text
.global _start
_start:
    mov $39, %eax
    syscall
    mov %eax, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    mov $60, %eax
    mov $37, %edi
    syscall
`)
	for _, deliver := range []bool{false, true} {
		name := "suppress"
		if deliver {
			name = "deliver"
		}
		t.Run(name, func(t *testing.T) {
			s := nativeLaunch(t, path)
			stop := nativeStop(t, s, target.Signal{}, false)
			if stop.Reason != target.StopSignal || stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(syscall.SIGUSR1) {
				t.Fatalf("expected SIGUSR1 delivery stop: %+v", stop)
			}
			signal := target.Signal{}
			if deliver {
				signal = target.Signal{Domain: target.SignalLinux, Number: uint32(syscall.SIGUSR1)}
			}
			stop = nativeStop(t, s, signal, false)
			if deliver {
				if stop.Reason != target.StopSignaled || stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(syscall.SIGUSR1) {
					t.Fatalf("expected SIGUSR1 termination: %+v", stop)
				}
			} else if stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 37 {
				t.Fatalf("suppressed signal should allow exit(37): %+v", stop)
			}
		})
	}
}

func TestNativeIntegrationSignalDuringBreakpointStep(t *testing.T) {
	path, symbols := nativeFixture(t, `
.text
.global _start, breakpoint_loop
_start:
    mov $0, %eax
breakpoint_loop:
    inc %eax
    cmp $2, %eax
    jne breakpoint_loop
    mov $60, %eax
    xor %edi, %edi
    syscall
`)
	address := symbols["breakpoint_loop"]
	if address == 0 {
		t.Fatal("missing fixture breakpoint")
	}
	s := nativeLaunch(t, path)
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	nativeBreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), address)
	if err := syscall.Kill(s.PID(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	stop := nativeStop(t, s, target.Signal{}, false)
	if stop.Reason != target.StopSignal || stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(syscall.SIGUSR1) {
		t.Fatalf("queued signal during breakpoint step: %+v", stop)
	}
	if stop.RawPC == nil || *stop.RawPC != address {
		t.Fatalf("queued signal did not interrupt the breakpoint instruction: %+v", stop)
	}
	if value := nativeRegister(t, s, "rax"); value != 0 {
		t.Fatalf("breakpoint instruction executed before queued signal: rax=%d", value)
	}
	pc := make([]byte, 8)
	binary.LittleEndian.PutUint64(pc, uint64(*stop.RawPC))
	if err := s.WriteRegisters([]target.Register{{Name: "rip", Bits: 64, Data: pc, Available: true}}); !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("RIP write during interrupted breakpoint step must require breakpoint removal: %v", err)
	}
	nativeBreakpointStop(t, s, nativeStop(t, s, target.Signal{}, false), address)
	if value := nativeRegister(t, s, "rax"); value != 1 {
		t.Fatalf("interrupted breakpoint instruction did not execute exactly once: rax=%d", value)
	}
	if err := s.RemoveBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	stop = nativeStop(t, s, target.Signal{}, false)
	if stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 0 {
		t.Fatalf("final stop after interrupted breakpoint step: %+v", stop)
	}
}

func TestNativeIntegrationRegisterWrites(t *testing.T) {
	path, symbols := nativeFixture(t, `
.text
.global _start, breakpoint_set
_start:
    clc
breakpoint_set:
    stc
    mov $0, %edi
    setc %dil
    mov $60, %eax
    syscall
`)
	s := nativeLaunch(t, path)
	register := func(name string, value uint64) target.Register {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, value)
		return target.Register{Name: name, Bits: 64, Data: data, Available: true}
	}
	values := func() map[string]uint64 {
		t.Helper()
		registers, err := s.ReadRegisters()
		if err != nil {
			t.Fatal(err)
		}
		result := make(map[string]uint64, len(registers))
		for _, r := range registers {
			if !r.Available || r.Bits != 64 || len(r.Data) != 8 {
				t.Fatalf("invalid native register: %+v", r)
			}
			if _, exists := result[r.Name]; exists {
				t.Fatalf("duplicate register %q", r.Name)
			}
			result[r.Name] = binary.LittleEndian.Uint64(r.Data)
		}
		return result
	}
	if err := s.WriteRegisters([]target.Register{register("rax", 0x123456789abcdef0), register("rbx", 0xfedcba9876543210)}); err != nil {
		t.Fatal(err)
	}
	before := values()
	if before["rax"] != 0x123456789abcdef0 || before["rbx"] != 0xfedcba9876543210 {
		t.Fatalf("register write did not persist: rax=%#x, rbx=%#x", before["rax"], before["rbx"])
	}
	invalid := []target.Register{
		register("missing_register", 0),
		register("rax", 2),
		{Name: "rbx", Bits: 32, Data: make([]byte, 8), Available: true},
		{Name: "rbx", Bits: 64, Data: make([]byte, 7), Available: true},
		{Name: "rbx", Bits: 64, Data: make([]byte, 8)},
	}
	for i, bad := range invalid {
		if err := s.WriteRegisters([]target.Register{register("rax", 1), bad}); err == nil {
			t.Fatalf("invalid register batch %d succeeded", i)
		}
		after := values()
		for name, want := range before {
			if after[name] != want {
				t.Fatalf("invalid batch %d partially modified %s: got %#x, want %#x", i, name, after[name], want)
			}
		}
	}
	address := symbols["breakpoint_set"]
	if address == 0 {
		t.Fatal("missing fixture breakpoint")
	}
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	stop := nativeStop(t, s, target.Signal{}, false)
	nativeBreakpointStop(t, s, stop, address)
	if err := s.WriteRegisters([]target.Register{register("rip", uint64(*stop.RawPC))}); err != nil {
		t.Fatal(err)
	}
	stop = nativeStop(t, s, target.Signal{}, false)
	if stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 0 {
		t.Fatalf("explicit raw RIP write did not override pending breakpoint rewind: %+v", stop)
	}
	t.Run("kernel_rejection", func(t *testing.T) {
		rejected := nativeLaunch(t, path)
		err := rejected.WriteRegisters([]target.Register{register("rax", 0x1234), register("cs", 0)})
		if !errors.Is(err, target.ErrPartial) {
			t.Fatalf("kernel register rejection must report possible partial write: %v", err)
		}
		var partial *target.PartialError
		if !errors.As(err, &partial) || partial.Completed != 0 || partial.Total != 2 {
			t.Fatalf("unexpected partial register write detail: %v", err)
		}
		result := nativeWait(t, nativeResume(rejected, target.Signal{}, false))
		if result.err == nil {
			t.Fatalf("resume accepted after unconfirmed register write: %+v", result.stop)
		}
	})
}

func TestNativeIntegrationConcurrentInterruptAndClose(t *testing.T) {
	path, _ := nativeFixture(t, `
.text
.global _start
_start:
    pause
    jmp _start
`)
	a, b := nativeLaunch(t, path), nativeLaunch(t, path)
	aDone, bDone := nativeResume(a, target.Signal{}, false), nativeResume(b, target.Signal{}, false)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for a.State() != target.StateRunning || b.State() != target.StateRunning {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("sessions did not enter running state")
		}
	}
	interrupt := make(chan error, 1)
	go func() { interrupt <- a.Interrupt() }()
	select {
	case err := <-interrupt:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupt blocked behind continue")
	}
	result := nativeWait(t, aDone)
	if result.err != nil || result.stop.Reason != target.StopInterrupt {
		t.Fatalf("interrupt stop: %+v, %v", result.stop, result.err)
	}
	if a.State() != target.StateStopped || b.State() != target.StateRunning {
		t.Fatalf("interrupted wrong session: a=%s, b=%s", a.State(), b.State())
	}
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close blocked behind continue")
	}
	result = nativeWait(t, bDone)
	if result.err != nil && !errors.Is(result.err, target.ErrClosed) {
		t.Fatalf("resume after close: %+v, %v", result.stop, result.err)
	}
	if result.err == nil && (result.stop.Reason != target.StopSignaled || result.stop.Signal.Domain != target.SignalLinux || result.stop.Signal.Number != uint32(syscall.SIGKILL)) {
		t.Fatalf("close should report SIGKILL termination: %+v", result.stop)
	}
	if b.State() != target.StateClosed {
		t.Fatalf("closed session state: %s", b.State())
	}
	if pid, err := syscall.Wait4(b.PID(), nil, syscall.WNOHANG, nil); pid != -1 || !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("close did not reap child: pid=%d, err=%v", pid, err)
	}
}

type nativeFixtureProcess struct {
	command  *exec.Cmd
	input    io.WriteCloser
	output   io.ReadCloser
	waitOnce sync.Once
	waited   chan struct{}
	err      error
}

func nativeStartProcess(t *testing.T, path string) *nativeFixtureProcess {
	t.Helper()
	p := &nativeFixtureProcess{command: exec.Command(path), waited: make(chan struct{})}
	var err error
	p.input, err = p.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.output, err = p.command.StdoutPipe()
	if err != nil {
		p.input.Close()
		t.Fatal(err)
	}
	if err := p.command.Start(); err != nil {
		p.input.Close()
		p.output.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.input.Close()
		p.output.Close()
		_ = p.command.Process.Kill()
		p.beginWait()
		select {
		case <-p.waited:
		case <-time.After(5 * time.Second):
			t.Error("fixture process did not terminate")
		}
	})
	p.read(t, 'R')
	return p
}

func (p *nativeFixtureProcess) read(t *testing.T, want byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := io.ReadFull(p.output, data[:])
		if err == nil && data[0] != want {
			err = fmt.Errorf("fixture output: got %q, want %q", data[0], want)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture output exceeded 5 seconds")
	}
}

func (p *nativeFixtureProcess) beginWait() {
	p.waitOnce.Do(func() {
		go func() {
			p.err = p.command.Wait()
			close(p.waited)
		}()
	})
}

func (p *nativeFixtureProcess) finish(t *testing.T) {
	t.Helper()
	if n, err := p.input.Write([]byte{'x'}); n != 1 || err != nil {
		t.Fatalf("fixture input: %d, %v", n, err)
	}
	p.expectExit(t)
}

func (p *nativeFixtureProcess) expectExit(t *testing.T) {
	t.Helper()
	p.read(t, 'A')
	p.beginWait()
	select {
	case <-p.waited:
		if p.err != nil {
			t.Fatalf("fixture exit: %v", p.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not exit after acknowledgement")
	}
}

func nativeCommand(t *testing.T, operation func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- operation() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native operation exceeded 5 seconds")
	}
}

func TestNativeIntegrationAttachDetach(t *testing.T) {
	path, symbols := nativeFixture(t, `
.section .rodata
ready: .byte 82
ack: .byte 65
.section .bss
buffer: .skip 1
.text
.global _start
_start:
    mov $1, %eax
    mov $1, %edi
    lea ready(%rip), %rsi
    mov $1, %edx
    syscall
    xor %eax, %eax
    xor %edi, %edi
    lea buffer(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failure
    mov $1, %eax
    mov $1, %edi
    lea ack(%rip), %rsi
    mov $1, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
failure:
    mov $60, %eax
    mov $42, %edi
    syscall
`)
	t.Run("running", func(t *testing.T) {
		p := nativeStartProcess(t, path)
		s, err := native.Attach(p.command.Process.Pid)
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("ptrace attach denied by this environment: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		nativeSessionCleanup(t, s, false)
		if s.State() != target.StateStopped || s.LastStop().Reason != target.StopAttach {
			t.Fatalf("initial attach state: %s, %+v", s.State(), s.LastStop())
		}
		if pc := nativePC(t, s); pc == 0 {
			t.Fatal("attached RIP is zero")
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
				t.Fatal("attached process did not enter running state")
			}
		}
		nativeCommand(t, func() error { return s.Interrupt() })
		result := nativeWait(t, done)
		if result.err != nil || result.stop.Reason != target.StopInterrupt {
			t.Fatalf("attached interrupt: %+v, %v", result.stop, result.err)
		}
		if result.stop.RawPC == nil || nativePC(t, s) != *result.stop.RawPC {
			t.Fatalf("attached raw register PC does not match stop: %+v", result.stop)
		}
		nativeCommand(t, s.Detach)
		if s.State() != target.StateDetached {
			t.Fatalf("detached state: %s", s.State())
		}
		p.finish(t)
	})
	t.Run("group_stopped", func(t *testing.T) {
		p := nativeStartProcess(t, path)
		if err := p.command.Process.Signal(syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(p.command.Process.Pid, &status, syscall.WUNTRACED, nil)
			if err == nil && (pid != p.command.Process.Pid || !status.Stopped() || status.StopSignal() != syscall.SIGSTOP) {
				err = fmt.Errorf("unexpected group stop: pid=%d status=%x", pid, uint32(status))
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("fixture did not enter SIGSTOP group stop")
		}
		if n, err := p.input.Write([]byte{'x'}); n != 1 || err != nil {
			t.Fatalf("input to group-stopped fixture: %d, %v", n, err)
		}
		s, err := native.Attach(p.command.Process.Pid)
		if s != nil {
			nativeSessionCleanup(t, s, false)
		}
		if err != nil {
			t.Fatalf("group-stopped attach: %v", err)
		}
		if s.State() != target.StateStopped || s.LastStop().Reason != target.StopGroupStop {
			t.Fatalf("group-stopped attach state: %s, %+v", s.State(), s.LastStop())
		}
		snapshot, err := s.Snapshot()
		if err != nil || len(snapshot.Threads) != 1 || !snapshot.Threads[0].GroupStopped {
			t.Fatalf("group-stop metadata: %+v, %v", snapshot, err)
		}
		nativeCommand(t, s.Detach)
		if s.State() != target.StateDetached {
			t.Fatalf("group-stop detach state: %s", s.State())
		}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.command.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			fields := make(map[string]string)
			for _, line := range strings.Split(string(data), "\n") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					fields[parts[0]] = parts[1]
				}
			}
			if fields["TracerPid:"] != "0" {
				t.Fatalf("detach retained tracing: %s", fields["TracerPid:"])
			}
			if fields["State:"] == "T" {
				break
			}
			select {
			case <-ticker.C:
			case <-timer.C:
				t.Fatalf("kernel did not restore group stop: %s", fields["State:"])
			}
		}
		output, ok := p.output.(interface{ Fd() uintptr })
		if !ok {
			t.Fatal("fixture output has no file descriptor")
		}
		poll := []unix.PollFd{{Fd: int32(output.Fd()), Events: unix.POLLIN}}
		if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
			t.Fatalf("fixture responded before explicit SIGCONT: n=%d events=%x err=%v", n, poll[0].Revents, err)
		}
		if err := p.command.Process.Signal(syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
		p.expectExit(t)
	})
	t.Run("externally_killed_with_breakpoint", func(t *testing.T) {
		p := nativeStartProcess(t, path)
		s, err := native.Attach(p.command.Process.Pid)
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("ptrace attach denied by this environment: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		nativeSessionCleanup(t, s, false)
		if err := s.AddBreakpoint(symbols["_start"]); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.PidfdOpen(p.command.Process.Pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		if err := p.command.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		deadline := time.Now().Add(5 * time.Second)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				t.Fatal("killed attached process did not terminate")
			}
			n, err := unix.Poll(poll, int((remaining+time.Millisecond-1)/time.Millisecond))
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
				t.Fatalf("killed process pidfd: n=%d events=%x err=%v", n, poll[0].Revents, err)
			}
			break
		}
		nativeCommand(t, s.Close)
		if s.State() != target.StateClosed {
			t.Fatalf("externally killed session state: %s", s.State())
		}
		if pid, err := syscall.Wait4(p.command.Process.Pid, nil, syscall.WNOHANG, nil); pid != -1 || !errors.Is(err, syscall.ECHILD) {
			t.Fatalf("close did not collect externally killed tracee: pid=%d err=%v", pid, err)
		}
	})
}
