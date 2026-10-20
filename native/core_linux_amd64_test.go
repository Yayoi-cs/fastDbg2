package native

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func coreTempDir(t *testing.T) string {
	t.Helper()
	tmp, err := filepath.Abs(filepath.Join("..", ".cache", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	return t.TempDir()
}

func coreFixture(t *testing.T) string {
	t.Helper()
	dir := coreTempDir(t)
	source := filepath.Join(dir, "fixture.c")
	path := filepath.Join(dir, "fixture")
	code := `#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void *spin(void *p) { for (;;) __asm__ volatile(""); return p; }
int main(int n, char **v) {
    if (n > 1 && !strcmp(v[1], "exit")) return 7;
    if (n > 1 && !strcmp(v[1], "exec")) { execl(v[0], v[0], "exit", (char *)0); return 99; }
    if (n > 1 && (!strcmp(v[1], "thread") || !strcmp(v[1], "readythread"))) {
        pthread_t t;
        if (pthread_create(&t, 0, spin, 0)) return 98;
        if (!strcmp(v[1], "readythread")) { puts("ready"); fflush(stdout); }
    }
    if (n > 1 && !strcmp(v[1], "fork")) { if (fork() < 0) return 97; }
    spin(0);
    return 0;
}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O0", "-pthread", "-o", path, source).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, out)
	}
	return path
}

func TestCoreLaunchFailures(t *testing.T) {
	if _, err := Launch("/does/not/exist/fastdbg2"); err == nil {
		t.Fatal("missing executable accepted")
	}
	path := coreFixture(t)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Launch(path); err == nil {
		t.Fatal("non-executable ELF accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[18], data[19] = 183, 0
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Launch(path); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("foreign ELF: %v", err)
	}
}

func TestCoreExitAndClose(t *testing.T) {
	s, err := Launch(coreFixture(t), "exit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	stop, err := s.Continue(target.Signal{})
	if err != nil || stop.Reason != target.StopExited || stop.ExitCode == nil || *stop.ExitCode != 7 {
		t.Fatalf("exit stop=%+v error=%v", stop, err)
	}
	if _, err := s.Step(target.Signal{}); !errors.Is(err, target.ErrExited) {
		t.Fatalf("step after exit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.State() != target.StateClosed {
		t.Fatalf("state=%v", s.State())
	}
	if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
}

func TestCoreRejectsTaskAndImageChanges(t *testing.T) {
	path := coreFixture(t)
	for _, tc := range []struct {
		mode   string
		reason target.StopReason
	}{
		{"thread", target.StopClone}, {"fork", target.StopFork}, {"exec", target.StopExec},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			s, err := Launch(path, tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			stop, err := s.Continue(target.Signal{})
			if !errors.Is(err, target.ErrUnsupported) || stop.Reason != tc.reason {
				t.Fatalf("unsupported stop=%+v error=%v", stop, err)
			}
			if _, err := s.ReadRegisters(); !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("data after unsupported: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func startUntraced(t *testing.T, path, mode string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, mode)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

func TestCoreAttachAndDetach(t *testing.T) {
	cmd := startUntraced(t, coreFixture(t), "loop")
	s, err := Attach(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if s.LastStop().Reason != target.StopAttach {
		t.Fatalf("initial stop=%+v", s.LastStop())
	}
	if _, err := s.ReadRegisters(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(unix.Signal(0)); err != nil {
		t.Fatalf("attach close killed target: %v", err)
	}
}

func TestCoreAttachRejectsMultipleThreads(t *testing.T) {
	cmd := exec.Command(coreFixture(t), "readythread")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("fixture readiness %q: %v", line, err)
	}
	if _, err := Attach(cmd.Process.Pid); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("multi-thread attach: %v", err)
	}
	if err := cmd.Process.Signal(unix.Signal(0)); err != nil {
		t.Fatalf("rejected attach killed target: %v", err)
	}
}

func TestCoreAttachPreservesGroupStop(t *testing.T) {
	cmd := startUntraced(t, coreFixture(t), "loop")
	if err := cmd.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(cmd.Process.Pid, &ws, unix.WUNTRACED, nil); err != nil {
		t.Fatal(err)
	}
	if !ws.Stopped() {
		t.Fatalf("initial state: %v", ws)
	}
	if _, err := Attach(cmd.Process.Pid); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("group-stop attach: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/status")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(status), "State:\tT (stopped)") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kernel group-stop transition did not complete:\n%s", status)
		}
		runtime.Gosched()
	}
}

func TestCoreChildExitCompletesUnsupported(t *testing.T) {
	s := &Session{pid: 41}
	s.state.Store(uint32(target.StateStopped))
	reply := make(chan response[target.Stop], 1)
	stop := target.Stop{Reason: target.StopClone}
	e := &engine{
		s:            s,
		tasks:        map[int]*task{41: {pid: 41, tgid: 41, stopped: true}, 42: {pid: 42, waiting: true}},
		deferredStop: &stop,
		unsupported:  target.ErrUnsupported,
		run:          &runOperation{reply: reply},
	}
	e.handleWait(waitResult{pid: 42, status: unix.WaitStatus(unix.SIGKILL)})
	select {
	case result := <-reply:
		if result.value.Reason != target.StopClone || !errors.Is(result.err, target.ErrUnsupported) {
			t.Fatalf("result=%+v", result)
		}
	default:
		t.Fatal("child terminal did not resolve the pending run")
	}
}

func TestCoreTerminalDoesNotRepublishOldStop(t *testing.T) {
	s := &Session{pid: 41}
	s.state.Store(uint32(target.StateStopped))
	stop := target.Stop{Reason: target.StopFork}
	e := &engine{
		s:            s,
		tasks:        map[int]*task{41: {pid: 41, tgid: 41, waiting: true}, 42: {pid: 42, waiting: true}},
		deferredStop: &stop,
		unsupported:  target.ErrUnsupported,
	}
	e.handleWait(waitResult{pid: 41, status: unix.WaitStatus(unix.SIGKILL)})
	e.handleWait(waitResult{pid: 42, status: unix.WaitStatus(unix.SIGKILL)})
	if s.State() != target.StateExited || s.LastStop().Reason != target.StopSignaled {
		t.Fatalf("state=%v last=%+v", s.State(), s.LastStop())
	}
}

func TestCoreELFProfiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		class   elf.Class
		machine elf.Machine
		order   elf.Data
		want    target.Architecture
	}{
		{"i386", elf.ELFCLASS32, elf.EM_386, elf.ELFDATA2LSB, target.X86},
		{"amd64", elf.ELFCLASS64, elf.EM_X86_64, elf.ELFDATA2LSB, target.AMD64},
		{"x32", elf.ELFCLASS32, elf.EM_X86_64, elf.ELFDATA2LSB, ""},
		{"arm32", elf.ELFCLASS32, elf.EM_ARM, elf.ELFDATA2LSB, ""},
		{"wrong_class", elf.ELFCLASS64, elf.EM_386, elf.ELFDATA2LSB, ""},
		{"big_endian", elf.ELFCLASS32, elf.EM_386, elf.ELFDATA2MSB, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Create(filepath.Join(coreTempDir(t), "header.elf"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var ident [elf.EI_NIDENT]byte
			copy(ident[:], elf.ELFMAG)
			ident[elf.EI_CLASS], ident[elf.EI_DATA], ident[elf.EI_VERSION] = byte(tc.class), byte(tc.order), byte(elf.EV_CURRENT)
			var order binary.ByteOrder = binary.LittleEndian
			if tc.order == elf.ELFDATA2MSB {
				order = binary.BigEndian
			}
			if tc.class == elf.ELFCLASS32 {
				err = binary.Write(f, order, elf.Header32{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(tc.machine), Version: 1, Ehsize: 52, Phentsize: 32, Shentsize: 40})
			} else {
				err = binary.Write(f, order, elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(tc.machine), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64})
			}
			if err != nil {
				t.Fatal(err)
			}
			profile, err := profileForELF(f)
			if tc.want == "" {
				if !errors.Is(err, target.ErrUnsupported) {
					t.Fatalf("profile=%+v error=%v", profile, err)
				}
			} else if err != nil || profile.Architecture != tc.want {
				t.Fatalf("profile=%+v error=%v", profile, err)
			}
		})
	}
}

func TestCoreBreakpointAddressWidths(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		t.Run(string(profile.Architecture), func(t *testing.T) {
			e := &engine{profile: &profile}
			maximum, err := profile.MaxAddress()
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range []target.Address{0, 0xf0000000, maximum - 1} {
				if err := e.checkBreakpointAddress(address); err != nil {
					t.Errorf("address=%x: %v", address, err)
				}
			}
			if err := e.checkBreakpointAddress(maximum); !errors.Is(err, target.ErrOverflow) {
				t.Fatalf("maximum: %v", err)
			}
			if profile.Architecture == target.X86 {
				for _, address := range []target.Address{maximum + 1, math.MaxUint64} {
					if err := e.checkBreakpointAddress(address); !errors.Is(err, target.ErrOverflow) {
						t.Errorf("address=%x: %v", address, err)
					}
				}
			}
		})
	}
	if err := (&engine{}).checkBreakpointAddress(0); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("unknown profile: %v", err)
	}
}

func TestCoreExecInvalidatesBeforeRegisterDecode(t *testing.T) {
	s := &Session{pid: 41}
	s.state.Store(uint32(target.StateRunning))
	address := target.Address(0x401000)
	bp := &breakpoint{addr: address, original: 0x90, armed: true}
	reply := make(chan response[target.Stop], 1)
	e := &engine{
		s:           s,
		tasks:       map[int]*task{41: {pid: 41, tgid: 41, waiting: true}},
		breakpoints: map[target.Address]*breakpoint{address: bp},
		hit:         &address, suspended: bp, run: &runOperation{reply: reply, over: bp},
	}
	status := unix.WaitStatus(unix.PTRACE_EVENT_EXEC<<16 | int(unix.SIGTRAP)<<8 | 0x7f)
	e.handleWait(waitResult{pid: 41, status: status})
	result := <-reply
	if result.value.Reason != target.StopExec || result.value.RawPC != nil || !errors.Is(result.err, target.ErrUnsupported) {
		t.Fatalf("exec=%+v error=%v", result.value, result.err)
	}
	if len(e.breakpoints) != 0 || e.hit != nil || e.suspended != nil {
		t.Fatal("old image breakpoint state survived exec")
	}
}

func coreAssembly(t *testing.T, bits int, code string) (string, target.Address) {
	t.Helper()
	dir := coreTempDir(t)
	source, object, path := filepath.Join(dir, "fixture.S"), filepath.Join(dir, "fixture.o"), filepath.Join(dir, "fixture")
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("as", fmt.Sprintf("--%d", bits), "-o", object, source).CombinedOutput(); err != nil {
		t.Fatalf("assemble: %v\n%s", err, out)
	}
	emulation := "elf_x86_64"
	if bits == 32 {
		emulation = "elf_i386"
	}
	if out, err := exec.Command("ld", "-m", emulation, "-o", path, object).CombinedOutput(); err != nil {
		t.Fatalf("link: %v\n%s", err, out)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return path, target.Address(f.Entry)
}

func TestCoreExecArchitectureChanges(t *testing.T) {
	for _, bits := range []int{32, 64} {
		t.Run(fmt.Sprintf("from_%d", bits), func(t *testing.T) {
			toBits := 64
			if bits == 64 {
				toBits = 32
			}
			to, _ := coreAssembly(t, toBits, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
			body := "mov $11, %eax\n mov $destination, %ebx\n xor %ecx, %ecx\n xor %edx, %edx\n int $0x80\n ud2\n"
			want := target.X86
			if bits == 64 {
				body = "mov $59, %eax\n lea destination(%rip), %rdi\n xor %esi, %esi\n xor %edx, %edx\n syscall\n ud2\n"
				want = target.AMD64
			}
			from, entry := coreAssembly(t, bits, ".text\n.global _start\n_start:\n"+body+fmt.Sprintf(".section .rodata\ndestination: .asciz %q\n", to))
			s, err := Launch(from)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			if s.Architecture() != want {
				t.Fatalf("architecture=%s", s.Architecture())
			}
			if err := s.AddBreakpoint(entry); err != nil {
				t.Fatal(err)
			}
			stop, err := s.Continue(target.Signal{})
			if err != nil || stop.Reason != target.StopBreakpoint {
				t.Fatalf("first stop=%+v error=%v", stop, err)
			}
			stop, err = s.Continue(target.Signal{})
			if !errors.Is(err, target.ErrUnsupported) || stop.Reason != target.StopExec || stop.RawPC != nil {
				t.Fatalf("exec stop=%+v error=%v", stop, err)
			}
			count, err := call(s, func(e *engine) (int, error) { return len(e.breakpoints), nil })
			if err != nil || count != 0 {
				t.Fatalf("old breakpoints=%d error=%v", count, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCoreForkOwnershipBeforeRegisterViewRejection(t *testing.T) {
	path, _ := coreAssembly(t, 32, ".text\n.global _start\n.code32\n_start:\n ljmp $0x33, $long_mode\n.code64\nlong_mode:\n mov $57, %eax\n syscall\nloop:\n jmp loop\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	stop, err := s.Continue(target.Signal{})
	if !errors.Is(err, target.ErrUnsupported) || stop.Reason != target.StopFork || stop.RawPC != nil {
		t.Fatalf("fork stop=%+v error=%v", stop, err)
	}
	child, err := call(s, func(e *engine) (int, error) {
		if len(e.tasks) != 2 || !e.allStopped() {
			return 0, target.ErrInvalidState
		}
		for pid, task := range e.tasks {
			if pid != e.s.pid {
				if _, ok := e.groups[task.tgid]; !ok {
					return 0, target.ErrUnavailable
				}
				return pid, nil
			}
		}
		return 0, target.ErrNotFound
	})
	if err != nil || child <= 0 {
		t.Fatalf("child ownership=%d error=%v", child, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(child, &ws, unix.WALL|unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("child remained waitable after close: %v", err)
	}
}
