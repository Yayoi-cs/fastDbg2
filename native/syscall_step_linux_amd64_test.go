package native

import (
	"encoding/binary"
	"errors"
	"fastdbg2/target"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func syscallTestRecord(op uint8) []byte {
	data := make([]byte, syscallInfoSize)
	data[0] = op
	binary.LittleEndian.PutUint32(data[4:8], syscallAuditAMD64)
	binary.LittleEndian.PutUint64(data[8:16], 0x1002)
	binary.LittleEndian.PutUint64(data[16:24], 0x7000)
	return data
}

func TestBreakpointSyscallInfoLayout(t *testing.T) {
	entry := syscallTestRecord(unix.PTRACE_SYSCALL_INFO_ENTRY)
	binary.LittleEndian.PutUint64(entry[24:32], ^uint64(0))
	for i := 0; i < 6; i++ {
		binary.LittleEndian.PutUint64(entry[32+i*8:40+i*8], uint64(i+1))
	}
	info, err := decodeSyscallInfo(entry, 80)
	if err != nil || info.arch != syscallAuditAMD64 || info.pc != 0x1002 || info.sp != 0x7000 || info.number != ^uint64(0) || info.args != [6]uint64{1, 2, 3, 4, 5, 6} {
		t.Fatalf("entry=%+v error=%v", info, err)
	}
	exit := syscallTestRecord(unix.PTRACE_SYSCALL_INFO_EXIT)
	binary.LittleEndian.PutUint64(exit[24:32], uint64(^uint64(511)))
	exit[32] = 1
	info, err = decodeSyscallInfo(exit, 33)
	if err != nil || info.result != -512 || !info.isError {
		t.Fatalf("exit=%+v error=%v", info, err)
	}
	for _, size := range []int{-1, 0, 23, syscallInfoSize + 1} {
		if _, err := decodeSyscallInfo(entry, size); !errors.Is(err, target.ErrUnknown) {
			t.Fatalf("invalid size %d accepted: %v", size, err)
		}
	}
	if _, err := decodeSyscallInfo(entry, 79); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("short entry accepted: %v", err)
	}
	if _, err := decodeSyscallInfo(exit, 32); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("short exit accepted: %v", err)
	}
	exit[32] = 2
	if _, err := decodeSyscallInfo(exit, 33); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("invalid error flag accepted: %v", err)
	}
	for _, op := range []uint8{unix.PTRACE_SYSCALL_INFO_NONE, unix.PTRACE_SYSCALL_INFO_SECCOMP, 255} {
		if _, err := decodeSyscallInfo(syscallTestRecord(op), syscallInfoSize); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("unknown op %d accepted: %v", op, err)
		}
	}
}

func TestBreakpointSyscallExactInstructionSet(t *testing.T) {
	for _, test := range []struct {
		architecture target.Architecture
		instruction  [2]byte
		arch         uint32
		matches      bool
		want         error
	}{
		{target.AMD64, [2]byte{0x0f, 0x05}, syscallAuditAMD64, true, nil},
		{target.X86, [2]byte{0xcd, 0x80}, syscallAuditX86, true, nil},
		{target.AMD64, [2]byte{0xcd, 0x80}, syscallAuditAMD64, false, nil},
		{target.X86, [2]byte{0x0f, 0x05}, syscallAuditX86, false, nil},
		{target.AMD64, [2]byte{0x66, 0x0f}, syscallAuditAMD64, false, nil},
		{target.X86, [2]byte{0x0f, 0x34}, 0, false, target.ErrUnsupported},
		{target.AMD64, [2]byte{0x0f, 0x34}, 0, false, target.ErrUnsupported},
	} {
		arch, matches, err := breakpointSyscallArch(test.architecture, test.instruction)
		if arch != test.arch || matches != test.matches || !errors.Is(err, test.want) {
			t.Fatalf("instruction=%x architecture=%s arch=%x matches=%t error=%v", test.instruction, test.architecture, arch, matches, err)
		}
	}
}

func syscallTestPending() *breakpointSyscall {
	space := breakpointTestSpace(1)
	bp := breakpointTestSite(space, 0x1000, 1, false)
	return &breakpointSyscall{bp: bp, space: space.ref, pc: bp.addr, nextPC: bp.addr + 2,
		number: 39, arch: syscallAuditAMD64, phase: syscallEntering, needExit: true, generation: bp.generation}
}

func TestBreakpointSyscallEntryRequiresExactProvenance(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*breakpointSyscall, *syscallInfo)
	}{
		{"arch", func(_ *breakpointSyscall, info *syscallInfo) { info.arch = syscallAuditX86 }},
		{"pc", func(_ *breakpointSyscall, info *syscallInfo) { info.pc++ }},
		{"number", func(_ *breakpointSyscall, info *syscallInfo) { info.number++ }},
		{"phase", func(p *breakpointSyscall, _ *syscallInfo) { p.phase = syscallParked }},
		{"site", func(p *breakpointSyscall, _ *syscallInfo) { delete(p.bp.space.breakpoints, p.bp.addr) }},
		{"generation", func(p *breakpointSyscall, _ *syscallInfo) { p.generation++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			pending := syscallTestPending()
			info := syscallInfo{op: unix.PTRACE_SYSCALL_INFO_ENTRY, arch: pending.arch, pc: pending.nextPC, number: pending.number}
			test.modify(pending, &info)
			before := *pending
			if err := applyBreakpointSyscallInfo(pending, pending.space, info); !errors.Is(err, target.ErrStale) {
				t.Fatalf("invalid entry accepted: %v", err)
			}
			if *pending != before {
				t.Fatal("rejected entry changed its obligation")
			}
		})
	}
	pending := syscallTestPending()
	info := syscallInfo{op: unix.PTRACE_SYSCALL_INFO_ENTRY, arch: pending.arch, pc: pending.nextPC, number: pending.number}
	if err := applyBreakpointSyscallInfo(pending, pending.space, info); err != nil || pending.phase != syscallEntry {
		t.Fatalf("verified entry=%+v error=%v", pending, err)
	}
	if err := applyBreakpointSyscallInfo(pending, pending.space, info); !errors.Is(err, target.ErrStale) {
		t.Fatalf("entry/exit alternation guessed: %v", err)
	}
}

func TestBreakpointSyscallExitPreservesRestartUncertainty(t *testing.T) {
	for _, value := range []int64{-512, -513, -514, -516, -4, -38, 0, 10} {
		pending := syscallTestPending()
		pending.phase = syscallExecuting
		info := syscallInfo{op: unix.PTRACE_SYSCALL_INFO_EXIT, arch: pending.arch, pc: pending.nextPC, result: value, isError: value < 0}
		if err := applyBreakpointSyscallInfo(pending, pending.space, info); err != nil {
			t.Fatal(err)
		}
		want := value == -512 || value == -513 || value == -514 || value == -516
		if pending.phase != syscallExit || pending.result != value || pending.restart != want || !pending.needExit {
			t.Fatalf("rval=%d record=%+v", value, pending)
		}
		if syscallRestartResult(value, false) {
			t.Fatal("non-error value became an assumed restart")
		}
	}
}

func TestBreakpointSyscallExitDoesNotInventReturnAddress(t *testing.T) {
	pending := syscallTestPending()
	pending.phase = syscallExecuting
	delete(pending.bp.space.breakpoints, pending.pc)
	info := syscallInfo{op: unix.PTRACE_SYSCALL_INFO_EXIT, arch: pending.arch, pc: 0x5555, result: 7}
	if err := applyBreakpointSyscallInfo(pending, pending.space, info); err != nil || pending.phase != syscallExit {
		t.Fatalf("nonlocal return or removed breakpoint invalidated formal exit: %v", err)
	}
	for _, phase := range []syscallPhase{syscallEntering, syscallEntry, syscallParked, syscallExit} {
		pending := syscallTestPending()
		pending.phase = phase
		if err := applyBreakpointSyscallInfo(pending, pending.space, info); !errors.Is(err, target.ErrStale) {
			t.Fatalf("phase %d accepted an unowned exit: %v", phase, err)
		}
	}
}

func TestBreakpointSyscallForgetUsesConfirmedEntryOnly(t *testing.T) {
	for _, phase := range []syscallPhase{syscallEntering, syscallEntry, syscallParked, syscallExecuting, syscallExit} {
		pending := syscallTestPending()
		pending.phase = phase
		current := &thread{syscall: pending}
		(&engine{}).forgetBreakpointSyscall(current)
		if current.syscall != nil || current.needsUserBoundary != (phase >= syscallEntry) {
			t.Fatalf("phase=%d thread=%+v", phase, current)
		}
	}
}

func TestBreakpointSyscallIgnoresNonSyscallTraps(t *testing.T) {
	e := &engine{}
	for _, status := range []unix.WaitStatus{
		unix.WaitStatus(int(unix.SIGTRAP)<<8 | 0x7f),
		unix.WaitStatus(unix.PTRACE_EVENT_STOP<<16 | int(unix.SIGTRAP)<<8 | 0x7f),
		unix.WaitStatus(int(unix.SIGUSR1)<<8 | 0x7f),
	} {
		if _, handled, err := e.classifyBreakpointSyscall(nil, waitResult{pid: 1, status: status}); handled || err != nil {
			t.Fatalf("unrelated stop consumed: status=%x handled=%t error=%v", status, handled, err)
		}
	}
	status := unix.WaitStatus((int(unix.SIGTRAP)|0x80)<<8 | 0x7f)
	if _, handled, err := e.classifyBreakpointSyscall(nil, waitResult{pid: 1, status: status}); !handled || !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("unowned syscall stop=%t error=%v", handled, err)
	}
}

func TestBreakpointSyscallFormalStepDoesNotExecuteSuccessor(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for _, number := range []int{0, -1} {
			t.Run(fmt.Sprintf("bits%d_nr%d", bits, number), func(t *testing.T) {
				instruction := "syscall"
				nr := 39
				if bits == 32 {
					instruction, nr = "int $0x80", 20
				}
				if number == -1 {
					nr = -1
				}
				path, entry := coreAssembly(t, bits, fmt.Sprintf(".text\n.global _start\n_start:\n mov $%d, %%eax\n %s\n nop\n jmp .\n", nr, instruction))
				s, err := Launch(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := s.Close(); err != nil {
						t.Error(err)
					}
				})
				site := entry + 5
				if err := s.AddBreakpoint(site); err != nil {
					t.Fatal(err)
				}
				if stop, err := s.Continue(target.Signal{}); err != nil || stop.Reason != target.StopBreakpoint {
					t.Fatalf("initial hit=%+v error=%v", stop, err)
				}
				stop, err := s.Step(target.Signal{})
				if err != nil || stop.Reason != target.StopStep || !stop.StepCompleted || stop.RawPC == nil || *stop.RawPC != site+2 {
					t.Fatalf("formal syscall completion=%+v error=%v", stop, err)
				}
				err = command(s, func(e *engine) error {
					current := e.threads[s.pid]
					if current.syscall != nil || current.suspended != nil || current.process.space.stepping != nil || !current.process.space.breakpoints[site].armed {
						return errors.New("formal syscall completion left an unsafe physical state")
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				stop, err = s.Step(target.Signal{})
				if err != nil || stop.Reason != target.StopStep || !stop.StepCompleted || stop.RawPC == nil || *stop.RawPC != site+3 {
					t.Fatalf("successor instruction step=%+v error=%v", stop, err)
				}
			})
		}
	}
}

func TestBreakpointSyscallEnteringRetryRechecksBytesAndRemoveCancels(t *testing.T) {
	for _, bits := range []int{32, 64} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			instruction, number, second := "syscall", 39, byte(0x05)
			if bits == 32 {
				instruction, number, second = "int $0x80", 20, 0x80
			}
			path, entry := coreAssembly(t, bits, fmt.Sprintf(".text\n.global _start\n_start:\n mov $%d, %%eax\n %s\n jmp .\n", number, instruction))
			s, err := Launch(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			site := entry + 5
			if err := s.AddBreakpoint(site); err != nil {
				t.Fatal(err)
			}
			if stop, err := s.Continue(target.Signal{}); err != nil || stop.Reason != target.StopBreakpoint {
				t.Fatalf("initial breakpoint=%+v error=%v", stop, err)
			}
			err = command(s, func(e *engine) error {
				current := e.threads[s.pid]
				bp, err := e.prepareBreakpointStep(current)
				if err != nil {
					return err
				}
				if matches, err := e.prepareBreakpointSyscall(current, bp); err != nil || !matches {
					return errors.Join(err, errors.New("canonical syscall was not prepared"))
				}
				pending := current.syscall
				if err := e.writeByte(current.tid, site+1, 0x90); err != nil {
					return err
				}
				if _, err := e.prepareBreakpointSyscall(current, bp); !errors.Is(err, target.ErrStale) {
					return errors.New("changed syscall bytes were accepted on retry")
				}
				if current.syscall != pending || pending.phase != syscallEntering || bp.armed || current.process.space.stepping != current {
					return errors.New("failed retry released the missing-patch barrier")
				}
				if err := e.writeByte(current.tid, site+1, second); err != nil {
					return err
				}
				if matches, err := e.prepareBreakpointSyscall(current, bp); err != nil || !matches || current.syscall != pending {
					return errors.Join(err, errors.New("valid retry did not retain its syscall operation"))
				}
				if err := e.removeBreakpoint(bp); err != nil {
					return err
				}
				if current.syscall != nil || current.suspended != nil || current.process.space.stepping != nil {
					return errors.New("breakpoint removal retained the unentered syscall obligation")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBreakpointSyscallEntryRearmFailureRetainsOwnership(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n mov $39, %eax\n syscall\n jmp .\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	site := entry + 5
	if err := s.AddBreakpoint(site); err != nil {
		t.Fatal(err)
	}
	if stop, err := s.Continue(target.Signal{}); err != nil || stop.Reason != target.StopBreakpoint {
		t.Fatalf("initial breakpoint=%+v error=%v", stop, err)
	}
	err = command(s, func(e *engine) error {
		current := e.threads[s.pid]
		bp, err := e.prepareBreakpointStep(current)
		if err != nil {
			return err
		}
		if matches, err := e.prepareBreakpointSyscall(current, bp); err != nil || !matches {
			return errors.Join(err, errors.New("canonical syscall was not prepared"))
		}
		pending := current.syscall
		info := syscallInfo{op: unix.PTRACE_SYSCALL_INFO_ENTRY, arch: pending.arch, pc: pending.nextPC, number: pending.number}
		if err := applyBreakpointSyscallInfo(pending, pending.space, info); err != nil {
			return err
		}
		pending.needExit = true
		if err := e.writeByte(current.tid, site, 0x90); err != nil {
			return err
		}
		if err := e.finishBreakpointSyscallEntry(current); !errors.Is(err, target.ErrStale) {
			return errors.New("syscall entry rearmed an unexpected instruction byte")
		}
		if current.syscall != pending || pending.phase != syscallEntry || current.suspended != bp || bp.armed || bp.space.stepping != current {
			return errors.New("failed syscall entry rearm released its physical ownership")
		}
		if err := e.writeByte(current.tid, site, bp.original); err != nil {
			return err
		}
		if err := e.finishBreakpointSyscallEntry(current); err != nil {
			return err
		}
		if current.syscall != pending || pending.phase != syscallParked || current.suspended != nil || !bp.armed || bp.space.stepping != nil {
			return errors.New("confirmed syscall entry rearm did not park its owner")
		}
		if err := e.removeBreakpoint(bp); err != nil {
			return err
		}
		if current.syscall != pending || !pending.needExit {
			return errors.New("removing a rearmed site lost its syscall exit obligation")
		}
		if err := e.restoreBreakpoints(); err != nil {
			return err
		}
		if current.syscall != nil || !current.needsUserBoundary {
			return errors.New("cleanup retained the consumed syscall obligation")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
