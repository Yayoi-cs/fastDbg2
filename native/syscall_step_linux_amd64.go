package native

import (
	"encoding/binary"
	"fastdbg2/target"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

type syscallPhase uint8

const (
	syscallEntering syscallPhase = iota + 1
	syscallEntry
	syscallParked
	syscallExecuting
	syscallExit
)

const (
	syscallAuditAMD64 = uint32(0xc000003e)
	syscallAuditX86   = uint32(0x40000003)
	syscallInfoSize   = 88
)

type breakpointSyscall struct {
	bp         *breakpoint
	space      target.SpaceRef
	pc         target.Address
	nextPC     target.Address
	number     uint64
	arch       uint32
	phase      syscallPhase
	needExit   bool
	result     int64
	restart    bool
	generation uint64
}

type syscallInfo struct {
	op      uint8
	arch    uint32
	pc      target.Address
	sp      target.Address
	number  uint64
	args    [6]uint64
	result  int64
	isError bool
}

func decodeSyscallInfo(data []byte, size int) (syscallInfo, error) {
	var info syscallInfo
	if size < 24 || size > len(data) {
		return info, fmt.Errorf("syscall info size %d: %w", size, target.ErrUnknown)
	}
	info.op = data[0]
	info.arch = binary.LittleEndian.Uint32(data[4:8])
	info.pc = target.Address(binary.LittleEndian.Uint64(data[8:16]))
	info.sp = target.Address(binary.LittleEndian.Uint64(data[16:24]))
	switch info.op {
	case unix.PTRACE_SYSCALL_INFO_ENTRY:
		if size < 80 {
			return info, fmt.Errorf("truncated syscall entry: %w", target.ErrUnknown)
		}
		info.number = binary.LittleEndian.Uint64(data[24:32])
		for i := range info.args {
			info.args[i] = binary.LittleEndian.Uint64(data[32+i*8 : 40+i*8])
		}
	case unix.PTRACE_SYSCALL_INFO_EXIT:
		if size < 33 || data[32] > 1 {
			return info, fmt.Errorf("invalid syscall exit record: %w", target.ErrUnknown)
		}
		info.result = int64(binary.LittleEndian.Uint64(data[24:32]))
		info.isError = data[32] != 0
	default:
		return info, fmt.Errorf("syscall info operation %d is not an entry or exit: %w", info.op, target.ErrUnsupported)
	}
	return info, nil
}

func readSyscallInfo(tid int) (syscallInfo, error) {
	var data [syscallInfoSize]byte
	n, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO, uintptr(tid), uintptr(len(data)), uintptr(unsafe.Pointer(&data[0])), 0, 0)
	runtime.KeepAlive(data)
	if errno != 0 {
		return syscallInfo{}, fmt.Errorf("get TID %d syscall info: %w", tid, errno)
	}
	if n > uintptr(len(data)) {
		return syscallInfo{}, fmt.Errorf("syscall info size %d exceeds the supported layout: %w", n, target.ErrUnsupported)
	}
	return decodeSyscallInfo(data[:], int(n))
}

func breakpointSyscallArch(architecture target.Architecture, instruction [2]byte) (uint32, bool, error) {
	if instruction == [2]byte{0x0f, 0x34} {
		return 0, false, fmt.Errorf("SYSENTER can return before a syscall-entry stop: %w", target.ErrUnsupported)
	}
	switch architecture {
	case target.AMD64:
		return syscallAuditAMD64, instruction == [2]byte{0x0f, 0x05}, nil
	case target.X86:
		return syscallAuditX86, instruction == [2]byte{0xcd, 0x80}, nil
	default:
		return 0, false, target.ErrUnsupported
	}
}

func (e *engine) breakpointSyscallInstruction(t *thread, bp *breakpoint) (uint32, bool, error) {
	first, err := e.readByte(t.tid, bp.addr)
	if err != nil {
		return 0, false, err
	}
	if first != bp.original {
		return 0, false, fmt.Errorf("syscall breakpoint instruction changed: %w", target.ErrStale)
	}
	if first != 0x0f && first != 0xcd {
		return 0, false, nil
	}
	second, err := e.readByte(t.tid, bp.addr+1)
	if err != nil {
		return 0, false, nil
	}
	return breakpointSyscallArch(t.process.profile.Architecture, [2]byte{first, second})
}

func (e *engine) breakpointSyscallNumber(t *thread) (uint64, error) {
	registers, err := e.readRegisterSet(t.tid)
	if err != nil {
		return 0, err
	}
	name := "rax"
	if t.process.profile.Architecture == target.X86 {
		name = "eax"
	}
	field, ok := t.process.profile.Register(name)
	if !ok || field.Bits != 32 && field.Bits != 64 {
		return 0, target.ErrUnknown
	}
	return uint64(int64(int32(binary.LittleEndian.Uint32(registers[field.Offset : field.Offset+4])))), nil
}

func (e *engine) prepareBreakpointSyscall(t *thread, bp *breakpoint) (bool, error) {
	if t == nil || t.process == nil || t.process.profile == nil || t.process.space == nil || t.state != target.StateStopped || t.listening || t.exiting {
		return false, target.ErrInvalidState
	}
	if !e.allStopped() {
		return false, target.ErrRunning
	}
	if err := validateBreakpoint(bp); err != nil {
		return false, err
	}
	if bp.space != t.process.space || bp.armed || bp.pending != nil || t.suspended != bp || bp.space.stepping != t {
		return false, target.ErrStale
	}
	pc, err := e.readPC(t.tid)
	if err != nil {
		return false, err
	}
	if pc != bp.addr {
		return false, target.ErrStale
	}
	arch, matches, err := e.breakpointSyscallInstruction(t, bp)
	if err != nil {
		return false, err
	}
	if !matches {
		if t.syscall != nil {
			return false, target.ErrStale
		}
		return false, nil
	}
	if err := t.process.profile.ValidateRange(pc, 3); err != nil {
		return false, err
	}
	number, err := e.breakpointSyscallNumber(t)
	if err != nil {
		return false, err
	}
	if pending := t.syscall; pending != nil {
		if pending.phase != syscallEntering || pending.bp != bp || pending.space != bp.space.ref || pending.pc != pc || pending.nextPC != pc+2 || pending.number != number || pending.arch != arch || pending.generation != bp.generation {
			return false, target.ErrStale
		}
		return true, nil
	}
	t.syscall = &breakpointSyscall{
		bp: bp, space: bp.space.ref, pc: pc, nextPC: pc + 2,
		number: number, arch: arch, phase: syscallEntering, generation: bp.generation,
		needExit: e.run != nil && e.run.step == t.ref,
	}
	return true, nil
}

func syscallRestartResult(result int64, isError bool) bool {
	if !isError {
		return false
	}
	switch result {
	case -512, -513, -514, -516:
		return true
	default:
		return false
	}
}

func applyBreakpointSyscallInfo(pending *breakpointSyscall, space target.SpaceRef, info syscallInfo) error {
	if pending == nil || pending.space != space || info.arch != pending.arch {
		return target.ErrStale
	}
	switch info.op {
	case unix.PTRACE_SYSCALL_INFO_ENTRY:
		if pending.phase != syscallEntering || info.pc != pending.nextPC || info.number != pending.number {
			return fmt.Errorf("syscall entry does not match the resumed instruction: %w", target.ErrStale)
		}
		if err := validateBreakpoint(pending.bp); err != nil {
			return err
		}
		if pending.bp.generation != pending.generation {
			return target.ErrStale
		}
		pending.phase = syscallEntry
	case unix.PTRACE_SYSCALL_INFO_EXIT:
		if pending.phase != syscallExecuting || !pending.needExit {
			return fmt.Errorf("syscall exit has no matching entry obligation: %w", target.ErrStale)
		}
		pending.result = info.result
		pending.restart = syscallRestartResult(info.result, info.isError)
		pending.phase = syscallExit
	default:
		return target.ErrUnsupported
	}
	return nil
}

func (e *engine) classifyBreakpointSyscall(t *thread, w waitResult) (target.Stop, bool, error) {
	if !w.status.Stopped() || w.status.StopSignal() != unix.Signal(int(unix.SIGTRAP)|0x80) || uint32(w.status)>>16 != 0 {
		return target.Stop{}, false, nil
	}
	stop := rawStop(w)
	stop.Reason, stop.Signal = target.StopUnknown, target.Signal{}
	if t == nil || t.process == nil || t.process.space == nil || t.process.profile == nil || t.syscall == nil {
		return stop, true, fmt.Errorf("syscall stop has no owned breakpoint operation: %w", target.ErrUnsupported)
	}
	t.pendingSignal = 0
	info, err := readSyscallInfo(t.tid)
	if err != nil {
		return stop, true, err
	}
	pc := info.pc
	stop.RawPC = &pc
	stop.Raw += fmt.Sprintf(" syscall_op=%d arch=%#x ip=%#x sp=%#x", info.op, info.arch, info.pc, info.sp)
	if info.op == unix.PTRACE_SYSCALL_INFO_ENTRY {
		stop.Raw += fmt.Sprintf(" nr=%#x", info.number)
	} else {
		stop.Raw += fmt.Sprintf(" rval=%d is_error=%t", info.result, info.isError)
	}
	actual, err := e.readPC(t.tid)
	if err != nil {
		return stop, true, err
	}
	if actual != info.pc {
		return stop, true, fmt.Errorf("syscall info PC disagrees with the stopped registers: %w", target.ErrStale)
	}
	return stop, true, applyBreakpointSyscallInfo(t.syscall, t.process.space.ref, info)
}

func (e *engine) finishBreakpointSyscallEntry(t *thread) error {
	if t == nil || t.syscall == nil || t.process == nil || t.process.space == nil || !e.allStopped() {
		return target.ErrInvalidState
	}
	pending := t.syscall
	bp := pending.bp
	if pending.phase != syscallEntry || pending.space != t.process.space.ref || bp == nil || t.suspended != bp || bp.space.stepping != t || bp.generation != pending.generation {
		return target.ErrStale
	}
	if err := e.arm(bp); err != nil {
		return err
	}
	t.suspended = nil
	bp.space.stepping = nil
	pending.phase = syscallParked
	return nil
}

func (e *engine) forgetBreakpointSyscall(t *thread) {
	if t == nil || t.syscall == nil {
		return
	}
	if t.syscall.phase >= syscallEntry {
		t.needsUserBoundary = true
	}
	t.syscall = nil
}
