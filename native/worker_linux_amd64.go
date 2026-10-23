package native

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

type signalInfo struct {
	Signo int32
	Errno int32
	Code  int32
	Pad   int32
	Data  [112]byte
}

func (s *Session) worker(start func(*engine) error, ready chan response[*Session]) {
	runtime.LockOSThread()
	e := &engine{s: s, threads: make(map[int]*thread), processes: make(map[int]*process)}
	e.life = lifecycleState{
		ready: ready, initializing: true, tracer: unix.Gettid(), signals: make(chan os.Signal, 1),
		births: make(map[int]*birth), lost: make(map[int]error),
	}
	signal.Notify(e.life.signals, unix.SIGCHLD)
	defer close(s.done)
	defer signal.Stop(e.life.signals)
	defer e.release()
	if err := start(e); err != nil {
		if len(e.threads) == 0 {
			ready <- response[*Session]{err: err}
			return
		}
		e.failInitialization(err)
	}
	for !e.life.finished {
		e.drainWaits()
		e.advanceExits()
		if e.life.initializing {
			e.advanceInitialization()
		}
		if e.life.shutdownKind != "" {
			e.advanceShutdown()
		}
		if e.life.finished {
			break
		}
		select {
		case req := <-s.requests:
			req(e)
		case <-e.life.signals:
		case <-e.exitTicks():
		}
	}
}

func (e *engine) canRetryLaunchInterrupt(t *thread, w waitResult) bool {
	return e.life.launch != nil && e.life.initializing && e.life.launchReleased && !e.life.launchExec &&
		e.life.shutdownKind == "" && e.barrier == nil && e.run == nil && e.unsupported == nil && e.ownershipError() == nil &&
		t != nil && t.process != nil && t.process == e.primary && t.process.owned && t.tid == t.process.tgid &&
		t.seized && !t.exiting && !t.listening && t.state == target.StateStopped &&
		t.interruptDeferred && t.interruptResumed && !t.interruptRequested &&
		w.err == nil && w.pid == t.tid && w.status.Stopped() && w.status.StopSignal() == unix.SIGTRAP &&
		uint32(w.status)>>16 == unix.PTRACE_EVENT_STOP
}

func (e *engine) retryLaunchInterrupt(t *thread, w waitResult) bool {
	if !e.canRetryLaunchInterrupt(t, w) {
		return false
	}
	t.interruptDeferred, t.interruptResumed = false, false
	if err := unix.PtraceCont(t.tid, 0); err != nil {
		e.failInitialization(err)
		return true
	}
	t.state = target.StateRunning
	return true
}

func profileForELF(f *os.File) (*arch.Descriptor, error) {
	b, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("ELF: %w", err)
	}
	if b.Data == elf.ELFDATA2LSB {
		for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
			if b.Class == profile.ELFClass && b.Machine == profile.ELFMachine {
				return &profile, nil
			}
		}
	}
	return nil, fmt.Errorf("native requires little-endian ELF64 x86-64 or ELF32 i386: %w", target.ErrUnsupported)
}

func readSignalInfo(tid int) (*signalInfo, error) {
	var info signalInfo
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GETSIGINFO, uintptr(tid), 0, uintptr(unsafe.Pointer(&info)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return &info, nil
}

func (e *engine) capturePC(stop target.Stop) (target.Stop, error) {
	if stop.ThreadID == nil {
		return stop, target.ErrUnknown
	}
	pc, err := e.readPC(int(*stop.ThreadID))
	if err != nil {
		return stop, err
	}
	stop.RawPC = &pc
	return stop, nil
}

func stoppedSignal(signal unix.Signal) bool {
	return signal == unix.SIGSTOP || signal == unix.SIGTSTP || signal == unix.SIGTTIN || signal == unix.SIGTTOU
}

func rawStop(w waitResult) target.Stop {
	id := uint64(w.pid)
	return target.Stop{
		ThreadID: &id,
		Signal:   target.Signal{Domain: target.SignalLinux, Number: uint32(w.status.StopSignal())},
		Raw:      fmt.Sprintf("wait_status=0x%x", uint32(w.status)),
	}
}

func (e *engine) classifySignal(t *thread, w waitResult, stepping bool) (target.Stop, *signalInfo, error) {
	stop := rawStop(w)
	sig := w.status.StopSignal()
	cause := int(uint32(w.status) >> 16)
	t.pendingSignal = 0
	t.groupStopped = false
	if cause == unix.PTRACE_EVENT_STOP {
		if stoppedSignal(sig) {
			t.groupStopped = true
			stop.Reason = target.StopGroupStop
			return stop, nil, nil
		}
		if sig == unix.SIGTRAP {
			stop.Reason = target.StopInterrupt
			return stop, nil, nil
		}
		return stop, nil, fmt.Errorf("unexpected event-stop signal %d: %w", sig, target.ErrUnknown)
	}
	if cause != 0 {
		if sig != unix.SIGTRAP {
			return stop, nil, fmt.Errorf("unexpected ptrace event signal %d: %w", sig, target.ErrUnknown)
		}
		switch cause {
		case unix.PTRACE_EVENT_CLONE:
			stop.Reason = target.StopClone
		case unix.PTRACE_EVENT_FORK:
			stop.Reason = target.StopFork
		case unix.PTRACE_EVENT_VFORK:
			stop.Reason = target.StopVFork
		case unix.PTRACE_EVENT_EXEC:
			stop.Reason = target.StopExec
		default:
			return stop, nil, fmt.Errorf("unsupported ptrace event %d: %w", cause, target.ErrUnsupported)
		}
		return stop, nil, nil
	}
	info, err := readSignalInfo(t.tid)
	if err != nil {
		if errors.Is(err, unix.EINVAL) && stoppedSignal(sig) {
			t.groupStopped = true
			stop.Reason = target.StopGroupStop
			return stop, nil, nil
		}
		return stop, nil, err
	}
	stop.Raw += fmt.Sprintf(" si_code=%d", info.Code)
	if sig == unix.SIGTRAP && info.Code == 2 && stepping {
		stop.Reason = target.StopStep
		stop.StepCompleted = true
		return stop, info, nil
	}
	stop.Reason = target.StopSignal
	t.pendingSignal = int(sig)
	return stop, info, nil
}

func (e *engine) classify(t *thread, w waitResult, stepping bool) (target.Stop, error) {
	if stop, handled, err := e.classifyBreakpointSyscall(t, w); handled || err != nil {
		return stop, err
	}
	stop, info, err := e.classifySignal(t, w, stepping)
	if err != nil || stop.Reason == target.StopExec {
		return stop, err
	}
	if info != nil && w.status.StopSignal() == unix.SIGTRAP && (info.Code == 2 || info.Code == 4) {
		stop.StepCompleted = false
		hits, execution, stepBit, dr6, err := e.watchpointStop(t, info.Code)
		stop.RawDR6 = dr6
		if dr6 != nil {
			stop.Raw += fmt.Sprintf(" dr6=0x%x", *dr6)
		}
		if err != nil || dr6 == nil {
			stop.Reason = target.StopUnknown
			t.pendingSignal = int(unix.SIGTRAP)
			if err == nil {
				err = target.ErrUnknown
			}
			return stop, err
		}
		stop.HardwareBreakpoints = execution
		stop, t.pendingSignal = applyWatchpointStop(stop, info.Code, hits, stepBit, *dr6, stepping)
	}
	stop, err = e.capturePC(stop)
	if err != nil {
		if len(stop.HardwareBreakpoints) != 0 {
			stop.Reason, stop.StepCompleted = target.StopUnknown, false
			t.pendingSignal = int(unix.SIGTRAP)
		}
		return stop, err
	}
	if err := validateHardwareBreakpointPC(stop); err != nil {
		stop.Reason, stop.StepCompleted = target.StopUnknown, false
		t.pendingSignal = int(unix.SIGTRAP)
		return stop, err
	}
	if len(stop.Watchpoints) != 0 || len(stop.HardwareBreakpoints) != 0 {
		t.needsUserBoundary = false
	}
	if info != nil && info.Code == 1 && w.status.StopSignal() == unix.SIGTRAP {
		if expected, ok := e.life.syscallSteps[t]; ok && expected.space == t.process.space.ref && *stop.RawPC == expected.pc && target.Address(binary.LittleEndian.Uint64(info.Data[:8])) == expected.pc {
			matches, err := e.syscallStepNumber(t, expected)
			if err != nil {
				return stop, err
			}
			if !matches {
				return stop, nil
			}
			e.forgetSyscallStep(t)
			t.pendingSignal = 0
			t.internalStepTrap = !stepping
			t.needsUserBoundary = true
			stop.Reason = target.StopStep
			stop.StepCompleted = true
			return stop, nil
		}
	}
	if stop.Reason == target.StopSignal && info != nil && w.status.StopSignal() == unix.SIGTRAP && (info.Code == 1 || info.Code == 128) && *stop.RawPC > 0 {
		addr := *stop.RawPC - 1
		if bp := t.process.space.breakpoints[addr]; bp != nil && bp.armed {
			if err := e.recordBreakpointHit(t, addr, *stop.RawPC); err != nil {
				return stop, err
			}
			stop.Reason, stop.Breakpoint = target.StopBreakpoint, &addr
			t.pendingSignal = 0
			t.needsUserBoundary = false
		}
	}
	return stop, nil
}

type syscallStep struct {
	space  target.SpaceRef
	pc     target.Address
	number uint32
}

func (e *engine) forgetSyscallStep(t *thread) {
	delete(e.life.syscallSteps, t)
	delete(e.life.cloneChildren, t)
	e.forgetBreakpointSyscall(t)
}

func (e *engine) prepareSyscallStep(t *thread, action *resumeAction, step bool) (func(), error) {
	if step && e.life.cloneChildren[t] != nil {
		if _, pending := e.life.syscallSteps[t]; pending {
			return nil, fmt.Errorf("finish the interrupted clone before starting a new instruction step: %w", target.ErrUnsupported)
		}
	}
	clear := func() { e.forgetSyscallStep(t) }
	if action.signal != 0 {
		return clear, nil
	}
	if !step {
		return nil, nil
	}
	pc, err := e.readPC(t.tid)
	if err != nil {
		return nil, err
	}
	first, err := e.readByte(t.tid, pc)
	if err != nil {
		return clear, nil
	}
	profile := t.process.profile
	if profile.Architecture == target.AMD64 && first != 0x0f || profile.Architecture == target.X86 && first != 0xcd {
		return clear, nil
	}
	second, err := e.readByte(t.tid, pc+1)
	if err != nil {
		return clear, nil
	}
	if profile.Architecture == target.AMD64 && second != 0x05 || profile.Architecture == target.X86 && second != 0x80 {
		return clear, nil
	}
	registers, err := e.readRegisterSet(t.tid)
	if err != nil {
		return nil, err
	}
	name := "rax"
	if profile.Architecture == target.X86 {
		name = "eax"
	}
	field, ok := profile.Register(name)
	if !ok {
		return nil, target.ErrUnknown
	}
	var number uint64
	if field.Bits == 32 {
		number = uint64(binary.LittleEndian.Uint32(registers[field.Offset:]))
	} else {
		number = binary.LittleEndian.Uint64(registers[field.Offset:])
	}
	if uint32(number) == ^uint32(0) || profile.Architecture == target.AMD64 && number == 15 || profile.Architecture == target.X86 && (number == 119 || number == 173) {
		return clear, nil
	}
	expected := syscallStep{space: t.process.space.ref, pc: pc + 2, number: uint32(number)}
	return func() {
		if e.life.syscallSteps == nil {
			e.life.syscallSteps = make(map[*thread]syscallStep)
		}
		e.life.syscallSteps[t] = expected
	}, nil
}

func (e *engine) syscallStepNumber(t *thread, expected syscallStep) (bool, error) {
	registers, err := e.readRegisterSet(t.tid)
	if err != nil {
		return false, err
	}
	name := "orig_rax"
	if t.process.profile.Architecture == target.X86 {
		name = "orig_eax"
	}
	field, ok := t.process.profile.Register(name)
	if !ok {
		return false, target.ErrUnknown
	}
	return binary.LittleEndian.Uint32(registers[field.Offset:]) == expected.number, nil
}

func (e *engine) validateCloneStep(t *thread) error {
	if t == nil || t.process == nil || t.process.profile == nil || t.process.space == nil {
		return target.ErrUnavailable
	}
	if t.state != target.StateStopped || t.exiting || t.listening {
		return target.ErrInvalidState
	}
	expected, ok := e.life.syscallSteps[t]
	if !ok || expected.space != t.process.space.ref {
		return fmt.Errorf("clone step has no matching syscall proof: %w", target.ErrUnsupported)
	}
	clone := uint32(56)
	if t.process.profile.Architecture == target.X86 {
		clone = 120
	}
	if expected.number != clone && expected.number != 435 {
		return fmt.Errorf("clone step syscall %d is not supported: %w", expected.number, target.ErrUnsupported)
	}
	child := e.life.cloneChildren[t]
	if child == nil || child.process == nil {
		return target.ErrBusy
	}
	if child.process != t.process || t.process.space.unknown {
		return fmt.Errorf("clone step changed process or address space: %w", target.ErrUnsupported)
	}
	if e.life.births[child.tid] != nil || child.live() && (child.state != target.StateStopped || child.listening) && !(child.exiting && child.exitComplete) {
		return target.ErrBusy
	}
	pc, err := e.readPC(t.tid)
	if err != nil {
		return err
	}
	if pc != expected.pc {
		return fmt.Errorf("clone step return PC changed: %w", target.ErrStale)
	}
	matches, err := e.syscallStepNumber(t, expected)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("clone step syscall identity changed: %w", target.ErrStale)
	}
	return nil
}

func applyWatchpointStop(stop target.Stop, code int32, hits []target.WatchpointHit, stepBit bool, dr6 uint64, stepping bool) (target.Stop, int) {
	stop.StepCompleted = code == 2 && stepping && stepBit
	stop.Watchpoints = hits
	if len(stop.HardwareBreakpoints) != 0 {
		stop.Reason, stop.StepCompleted = target.StopHardwareBreakpoint, false
		return stop, 0
	}
	if len(hits) != 0 {
		stop.Reason = target.StopWatchpoint
		if stepBit && !stepping {
			return stop, int(unix.SIGTRAP)
		}
		return stop, 0
	}
	if code == 2 && stepping && stepBit && dr6&15 == 0 {
		stop.Reason = target.StopStep
		return stop, 0
	}
	stop.Reason = target.StopSignal
	return stop, int(unix.SIGTRAP)
}

func validateHardwareBreakpointPC(stop target.Stop) error {
	for _, hit := range stop.HardwareBreakpoints {
		if stop.RawPC == nil || *stop.RawPC != hit.Address {
			return fmt.Errorf("hardware execution breakpoint slot %d disagrees with the stopped PC: %w", hit.Ref.Slot, target.ErrUnknown)
		}
	}
	return nil
}
