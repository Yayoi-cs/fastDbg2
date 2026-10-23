package native

import (
	"encoding/binary"
	"errors"
	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

const (
	debugRegisterOffset = 848
	debugStatusReserved = uint64(0xffff0ff0)
	debugStep           = uint64(0x4000)
)

type debugImage struct {
	address [4]uint64
	status  uint64
	control uint64
}

type physicalWatchpoint struct {
	ref     target.WatchpointRef
	request target.WatchpointRequest
	execute bool
}

type debugTransaction struct {
	before debugImage
	after  debugImage
	dirty  uint8
}

type watchpointState struct {
	space          target.SpaceRef
	baseline       debugImage
	current        debugImage
	slots          [4]*physicalWatchpoint
	nextGeneration uint64
	pending        *debugTransaction
	fault          error
	uncaptured     bool
}

type debugAccess struct {
	read  func() (debugImage, error)
	write func(int, uint64) error
}

func debugOffset(register int) (uintptr, error) {
	if register < 0 || register > 7 || register == 4 || register == 5 {
		return 0, target.ErrInvalidArgument
	}
	return uintptr(debugRegisterOffset + 8*register), nil
}

func readDebugRegister(tid, register int) (uint64, error) {
	offset, err := debugOffset(register)
	if err != nil {
		return 0, err
	}
	var raw [8]byte
	n, err := unix.PtracePeekUser(tid, offset, raw[:])
	if err == nil && n != len(raw) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, fmt.Errorf("read TID %d DR%d: %w", tid, register, err)
	}
	return binary.LittleEndian.Uint64(raw[:]), nil
}

func (e *engine) debugAccess(t *thread) debugAccess {
	return debugAccess{
		read: func() (debugImage, error) { return readDebugImage(t) },
		write: func(register int, value uint64) error {
			offset, err := debugOffset(register)
			if err != nil {
				return err
			}
			if t == nil || t.state != target.StateStopped || t.listening {
				return target.ErrRunning
			}
			_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_POKEUSR, uintptr(t.tid), offset, uintptr(value), 0, 0)
			e.registersChanged(t)
			if errno != 0 {
				return fmt.Errorf("write TID %d DR%d: %w", t.tid, register, errno)
			}
			return nil
		},
	}
}

func readDebugImage(t *thread) (debugImage, error) {
	var image debugImage
	if t == nil || t.state != target.StateStopped || t.listening {
		return image, target.ErrRunning
	}
	var err error
	for slot := range image.address {
		image.address[slot], err = readDebugRegister(t.tid, slot)
		if err != nil {
			return image, err
		}
	}
	image.status, err = readDebugRegister(t.tid, 6)
	if err == nil {
		image.control, err = readDebugRegister(t.tid, 7)
	}
	return image, err
}

func enabledDebugSlots(control uint64) uint8 {
	var result uint8
	for slot := 0; slot < 4; slot++ {
		if control&(3<<(2*slot)) != 0 {
			result |= 1 << slot
		}
	}
	return result
}

func (state *watchpointState) ownedSlots() uint8 {
	var mask uint8
	for slot, watch := range state.slots {
		if watch != nil {
			mask |= 1 << slot
		}
	}
	return mask
}

func (state *watchpointState) checkImage(image debugImage) error {
	if state.pending != nil || state.fault != nil {
		return errors.Join(target.ErrUnavailable, state.fault)
	}
	if image.address != state.current.address || image.control != state.current.control {
		return fmt.Errorf("debug register configuration changed: %w", target.ErrStale)
	}
	return nil
}

func watchpointEncoding(profile *arch.Descriptor, request target.WatchpointRequest) (uint64, error) {
	if request.Slot < 0 || request.Slot >= 4 {
		return 0, target.ErrInvalidArgument
	}
	var length uint64
	switch request.Size {
	case 1:
	case 2:
		length = 4
	case 4:
		length = 12
	case 8:
		length = 8
	default:
		return 0, fmt.Errorf("hardware watchpoint size %d: %w", request.Size, target.ErrUnsupported)
	}
	if profile == nil || (profile.Architecture != target.AMD64 && profile.Architecture != target.X86) {
		return 0, target.ErrUnsupported
	}
	if err := profile.ValidateRange(request.Address, request.Size); err != nil {
		return 0, err
	}
	if uint64(request.Address)%uint64(request.Size) != 0 {
		return 0, fmt.Errorf("hardware watchpoint address must be aligned to its size: %w", target.ErrInvalidArgument)
	}
	switch request.Access {
	case target.WatchWrite:
		return length | 1, nil
	case target.WatchReadWrite:
		return length | 3, nil
	default:
		return 0, fmt.Errorf("hardware watchpoint access %d: %w", request.Access, target.ErrUnsupported)
	}
}

func hardwareBreakpointEncoding(profile *arch.Descriptor, request target.HardwareBreakpointRequest) (uint64, error) {
	if request.Slot < 0 || request.Slot >= 4 {
		return 0, target.ErrInvalidArgument
	}
	if profile == nil || (profile.Architecture != target.AMD64 && profile.Architecture != target.X86) {
		return 0, target.ErrUnsupported
	}
	if err := profile.ValidateRange(request.Address, 1); err != nil {
		return 0, err
	}
	return 0, nil
}

func watchpointImage(state *watchpointState, before debugImage, request target.WatchpointRequest, encoding uint64) (debugImage, error) {
	if enabledDebugSlots(before.control)&^state.ownedSlots() != 0 {
		return debugImage{}, fmt.Errorf("hardware debug register bank has foreign enabled slots: %w", target.ErrBusy)
	}
	shift := 16 + 4*request.Slot
	baseline := (state.baseline.control >> shift) & 15
	if baseline&3 == 2 || baseline&3 == 0 && baseline&12 != 0 {
		return debugImage{}, fmt.Errorf("original disabled slot configuration cannot be restored: %w", target.ErrUnsupported)
	}
	after := before
	after.address[request.Slot] = uint64(request.Address)
	after.control &^= 3<<(2*request.Slot) | 15<<shift
	after.control |= 1<<(2*request.Slot) | encoding<<shift
	after.status &^= 1 << request.Slot
	return after, nil
}

func writeDebugImage(access debugAccess, image debugImage, dirty uint8) error {
	if err := access.write(7, 0); err != nil {
		return err
	}
	for slot := range image.address {
		if dirty&(1<<slot) != 0 {
			if err := access.write(slot, image.address[slot]); err != nil {
				return err
			}
		}
	}
	if err := access.write(6, image.status); err != nil {
		return err
	}
	if err := access.write(7, image.control); err != nil {
		return err
	}
	actual, err := access.read()
	if err != nil {
		return err
	}
	if actual != image {
		return fmt.Errorf("debug register write could not be confirmed: %w", target.ErrStale)
	}
	return nil
}

func changeDebugImage(state *watchpointState, access debugAccess, before, after debugImage, dirty uint8) error {
	state.pending = &debugTransaction{before: before, after: after, dirty: dirty}
	if err := writeDebugImage(access, after, dirty); err != nil {
		actual, observedErr := access.read()
		if observedErr == nil && !state.pending.matches(actual) {
			observedErr = fmt.Errorf("partial debug register state changed: %w", target.ErrStale)
		}
		if observedErr != nil {
			state.fault = &target.PartialError{Op: "write debug registers", Total: 1, Err: errors.Join(err, observedErr)}
			return state.fault
		}
		if rollback := writeDebugImage(access, before, dirty); rollback != nil {
			state.fault = &target.PartialError{Op: "write debug registers", Completed: 0, Total: 1, Err: errors.Join(err, rollback)}
			return state.fault
		}
		state.current, state.pending = before, nil
		return err
	}
	state.current, state.pending = after, nil
	return nil
}

func (e *engine) initializeWatchpoints(t *thread) error {
	if t.watchpoints != nil {
		if t.watchpoints.uncaptured {
			return t.watchpoints.fault
		}
		return nil
	}
	if t.process == nil || t.process.space == nil {
		return target.ErrUnavailable
	}
	state := &watchpointState{space: t.process.space.ref, uncaptured: true}
	t.watchpoints = state
	image, err := readDebugImage(t)
	if err != nil {
		state.fault = err
		return err
	}
	state.baseline, state.current, state.uncaptured = image, image, false
	return nil
}

func (e *engine) setWatchpoint(token target.ThreadToken, request target.WatchpointRequest) (target.WatchpointResult, error) {
	return e.setPhysicalBreakpoint(token, request, false)
}

func (e *engine) setHardwareBreakpoint(token target.ThreadToken, request target.HardwareBreakpointRequest) (target.HardwareBreakpointResult, error) {
	result, err := e.setPhysicalBreakpoint(token, target.WatchpointRequest{Slot: request.Slot, Address: request.Address, Size: 1}, true)
	if err != nil {
		return target.HardwareBreakpointResult{}, err
	}
	return target.HardwareBreakpointResult{Ref: target.HardwareBreakpointRef(result.Ref), Token: result.Token}, nil
}

func (e *engine) setPhysicalBreakpoint(token target.ThreadToken, request target.WatchpointRequest, execute bool) (target.WatchpointResult, error) {
	var result target.WatchpointResult
	if err := e.requireAllStopped(); err != nil {
		return result, err
	}
	t, err := e.requireThread(token)
	if err != nil {
		return result, err
	}
	var encoding uint64
	if execute {
		encoding, err = hardwareBreakpointEncoding(t.process.profile, target.HardwareBreakpointRequest{Slot: request.Slot, Address: request.Address})
	} else {
		encoding, err = watchpointEncoding(t.process.profile, request)
	}
	if err != nil {
		return result, err
	}
	if err := e.initializeWatchpoints(t); err != nil {
		return result, err
	}
	state := t.watchpoints
	if state.space != t.process.space.ref {
		return result, target.ErrStale
	}
	if point := state.slots[request.Slot]; point != nil && point.execute != execute {
		return result, fmt.Errorf("hardware slot %d has a different breakpoint kind: %w", request.Slot, target.ErrBusy)
	}
	before, err := readDebugImage(t)
	if err != nil {
		return result, err
	}
	if err := state.checkImage(before); err != nil {
		return result, err
	}
	if state.ownedSlots() == 0 {
		state.baseline = before
	}
	after, err := watchpointImage(state, before, request, encoding)
	if err != nil {
		return result, err
	}
	if state.nextGeneration == ^uint64(0) {
		return result, target.ErrOverflow
	}
	state.nextGeneration++
	if err := changeDebugImage(state, e.debugAccess(t), before, after, 1<<request.Slot); err != nil {
		return result, err
	}
	ref := target.WatchpointRef{Thread: t.ref, Slot: request.Slot, Generation: state.nextGeneration}
	state.slots[request.Slot] = &physicalWatchpoint{ref: ref, request: request, execute: execute}
	return target.WatchpointResult{Ref: ref, Token: t.token()}, nil
}

func (e *engine) clearWatchpoint(token target.ThreadToken, ref target.WatchpointRef) (target.ThreadToken, error) {
	return e.clearPhysicalBreakpoint(token, ref, false)
}

func (e *engine) clearHardwareBreakpoint(token target.ThreadToken, ref target.HardwareBreakpointRef) (target.ThreadToken, error) {
	return e.clearPhysicalBreakpoint(token, target.WatchpointRef(ref), true)
}

func (e *engine) clearPhysicalBreakpoint(token target.ThreadToken, ref target.WatchpointRef, execute bool) (target.ThreadToken, error) {
	if ref.Thread != token.Thread || ref.Slot < 0 || ref.Slot >= 4 || ref.Generation == 0 {
		return target.ThreadToken{}, target.ErrInvalidArgument
	}
	if err := e.requireAllStopped(); err != nil {
		return target.ThreadToken{}, err
	}
	t, err := e.requireThread(token)
	if err != nil {
		return target.ThreadToken{}, err
	}
	state := t.watchpoints
	if state == nil || state.space != t.process.space.ref || state.slots[ref.Slot] == nil || state.slots[ref.Slot].ref != ref || state.slots[ref.Slot].execute != execute {
		return target.ThreadToken{}, target.ErrStale
	}
	before, err := readDebugImage(t)
	if err != nil {
		return target.ThreadToken{}, err
	}
	if err := state.checkImage(before); err != nil {
		return target.ThreadToken{}, err
	}
	after := before
	mask := uint64(3<<(2*ref.Slot) | 15<<(16+4*ref.Slot))
	after.control = (after.control &^ mask) | (state.baseline.control & mask)
	after.address[ref.Slot] = state.baseline.address[ref.Slot]
	after.status = (after.status &^ (1 << ref.Slot)) | (state.baseline.status & (1 << ref.Slot))
	if state.ownedSlots() == 1<<ref.Slot {
		after = state.baseline
	}
	if err := changeDebugImage(state, e.debugAccess(t), before, after, 1<<ref.Slot); err != nil {
		return target.ThreadToken{}, err
	}
	state.slots[ref.Slot] = nil
	return t.token(), nil
}

func (e *engine) watchpointStop(t *thread, code int32) ([]target.WatchpointHit, []target.HardwareBreakpointHit, bool, *uint64, error) {
	if code != 2 && code != 4 {
		return nil, nil, false, nil, target.ErrInvalidArgument
	}
	image, err := readDebugImage(t)
	if err != nil {
		return nil, nil, false, nil, err
	}
	state := t.watchpoints
	if state != nil && (t.process == nil || t.process.space == nil || state.space != t.process.space.ref) {
		return nil, nil, false, &image.status, target.ErrStale
	}
	if state != nil && state.ownedSlots() != 0 {
		if err := validateWatchpointCause(code, image.status); err != nil {
			return nil, nil, image.status&debugStep != 0, &image.status, err
		}
	}
	hits, execution, step, _, err := decodeWatchpointStop(state, image)
	return hits, execution, step, &image.status, err
}

func validateWatchpointCause(code int32, status uint64) error {
	if code == 2 && status&debugStep == 0 || code == 4 && status&debugStep != 0 {
		return fmt.Errorf("hardware trap code %d disagrees with DR6 %#x: %w", code, status, target.ErrUnknown)
	}
	return nil
}

func decodeWatchpointStop(state *watchpointState, image debugImage) ([]target.WatchpointHit, []target.HardwareBreakpointHit, bool, uint64, error) {
	step := image.status&debugStep != 0
	if state == nil || state.ownedSlots() == 0 {
		return nil, nil, step, image.status, nil
	}
	if err := state.checkImage(image); err != nil {
		return nil, nil, step, image.status, err
	}
	bits := uint8(image.status & 15)
	if bits&^state.ownedSlots() != 0 {
		return nil, nil, step, image.status, fmt.Errorf("hardware trap includes unowned slots: %w", target.ErrUnsupported)
	}
	var hits []target.WatchpointHit
	var execution []target.HardwareBreakpointHit
	for slot, watch := range state.slots {
		if bits&(1<<slot) != 0 {
			if watch == nil || enabledDebugSlots(image.control)&(1<<slot) == 0 {
				return nil, nil, step, image.status, target.ErrStale
			}
			if watch.execute {
				if step {
					return nil, nil, step, image.status, fmt.Errorf("hardware execution breakpoint and single-step causes conflict: %w", target.ErrUnknown)
				}
				execution = append(execution, target.HardwareBreakpointHit{Ref: target.HardwareBreakpointRef(watch.ref), Address: watch.request.Address})
			} else {
				hits = append(hits, target.WatchpointHit{Ref: watch.ref, Address: watch.request.Address, Size: watch.request.Size, Access: watch.request.Access})
			}
		}
	}
	state.current.status = image.status
	return hits, execution, step, image.status, nil
}

func (e *engine) prepareWatchpointResume(t *thread) error {
	state := t.watchpoints
	if state == nil {
		return nil
	}
	if state.fault != nil || state.pending != nil {
		return errors.Join(target.ErrUnavailable, state.fault)
	}
	if state.ownedSlots() == 0 {
		return nil
	}
	if t.process == nil || t.process.space == nil || state.space != t.process.space.ref {
		return target.ErrStale
	}
	before, err := readDebugImage(t)
	if err != nil {
		return err
	}
	if err := state.checkImage(before); err != nil {
		return err
	}
	after := before
	after.status &^= uint64(state.ownedSlots())
	if after.status == before.status {
		state.current.status = before.status
		return nil
	}
	return changeDebugImage(state, e.debugAccess(t), before, after, 0)
}

func (e *engine) resetNewbornWatchpoints(t *thread) error {
	if t == nil || t.process == nil || t.process.space == nil {
		return target.ErrUnavailable
	}
	next := uint64(0)
	if t.watchpoints != nil {
		next = t.watchpoints.nextGeneration
	}
	after := debugImage{status: debugStatusReserved}
	state := &watchpointState{space: t.process.space.ref, baseline: after, current: after, nextGeneration: next}
	t.watchpoints = state
	before, err := readDebugImage(t)
	if err != nil {
		state.fault = err
		return err
	}
	state.current = before
	if before.address != [4]uint64{} {
		state.fault = fmt.Errorf("new image has unexpected hardware breakpoint addresses: %w", target.ErrUnsupported)
		return state.fault
	}
	if before == after {
		return nil
	}
	state.pending = &debugTransaction{before: before, after: after}
	if err := writeDebugImage(e.debugAccess(t), after, 0); err != nil {
		state.fault = &target.PartialError{Op: "initialize thread debug registers", Total: 1, Err: err}
		return state.fault
	}
	state.current, state.pending = after, nil
	return nil
}

func (e *engine) resetExecWatchpoints(t *thread) error {
	return e.resetNewbornWatchpoints(t)
}

func (tx *debugTransaction) matches(image debugImage) bool {
	for slot, address := range image.address {
		if tx.dirty&(1<<slot) == 0 {
			if address != tx.before.address[slot] {
				return false
			}
		} else if address != tx.before.address[slot] && address != tx.after.address[slot] {
			return false
		}
	}
	return (image.control == 0 || image.control == tx.before.control || image.control == tx.after.control) &&
		(image.status == tx.before.status || image.status == tx.after.status)
}

func (e *engine) restoreThreadWatchpoints(t *thread) error {
	state := t.watchpoints
	if state == nil || state.ownedSlots() == 0 && state.pending == nil && state.fault == nil {
		return nil
	}
	if t.process == nil || t.process.space == nil || state.space != t.process.space.ref {
		return target.ErrStale
	}
	return restoreWatchpointState(state, e.debugAccess(t))
}

func restoreWatchpointState(state *watchpointState, access debugAccess) error {
	actual, err := access.read()
	if err != nil {
		return err
	}
	if state.uncaptured {
		state.baseline, state.current = actual, actual
		state.uncaptured, state.fault = false, nil
		return nil
	}
	if state.ownedSlots() == 0 && state.pending == nil && state.fault != nil {
		if actual != state.baseline {
			return state.fault
		}
		state.current, state.fault = actual, nil
		return nil
	}
	dirty := state.ownedSlots()
	if state.pending != nil {
		if !state.pending.matches(actual) {
			return fmt.Errorf("partial debug register state changed: %w", target.ErrStale)
		}
		dirty |= state.pending.dirty
	} else if err := state.checkImage(actual); err != nil {
		return err
	}
	state.pending = &debugTransaction{before: actual, after: state.baseline, dirty: dirty}
	if err := writeDebugImage(access, state.baseline, dirty); err != nil {
		state.fault = &target.PartialError{Op: "restore debug registers", Total: 1, Err: err}
		return state.fault
	}
	state.current, state.pending, state.fault = state.baseline, nil, nil
	state.slots = [4]*physicalWatchpoint{}
	return nil
}

func (e *engine) restoreWatchpoints() error {
	if !e.allStopped() {
		return target.ErrRunning
	}
	for _, t := range e.sortedThreads() {
		if !t.live() || t.exitComplete {
			continue
		}
		if err := e.restoreThreadWatchpoints(t); err != nil {
			return &taskError{t.tid, err}
		}
	}
	return nil
}
