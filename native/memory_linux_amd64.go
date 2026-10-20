package native

import (
	"fmt"
	"io"
	"slices"

	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func (s *Session) ReadMemory(address target.Address, dst []byte) (int, error) {
	return call(s, func(e *engine) (int, error) {
		token, err := e.primaryMemory()
		if err != nil {
			return 0, err
		}
		return e.readSpaceMemory(token, address, dst)
	})
}

func (s *Session) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	return call(s, func(e *engine) (int, error) {
		return e.readSpaceMemory(token, address, dst)
	})
}

func (s *Session) WriteMemory(address target.Address, src []byte) (int, error) {
	src = slices.Clone(src)
	return call(s, func(e *engine) (int, error) {
		token, err := e.primaryMemory()
		if err != nil {
			return 0, err
		}
		return e.writeSpaceMemory(token, address, src)
	})
}

func (s *Session) WriteSpaceMemory(token target.MemoryToken, address target.Address, src []byte) (int, error) {
	src = slices.Clone(src)
	return call(s, func(e *engine) (int, error) {
		return e.writeSpaceMemory(token, address, src)
	})
}

func (e *engine) readSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	_, t, err := e.requireMemory(token)
	if err != nil {
		return 0, err
	}
	if err := validateMemoryRange(t.process.profile, address, len(dst)); err != nil {
		return 0, err
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if _, err := e.readRegisterSet(t.tid); err != nil {
		return 0, err
	}
	n, err := unix.PtracePeekData(t.tid, uintptr(address), dst)
	return n, memoryTransferError("read memory", address, n, len(dst), err, io.ErrUnexpectedEOF)
}

func (e *engine) writeSpaceMemory(token target.MemoryToken, address target.Address, src []byte) (int, error) {
	space, t, err := e.requireMemory(token)
	if err != nil {
		return 0, err
	}
	if err := e.checkMemoryWrite(space, t.process.profile, address, len(src)); err != nil {
		return 0, err
	}
	if len(src) == 0 {
		return 0, nil
	}
	if _, err := e.readRegisterSet(t.tid); err != nil {
		return 0, err
	}
	n, err := unix.PtracePokeData(t.tid, uintptr(address), src)
	e.memoryChanged(space)
	return n, memoryTransferError("write memory", address, n, len(src), err, io.ErrShortWrite)
}

func validateMemoryRange(profile *arch.Descriptor, address target.Address, size int) error {
	if profile == nil {
		return fmt.Errorf("memory profile is missing: %w", target.ErrUnknown)
	}
	return profile.ValidateRange(address, size)
}

func (e *engine) checkMemoryWrite(space *addressSpace, profile *arch.Descriptor, address target.Address, size int) error {
	if err := validateMemoryRange(profile, address, size); err != nil {
		return err
	}
	if space == nil {
		return fmt.Errorf("memory address space is missing: %w", target.ErrUnknown)
	}
	for location := range space.breakpoints {
		if location >= address && uint64(location-address) < uint64(size) {
			return fmt.Errorf("write at %#x of size %d overlaps a registered breakpoint: %w", address, size, target.ErrInvalidState)
		}
	}
	return nil
}

func memoryTransferError(op string, address target.Address, completed, total int, err, short error) error {
	if completed < 0 || completed > total {
		return fmt.Errorf("%s at %#x returned invalid count %d/%d: %w", op, address, completed, total, target.ErrUnknown)
	}
	if err == nil && completed != total {
		err = short
	}
	if err == nil {
		return nil
	}
	err = fmt.Errorf("%s at %#x: %w", op, address, err)
	if completed > 0 && completed < total {
		return &target.PartialError{Op: op, Completed: completed, Total: total, Err: err}
	}
	return err
}

func (e *engine) readByte(tid int, address target.Address) (byte, error) {
	t, err := e.dataThread(tid)
	if err != nil {
		return 0, err
	}
	if err := validateMemoryRange(t.process.profile, address, 1); err != nil {
		return 0, err
	}
	var data [1]byte
	n, err := unix.PtracePeekData(tid, uintptr(address), data[:])
	if err := memoryTransferError("read byte", address, n, len(data), err, io.ErrUnexpectedEOF); err != nil {
		return 0, err
	}
	return data[0], nil
}

func (e *engine) writeByte(tid int, address target.Address, value byte) error {
	t, err := e.dataThread(tid)
	if err != nil {
		return err
	}
	if err := validateMemoryRange(t.process.profile, address, 1); err != nil {
		return err
	}
	if t.process.space == nil {
		return fmt.Errorf("memory address space is missing: %w", target.ErrUnknown)
	}
	data := [1]byte{value}
	n, err := unix.PtracePokeData(tid, uintptr(address), data[:])
	e.memoryChanged(t.process.space)
	return memoryTransferError("write byte", address, n, len(data), err, io.ErrShortWrite)
}
