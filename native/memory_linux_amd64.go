package native

import (
	"fmt"
	"io"

	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func (s *Session) ReadMemory(address target.Address, dst []byte) (int, error) {
	return call(s, func(e *engine) (int, error) {
		if err := e.requireStopped(); err != nil {
			return 0, err
		}
		if err := validateMemoryRange(e.profile, address, len(dst)); err != nil {
			return 0, err
		}
		if len(dst) == 0 {
			return 0, nil
		}
		n, err := unix.PtracePeekData(e.s.pid, uintptr(address), dst)
		return n, memoryTransferError("read memory", address, n, len(dst), err, io.ErrUnexpectedEOF)
	})
}

func (s *Session) WriteMemory(address target.Address, src []byte) (int, error) {
	return call(s, func(e *engine) (int, error) {
		if err := e.requireStopped(); err != nil {
			return 0, err
		}
		if err := e.checkMemoryWrite(address, len(src)); err != nil {
			return 0, err
		}
		if len(src) == 0 {
			return 0, nil
		}
		n, err := unix.PtracePokeData(e.s.pid, uintptr(address), src)
		return n, memoryTransferError("write memory", address, n, len(src), err, io.ErrShortWrite)
	})
}

func validateMemoryRange(profile *arch.Descriptor, address target.Address, size int) error {
	if profile == nil {
		return fmt.Errorf("memory profile is missing: %w", target.ErrUnknown)
	}
	return profile.ValidateRange(address, size)
}

func (e *engine) checkMemoryWrite(address target.Address, size int) error {
	if err := validateMemoryRange(e.profile, address, size); err != nil {
		return err
	}
	for location, bp := range e.breakpoints {
		if (bp.armed || e.suspended == bp) && location >= address && uint64(location-address) < uint64(size) {
			return fmt.Errorf("write at %#x of size %d overlaps an active breakpoint: %w", address, size, target.ErrInvalidState)
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

func (e *engine) readByte(pid int, address target.Address) (byte, error) {
	if err := validateMemoryRange(e.profile, address, 1); err != nil {
		return 0, err
	}
	var data [1]byte
	n, err := unix.PtracePeekData(pid, uintptr(address), data[:])
	if err := memoryTransferError("read byte", address, n, len(data), err, io.ErrUnexpectedEOF); err != nil {
		return 0, err
	}
	return data[0], nil
}

func (e *engine) writeByte(pid int, address target.Address, value byte) error {
	if err := validateMemoryRange(e.profile, address, 1); err != nil {
		return err
	}
	data := [1]byte{value}
	n, err := unix.PtracePokeData(pid, uintptr(address), data[:])
	return memoryTransferError("write byte", address, n, len(data), err, io.ErrShortWrite)
}
