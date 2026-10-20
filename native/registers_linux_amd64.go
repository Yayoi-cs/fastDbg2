package native

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"
	"unsafe"

	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const generalRegisterBufferSize = 224

func (s *Session) ReadRegisters() ([]target.Register, error) {
	return call(s, func(e *engine) ([]target.Register, error) {
		if err := e.requireStopped(); err != nil {
			return nil, err
		}
		data, err := e.readRegisterSet(e.s.pid)
		if err != nil {
			return nil, err
		}
		return encodeRegisters(e.profile, data)
	})
}

func (s *Session) WriteRegisters(registers []target.Register) error {
	return command(s, func(e *engine) error {
		if err := e.requireStopped(); err != nil {
			return err
		}
		if err := e.checkRegisterWrites(registers); err != nil {
			return err
		}
		if len(registers) == 0 {
			return nil
		}
		data, err := e.readRegisterSet(e.s.pid)
		if err != nil {
			return err
		}
		writePC := false
		for _, register := range registers {
			field, _ := e.profile.Register(register.Name)
			copy(data[field.Offset:field.Offset+field.Bits/8], register.Data)
			writePC = writePC || register.Name == e.profile.PCName
		}
		if err := e.writeRegisterSet(e.s.pid, data, len(registers)); err != nil {
			return err
		}
		if writePC {
			e.hit = nil
		}
		return nil
	})
}

func (e *engine) readRegisterSet(pid int) ([]byte, error) {
	if e.profile == nil {
		return nil, fmt.Errorf("register profile is missing: %w", target.ErrUnknown)
	}
	data := make([]byte, generalRegisterBufferSize)
	n, err := ptraceRegisterSet(unix.PTRACE_GETREGSET, pid, data)
	if err != nil {
		return nil, fmt.Errorf("read register set: %w", err)
	}
	data = data[:n]
	if err := validateRegisterSet(e.profile, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (e *engine) writeRegisterSet(pid int, data []byte, count int) error {
	if err := validateRegisterSet(e.profile, data); err != nil {
		return err
	}
	n, err := ptraceRegisterSet(unix.PTRACE_SETREGSET, pid, data)
	if err == nil && n != len(data) {
		err = fmt.Errorf("written register set size %d, expected %d: %w", n, len(data), target.ErrUnknown)
	}
	if err == nil {
		_, err = e.readRegisterSet(pid)
	}
	if err != nil {
		partial := &target.PartialError{
			Op:        "write registers",
			Completed: 0,
			Total:     count,
			Err:       fmt.Errorf("register state could not be confirmed after write: %w", err),
		}
		e.hit = nil
		e.unsupported = partial
		return partial
	}
	return nil
}

func ptraceRegisterSet(request, pid int, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, target.ErrInvalidArgument
	}
	iov := unix.Iovec{Base: &data[0]}
	iov.SetLen(len(data))
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(request), uintptr(pid), uintptr(elf.NT_PRSTATUS), uintptr(unsafe.Pointer(&iov)), 0, 0)
	runtime.KeepAlive(data)
	if errno != 0 {
		return 0, errno
	}
	if iov.Len > uint64(len(data)) {
		return 0, fmt.Errorf("register set returned length %d beyond buffer %d: %w", iov.Len, len(data), target.ErrUnknown)
	}
	return int(iov.Len), nil
}

func validateRegisterSet(profile *arch.Descriptor, data []byte) error {
	if profile == nil {
		return fmt.Errorf("register profile is missing: %w", target.ErrUnknown)
	}
	if len(data) != profile.RegisterSetSize {
		return fmt.Errorf("%s register set size %d, expected %d: %w", profile.Architecture, len(data), profile.RegisterSetSize, target.ErrUnsupported)
	}
	if profile.ValidateRegisters != nil {
		return profile.ValidateRegisters(data)
	}
	return nil
}

func encodeRegisters(profile *arch.Descriptor, data []byte) ([]target.Register, error) {
	if err := validateRegisterSet(profile, data); err != nil {
		return nil, err
	}
	result := make([]target.Register, len(profile.Registers))
	for i, register := range profile.Registers {
		result[i] = target.Register{
			Name:      register.Name,
			Bits:      register.Bits,
			Data:      slices.Clone(data[register.Offset : register.Offset+register.Bits/8]),
			Available: true,
		}
	}
	return result, nil
}

func validateRegisterWrites(profile *arch.Descriptor, registers []target.Register) error {
	if profile == nil {
		return fmt.Errorf("register profile is missing: %w", target.ErrUnknown)
	}
	seen := make(map[string]struct{}, len(registers))
	for _, register := range registers {
		field, exists := profile.Register(register.Name)
		if !exists {
			return fmt.Errorf("unknown register %q: %w", register.Name, target.ErrInvalidArgument)
		}
		if _, exists := seen[register.Name]; exists {
			return fmt.Errorf("duplicate register %q: %w", register.Name, target.ErrInvalidArgument)
		}
		seen[register.Name] = struct{}{}
		if register.Bits != field.Bits || len(register.Data) != field.Bits/8 || !register.Available {
			return fmt.Errorf("register %q requires an available %d-bit little-endian value: %w", register.Name, field.Bits, target.ErrInvalidArgument)
		}
	}
	return nil
}

func (e *engine) checkRegisterWrites(registers []target.Register) error {
	if err := validateRegisterWrites(e.profile, registers); err != nil {
		return err
	}
	if e.suspended != nil {
		for _, register := range registers {
			if register.Name == e.profile.PCName {
				return fmt.Errorf("remove the suspended breakpoint before writing %s: %w", e.profile.PCName, target.ErrInvalidState)
			}
		}
	}
	return nil
}

func (e *engine) readPC(pid int) (target.Address, error) {
	data, err := e.readRegisterSet(pid)
	if err != nil {
		return 0, err
	}
	field, ok := e.profile.Register(e.profile.PCName)
	if !ok {
		return 0, fmt.Errorf("PC register is missing: %w", target.ErrUnknown)
	}
	switch field.Bits {
	case 32:
		return target.Address(binary.LittleEndian.Uint32(data[field.Offset : field.Offset+4])), nil
	case 64:
		return target.Address(binary.LittleEndian.Uint64(data[field.Offset : field.Offset+8])), nil
	default:
		return 0, fmt.Errorf("PC register width %d: %w", field.Bits, target.ErrUnsupported)
	}
}

func (e *engine) writePC(pid int, pc target.Address) error {
	if e.profile == nil {
		return fmt.Errorf("register profile is missing: %w", target.ErrUnknown)
	}
	if err := e.profile.ValidateRange(pc, 0); err != nil {
		return err
	}
	data, err := e.readRegisterSet(pid)
	if err != nil {
		return err
	}
	field, ok := e.profile.Register(e.profile.PCName)
	if !ok {
		return fmt.Errorf("PC register is missing: %w", target.ErrUnknown)
	}
	switch field.Bits {
	case 32:
		binary.LittleEndian.PutUint32(data[field.Offset:field.Offset+4], uint32(pc))
	case 64:
		binary.LittleEndian.PutUint64(data[field.Offset:field.Offset+8], uint64(pc))
	default:
		return fmt.Errorf("PC register width %d: %w", field.Bits, target.ErrUnsupported)
	}
	return e.writeRegisterSet(pid, data, 1)
}
