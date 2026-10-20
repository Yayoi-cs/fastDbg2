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
		t, err := e.singleStoppedThread()
		if err != nil {
			return nil, err
		}
		return e.readThreadRegisters(t)
	})
}

func (s *Session) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	return call(s, func(e *engine) ([]target.Register, error) {
		t, err := e.requireThread(token)
		if err != nil {
			return nil, err
		}
		return e.readThreadRegisters(t)
	})
}

func (s *Session) WriteRegisters(registers []target.Register) error {
	registers = cloneRegisters(registers)
	return command(s, func(e *engine) error {
		t, err := e.singleStoppedThread()
		if err != nil {
			return err
		}
		return e.writeThreadRegisters(t, registers)
	})
}

func (s *Session) WriteThreadRegisters(token target.ThreadToken, registers []target.Register) error {
	registers = cloneRegisters(registers)
	return command(s, func(e *engine) error {
		t, err := e.requireThread(token)
		if err != nil {
			return err
		}
		return e.writeThreadRegisters(t, registers)
	})
}

func cloneRegisters(registers []target.Register) []target.Register {
	result := slices.Clone(registers)
	for i := range result {
		result[i].Data = slices.Clone(result[i].Data)
	}
	return result
}

func (e *engine) readThreadRegisters(t *thread) ([]target.Register, error) {
	data, err := e.readRegisterSet(t.tid)
	if err != nil {
		return nil, err
	}
	return encodeRegisters(t.process.profile, data)
}

func (e *engine) writeThreadRegisters(t *thread, registers []target.Register) error {
	if err := e.checkRegisterWrites(t, registers); err != nil {
		return err
	}
	if len(registers) == 0 {
		return nil
	}
	data, err := e.readRegisterSet(t.tid)
	if err != nil {
		return err
	}
	profile := t.process.profile
	writePC := false
	for _, register := range registers {
		field, _ := profile.Register(register.Name)
		copy(data[field.Offset:field.Offset+field.Bits/8], register.Data)
		writePC = writePC || register.Name == profile.PCName
	}
	if err := e.writeRegisterSet(t.tid, data, len(registers)); err != nil {
		return err
	}
	if writePC {
		t.hit = nil
	}
	return nil
}

func (e *engine) dataThread(tid int) (*thread, error) {
	t := e.threads[tid]
	if t == nil {
		return nil, fmt.Errorf("unknown thread %d: %w", tid, target.ErrNotFound)
	}
	switch t.state {
	case target.StateStopped:
	case target.StateRunning:
		return nil, target.ErrRunning
	case target.StateExited:
		return nil, target.ErrExited
	case target.StateDetached:
		return nil, target.ErrDetached
	default:
		return nil, target.ErrInvalidState
	}
	if t.process == nil || t.process.profile == nil {
		return nil, fmt.Errorf("thread %d profile is missing: %w", tid, target.ErrUnknown)
	}
	return t, nil
}

func (e *engine) readRegisterSet(tid int) ([]byte, error) {
	t, err := e.dataThread(tid)
	if err != nil {
		return nil, err
	}
	data := make([]byte, generalRegisterBufferSize)
	n, err := ptraceRegisterSet(unix.PTRACE_GETREGSET, tid, data)
	if err != nil {
		return nil, fmt.Errorf("read thread %d register set: %w", tid, err)
	}
	data = data[:n]
	if err := validateRegisterSet(t.process.profile, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (e *engine) writeRegisterSet(tid int, data []byte, count int) error {
	t, err := e.dataThread(tid)
	if err != nil {
		return err
	}
	if err := validateRegisterSet(t.process.profile, data); err != nil {
		return err
	}
	e.forgetSyscallStep(t)
	n, err := ptraceRegisterSet(unix.PTRACE_SETREGSET, tid, data)
	e.registersChanged(t)
	if err == nil && n != len(data) {
		err = fmt.Errorf("written register set size %d, expected %d: %w", n, len(data), target.ErrUnknown)
	}
	if err == nil {
		_, err = e.readRegisterSet(tid)
	}
	if err != nil {
		partial := &target.PartialError{
			Op:        "write registers",
			Completed: 0,
			Total:     count,
			Err:       fmt.Errorf("thread %d register state could not be confirmed after write: %w", tid, err),
		}
		t.hit = nil
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

func (e *engine) checkRegisterWrites(t *thread, registers []target.Register) error {
	if t == nil || t.process == nil {
		return fmt.Errorf("register profile is missing: %w", target.ErrUnknown)
	}
	profile := t.process.profile
	if err := validateRegisterWrites(profile, registers); err != nil {
		return err
	}
	if t.suspended != nil {
		for _, register := range registers {
			if register.Name == profile.PCName {
				return fmt.Errorf("remove the suspended breakpoint before writing %s: %w", profile.PCName, target.ErrInvalidState)
			}
		}
	}
	return nil
}

func (e *engine) readPC(tid int) (target.Address, error) {
	data, err := e.readRegisterSet(tid)
	if err != nil {
		return 0, err
	}
	profile := e.threads[tid].process.profile
	field, ok := profile.Register(profile.PCName)
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

func (e *engine) writePC(tid int, pc target.Address) error {
	t, err := e.dataThread(tid)
	if err != nil {
		return err
	}
	profile := t.process.profile
	if err := profile.ValidateRange(pc, 0); err != nil {
		return err
	}
	data, err := e.readRegisterSet(tid)
	if err != nil {
		return err
	}
	field, ok := profile.Register(profile.PCName)
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
	return e.writeRegisterSet(tid, data, 1)
}
