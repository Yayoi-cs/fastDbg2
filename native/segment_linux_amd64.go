package native

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func (s *Session) ReadThreadSegmentBase(token target.ThreadToken, name string) (target.Address, error) {
	return call(s, func(e *engine) (target.Address, error) {
		t, err := e.requireThread(token)
		if err != nil {
			return 0, err
		}
		if name != "fs" && name != "gs" {
			return 0, target.ErrInvalidArgument
		}
		registers, err := e.readThreadRegisters(t)
		if err != nil {
			return 0, err
		}
		if t.process.profile.Architecture == target.AMD64 {
			for _, r := range registers {
				if r.Name == name+"_base" && r.Available && len(r.Data) == 8 {
					return target.Address(binary.LittleEndian.Uint64(r.Data)), nil
				}
			}
			return 0, target.ErrUnavailable
		}
		if t.process.profile.Architecture != target.X86 {
			return 0, target.ErrUnsupported
		}
		var selector uint32
		found := false
		for _, r := range registers {
			if r.Name == name && r.Available && len(r.Data) == 4 {
				selector = binary.LittleEndian.Uint32(r.Data)
				found = true
			}
		}
		if !found {
			return 0, target.ErrUnavailable
		}
		if selector == 0 {
			return 0, nil
		}
		if selector > 0xffff || selector&7 != 3 {
			return 0, fmt.Errorf("non-GDT user TLS selector %#x: %w", selector, target.ErrUnsupported)
		}
		var descriptor [16]byte
		index := selector >> 3
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_THREAD_AREA, uintptr(t.tid), uintptr(index), uintptr(unsafe.Pointer(&descriptor[0])), 0, 0)
		runtime.KeepAlive(descriptor)
		if errno != 0 {
			return 0, errno
		}
		if binary.LittleEndian.Uint32(descriptor[:4]) != index {
			return 0, target.ErrStale
		}
		flags := binary.LittleEndian.Uint32(descriptor[12:])
		if flags&1 == 0 || flags&6 != 0 || flags&32 != 0 {
			return 0, fmt.Errorf("TLS descriptor is not present 32-bit data: %w", target.ErrUnsupported)
		}
		return target.Address(binary.LittleEndian.Uint32(descriptor[4:8])), nil
	})
}
