package xstate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"unsafe"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

type Component struct {
	ID     uint8
	Offset uint32
	Size   uint32
}

type CPU struct {
	XSave      bool
	Size       uint32
	Supported  uint64
	Enabled    uint64
	MXCSRMask  uint32
	Components []Component
}

func cpuid(leaf, subleaf uint32) (a, b, c, d uint32)
func xgetbv() (a, d uint32)
func fxsave(address *byte)

func Host() (CPU, error) {
	enabled, _, errno := unix.Syscall(unix.SYS_ARCH_PRCTL, 0x1011, 0, 0)
	if errno != 0 || enabled != 1 {
		err := target.ErrUnsupported
		if errno != 0 {
			err = errors.Join(err, errno)
		}
		return CPU{}, fmt.Errorf("CPUID is unavailable: %w", err)
	}
	maximum, _, _, _ := cpuid(0, 0)
	if maximum < 1 {
		return CPU{}, target.ErrUnsupported
	}
	_, _, features, legacy := cpuid(1, 0)
	if legacy&(1<<24) == 0 {
		return CPU{}, fmt.Errorf("FXSAVE is unavailable: %w", target.ErrUnsupported)
	}
	data := make([]byte, 512+15)
	offset := int(-uintptr(unsafe.Pointer(&data[0])) & 15)
	fxsave(&data[offset])
	mask := binary.LittleEndian.Uint32(data[offset+28 : offset+32])
	runtime.KeepAlive(data)
	if mask == 0 {
		mask = 0xffbf
	}
	result := CPU{Size: 512, MXCSRMask: mask}
	if features&(1<<26|1<<27) != 1<<26|1<<27 {
		return result, nil
	}
	if maximum < 0xd {
		return CPU{}, fmt.Errorf("XSAVE CPUID leaf is missing: %w", target.ErrUnsupported)
	}
	a, d := xgetbv()
	result.Enabled = uint64(a) | uint64(d)<<32
	return decode(cpuid, result)
}

func decode(query func(uint32, uint32) (uint32, uint32, uint32, uint32), result CPU) (CPU, error) {
	a, size, maximum, d := query(0xd, 0)
	result.XSave = true
	result.Size = size
	result.Supported = uint64(a) | uint64(d)<<32
	if size < 576 || size%8 != 0 || maximum < size || result.Enabled&1 == 0 || result.Enabled&^result.Supported != 0 || result.Supported&(uint64(1)<<63) != 0 {
		return CPU{}, fmt.Errorf("inconsistent XSAVE enumeration: %w", target.ErrUnsupported)
	}
	for id := uint8(2); id < 63; id++ {
		if result.Enabled&(uint64(1)<<id) == 0 {
			continue
		}
		length, offset, flags, _ := query(0xd, uint32(id))
		if length == 0 || offset < 576 || uint64(offset)+uint64(length) > uint64(size) || flags&1 != 0 {
			return CPU{}, fmt.Errorf("invalid user XSAVE component %d: %w", id, target.ErrUnsupported)
		}
		result.Components = append(result.Components, Component{ID: id, Offset: offset, Size: length})
	}
	ordered := append([]Component(nil), result.Components...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	for i := 1; i < len(ordered); i++ {
		if uint64(ordered[i-1].Offset)+uint64(ordered[i-1].Size) > uint64(ordered[i].Offset) {
			return CPU{}, fmt.Errorf("overlapping XSAVE components: %w", target.ErrUnsupported)
		}
	}
	return result, nil
}
