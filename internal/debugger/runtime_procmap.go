package debugger

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"unsafe"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const procmapQueryIOCTL = 0xc0686611

type runtimeProcmapQuery struct {
	Size        uint64
	QueryFlags  uint64
	QueryAddr   uint64
	Start       uint64
	End         uint64
	Flags       uint64
	PageSize    uint64
	Offset      uint64
	Inode       uint64
	DevMajor    uint32
	DevMinor    uint32
	NameSize    uint32
	BuildIDSize uint32
	NameAddr    uint64
	BuildIDAddr uint64
}

func (p *stoppedProc) mappedBuildID(mapping procMap) (id []byte, err error) {
	if p == nil || p.ctx == nil || p.dir == nil || mapping.Start >= mapping.End {
		return nil, target.ErrInvalidArgument
	}
	if err := contextReady(p.ctx); err != nil {
		return nil, err
	}
	mappings, err := p.maps()
	if err != nil {
		return nil, err
	}
	index, ok := slices.BinarySearchFunc(mappings, mapping.Start, func(candidate procMap, address target.Address) int {
		if candidate.Start < address {
			return -1
		}
		if candidate.Start > address {
			return 1
		}
		return 0
	})
	if !ok || mappings[index] != mapping {
		return nil, fmt.Errorf("build ID mapping differs from procfs snapshot: %w", target.ErrStale)
	}
	if mapping.Inode == 0 {
		return nil, fmt.Errorf("mapping has no backing ELF build ID: %w", target.ErrUnavailable)
	}
	file, err := p.openFile("maps")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var bytes [128]byte
	var pin runtime.Pinner
	pin.Pin(&bytes[0])
	defer pin.Unpin()
	var query runtimeProcmapQuery
	for {
		if err := contextReady(p.ctx); err != nil {
			return nil, err
		}
		query = runtimeProcmapQuery{
			Size:        uint64(unsafe.Sizeof(runtimeProcmapQuery{})),
			QueryAddr:   uint64(mapping.Start),
			BuildIDSize: uint32(len(bytes)),
			BuildIDAddr: uint64(uintptr(unsafe.Pointer(&bytes[0]))),
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), procmapQueryIOCTL, uintptr(unsafe.Pointer(&query)))
		runtime.KeepAlive(&bytes)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			kind := target.ErrUnavailable
			switch errno {
			case unix.ENOTTY, unix.EINVAL:
				kind = target.ErrUnsupported
			case unix.ENOENT, unix.ESRCH:
				kind = target.ErrStale
			case unix.E2BIG, unix.ENAMETOOLONG:
				kind = target.ErrOverflow
			}
			return nil, fmt.Errorf("PROCMAP_QUERY build ID: %w", errors.Join(kind, errno))
		}
		break
	}
	if err := validateRuntimeProcmapQuery(mapping, query, len(bytes)); err != nil {
		return nil, err
	}
	if err := contextReady(p.ctx); err != nil {
		return nil, err
	}
	return slices.Clone(bytes[:query.BuildIDSize]), nil
}

func validateRuntimeProcmapQuery(mapping procMap, query runtimeProcmapQuery, capacity int) error {
	var flags uint64
	if mapping.Read {
		flags |= 1
	}
	if mapping.Write {
		flags |= 2
	}
	if mapping.Execute {
		flags |= 4
	}
	if !mapping.Private {
		flags |= 8
	}
	if query.Start != uint64(mapping.Start) || query.End != uint64(mapping.End) || query.Offset != mapping.Offset ||
		query.Inode != mapping.Inode || query.DevMajor != mapping.DevMajor || query.DevMinor != mapping.DevMinor || query.Flags != flags {
		return fmt.Errorf("PROCMAP_QUERY differs from procfs mapping: %w", target.ErrStale)
	}
	if query.PageSize == 0 || query.PageSize&(query.PageSize-1) != 0 {
		return fmt.Errorf("invalid PROCMAP_QUERY page size: %w", target.ErrInvalidArgument)
	}
	if uint64(query.BuildIDSize) > uint64(capacity) || capacity < 0 {
		return fmt.Errorf("PROCMAP_QUERY build ID exceeds buffer: %w", target.ErrOverflow)
	}
	if query.BuildIDSize == 0 {
		return fmt.Errorf("mapping has no backing ELF build ID: %w", target.ErrUnavailable)
	}
	return nil
}
