package amd64

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"fastdbg2/target"
)

type Paging struct{ CR0, CR3, CR4, EFER uint64 }
type PhysicalReader func(target.Address, []byte) (int, error)
type PageEntry struct {
	Level          int
	Address, Value uint64
}
type Page struct {
	Virtual, Physical, Size uint64
	Write, User, Execute    bool
}
type Translation struct {
	Page     Page
	Entries  []PageEntry
	Physical uint64
}

func (p Paging) levels() (int, error) {
	if p.CR0&(1<<31) == 0 || p.CR4&(1<<5) == 0 || p.EFER&(1<<10) == 0 {
		return 0, fmt.Errorf("AMD64 long-mode paging is not active: %w", target.ErrUnsupported)
	}
	if p.CR4&(1<<12) != 0 {
		return 5, nil
	}
	return 4, nil
}

func canonical(address uint64, levels int) bool {
	bits := uint(levels*9 + 12)
	high := address >> bits
	if address&(1<<(bits-1)) == 0 {
		return high == 0
	}
	return high == (uint64(1)<<(64-bits))-1
}

func (p Paging) entry(value uint64, level int) (uint64, uint64, error) {
	if value&1 == 0 {
		return 0, 0, target.ErrNotFound
	}
	if value>>63 != 0 && p.EFER&(1<<11) == 0 {
		return 0, 0, fmt.Errorf("NX entry with EFER.NXE disabled: %w", target.ErrInvalidArgument)
	}
	base := value & 0x000ffffffffff000
	size := uint64(0)
	if level == 1 {
		size = 4096
	} else if value&128 != 0 {
		if level != 2 && level != 3 {
			return 0, 0, fmt.Errorf("reserved page-size bit at level %d: %w", level, target.ErrInvalidArgument)
		}
		size = uint64(1) << uint(12+9*(level-1))
		if base&(size-1)&^uint64(4096) != 0 {
			return 0, 0, fmt.Errorf("misaligned large page: %w", target.ErrInvalidArgument)
		}
		base &^= size - 1
	}
	return base, size, nil
}

func (p Paging) Translate(ctx context.Context, address uint64, read PhysicalReader) (Translation, error) {
	var result Translation
	levels, err := p.levels()
	if err != nil {
		return result, err
	}
	if !canonical(address, levels) || read == nil {
		return result, target.ErrInvalidArgument
	}
	table := p.CR3 & 0x000ffffffffff000
	writable, user, execute := true, true, true
	for level := levels; level > 0; level-- {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		at := table + ((address>>uint(12+9*(level-1)))&511)*8
		var data [8]byte
		n, err := read(target.Address(at), data[:])
		if err != nil {
			return result, err
		}
		if n != 8 {
			return result, io.ErrUnexpectedEOF
		}
		value := binary.LittleEndian.Uint64(data[:])
		result.Entries = append(result.Entries, PageEntry{level, at, value})
		base, size, err := p.entry(value, level)
		if err != nil {
			return result, err
		}
		writable = writable && value&2 != 0
		user = user && value&4 != 0
		execute = execute && value>>63 == 0
		if size != 0 {
			result.Page = Page{address &^ (size - 1), base, size, writable, user, execute}
			result.Physical = base + address&(size-1)
			return result, nil
		}
		table = base
	}
	return result, target.ErrUnknown
}

func (p Paging) Mappings(ctx context.Context, read PhysicalReader) ([]Page, error) {
	levels, err := p.levels()
	if err != nil {
		return nil, err
	}
	if read == nil {
		return nil, target.ErrInvalidArgument
	}
	tables := make(map[uint64][]byte)
	var pages []Page
	visited := 0
	var visit func(uint64, int, uint64, bool, bool, bool) error
	visit = func(table uint64, level int, prefix uint64, writable, user, execute bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > 65536 {
			return fmt.Errorf("page-table traversal limit: %w", target.ErrOverflow)
		}
		data, ok := tables[table]
		if !ok {
			if len(tables) >= 16384 {
				return target.ErrOverflow
			}
			data = make([]byte, 4096)
			n, err := read(target.Address(table), data)
			if err != nil {
				return err
			}
			if n != len(data) {
				return io.ErrUnexpectedEOF
			}
			tables[table] = data
		}
		for i := 0; i < 512; i++ {
			value := binary.LittleEndian.Uint64(data[i*8:])
			if value&1 == 0 {
				continue
			}
			base, size, err := p.entry(value, level)
			if err != nil {
				return err
			}
			address := prefix | uint64(i)<<uint(12+9*(level-1))
			w, u, x := writable && value&2 != 0, user && value&4 != 0, execute && value>>63 == 0
			if size == 0 {
				if err := visit(base, level-1, address, w, u, x); err != nil {
					return err
				}
				continue
			}
			bits := uint(levels*9 + 12)
			if address&(1<<(bits-1)) != 0 {
				address |= math.MaxUint64 << bits
			}
			if size > math.MaxUint64-address {
				return target.ErrOverflow
			}
			if len(pages) >= 1<<20 {
				return target.ErrOverflow
			}
			if len(pages) > 0 {
				last := &pages[len(pages)-1]
				if last.Virtual+last.Size == address && last.Physical+last.Size == base && last.Write == w && last.User == u && last.Execute == x {
					last.Size += size
					continue
				}
			}
			pages = append(pages, Page{address, base, size, w, u, x})
		}
		return nil
	}
	if err := visit(p.CR3&0x000ffffffffff000, levels, 0, true, true, true); err != nil {
		return nil, err
	}
	return pages, nil
}
