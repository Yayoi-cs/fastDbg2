package inspect

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"fastdbg2/target"
)

var orcFormatHash = []byte{0xfe, 0x5d, 0x32, 0xbf, 0x58, 0x1b, 0xd6, 0x3b, 0x2c, 0xa9, 0xa5, 0xc6, 0x5b, 0xa5, 0xa6, 0x25, 0xea, 0xb3, 0xfe, 0x24}

type orcEntry struct {
	pc                 target.Address
	sp, bp             int16
	spReg, bpReg, kind byte
	signal             bool
}
type ORCIndex struct {
	address target.Address
	entries []orcEntry
	source  string
}

func ParseORC(ctx context.Context, header, ips, entries []byte, address target.Address, source string) (*ORCIndex, error) {
	if !bytes.Equal(header, orcFormatHash) {
		return nil, fmt.Errorf("unknown ORC format hash %x: %w", header, target.ErrUnsupported)
	}
	if len(ips) == 0 || len(ips)%4 != 0 || len(entries)%6 != 0 || len(ips)/4 != len(entries)/6 || len(ips) > 32<<20 {
		return nil, target.ErrInvalidArgument
	}
	index := &ORCIndex{source: source, address: address}
	for i := 0; i < len(ips)/4; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		at, err := unwindSignedAdd(uint64(address), int64(i)*4)
		if err != nil {
			return nil, err
		}
		pc, err := unwindSignedAdd(at, int64(int32(binary.LittleEndian.Uint32(ips[i*4:]))))
		if err != nil {
			return nil, err
		}
		data := entries[i*6:]
		entry := orcEntry{target.Address(pc), int16(binary.LittleEndian.Uint16(data)), int16(binary.LittleEndian.Uint16(data[2:])), data[4] & 15, data[4] >> 4, data[5] & 7, data[5]&8 != 0}
		if entry.kind > 4 || data[5]&0xf0 != 0 || entry.spReg > 9 || entry.bpReg > 9 {
			return nil, target.ErrUnsupported
		}
		if i > 0 && index.entries[i-1].pc > entry.pc {
			return nil, fmt.Errorf("ORC IP table is not sorted: %w", target.ErrInvalidArgument)
		}
		index.entries = append(index.entries, entry)
	}
	return index, nil
}

func (index *ORCIndex) Unwind(ctx context.Context, registers UnwindRegisters, pc target.Address, read CFIReader, limit int) (UnwindResult, error) {
	var result UnwindResult
	if index == nil || limit < 1 || limit > 256 || read == nil {
		return result, target.ErrInvalidArgument
	}
	signal := true
	seen := make(map[[2]uint64]bool)
	scalar := func(regs UnwindRegisters, n int) (uint64, error) {
		if regs.Known&(1<<n) == 0 {
			return 0, fmt.Errorf("ORC register %s: %w", amd64UnwindNames[n], target.ErrUnavailable)
		}
		return regs.Values[n], nil
	}
	word := func(address uint64) (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if address > ^uint64(0)-7 {
			return 0, target.ErrOverflow
		}
		var data [8]byte
		n, err := read(ctx, target.Address(address), data[:])
		if err != nil {
			return 0, err
		}
		if n != 8 {
			return 0, io.ErrUnexpectedEOF
		}
		return binary.LittleEndian.Uint64(data[:]), nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return UnwindResult{}, err
		}
		sp, err := scalar(registers, 7)
		if err != nil {
			return result, err
		}
		key := [2]uint64{uint64(pc), sp}
		if seen[key] {
			return result, target.ErrInvalidState
		}
		seen[key] = true
		lookup := pc
		if !signal {
			if pc == 0 {
				return result, target.ErrUnavailable
			}
			lookup--
		}
		result.Frames = append(result.Frames, UnwindFrame{PC: pc, RawPC: pc, LookupPC: lookup, ReturnPC: !signal, Registers: registers, Source: index.source})
		frame := &result.Frames[len(result.Frames)-1]
		frame.MetadataKind = "ORC"
		pos := sort.Search(len(index.entries), func(i int) bool { return index.entries[i].pc > lookup }) - 1
		if pos < 0 {
			return result, fmt.Errorf("ORC at %#x: %w", lookup, target.ErrNotFound)
		}
		entry := index.entries[pos]
		frame.FDE = index.address + target.Address(pos*4)
		frame.Start = entry.pc
		if pos+1 < len(index.entries) {
			frame.End = index.entries[pos+1].pc
		}
		frame.Signal = entry.signal
		if entry.kind == 0 {
			return result, fmt.Errorf("undefined ORC at %#x: %w", lookup, target.ErrUnavailable)
		}
		if entry.kind == 1 {
			result.Complete = true
			return result, nil
		}
		base := uint64(0)
		switch entry.spReg {
		case 5, 9:
			base, err = scalar(registers, 7)
		case 4, 8:
			base, err = scalar(registers, 6)
		case 2:
			base, err = scalar(registers, 1)
		case 3:
			base, err = scalar(registers, 5)
		case 6:
			base, err = scalar(registers, 10)
		case 7:
			base, err = scalar(registers, 13)
		default:
			err = target.ErrUnsupported
		}
		if err != nil {
			return result, err
		}
		if entry.spReg == 4 || entry.spReg == 5 || entry.spReg == 8 {
			base, err = unwindSignedAdd(base, int64(entry.sp))
			if err != nil {
				return result, err
			}
		}
		if entry.spReg == 8 || entry.spReg == 9 {
			base, err = word(base)
			if err != nil {
				return result, err
			}
			if entry.spReg == 9 {
				base, err = unwindSignedAdd(base, int64(entry.sp))
				if err != nil {
					return result, err
				}
			}
		}
		frame.CFA = target.Address(base)
		frame.CFAKnown = true
		frame.CFAOffset = int64(entry.sp)
		frame.CFARegister = 7
		frame.CFARule = fmt.Sprintf("rsp %+d", entry.sp)
		switch entry.spReg {
		case 4:
			frame.CFARule = fmt.Sprintf("rbp %+d", entry.sp)
		case 8:
			frame.CFARule = fmt.Sprintf("*[rbp %+d]", entry.sp)
		case 9:
			frame.CFARule = fmt.Sprintf("*[rsp] %+d", entry.sp)
		case 2:
			frame.CFARule = "rdx"
		case 3:
			frame.CFARule = "rdi"
		case 6:
			frame.CFARule = "r10"
		case 7:
			frame.CFARule = "r13"
		}
		if entry.spReg == 4 {
			frame.CFARegister = 6
		}
		next := UnwindRegisters{Architecture: target.AMD64}
		switch entry.kind {
		case 2:
			if base < 8 {
				return result, target.ErrOverflow
			}
			ip, err := word(base - 8)
			if err != nil {
				return result, err
			}
			next.Values[7], next.Values[16] = base, ip
			next.Known = 1<<7 | 1<<16
			if registers.Known&(1<<6) != 0 {
				next.Values[6] = registers.Values[6]
				next.Known |= 1 << 6
			}
			frame.Saved = append(frame.Saved, UnwindSavedRegister{Register: 16, Rule: "offset", Provenance: "ORC", Offset: -8, Address: target.Address(base - 8), AddressKnown: true, Value: ip, Available: true})
		case 3, 4:
			offset := 0
			size := 168
			if entry.kind == 4 {
				offset = 128
				size = 40
				next = registers
			}
			if base > ^uint64(0)-uint64(size-1) {
				return result, target.ErrOverflow
			}
			data := make([]byte, size)
			n, err := read(ctx, target.Address(base), data)
			if err != nil {
				return result, err
			}
			if n != size {
				return result, io.ErrUnexpectedEOF
			}
			positions := map[int]int{15: 0, 14: 8, 13: 16, 12: 24, 6: 32, 3: 40, 11: 48, 10: 56, 9: 64, 8: 72, 0: 80, 2: 88, 1: 96, 4: 104, 5: 112, 16: 128, 7: 152}
			for reg, at := range positions {
				at -= offset
				if at >= 0 && at+8 <= size {
					next.Values[reg] = binary.LittleEndian.Uint64(data[at:])
					next.Known |= 1 << reg
				}
			}
			if binary.LittleEndian.Uint64(data[136-offset:])&3 != 0 {
				result.Complete = true
				return result, nil
			}
		}
		switch entry.bpReg {
		case 0:
		case 1, 4:
			address := base
			if entry.bpReg == 4 {
				address, err = scalar(registers, 6)
				if err != nil {
					return result, err
				}
			}
			address, err = unwindSignedAdd(address, int64(entry.bp))
			if err != nil {
				return result, err
			}
			bp, err := word(address)
			if err != nil {
				return result, err
			}
			next.Values[6] = bp
			next.Known |= 1 << 6
			frame.Saved = append(frame.Saved, UnwindSavedRegister{Register: 6, Rule: "offset", Provenance: "ORC", Offset: int64(entry.bp), Address: target.Address(address), AddressKnown: true, Value: bp, Available: true})
		default:
			return result, target.ErrUnsupported
		}
		if len(result.Frames) == limit {
			result.Limited = true
			return result, &UnwindLimitError{Limit: limit}
		}
		registers = next
		pc = target.Address(next.Values[16])
		signal = entry.signal
	}
}
