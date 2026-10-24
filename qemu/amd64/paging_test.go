package amd64

import (
	"context"
	"encoding/binary"
	"errors"
	"fastdbg2/target"
	"testing"
)

func TestPagingWalkAndMappings(t *testing.T) {
	for _, levels := range []int{4, 5} {
		memory := make([]byte, 0x8000)
		put := func(at, value uint64) { binary.LittleEndian.PutUint64(memory[at:], value) }
		p := Paging{CR0: 1 << 31, CR3: 0x1000 | 0x27, CR4: 1 << 5, EFER: 1<<10 | 1<<11}
		root := uint64(0x1000)
		if levels == 5 {
			p.CR4 |= 1 << 12
			put(root, 0x2003)
			root = 0x2000
		}
		put(root, 0x3003)
		put(0x3000, 0x4007)
		put(0x3008, 0x40000083)
		put(0x4000, 0x5007)
		put(0x4008, 0x200083)
		put(0x5008, 0x9005|1<<63)
		read := func(at target.Address, data []byte) (int, error) {
			if int(at)+len(data) > len(memory) {
				return 0, target.ErrUnavailable
			}
			return copy(data, memory[int(at):]), nil
		}
		tr, err := p.Translate(context.Background(), 0x1123, read)
		if err != nil || tr.Physical != 0x9123 || tr.Page.Write || tr.Page.User || tr.Page.Execute || len(tr.Entries) != levels {
			t.Fatalf("L%d: %+v %v", levels, tr, err)
		}
		for address, size := range map[uint64]uint64{0x200123: 1 << 21, 0x40000123: 1 << 30} {
			tr, err = p.Translate(context.Background(), address, read)
			if err != nil || tr.Physical != address || tr.Page.Size != size {
				t.Fatalf("%+v %v", tr, err)
			}
		}
		maps, err := p.Mappings(context.Background(), read)
		if err != nil || len(maps) != 3 {
			t.Fatalf("%+v %v", maps, err)
		}
		if _, err := p.Translate(context.Background(), 0x8000, read); !errors.Is(err, target.ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := p.Translate(context.Background(), uint64(1)<<uint(levels*9+11), read); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := p.Mappings(ctx, read); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		p.EFER &^= 1 << 11
		if _, err := p.Translate(context.Background(), 0x1123, read); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
}

func TestPagingHighCanonicalAndReservedEntries(t *testing.T) {
	p := Paging{CR0: 1 << 31, CR3: 0x1000, CR4: 1 << 5, EFER: 1<<10 | 1<<11}
	memory := make([]byte, 0x4000)
	binary.LittleEndian.PutUint64(memory[0x1800:], 0x2003)
	binary.LittleEndian.PutUint64(memory[0x2000:], 0x83)
	read := func(at target.Address, data []byte) (int, error) { return copy(data, memory[int(at):]), nil }
	tr, err := p.Translate(context.Background(), 0xffff800000001234, read)
	if err != nil || tr.Physical != 0x1234 {
		t.Fatalf("%+v %v", tr, err)
	}
	maps, err := p.Mappings(context.Background(), read)
	if err != nil || len(maps) != 1 || maps[0].Virtual != 0xffff800000000000 {
		t.Fatalf("%+v %v", maps, err)
	}
	binary.LittleEndian.PutUint64(memory[0x1800:], 0x83)
	if _, err := p.Mappings(context.Background(), read); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
	p.CR0 = 0
	if _, err := p.Translate(context.Background(), 0, read); !errors.Is(err, target.ErrUnsupported) {
		t.Fatal(err)
	}
}
