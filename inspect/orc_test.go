package inspect

import (
	"context"
	"encoding/binary"
	"errors"
	"fastdbg2/target"
	"testing"
)

func TestORCMetadataUnwind(t *testing.T) {
	ips := make([]byte, 12)
	entries := make([]byte, 18)
	for i, pc := range []uint64{0x1000, 0x1100, 0x1200} {
		binary.LittleEndian.PutUint32(ips[i*4:], uint32(int32(int64(pc)-int64(0x2000+i*4))))
	}
	binary.LittleEndian.PutUint16(entries, 8)
	entries[4] = 5
	entries[5] = 2
	entries[11] = 1
	index, err := ParseORC(context.Background(), orcFormatHash, ips, entries, 0x2000, "fixture:ORC")
	if err != nil {
		t.Fatal(err)
	}
	registers := UnwindRegisters{Architecture: target.AMD64, Known: 1<<7 | 1<<16}
	registers.Values[7] = 0x8000
	registers.Values[16] = 0x1000
	read := func(ctx context.Context, address target.Address, data []byte) (int, error) {
		if address != 0x8000 {
			return 0, target.ErrUnavailable
		}
		binary.LittleEndian.PutUint64(data, 0x1101)
		return 8, nil
	}
	result, err := index.Unwind(context.Background(), registers, 0x1000, read, 16)
	if err != nil || !result.Complete || len(result.Frames) != 2 || result.Frames[1].LookupPC != 0x1100 || result.Frames[0].CFA != 0x8008 {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err := ParseORC(context.Background(), []byte("unknown"), ips, entries, 0x2000, ""); !errors.Is(err, target.ErrUnsupported) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := index.Unwind(ctx, registers, 0x1000, read, 16); !errors.Is(err, context.Canceled) || len(result.Frames) != 0 {
		t.Fatal(result, err)
	}
	entries[5] = 0
	index, err = ParseORC(context.Background(), orcFormatHash, ips, entries, 0x2000, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.Unwind(context.Background(), registers, 0x1000, read, 16); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestORCFullExceptionRegisters(t *testing.T) {
	ips := make([]byte, 8)
	binary.LittleEndian.PutUint32(ips, uint32(0xfffff000))
	binary.LittleEndian.PutUint32(ips[4:], uint32(0xfffff0fc))
	entries := make([]byte, 12)
	entries[4] = 5
	entries[5] = 3 | 8
	entries[11] = 1
	index, err := ParseORC(context.Background(), orcFormatHash, ips, entries, 0x2000, "exception")
	if err != nil {
		t.Fatal(err)
	}
	regs := UnwindRegisters{Known: 1<<7 | 1<<16}
	regs.Values[7] = 0x8000
	regs.Values[16] = 0x1000
	read := func(ctx context.Context, address target.Address, data []byte) (int, error) {
		if address != 0x8000 || len(data) != 168 {
			return 0, target.ErrUnavailable
		}
		binary.LittleEndian.PutUint64(data[128:], 0x1100)
		binary.LittleEndian.PutUint64(data[152:], 0x9000)
		binary.LittleEndian.PutUint64(data[32:], 0x9100)
		return len(data), nil
	}
	result, err := index.Unwind(context.Background(), regs, 0x1000, read, 8)
	if err != nil || !result.Complete || len(result.Frames) != 2 || result.Frames[1].ReturnPC || result.Frames[1].Registers.Values[6] != 0x9100 {
		t.Fatalf("%+v %v", result, err)
	}
}
