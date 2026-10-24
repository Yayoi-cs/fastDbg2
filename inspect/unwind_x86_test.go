package inspect

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"fastdbg2/target"
)

func TestUnwindX86FourByteSlots(t *testing.T) {
	frame := unwindTestFrame(0x1000)
	frame.cie.addressSize = 4
	frame.cie.returnRegister = 8
	frame.cie.dataAlign = -4
	frame.cie.initial.data = []byte{0x0c, 4, 4, 0x88, 1}
	bottom := unwindTestFrame(0x2000)
	bottom.cie.addressSize = 4
	bottom.cie.returnRegister = 8
	bottom.cie.initial.data = []byte{0x07, 8}
	registers := UnwindRegisters{Architecture: target.X86, Known: (1 << 4) | (1 << 8)}
	registers.Values[4] = 0x8000
	registers.Values[8] = 0x1000
	result, err := Unwind(context.Background(), UnwindRequest{Profile: UnwindSysVX86, Registers: registers, PC: 0x1000, MaxFrames: 8, Find: unwindTestFind(frame, bottom), Read: func(_ context.Context, a target.Address, data []byte) (int, error) {
		if a != 0x8000 || len(data) != 4 {
			t.Fatalf("incorrect i386 slot %#x/%d", a, len(data))
		}
		binary.LittleEndian.PutUint32(data, 0x2001)
		return 4, nil
	}})
	if err != nil || !result.Complete || len(result.Frames) != 2 || result.Frames[1].Registers.Values[4] != 0x8004 {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestX86ExpressionWidth(t *testing.T) {
	for _, test := range []struct {
		op         byte
		a, b, want uint64
	}{{0x22, 0xffffffff, 2, 1}, {0x26, 0x80000000, 31, 0xffffffff}, {0x1b, 0xfffffffc, 2, 0xfffffffe}, {0x2d, 0xffffffff, 0, 1}, {0x1c, 0, 1, 0xffffffff}} {
		got, err := unwindExpressionBinary32(test.op, test.a, test.b)
		if err != nil || got != test.want {
			t.Fatalf("%+v: %#x %v", test, got, err)
		}
	}
	if _, err := unwindExpressionBinary32(0x24, 1, 32); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
	data := []byte{3, 0x78, 0x56, 0x34, 0x12}
	instructions, err := decodeUnwindExpression(context.Background(), data, 4)
	if err != nil || len(instructions) != 1 || instructions[0].value != 0x12345678 {
		t.Fatalf("32bit DW_OP_addr: %+v %v", instructions, err)
	}
}
