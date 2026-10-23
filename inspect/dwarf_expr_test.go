package inspect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"

	"fastdbg2/target"
)

func TestUnwindLEB128Boundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		data   []byte
		signed bool
		want   uint64
		err    error
	}{
		{"zero", []byte{0}, false, 0, nil},
		{"127", []byte{0x7f}, false, 127, nil},
		{"128", []byte{0x80, 1}, false, 128, nil},
		{"max_unsigned", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1}, false, math.MaxUint64, nil},
		{"unsigned_overflow", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2}, false, 0, target.ErrOverflow},
		{"unsigned_continuation", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, false, 0, target.ErrOverflow},
		{"minus1", []byte{0x7f}, true, math.MaxUint64, nil},
		{"minus64", []byte{0x40}, true, math.MaxUint64 - 63, nil},
		{"plus64", []byte{0xc0, 0}, true, 64, nil},
		{"min_signed", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}, true, 1 << 63, nil},
		{"max_signed", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}, true, math.MaxInt64, nil},
		{"signed_overflow", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1}, true, 0, target.ErrOverflow},
		{"truncated_unsigned", []byte{0x80}, false, 0, io.ErrUnexpectedEOF},
		{"truncated_signed", []byte{0x80}, true, 0, io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := unwindBytes{data: test.data}
			var value uint64
			if test.signed {
				value = uint64(reader.sleb())
			} else {
				value = reader.uleb()
			}
			if !errors.Is(reader.err, test.err) || reader.err == nil && value != test.want {
				t.Fatalf("value=%#x error=%v; want %#x,%v", value, reader.err, test.want, test.err)
			}
		})
	}
}

func TestUnwindExpressionScalarOperations(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want uint64
	}{
		{"constant1u", []byte{0x08, 0xfe}, 254},
		{"constant1s", []byte{0x09, 0xfe}, math.MaxUint64 - 1},
		{"constant2u", []byte{0x0a, 1, 2}, 513},
		{"constant2s", []byte{0x0b, 0, 0x80}, math.MaxUint64 - 32767},
		{"constant4u", []byte{0x0c, 1, 2, 3, 4}, 0x04030201},
		{"constant4s", []byte{0x0d, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64},
		{"constant8u", []byte{0x0e, 1, 2, 3, 4, 5, 6, 7, 8}, 0x0807060504030201},
		{"constant8s", []byte{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64},
		{"constant_uleb", []byte{0x10, 0x80, 1}, 128},
		{"constant_sleb", []byte{0x11, 0x7f}, math.MaxUint64},
		{"literal", []byte{0x4f}, 31},
		{"dup", []byte{0x31, 0x12, 0x22}, 2},
		{"drop", []byte{0x31, 0x32, 0x13}, 1},
		{"over", []byte{0x31, 0x32, 0x14}, 1},
		{"pick", []byte{0x31, 0x32, 0x33, 0x15, 2}, 1},
		{"swap", []byte{0x31, 0x32, 0x16}, 1},
		{"rot", []byte{0x31, 0x32, 0x33, 0x17}, 2},
		{"abs", []byte{0x09, 0xf8, 0x19}, 8},
		{"and", []byte{0x33, 0x36, 0x1a}, 2},
		{"div", []byte{0x09, 0xf8, 0x32, 0x1b}, math.MaxUint64 - 3},
		{"minus", []byte{0x31, 0x32, 0x1c}, math.MaxUint64},
		{"mod", []byte{0x37, 0x33, 0x1d}, 1},
		{"mul", []byte{0x37, 0x33, 0x1e}, 21},
		{"neg", []byte{0x32, 0x1f}, math.MaxUint64 - 1},
		{"not", []byte{0x32, 0x20}, math.MaxUint64 - 2},
		{"or", []byte{0x32, 0x34, 0x21}, 6},
		{"plus", []byte{0x32, 0x34, 0x22}, 6},
		{"plus_unsigned", []byte{0x32, 0x23, 0x80, 1}, 130},
		{"wrap_plus", []byte{0x11, 0x7f, 0x31, 0x22}, 0},
		{"shl", []byte{0x32, 0x34, 0x24}, 32},
		{"shr", []byte{0x11, 0x7f, 0x31, 0x25}, math.MaxInt64},
		{"shra", []byte{0x11, 0x7f, 0x31, 0x26}, math.MaxUint64},
		{"xor", []byte{0x33, 0x36, 0x27}, 5},
		{"eq", []byte{0x33, 0x33, 0x29}, 1},
		{"ge_signed", []byte{0x11, 0x7f, 0x33, 0x2a}, 0},
		{"gt", []byte{0x33, 0x32, 0x2b}, 1},
		{"le", []byte{0x33, 0x33, 0x2c}, 1},
		{"lt_signed", []byte{0x11, 0x7f, 0x33, 0x2d}, 1},
		{"ne", []byte{0x33, 0x32, 0x2e}, 1},
		{"nop", []byte{0x33, 0x96}, 3},
		{"branch_taken", []byte{0x31, 0x28, 1, 0, 0x32, 0x33}, 3},
		{"branch_not_taken", []byte{0x30, 0x28, 1, 0, 0x32}, 2},
		{"skip_to_end", []byte{0x32, 0x2f, 1, 0, 0x33}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := evaluateUnwindExpression(context.Background(), test.data, AMD64UnwindRegisters{}, nil, &CFIFrame{}, &unwindBudget{operations: 10000, bytes: 1024})
			if err != nil || value != test.want {
				t.Fatalf("value=%#x err=%v, want %#x", value, err, test.want)
			}
		})
	}
}

func TestUnwindExpressionAddressesAndMemory(t *testing.T) {
	registers := unwindTestRegisters(0x1000, 0x8000)
	for _, test := range []struct {
		name string
		data []byte
		want uint64
	}{
		{"breg", []byte{0x77, 0x78}, 0x7ff8},
		{"bregx", []byte{0x92, 7, 0x10}, 0x8010},
		{"address", []byte{0x03, 0, 0x10, 0, 0, 0, 0, 0, 0}, 0x1000},
		{"deref", []byte{0x77, 0, 0x06}, 0x8877665544332211},
		{"deref_size1", []byte{0x77, 0, 0x94, 1}, 0x11},
		{"deref_size2", []byte{0x77, 0, 0x94, 2}, 0x2211},
		{"deref_size4", []byte{0x77, 0, 0x94, 4}, 0x44332211},
	} {
		t.Run(test.name, func(t *testing.T) {
			read := func(ctx context.Context, address target.Address, data []byte) (int, error) {
				if address != 0x8000 {
					t.Fatalf("address=%#x", address)
				}
				return copy(data, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}), nil
			}
			value, err := evaluateUnwindExpression(context.Background(), test.data, registers, nil, &CFIFrame{}, &unwindBudget{operations: 10000, bytes: 1024, read: read})
			if err != nil || value != test.want {
				t.Fatalf("value=%#x err=%v, want %#x", value, err, test.want)
			}
		})
	}
	cfa := uint64(0x9000)
	value, err := evaluateUnwindExpression(context.Background(), []byte{0x23, 8}, registers, &cfa, &CFIFrame{}, &unwindBudget{operations: 1000})
	if err != nil || value != 0x9008 {
		t.Fatalf("initial CFA = %#x,%v", value, err)
	}
	_, err = evaluateUnwindExpression(context.Background(), []byte{0x23, 8}, registers, nil, &CFIFrame{}, &unwindBudget{operations: 1000})
	if !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("CFA expression starts empty = %v", err)
	}
	value, err = evaluateUnwindExpression(context.Background(), []byte{0x03, 0, 0x10, 0, 0, 0, 0, 0, 0}, registers, nil, &CFIFrame{debug: true, loadBias: 0x400000}, &unwindBudget{operations: 1000})
	if err != nil || value != 0x401000 {
		t.Fatalf("debug address relocation = %#x,%v", value, err)
	}
}

func TestUnwindExpressionGlibcPLTCFA(t *testing.T) {
	data := []byte{0x77, 8, 0x80, 0, 0x3f, 0x1a, 0x39, 0x2a, 0x33, 0x24, 0x22}
	for _, pc := range []uint64{0x1008, 0x1009, 0x100f, 0x1010} {
		registers := unwindTestRegisters(pc, 0x8000)
		value, err := evaluateUnwindExpression(context.Background(), data, registers, nil, &CFIFrame{}, &unwindBudget{operations: 1000})
		want := uint64(0x8008)
		if pc&15 >= 9 {
			want += 8
		}
		if err != nil || value != want {
			t.Fatalf("PLT PC %#x CFA=%#x err=%v, want %#x", pc, value, err, want)
		}
	}
}

func TestUnwindExpressionRejectsUndefinedOrUnsupported(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		err  error
	}{
		{"empty", nil, target.ErrInvalidArgument},
		{"empty_stack", []byte{0x96}, target.ErrInvalidArgument},
		{"underflow", []byte{0x22}, target.ErrInvalidArgument},
		{"pick_underflow", []byte{0x31, 0x15, 1}, target.ErrInvalidArgument},
		{"zero_divisor", []byte{0x31, 0x30, 0x1b}, target.ErrInvalidArgument},
		{"zero_modulus", []byte{0x31, 0x30, 0x1d}, target.ErrInvalidArgument},
		{"overshift", []byte{0x31, 0x08, 64, 0x24}, target.ErrInvalidArgument},
		{"branch_outside", []byte{0x2f, 0xff, 0x7f}, target.ErrInvalidArgument},
		{"branch_into_operand", []byte{0x2f, 1, 0, 0x10, 0x80, 1}, target.ErrInvalidArgument},
		{"loop", []byte{0x2f, 0xfd, 0xff}, target.ErrOverflow},
		{"stack_depth", bytes.Repeat([]byte{0x30}, 65), target.ErrOverflow},
		{"bad_deref_width", []byte{0x30, 0x94, 9}, target.ErrInvalidArgument},
		{"undefined_abs", []byte{0x0e, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x19}, target.ErrOverflow},
		{"unknown_register", []byte{0x92, 17, 0}, target.ErrUnsupported},
		{"missing_register", []byte{0x70, 0}, target.ErrUnavailable},
		{"call_frame_cfa", []byte{0x9c}, target.ErrUnsupported},
		{"register_location", []byte{0x50}, target.ErrUnsupported},
		{"piece", []byte{0x93, 8}, target.ErrUnsupported},
		{"frame_base", []byte{0x91, 8}, target.ErrUnsupported},
		{"call_reference", []byte{0x9a}, target.ErrUnsupported},
		{"tls", []byte{0x9b}, target.ErrUnsupported},
		{"entry_value", []byte{0xa3}, target.ErrUnsupported},
		{"typed", []byte{0xa4}, target.ErrUnsupported},
		{"truncated", []byte{0x03, 1}, io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := evaluateUnwindExpression(context.Background(), test.data, AMD64UnwindRegisters{}, nil, &CFIFrame{}, &unwindBudget{operations: 10000, bytes: 1024})
			if !errors.Is(err, test.err) {
				t.Fatalf("error=%v, want %v", err, test.err)
			}
		})
	}
}

func TestUnwindExpressionBudgetsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := evaluateUnwindExpression(ctx, []byte{0x31}, AMD64UnwindRegisters{}, nil, &CFIFrame{}, &unwindBudget{operations: 1000}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v", err)
	}
	if _, err := evaluateUnwindExpression(context.Background(), []byte{0x31, 0x96}, AMD64UnwindRegisters{}, nil, &CFIFrame{}, &unwindBudget{operations: 1}); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("global steps = %v", err)
	}
	if _, err := evaluateUnwindExpression(context.Background(), []byte{0x30, 0x06}, AMD64UnwindRegisters{}, nil, &CFIFrame{}, &unwindBudget{operations: 1000, bytes: 7}); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("global reads = %v", err)
	}
	if _, err := evaluateUnwindExpression(context.Background(), bytes.Repeat([]byte{0x96}, 4097), AMD64UnwindRegisters{}, nil, &CFIFrame{}, &unwindBudget{operations: 10000}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("length = %v", err)
	}
}
