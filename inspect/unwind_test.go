package inspect

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"

	"fastdbg2/target"
)

func unwindTestFrame(start target.Address, instructions ...byte) *CFIFrame {
	return &CFIFrame{start: start, end: start + 0x100, source: "fixture", entry: start + 0x10000,
		cie: cfiCIE{codeAlign: 1, dataAlign: -8, addressSize: 8, returnRegister: 16,
			initial: cfiProgram{data: []byte{0x0c, 7, 8, 0x90, 1}}},
		program: cfiProgram{data: instructions}}
}

func unwindTestRegisters(pc, sp uint64) AMD64UnwindRegisters {
	registers := AMD64UnwindRegisters{Known: (1 << 17) - 1}
	for i := range registers.Values {
		registers.Values[i] = uint64(0x9000 + i*16)
	}
	registers.Values[7], registers.Values[16] = sp, pc
	return registers
}

func unwindTestMemory(values map[target.Address]uint64) CFIReader {
	return func(ctx context.Context, address target.Address, data []byte) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		value, exists := values[address]
		if !exists || len(data) != 8 {
			return 0, io.EOF
		}
		binary.LittleEndian.PutUint64(data, value)
		return len(data), nil
	}
}

func unwindTestFind(frames ...*CFIFrame) func(context.Context, target.Address) (*CFIFrame, error) {
	return func(ctx context.Context, pc target.Address) (*CFIFrame, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, frame := range frames {
			if pc >= frame.start && pc < frame.end {
				return frame, nil
			}
		}
		return nil, target.ErrUnavailable
	}
}

func TestAMD64UnwindRegistersFromTarget(t *testing.T) {
	var registers []target.Register
	for number, name := range amd64UnwindNames {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(number+1))
		registers = append(registers, target.Register{Name: name, Bits: 64, Data: data, Available: true})
	}
	state, err := AMD64UnwindRegistersFromTarget(registers)
	if err != nil || state.Known != (1<<17)-1 {
		t.Fatalf("registers = %+v, %v", state, err)
	}
	for number := range state.Values {
		if state.Values[number] != uint64(number+1) {
			t.Fatalf("DWARF register %d = %d", number, state.Values[number])
		}
	}
	if _, err := AMD64UnwindRegistersFromTarget(append(registers, registers[0])); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("duplicate = %v", err)
	}
	registers[0].Available = false
	registers[0].Data = nil
	state, err = AMD64UnwindRegistersFromTarget(registers)
	if err != nil || state.Known&1 != 0 {
		t.Fatalf("unavailable = %+v, %v", state, err)
	}
	registers[1].Bits = 32
	if _, err := AMD64UnwindRegistersFromTarget(registers); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("width = %v", err)
	}
}

func TestUnwindAMD64ExactPCAndABIProfile(t *testing.T) {
	seed := unwindTestRegisters(0x1001, 0x8000)
	top, bottom := unwindTestFrame(0x1000), unwindTestFrame(0x2000, 0x07, 16)
	result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: seed, PC: 0x1000, Find: unwindTestFind(top, bottom), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0x2001}), MaxFrames: 8})
	if err != nil || !result.Complete || len(result.Frames) != 2 {
		t.Fatalf("unwind = %+v, %v", result, err)
	}
	first, caller := result.Frames[0], result.Frames[1]
	if first.PC != 0x1000 || first.RawPC != 0x1001 || first.LookupPC != 0x1000 || first.ReturnPC || first.Registers != seed || first.CFA != 0x8008 {
		t.Fatalf("first = %+v", first)
	}
	if caller.PC != 0x2001 || caller.RawPC != 0x2001 || caller.LookupPC != 0x2000 || !caller.ReturnPC || caller.Registers.Values[7] != 0x8008 {
		t.Fatalf("caller = %+v", caller)
	}
	for _, number := range []int{3, 6, 12, 13, 14, 15} {
		if caller.Registers.Known&(1<<number) == 0 || caller.Registers.Values[number] != seed.Values[number] {
			t.Fatalf("callee-saved register %d = %+v", number, caller.Registers)
		}
	}
	for _, number := range []int{0, 1, 2, 4, 5, 8, 9, 10, 11} {
		if caller.Registers.Known&(1<<number) != 0 {
			t.Fatalf("caller-saved register %d fabricated", number)
		}
	}
}

func TestUnwindAMD64TrapAdjustedExpressionRegister(t *testing.T) {
	top := unwindTestFrame(0x1000, 0x0f, 2, 0x80, 0)
	bottom := unwindTestFrame(0x2000, 0x07, 16)
	result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: unwindTestRegisters(0x1001, 0x8000), PC: 0x1000, Find: unwindTestFind(top, bottom), Read: unwindTestMemory(map[target.Address]uint64{0xff8: 0x2001}), MaxFrames: 2})
	if err != nil || !result.Complete || len(result.Frames) != 2 || result.Frames[0].CFA != 0x1000 || result.Frames[0].RawPC != 0x1001 {
		t.Fatalf("trap expression = %+v, %v", result, err)
	}
}

func TestUnwindAMD64SignalCFINoPCDecrement(t *testing.T) {
	top := unwindTestFrame(0x1000, 0x0f, 3, 0x77, 0x10, 0x06, 0x10, 7, 2, 0x77, 0x10, 0x10, 16, 2, 0x77, 0x18)
	top.cie.signal = true
	bottom := unwindTestFrame(0x2000, 0x07, 16)
	result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, Find: unwindTestFind(top, bottom), Read: unwindTestMemory(map[target.Address]uint64{0x8010: 0x5000, 0x8018: 0x2000}), MaxFrames: 8})
	if err != nil || !result.Complete || len(result.Frames) != 2 {
		t.Fatalf("signal = %+v, %v", result, err)
	}
	if result.Frames[1].PC != 0x2000 || result.Frames[1].LookupPC != 0x2000 || result.Frames[1].ReturnPC || result.Frames[1].Registers.Values[7] != 0x5000 {
		t.Fatalf("signal interrupted frame = %+v", result.Frames[1])
	}
}

func TestUnwindAMD64SimultaneousRegisterRecovery(t *testing.T) {
	top := unwindTestFrame(0x1000, 0x09, 3, 6, 0x09, 6, 3)
	bottom := unwindTestFrame(0x2000, 0x07, 16)
	seed := unwindTestRegisters(0x1000, 0x8000)
	result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: seed, PC: 0x1000, Find: unwindTestFind(top, bottom), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0x2001}), MaxFrames: 8})
	if err != nil || result.Frames[1].Registers.Values[3] != seed.Values[6] || result.Frames[1].Registers.Values[6] != seed.Values[3] {
		t.Fatalf("simultaneous = %+v, %v", result, err)
	}
}

func TestUnwindAMD64PartialAndFatalResults(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"unavailable", target.ErrUnavailable, 1},
		{"ambiguous", target.ErrAmbiguous, 1},
		{"stale", target.ErrStale, 0},
		{"cancel", context.Canceled, 0},
		{"deadline", context.DeadlineExceeded, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, MaxFrames: 2}
			request.Find = func(context.Context, target.Address) (*CFIFrame, error) { return nil, test.err }
			result, err := UnwindAMD64(context.Background(), request)
			if !errors.Is(err, test.err) || len(result.Frames) != test.want {
				t.Fatalf("find error = %+v, %v", result, err)
			}
			request.Find = unwindTestFind(unwindTestFrame(0x1000))
			request.Read = func(context.Context, target.Address, []byte) (int, error) { return 0, test.err }
			result, err = UnwindAMD64(context.Background(), request)
			if !errors.Is(err, test.err) || len(result.Frames) != test.want {
				t.Fatalf("read error = %+v, %v", result, err)
			}
		})
	}
	request := AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, Find: unwindTestFind(unwindTestFrame(0x1000)), Read: func(context.Context, target.Address, []byte) (int, error) { return 7, nil }, MaxFrames: 2}
	result, err := UnwindAMD64(context.Background(), request)
	if !errors.Is(err, target.ErrPartial) || len(result.Frames) != 1 || result.Complete || result.Limited {
		t.Fatalf("short read = %+v, %v", result, err)
	}
}

func TestUnwindAMD64LimitAndTermination(t *testing.T) {
	request := AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, Find: unwindTestFind(unwindTestFrame(0x1000)), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0x2001}), MaxFrames: 1}
	result, err := UnwindAMD64(context.Background(), request)
	if _, ok := err.(*UnwindLimitError); !ok || !result.Limited || result.Complete || len(result.Frames) != 1 || !result.Frames[0].CFAKnown || len(result.Frames[0].Saved) != 17 {
		t.Fatalf("limit = %+v, %v", result, err)
	}
	top := unwindTestFrame(0x1000, 0x07, 16)
	top.cie.initial.data = nil
	request.Find = unwindTestFind(top)
	result, err = UnwindAMD64(context.Background(), request)
	if err != nil || !result.Complete || result.Limited || result.Frames[0].CFAKnown {
		t.Fatalf("explicit bottom = %+v, %v", result, err)
	}
	top.program.data = nil
	result, err = UnwindAMD64(context.Background(), request)
	if !errors.Is(err, target.ErrUnavailable) || result.Complete {
		t.Fatalf("missing CFI is not bottom = %+v, %v", result, err)
	}
}

func TestUnwindAMD64CyclesAndZeroReturn(t *testing.T) {
	top := unwindTestFrame(0x1000, 0x0e, 0, 0x08, 16)
	seed := unwindTestRegisters(0x1001, 0x8000)
	result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: seed, PC: 0x1001, Find: unwindTestFind(top), MaxFrames: 8})
	if !errors.Is(err, target.ErrInvalidState) || len(result.Frames) > 3 || result.Complete {
		t.Fatalf("cycle = %+v, %v", result, err)
	}
	top = unwindTestFrame(0x1000)
	result, err = UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: seed, PC: 0x1001, Find: unwindTestFind(top), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0}), MaxFrames: 8})
	if !errors.Is(err, target.ErrUnavailable) || result.Complete || len(result.Frames) != 1 {
		t.Fatalf("zero RA = %+v, %v", result, err)
	}
}

func TestUnwindCFIRowsRestoreAndBoundary(t *testing.T) {
	frame := unwindTestFrame(0x1000, 0x83, 2, 0x0a, 0x0e, 24, 0x44, 0x0b, 0xc3, 0x44, 0x0e, 16)
	for _, test := range []struct {
		pc     target.Address
		offset int64
		kind   unwindRuleKind
	}{{0x1003, 24, unwindOffset}, {0x1004, 8, unwindSame}, {0x1007, 8, unwindSame}, {0x1008, 16, unwindSame}} {
		row, err := evaluateCFIRow(context.Background(), frame, test.pc, &unwindBudget{operations: 1000, profile: UnwindSysVAMD64})
		if err != nil || row.cfa.offset != test.offset || row.rules[3].kind != test.kind {
			t.Fatalf("row %#x = %+v, %v", test.pc, row, err)
		}
	}
	frame.cie.initial.data = []byte{0x08, 3, 0x83, 2, 0xc3, 0x0c, 7, 8, 0x90, 1}
	frame.program.data = nil
	row, err := evaluateCFIRow(context.Background(), frame, 0x1000, &unwindBudget{operations: 1000, profile: UnwindSysVAMD64})
	if err != nil || row.rules[3].kind != unwindSame {
		t.Fatalf("CIE restore uses unmodified ABI defaults = %+v, %v", row, err)
	}
}

func TestUnwindCFIRowMalformed(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		err  error
	}{
		{"unknown", []byte{0x17}, target.ErrUnsupported},
		{"restore_underflow", []byte{0x0b}, target.ErrInvalidArgument},
		{"huge_register", []byte{0x07, 0x80, 0x08}, target.ErrUnsupported},
		{"truncated", []byte{0x0c, 7}, io.ErrUnexpectedEOF},
		{"advance_over_range", []byte{0x04, 1, 1, 0, 0}, target.ErrInvalidArgument},
		{"set_loc_backward", []byte{0x01, 0, 0x10, 0, 0, 0, 0, 0, 0}, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := unwindTestFrame(0x1000, test.data...)
			_, err := evaluateCFIRow(context.Background(), frame, 0x1000, &unwindBudget{operations: 1000, profile: UnwindSysVAMD64})
			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}
		})
	}
	frame := unwindTestFrame(0x1000, 0x0d, 7)
	frame.cie.initial.data = nil
	if _, err := evaluateCFIRow(context.Background(), frame, 0x1000, &unwindBudget{operations: 1000, profile: UnwindSysVAMD64}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("CFA update without rule = %v", err)
	}
	frame = unwindTestFrame(0x1000)
	frame.program.data = make([]byte, 65)
	for i := range frame.program.data {
		frame.program.data[i] = 0x0a
	}
	if _, err := evaluateCFIRow(context.Background(), frame, 0x1000, &unwindBudget{operations: 1000, profile: UnwindSysVAMD64}); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("remember depth = %v", err)
	}
}

func TestUnwindFactoredOffsets(t *testing.T) {
	for _, test := range []struct {
		value uint64
		align int64
		want  int64
		bad   bool
	}{{1 << 63, -1, math.MinInt64, false}, {math.MaxUint64, 0, 0, false}, {1, math.MinInt64, math.MinInt64, false}, {2, math.MinInt64, 0, true}, {math.MaxInt64, 1, math.MaxInt64, false}, {1 << 63, 1, 0, true}} {
		got, err := unwindUnsignedFactored(test.value, test.align)
		if (err != nil) != test.bad || !test.bad && got != test.want {
			t.Fatalf("factor(%d,%d)=%d,%v", test.value, test.align, got, err)
		}
	}
	if _, err := unwindFactored(math.MinInt64, -1); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("signed overflow = %v", err)
	}
}

func TestUnwindResultDoesNotAliasSeed(t *testing.T) {
	seed := unwindTestRegisters(0x1000, 0x8000)
	original := seed
	result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: seed, PC: 0x1000, Find: unwindTestFind(unwindTestFrame(0x1000, 0x07, 16)), MaxFrames: 1})
	if err != nil || !reflect.DeepEqual(seed, original) {
		t.Fatalf("seed mutated = %+v, %v", seed, err)
	}
	result.Frames[0].Registers.Values[0] = 1
	if seed != original {
		t.Fatal("result aliases seed")
	}
}

func TestUnwindCancellationOverridesCallbackErrors(t *testing.T) {
	for _, stage := range []string{"find", "read_short", "read_error", "read_bad_count"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := AMD64UnwindRequest{Profile: UnwindSysVAMD64, Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, MaxFrames: 2}
			request.Find = unwindTestFind(unwindTestFrame(0x1000))
			if stage == "find" {
				request.Find = func(context.Context, target.Address) (*CFIFrame, error) {
					cancel()
					return nil, target.ErrNotFound
				}
			} else {
				request.Read = func(context.Context, target.Address, []byte) (int, error) {
					cancel()
					if stage == "read_error" {
						return 0, io.ErrUnexpectedEOF
					}
					if stage == "read_bad_count" {
						return 100, nil
					}
					return 0, nil
				}
			}
			result, err := UnwindAMD64(ctx, request)
			if !errors.Is(err, context.Canceled) || len(result.Frames) != 0 || result.Complete || result.Limited {
				t.Fatalf("cancellation retained result: %+v, %v", result, err)
			}
		})
	}
}

func TestUnwindStrictCFIDoesNotInventABIRegisters(t *testing.T) {
	top, bottom := unwindTestFrame(0x1000), unwindTestFrame(0x2000, 0x07, 16)
	request := AMD64UnwindRequest{Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, Find: unwindTestFind(top, bottom), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0x2001}), MaxFrames: 8}
	result, err := UnwindAMD64(context.Background(), request)
	if !errors.Is(err, target.ErrUnavailable) || result.Complete || len(result.Frames) != 2 {
		t.Fatalf("strict result = %+v, %v", result, err)
	}
	caller := result.Frames[1]
	if caller.Registers.Known != 1<<16 || caller.CFAKnown {
		t.Fatalf("strict invented caller state: %+v", caller)
	}
	for _, number := range []int{3, 6, 7, 12, 13, 14, 15} {
		saved := result.Frames[0].Saved[number]
		if saved.Available || saved.Provenance != "unavailable" {
			t.Fatalf("strict fabricated register %d: %+v", number, saved)
		}
	}
	if saved := result.Frames[0].Saved[16]; !saved.Available || saved.Provenance != "cfi" {
		t.Fatalf("explicit RA not available: %+v", saved)
	}
	request.Profile = UnwindSysVAMD64
	result, err = UnwindAMD64(context.Background(), request)
	if err != nil || !result.Complete {
		t.Fatalf("explicit SysV result = %+v, %v", result, err)
	}
	for _, number := range []int{3, 6, 7, 12, 13, 14, 15} {
		saved := result.Frames[0].Saved[number]
		if !saved.Available || saved.Provenance != "abi:sysv-amd64" {
			t.Fatalf("ABI provenance %d = %+v", number, saved)
		}
	}
}

func TestUnwindStrictExplicitCFICallerStackPointer(t *testing.T) {
	top := unwindTestFrame(0x1000, 0x14, 7, 0, 0x08, 3)
	bottom := unwindTestFrame(0x2000, 0x07, 16)
	request := AMD64UnwindRequest{Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, Find: unwindTestFind(top, bottom), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0x2001}), MaxFrames: 8}
	result, err := UnwindAMD64(context.Background(), request)
	if err != nil || !result.Complete || len(result.Frames) != 2 {
		t.Fatalf("strict explicit CFI = %+v, %v", result, err)
	}
	for _, number := range []int{3, 7, 16} {
		saved := result.Frames[0].Saved[number]
		if !saved.Available || saved.Provenance != "cfi" {
			t.Fatalf("explicit CFI register %d = %+v", number, saved)
		}
	}
	if result.Frames[1].Registers.Known&(1<<6) != 0 {
		t.Fatal("unmentioned RBP inherited in strict mode")
	}
	top.program.data = []byte{0x07, 3}
	request.Profile = UnwindSysVAMD64
	result, err = UnwindAMD64(context.Background(), request)
	if err != nil || !result.Complete || result.Frames[1].Registers.Known&(1<<3) != 0 || result.Frames[0].Saved[3].Provenance != "cfi" {
		t.Fatalf("explicit undefined overrides ABI default = %+v, %v", result, err)
	}
}

func TestUnwindCFIExtendedRules(t *testing.T) {
	for _, test := range []struct {
		name         string
		program      []byte
		register     uint64
		value        uint64
		address      target.Address
		addressKnown bool
	}{
		{"offset_extended", []byte{0x05, 3, 2}, 3, 0x1111, 0x7ff8, true},
		{"offset_signed", []byte{0x11, 3, 0x7f}, 3, 0x2222, 0x8010, true},
		{"value_offset", []byte{0x14, 3, 2}, 3, 0x7ff8, 0, false},
		{"value_signed", []byte{0x15, 3, 0x7f}, 3, 0x8010, 0, false},
		{"gnu_negative_offset", []byte{0x2f, 3, 1}, 3, 0x2222, 0x8010, true},
		{"expression", []byte{0x10, 3, 2, 0x23, 8}, 3, 0x2222, 0x8010, true},
		{"value_expression", []byte{0x16, 3, 2, 0x23, 8}, 3, 0x8010, 0, false},
		{"same_volatile", []byte{0x08, 0}, 0, 0x9000, 0, false},
		{"signed_cfa", []byte{0x12, 7, 0x7f, 0x14, 3, 0}, 3, 0x8008, 0, false},
		{"signed_cfa_offset", []byte{0x13, 0x7e, 0x14, 3, 0, 0x90, 2}, 3, 0x8010, 0, false},
		{"gnu_args_size", []byte{0x2e, 0x80, 1, 0x14, 3, 0}, 3, 0x8008, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := unwindTestFrame(0x1000, test.program...)
			result, err := UnwindAMD64(context.Background(), AMD64UnwindRequest{Registers: unwindTestRegisters(0x1000, 0x8000), PC: 0x1000, Find: unwindTestFind(frame), Read: unwindTestMemory(map[target.Address]uint64{0x8000: 0x2001, 0x7ff8: 0x1111, 0x8010: 0x2222}), MaxFrames: 1})
			if _, ok := err.(*UnwindLimitError); !ok || len(result.Frames) != 1 {
				t.Fatalf("result=%+v, %v", result, err)
			}
			saved := result.Frames[0].Saved[test.register]
			if saved.Value != test.value || !saved.Available || saved.Address != test.address || saved.AddressKnown != test.addressKnown || saved.Provenance != "cfi" {
				t.Fatalf("saved=%+v, want %+v", saved, test)
			}
		})
	}
}
