package inspect_test

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestDisassembleAArch64(t *testing.T) {
	code := []byte{
		0x1f, 0x20, 0x03, 0xd5,
		0x20, 0x00, 0x80, 0xd2,
		0x00, 0x04, 0x00, 0x91,
		0xc0, 0x03, 0x5f, 0xd6,
	}
	result, err := inspect.Disassemble(target.AArch64, 0x401000, code, 0)
	if err != nil || len(result) != 4 {
		t.Fatalf("instructions: %+v, %v", result, err)
	}
	wantText := []string{"nop", "mov x0, #0x1", "add x0, x0, #0x1", "ret"}
	for i, inst := range result {
		if inst.Address != 0x401000+target.Address(i*4) || !bytes.Equal(inst.Bytes, code[i*4:i*4+4]) || inst.Text != wantText[i] {
			t.Fatalf("instruction %d: %+v; want %q", i, inst, wantText[i])
		}
	}
	code[0] = 0
	if result[0].Bytes[0] != 0x1f {
		t.Fatal("instruction bytes alias the input")
	}
	result[1].Bytes[0] = 0xff
	if code[4] != 0x20 || result[2].Bytes[0] != 0 {
		t.Fatal("instruction bytes alias another buffer")
	}
}

func TestDisassembleAArch64LimitAndForwardOnly(t *testing.T) {
	code := []byte{0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5}
	result, err := inspect.Disassemble(target.AArch64, 0x1000, code, 1)
	if err != nil || len(result) != 1 || result[0].Text != "ret" {
		t.Fatalf("limited decode: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AArch64, 0x1000, code, 0)
	if err != nil || len(result) != 3 {
		t.Fatalf("ret must not infer a function boundary: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AArch64, 0x1004, code[4:], 8)
	if err != nil || len(result) != 2 || result[0].Address != 0x1004 {
		t.Fatalf("explicit start address: %+v, %v", result, err)
	}
	for _, tail := range [][]byte{{0x1f}, {0xff, 0xff, 0xff, 0xff}} {
		result, err = inspect.Disassemble(target.AArch64, 0x1000, append(slices.Clone(code[:4]), tail...), 1)
		if err != nil || len(result) != 1 {
			t.Fatalf("bytes beyond limit must not be decoded: %+v, %v", result, err)
		}
	}
}

func TestDisassembleAArch64PCRelativeText(t *testing.T) {
	code := []byte{0x02, 0x00, 0x00, 0x14}
	for _, start := range []target.Address{0, 0x1000, math.MaxUint64 - 3} {
		result, err := inspect.Disassemble(target.AArch64, start, code, 0)
		if err != nil || len(result) != 1 || result[0].Address != start || result[0].Text != "b .+0x8" {
			t.Fatalf("relative branch at %#x: %+v, %v", start, result, err)
		}
	}
}

func TestDisassembleAArch64NeverSwapsInstructionByteOrder(t *testing.T) {
	result, err := inspect.Disassemble(target.AArch64, 0x1000, []byte{0x1f, 0x20, 0x03, 0xd5}, 0)
	if err != nil || len(result) != 1 || result[0].Text != "nop" {
		t.Fatalf("little-endian instruction: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AArch64, 0x1000, []byte{0xd5, 0x03, 0x20, 0x1f}, 0)
	if len(result) != 0 && result[0].Text == "nop" {
		t.Fatalf("byte-swapped instruction was automatically corrected: %+v, %v", result, err)
	}
}

func TestDisassembleAArch64PartialDoesNotSkipInvalidBytes(t *testing.T) {
	nop := []byte{0x1f, 0x20, 0x03, 0xd5}
	for _, tail := range [][]byte{{0x1f}, {0x1f, 0x20}, {0x1f, 0x20, 0x03}, {0xff, 0xff, 0xff, 0xff}} {
		result, err := inspect.Disassemble(target.AArch64, 0x1000, append(slices.Clone(nop), tail...), 0)
		if !errors.Is(err, target.ErrUnavailable) || len(result) != 1 || result[0].Text != "nop" || !strings.Contains(err.Error(), "0x1004") {
			t.Fatalf("tail=%x result=%+v err=%v", tail, result, err)
		}
		result, err = inspect.Disassemble(target.AArch64, 0x1000, tail, 0)
		if !errors.Is(err, target.ErrUnavailable) || len(result) != 0 {
			t.Fatalf("initial invalid instruction: %+v, %v", result, err)
		}
	}
	code := append(slices.Clone(nop), 0xff, 0xff, 0xff, 0xff)
	code = append(code, nop...)
	result, err := inspect.Disassemble(target.AArch64, 0x1000, code, 0)
	if !errors.Is(err, target.ErrUnavailable) || len(result) != 1 {
		t.Fatalf("decoder must not resume beyond unknown encoding: %+v, %v", result, err)
	}
}

func TestDisassembleAArch64Arguments(t *testing.T) {
	nop := []byte{0x1f, 0x20, 0x03, 0xd5}
	for _, test := range []struct {
		start target.Address
		code  []byte
		limit int
		want  error
	}{
		{0, nop, -1, target.ErrInvalidArgument},
		{1, nop, 0, target.ErrInvalidArgument},
		{2, nop, 0, target.ErrInvalidArgument},
		{3, nop, 0, target.ErrInvalidArgument},
		{1, nil, 0, target.ErrInvalidArgument},
		{math.MaxUint64 - 3, append(slices.Clone(nop), 0), 0, target.ErrOverflow},
		{math.MaxUint64 - 3, append(slices.Clone(nop), 0), 1, target.ErrOverflow},
	} {
		result, err := inspect.Disassemble(target.AArch64, test.start, test.code, test.limit)
		if len(result) != 0 || !errors.Is(err, test.want) {
			t.Fatalf("case=%+v result=%+v err=%v", test, result, err)
		}
	}
	if result, err := inspect.Disassemble(target.AArch64, 0, nil, 0); err != nil || len(result) != 0 {
		t.Fatalf("empty input: %+v, %v", result, err)
	}
	if result, err := inspect.Disassemble(target.AArch64, math.MaxUint64-3, nop, 0); err != nil || len(result) != 1 || result[0].Address != math.MaxUint64-3 {
		t.Fatalf("last representable instruction: %+v, %v", result, err)
	}
	for _, arch := range []target.Architecture{"arm", "arm64", "aarch32", "thumb"} {
		if result, err := inspect.Disassemble(arch, 0, nop, 0); !errors.Is(err, target.ErrUnsupported) || len(result) != 0 {
			t.Fatalf("architecture must not be inferred from %q: %+v, %v", arch, result, err)
		}
	}
}

func TestDisassembleAArch64Concurrent(t *testing.T) {
	code := []byte{0x1f, 0x20, 0x03, 0xd5, 0x20, 0x00, 0x80, 0xd2, 0x00, 0x04, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6}
	ready := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			for range 128 {
				result, err := inspect.Disassemble(target.AArch64, 0x1000, code, 0)
				if err != nil || len(result) != 4 || result[0].Text != "nop" || result[3].Text != "ret" {
					t.Errorf("concurrent AArch64 decode: %+v, %v", result, err)
					return
				}
				result, err = inspect.Disassemble(target.AMD64, 0x1000, []byte{0x90}, 0)
				if err != nil || len(result) != 1 || result[0].Text != "nop" {
					t.Errorf("concurrent AMD64 decode: %+v, %v", result, err)
					return
				}
			}
		}()
	}
	close(ready)
	wg.Wait()
}

func FuzzDisassembleAArch64(f *testing.F) {
	f.Add([]byte{0x1f, 0x20, 0x03, 0xd5}, uint64(0x1000), int8(0))
	f.Add([]byte{0x1f, 0x20, 0x03, 0xd5}, uint64(math.MaxUint64-3), int8(1))
	f.Add([]byte{0x1f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0xff}, uint64(0), int8(0))
	f.Add([]byte{0x1f, 0x20}, uint64(0x1000), int8(0))
	f.Fuzz(func(t *testing.T, code []byte, start uint64, limit int8) {
		if len(code) > 4096 {
			t.Skip()
		}
		original := slices.Clone(code)
		result, err := inspect.Disassemble(target.AArch64, target.Address(start), code, int(limit))
		if !bytes.Equal(code, original) {
			t.Fatal("decoder mutated input")
		}
		for i, inst := range result {
			if inst.Address != target.Address(start)+target.Address(i*4) || !bytes.Equal(inst.Bytes, code[i*4:i*4+4]) || inst.Text == "" {
				t.Fatalf("instruction %d is not an exact 4-byte prefix: %+v", i, inst)
			}
		}
		if limit > 0 && len(result) > int(limit) {
			t.Fatal("instruction count exceeds limit")
		}
		if err == nil && (limit == 0 || len(result) < int(limit)) && len(result)*4 != len(code) {
			t.Fatal("successful decode left undecoded bytes within limit")
		}
		repeated, repeatedErr := inspect.Disassemble(target.AArch64, target.Address(start), original, int(limit))
		if !reflect.DeepEqual(result, repeated) || (err == nil) != (repeatedErr == nil) {
			t.Fatal("decoder returned nondeterministic results")
		}
	})
}
