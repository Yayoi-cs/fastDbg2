package inspect_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestDisassembleX86(t *testing.T) {
	code := []byte{0x55, 0x89, 0xe5, 0x48, 0xc3}
	result, err := inspect.Disassemble(target.X86, 0x8048000, code, 0)
	want := []inspect.Instruction{
		{Address: 0x8048000, Bytes: []byte{0x55}, Text: "push ebp"},
		{Address: 0x8048001, Bytes: []byte{0x89, 0xe5}, Text: "mov ebp, esp"},
		{Address: 0x8048003, Bytes: []byte{0x48}, Text: "dec eax"},
		{Address: 0x8048004, Bytes: []byte{0xc3}, Text: "ret"},
	}
	if err != nil || !reflect.DeepEqual(result, want) {
		t.Fatalf("got %+v, %v; want %+v", result, err, want)
	}
	code[0] = 0
	if result[0].Bytes[0] != 0x55 {
		t.Fatal("instruction bytes alias input")
	}
	result[1].Bytes[0] = 0xff
	if code[1] != 0x89 || result[2].Bytes[0] != 0x48 {
		t.Fatal("instruction bytes alias another buffer")
	}
}

func TestDisassembleX86ModeIsExplicit(t *testing.T) {
	code := []byte{0x48, 0x89, 0xe5}
	result, err := inspect.Disassemble(target.X86, 0x1000, code, 0)
	if err != nil || len(result) != 2 || result[0].Text != "dec eax" || result[1].Text != "mov ebp, esp" {
		t.Fatalf("32-bit decode: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, 0x1000, code, 0)
	if err != nil || len(result) != 1 || result[0].Text != "mov rbp, rsp" {
		t.Fatalf("64-bit decode changed: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.X86, 0x1000, []byte{0x48}, 0)
	if err != nil || len(result) != 1 || result[0].Text != "dec eax" {
		t.Fatalf("single-byte DEC: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, 0x1000, []byte{0x48}, 0)
	if err == nil || len(result) != 0 {
		t.Fatalf("REX prefix must remain truncated in AMD64: %+v, %v", result, err)
	}
}

func TestDisassembleX86RelativeTargets(t *testing.T) {
	for _, test := range []struct {
		name  string
		start target.Address
		code  []byte
		text  string
	}{
		{"zero_pc", 0, []byte{0xeb, 0x05}, "jmp 0x7"},
		{"zero_target", 0, []byte{0xeb, 0xfe}, "jmp 0x0"},
		{"short_negative_wrap", 0, []byte{0xeb, 0xfc}, "jmp 0xfffffffe"},
		{"short_positive_wrap", math.MaxUint32 - 1, []byte{0xeb, 0x05}, "jmp 0x5"},
		{"near_negative_wrap", 0, []byte{0xe9, 0xf0, 0xff, 0xff, 0xff}, "jmp 0xfffffff5"},
		{"near_positive_wrap", math.MaxUint32 - 4, []byte{0xe9, 0x01, 0x00, 0x00, 0x00}, "jmp 0x1"},
		{"call_negative", 0, []byte{0xe8, 0xfc, 0xff, 0xff, 0xff}, "call 0x1"},
		{"call_positive_wrap", math.MaxUint32 - 4, []byte{0xe8, 0x05, 0x00, 0x00, 0x00}, "call 0x5"},
		{"short_condition", 0, []byte{0x74, 0xfe}, "jz 0x0"},
		{"near_condition", 0, []byte{0x0f, 0x85, 0x10, 0x00, 0x00, 0x00}, "jnz 0x16"},
		{"near_condition_signed_min", 0, []byte{0x0f, 0x85, 0x00, 0x00, 0x00, 0x80}, "jnz 0x80000006"},
		{"data16_near", 0x12345000, []byte{0x66, 0xe9, 0x00, 0x00}, "jmp 0x5004"},
		{"data16_near_positive_wrap", 0x12348000, []byte{0x66, 0xe9, 0xff, 0x7f}, "jmp 0x3"},
		{"data16_near_negative_wrap", 0, []byte{0x66, 0xe9, 0xfb, 0xff}, "jmp 0xffff"},
		{"data16_call", 0x12345000, []byte{0x66, 0xe8, 0x00, 0x00}, "call 0x5004"},
		{"data16_near_condition", 0x12345000, []byte{0x66, 0x0f, 0x85, 0x00, 0x00}, "jnz 0x5005"},
		{"data16_short", 0x12345000, []byte{0x66, 0xeb, 0x00}, "jmp 0x5003"},
		{"data16_short_condition", 0x12345000, []byte{0x66, 0x75, 0x00}, "jnz 0x5003"},
		{"data16_jecxz", 0x12345000, []byte{0x66, 0xe3, 0x00}, "jecxz 0x5003"},
		{"addr16_jcxz", 0x12345000, []byte{0x67, 0xe3, 0x00}, "addr16 jcxz 0x12345003"},
		{"data16_loop", 0x12345000, []byte{0x66, 0xe2, 0x00}, "loop 0x5003"},
		{"addr16_loop", 0x12345000, []byte{0x67, 0xe2, 0x00}, "addr16 loop 0x12345003"},
		{"xbegin32_positive_wrap", math.MaxUint32 - 5, []byte{0xc7, 0xf8, 0x04, 0x00, 0x00, 0x00}, "xbegin 0x4"},
		{"xbegin16_keeps_eip_width", 0x12345000, []byte{0x66, 0xc7, 0xf8, 0x00, 0x00}, "xbegin 0x12345005"},
		{"xbegin16_signed_offset", 0x12345000, []byte{0x66, 0xc7, 0xf8, 0xfc, 0xff}, "xbegin 0x12345001"},
		{"xbegin16_negative_wrap", 0, []byte{0x66, 0xc7, 0xf8, 0xfa, 0xff}, "xbegin 0xffffffff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := inspect.Disassemble(target.X86, test.start, test.code, 0)
			if err != nil || len(result) != 1 || result[0].Address != test.start || result[0].Text != test.text || !bytes.Equal(result[0].Bytes, test.code) {
				t.Fatalf("got %+v, %v; want %q", result, err, test.text)
			}
		})
	}
}

func TestDisassembleX86NonRelativeOperands(t *testing.T) {
	for _, test := range []struct {
		code []byte
		text string
	}{
		{[]byte{0xff, 0xe0}, "jmp eax"},
		{[]byte{0xb8, 0xff, 0xff, 0xff, 0xff}, "mov eax, 0xffffffff"},
		{[]byte{0x66, 0xb8, 0x34, 0x12}, "mov ax, 0x1234"},
		{[]byte{0x0f, 0x0b}, "ud2"},
	} {
		result, err := inspect.Disassemble(target.X86, 0x1000, test.code, 0)
		if err != nil || len(result) != 1 || result[0].Text != test.text {
			t.Fatalf("non-relative operand code=%x: %+v, %v; want %q", test.code, result, err, test.text)
		}
	}
}

func TestDisassembleX86EveryConditionalBranchWidth(t *testing.T) {
	mnemonics := []string{"jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "jnbe", "js", "jns", "jp", "jnp", "jl", "jnl", "jle", "jnle"}
	for condition, mnemonic := range mnemonics {
		for _, test := range []struct {
			code   []byte
			target uint32
		}{
			{[]byte{0x70 + byte(condition), 0}, 0x12345002},
			{[]byte{0x66, 0x70 + byte(condition), 0}, 0x5003},
			{[]byte{0x0f, 0x80 + byte(condition), 0, 0, 0, 0}, 0x12345006},
			{[]byte{0x66, 0x0f, 0x80 + byte(condition), 0, 0}, 0x5005},
		} {
			result, err := inspect.Disassemble(target.X86, 0x12345000, test.code, 0)
			want := fmt.Sprintf("%s %#x", mnemonic, test.target)
			if err != nil || len(result) != 1 || result[0].Text != want {
				t.Fatalf("code=%x: %+v, %v; want %q", test.code, result, err, want)
			}
		}
	}
	for opcode, mnemonic := range map[byte]string{0xe0: "loopne", 0xe1: "loope", 0xe2: "loop", 0xe3: "jecxz"} {
		result, err := inspect.Disassemble(target.X86, math.MaxUint32-1, []byte{opcode, 0x7f}, 0)
		if err != nil || len(result) != 1 || result[0].Text != mnemonic+" 0x7f" {
			t.Fatalf("counter branch code=%x: %+v, %v", opcode, result, err)
		}
	}
}

func TestDisassembleX86LimitAndForwardOnly(t *testing.T) {
	code := []byte{0xc3, 0x90, 0x48}
	result, err := inspect.Disassemble(target.X86, 0x1000, code, 1)
	if err != nil || len(result) != 1 || result[0].Text != "ret" {
		t.Fatalf("limited decode: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.X86, 0x1000, code, 0)
	if err != nil || len(result) != 3 {
		t.Fatalf("ret must not infer a function boundary: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.X86, 0x1001, code[1:], 10)
	if err != nil || len(result) != 2 || result[0].Address != 0x1001 {
		t.Fatalf("explicit unaligned start: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.X86, 0x1000, []byte{0x90, 0x66}, 1)
	if err != nil || len(result) != 1 {
		t.Fatalf("bytes after instruction limit must not be decoded: %+v, %v", result, err)
	}
}

func TestDisassembleX86PartialDoesNotSkipInvalidBytes(t *testing.T) {
	for _, tail := range [][]byte{{0x66}, {0x0f}, {0xe8, 0x01}, {0x8b}, {0x0f, 0xff}} {
		code := append([]byte{0x90}, tail...)
		result, err := inspect.Disassemble(target.X86, 0x1000, code, 0)
		if err == nil || len(result) != 1 || result[0].Text != "nop" || !strings.Contains(err.Error(), "0x1001") {
			t.Fatalf("code=%x result=%+v err=%v", code, result, err)
		}
		result, err = inspect.Disassemble(target.X86, 0x1000, tail, 0)
		if err == nil || len(result) != 0 {
			t.Fatalf("initial invalid encoding code=%x: %+v, %v", tail, result, err)
		}
	}
	result, err := inspect.Disassemble(target.X86, 0x1000, []byte{0x90, 0x0f, 0xff, 0x90}, 0)
	if err == nil || len(result) != 1 {
		t.Fatalf("decoder must not resume beyond unknown encoding: %+v, %v", result, err)
	}
}

func TestDisassembleX86AddressBounds(t *testing.T) {
	for _, test := range []struct {
		start target.Address
		code  []byte
		limit int
		want  error
	}{
		{0, []byte{0x90}, -1, target.ErrInvalidArgument},
		{math.MaxUint32 + 1, nil, 0, target.ErrOverflow},
		{math.MaxUint32 + 1, []byte{0x90}, 0, target.ErrOverflow},
		{math.MaxUint64, nil, 0, target.ErrOverflow},
		{math.MaxUint32, []byte{0x90, 0x90}, 0, target.ErrOverflow},
		{math.MaxUint32, []byte{0x90, 0x90}, 1, target.ErrOverflow},
	} {
		result, err := inspect.Disassemble(target.X86, test.start, test.code, test.limit)
		if len(result) != 0 || !errors.Is(err, test.want) {
			t.Fatalf("case=%+v result=%+v err=%v", test, result, err)
		}
	}
	for _, start := range []target.Address{0, math.MaxUint32} {
		if result, err := inspect.Disassemble(target.X86, start, nil, 0); err != nil || len(result) != 0 {
			t.Fatalf("empty input at %#x: %+v, %v", start, result, err)
		}
	}
	if result, err := inspect.Disassemble(target.X86, math.MaxUint32, []byte{0x90}, 0); err != nil || len(result) != 1 || result[0].Address != math.MaxUint32 {
		t.Fatalf("last representable byte: %+v, %v", result, err)
	}
	for _, arch := range []target.Architecture{"386", "i386", "x86_32"} {
		if result, err := inspect.Disassemble(arch, 0, []byte{0x90}, 0); !errors.Is(err, target.ErrUnsupported) || len(result) != 0 {
			t.Fatalf("architecture must not be inferred from %q: %+v, %v", arch, result, err)
		}
	}
}

func TestDisassembleX86Concurrent(t *testing.T) {
	var wg sync.WaitGroup
	ready := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			for range 128 {
				result, err := inspect.Disassemble(target.X86, 0, []byte{0x48, 0xeb, 0xfc}, 0)
				if err != nil || len(result) != 2 || result[0].Text != "dec eax" || result[1].Text != "jmp 0xffffffff" {
					t.Errorf("concurrent decode: %+v, %v", result, err)
					return
				}
			}
		}()
	}
	close(ready)
	wg.Wait()
}

func FuzzDisassembleX86(f *testing.F) {
	f.Add([]byte{0x48, 0x89, 0xe5}, uint64(0x1000), int8(0))
	f.Add([]byte{0xeb, 0x05}, uint64(math.MaxUint32-1), int8(0))
	f.Add([]byte{0xeb, 0xfc}, uint64(0), int8(1))
	f.Add([]byte{0x66, 0xc7, 0xf8, 0x00, 0x00}, uint64(0x12345000), int8(0))
	f.Add([]byte{0x90, 0x0f, 0xff}, uint64(0), int8(0))
	f.Fuzz(func(t *testing.T, code []byte, start uint64, limit int8) {
		if len(code) > 4096 {
			t.Skip()
		}
		original := slices.Clone(code)
		result, err := inspect.Disassemble(target.X86, target.Address(start), code, int(limit))
		if !bytes.Equal(code, original) {
			t.Fatal("decoder mutated input")
		}
		offset := 0
		for i, inst := range result {
			if inst.Address != target.Address(start)+target.Address(offset) || inst.Address > math.MaxUint32 || len(inst.Bytes) < 1 || len(inst.Bytes) > 15 || offset+len(inst.Bytes) > len(code) || inst.Text == "" {
				t.Fatalf("invalid instruction %d: %+v", i, inst)
			}
			if !bytes.Equal(inst.Bytes, code[offset:offset+len(inst.Bytes)]) {
				t.Fatal("instruction bytes are not an exact input prefix")
			}
			offset += len(inst.Bytes)
		}
		if limit > 0 && len(result) > int(limit) {
			t.Fatal("instruction count exceeds limit")
		}
		if err == nil && (limit == 0 || len(result) < int(limit)) && offset != len(code) {
			t.Fatal("successful decode left undecoded bytes within limit")
		}
		repeated, repeatedErr := inspect.Disassemble(target.X86, target.Address(start), original, int(limit))
		if !reflect.DeepEqual(result, repeated) || (err == nil) != (repeatedErr == nil) {
			t.Fatal("decoder returned nondeterministic results")
		}
	})
}
