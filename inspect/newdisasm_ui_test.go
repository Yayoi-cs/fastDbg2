package inspect_test

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestDisassembleAMD64EndbranchModernPrologue(t *testing.T) {
	for _, test := range []struct {
		last byte
		text string
	}{
		{0xfa, "endbr64"},
		{0xfb, "endbr32"},
	} {
		t.Run(test.text, func(t *testing.T) {
			code := []byte{0xf3, 0x0f, 0x1e, test.last, 0x55, 0x48, 0x89, 0xe5, 0xc3}
			result, err := inspect.Disassemble(target.AMD64, 0x401000, code, 0)
			if err != nil || len(result) != 4 {
				t.Fatalf("modern prologue: result=%+v error=%v", result, err)
			}
			addresses := []target.Address{0x401000, 0x401004, 0x401005, 0x401008}
			texts := []string{test.text, "push rbp", "mov rbp, rsp", "ret"}
			for i, instruction := range result {
				if instruction.Address != addresses[i] || instruction.Text != texts[i] {
					t.Fatalf("instruction %d: %+v", i, instruction)
				}
			}
			if !bytes.Equal(result[0].Bytes, code[:4]) {
				t.Fatalf("endbranch bytes=%x want=%x", result[0].Bytes, code[:4])
			}
			code[0], code[3] = 0, 0
			if !bytes.Equal(result[0].Bytes, []byte{0xf3, 0x0f, 0x1e, test.last}) {
				t.Fatal("endbranch instruction bytes alias input")
			}
		})
	}
}

func TestDisassembleAMD64EndbranchInstructionBoundaries(t *testing.T) {
	code := []byte{0x90, 0xf3, 0x0f, 0x1e, 0xfa, 0xeb, 0, 0xf3, 0x0f, 0x1e, 0xfb, 0xc3}
	result, err := inspect.Disassemble(target.AMD64, 0x1000, code, 0)
	if err != nil || len(result) != 5 {
		t.Fatalf("instruction sequence: result=%+v error=%v", result, err)
	}
	want := []struct {
		address target.Address
		text    string
	}{
		{0x1000, "nop"},
		{0x1001, "endbr64"},
		{0x1005, "jmp 0x1007"},
		{0x1007, "endbr32"},
		{0x100b, "ret"},
	}
	for i, instruction := range result {
		if instruction.Address != want[i].address || instruction.Text != want[i].text {
			t.Fatalf("instruction %d: %+v want=%+v", i, instruction, want[i])
		}
	}
	code = []byte{0xb8, 0xf3, 0x0f, 0x1e, 0xfa, 0xc3}
	result, err = inspect.Disassemble(target.AMD64, 0x1000, code, 0)
	if err != nil || len(result) != 2 || result[0].Address != 0x1000 || len(result[0].Bytes) != 5 ||
		result[0].Text != "mov eax, -0x5e1f00d" || result[1].Address != 0x1005 || result[1].Text != "ret" {
		t.Fatalf("embedded immediate was treated as an opcode: result=%+v error=%v", result, err)
	}
}

func TestDisassembleAMD64EndbranchLimitAndPartial(t *testing.T) {
	code := []byte{0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x04}
	result, err := inspect.Disassemble(target.AMD64, 0x2000, code, 1)
	if err != nil || len(result) != 1 || result[0].Text != "endbr64" {
		t.Fatalf("limited endbranch: result=%+v error=%v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, 0x2000, code, 0)
	if err == nil || len(result) != 1 || result[0].Text != "endbr64" || !strings.Contains(err.Error(), "0x2004") {
		t.Fatalf("invalid opcode after endbranch: result=%+v error=%v", result, err)
	}
	code = []byte{0x0f, 0x04, 0xf3, 0x0f, 0x1e, 0xfa}
	result, err = inspect.Disassemble(target.AMD64, 0x2000, code, 0)
	if err == nil || len(result) != 0 || !strings.Contains(err.Error(), "0x2000") {
		t.Fatalf("decoder skipped invalid bytes: result=%+v error=%v", result, err)
	}
	endbranch := []byte{0xf3, 0x0f, 0x1e, 0xfa}
	for length := 1; length < len(endbranch); length++ {
		code = append([]byte{0x90}, endbranch[:length]...)
		result, err = inspect.Disassemble(target.AMD64, 0x2000, code, 0)
		if err == nil || len(result) != 1 || result[0].Text != "nop" || !strings.Contains(err.Error(), "0x2001") {
			t.Fatalf("partial endbranch length=%d result=%+v error=%v", length, result, err)
		}
	}
}

func TestDisassembleAMD64EndbranchRequiresExactEncoding(t *testing.T) {
	encoding := []byte{0xf3, 0x0f, 0x1e, 0xfa}
	for position := range encoding {
		for replacement := 0; replacement < 256; replacement++ {
			if byte(replacement) == encoding[position] || position == 3 && replacement == 0xfb {
				continue
			}
			code := bytes.Clone(encoding)
			code[position] = byte(replacement)
			result, _ := inspect.Disassemble(target.AMD64, 0x1000, code, 0)
			for _, instruction := range result {
				if instruction.Text == "endbr32" || instruction.Text == "endbr64" {
					t.Fatalf("non-exact encoding %x decoded as %+v", code, instruction)
				}
			}
		}
	}
	for _, prefix := range []byte{0xf0, 0x66, 0xf2, 0xf3, 0x48} {
		code := append([]byte{prefix}, encoding...)
		result, _ := inspect.Disassemble(target.AMD64, 0x1000, code, 0)
		for _, instruction := range result {
			if instruction.Text == "endbr32" || instruction.Text == "endbr64" {
				t.Fatalf("unrecognized prefix %x was skipped: %+v", prefix, result)
			}
		}
	}
}

func TestDisassembleAMD64EndbranchAddressBounds(t *testing.T) {
	code := []byte{0xf3, 0x0f, 0x1e, 0xfa}
	start := target.Address(math.MaxUint64 - 3)
	result, err := inspect.Disassemble(target.AMD64, start, code, 0)
	if err != nil || len(result) != 1 || result[0].Address != start || result[0].Text != "endbr64" {
		t.Fatalf("last four addresses: result=%+v error=%v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, start+1, code, 0)
	if !errors.Is(err, target.ErrOverflow) || len(result) != 0 {
		t.Fatalf("overflow: result=%+v error=%v", result, err)
	}
}

func TestDisassembleEndbranchX86(t *testing.T) {
	for _, last := range []byte{0xfa, 0xfb} {
		result, err := inspect.Disassemble(target.X86, 0x1000, []byte{0xf3, 0x0f, 0x1e, last}, 0)
		name := "endbr32"
		if last == 0xfa {
			name = "endbr64"
		}
		if err != nil || len(result) != 1 || result[0].Text != name || len(result[0].Bytes) != 4 {
			t.Fatalf("32-bit ENDBR decode: result=%+v error=%v", result, err)
		}
	}
}
