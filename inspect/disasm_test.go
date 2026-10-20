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

func TestDisassembleAMD64(t *testing.T) {
	code := []byte{0x90, 0x48, 0x89, 0xe5, 0xc3}
	result, err := inspect.Disassemble(target.AMD64, 0x401000, code, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 || result[0].Address != 0x401000 || result[1].Address != 0x401001 || result[2].Address != 0x401004 {
		t.Fatalf("instructions: %+v", result)
	}
	if result[0].Text != "nop" || !strings.Contains(result[1].Text, "mov rbp, rsp") || result[2].Text != "ret" {
		t.Fatalf("unexpected assembly: %+v", result)
	}
	if !bytes.Equal(result[1].Bytes, []byte{0x48, 0x89, 0xe5}) {
		t.Fatalf("instruction bytes: %x", result[1].Bytes)
	}
	code[1] = 0
	if result[1].Bytes[0] != 0x48 {
		t.Fatal("instruction bytes alias the input")
	}
}

func TestDisassembleLimitAndForwardOnly(t *testing.T) {
	code := []byte{0xc3, 0x90, 0x90}
	result, err := inspect.Disassemble(target.AMD64, 0x1000, code, 1)
	if err != nil || len(result) != 1 || result[0].Text != "ret" {
		t.Fatalf("limited decode: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, 0x1000, code, 0)
	if err != nil || len(result) != 3 {
		t.Fatalf("ret must not infer a function boundary: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, 0x1001, code[1:], 8)
	if err != nil || len(result) != 2 || result[0].Address != 0x1001 {
		t.Fatalf("explicit start address: %+v, %v", result, err)
	}
}

func TestDisassembleRelativeAddress(t *testing.T) {
	result, err := inspect.Disassemble(target.AMD64, 0x1000, []byte{0xeb, 0x05}, 0)
	if err != nil || len(result) != 1 || !strings.Contains(result[0].Text, "0x1007") {
		t.Fatalf("relative branch: %+v, %v", result, err)
	}
}

func TestDisassemblePartialDoesNotSkipInvalidBytes(t *testing.T) {
	for _, tail := range [][]byte{{0x48}, {0x0f}, {0xe8, 0x01}, {0x48, 0x8b}, {0x0f, 0xff}} {
		code := append([]byte{0x90}, tail...)
		result, err := inspect.Disassemble(target.AMD64, 0x1000, code, 0)
		if err == nil || len(result) != 1 || result[0].Text != "nop" || !strings.Contains(err.Error(), "0x1001") {
			t.Fatalf("code=%x result=%+v err=%v", code, result, err)
		}
	}
	result, err := inspect.Disassemble(target.AMD64, 0x1000, []byte{0x48}, 0)
	if err == nil || len(result) != 0 {
		t.Fatalf("prefix pseudo-instruction must be rejected: %+v, %v", result, err)
	}
	result, err = inspect.Disassemble(target.AMD64, 0x1000, []byte{0x90, 0x48}, 1)
	if err != nil || len(result) != 1 {
		t.Fatalf("bytes beyond the limit must not be decoded: %+v, %v", result, err)
	}
}

func TestDisassembleArguments(t *testing.T) {
	cases := []struct {
		arch  target.Architecture
		start target.Address
		code  []byte
		limit int
		want  error
	}{
		{"", 0, []byte{0x90}, 0, target.ErrUnsupported},
		{"arm64", 0, []byte{0x90}, 0, target.ErrUnsupported},
		{target.AMD64, 0, []byte{0x90}, -1, target.ErrInvalidArgument},
		{target.AMD64, target.Address(math.MaxUint64), []byte{0x90, 0x90}, 0, target.ErrOverflow},
	}
	for _, test := range cases {
		result, err := inspect.Disassemble(test.arch, test.start, test.code, test.limit)
		if len(result) != 0 || !errors.Is(err, test.want) {
			t.Fatalf("case=%+v result=%+v err=%v", test, result, err)
		}
	}
	if result, err := inspect.Disassemble(target.AMD64, 0, nil, 0); err != nil || len(result) != 0 {
		t.Fatalf("empty input: %+v, %v", result, err)
	}
	if result, err := inspect.Disassemble(target.AMD64, target.Address(math.MaxUint64), []byte{0x90}, 0); err != nil || len(result) != 1 {
		t.Fatalf("last representable byte: %+v, %v", result, err)
	}
}
