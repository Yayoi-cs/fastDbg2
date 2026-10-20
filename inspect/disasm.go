package inspect

import (
	"fmt"
	"math"
	"slices"

	"fastdbg2/target"
	"golang.org/x/arch/x86/x86asm"
)

type Instruction struct {
	Address target.Address
	Bytes   []byte
	Text    string
}

func Disassemble(arch target.Architecture, start target.Address, code []byte, limit int) ([]Instruction, error) {
	if arch != target.AMD64 && arch != target.AArch64 && arch != target.X86 {
		return nil, fmt.Errorf("architecture %q: %w", arch, target.ErrUnsupported)
	}
	if limit < 0 {
		return nil, fmt.Errorf("negative instruction limit: %w", target.ErrInvalidArgument)
	}
	if len(code) > 0 && uint64(len(code)-1) > math.MaxUint64-uint64(start) {
		return nil, fmt.Errorf("disassembly address range: %w", target.ErrOverflow)
	}
	if arch == target.AArch64 {
		return disassembleAArch64(start, code, limit)
	}
	if arch == target.X86 {
		return disassembleX86(start, code, limit)
	}
	var result []Instruction
	for offset := 0; offset < len(code) && (limit == 0 || len(result) < limit); {
		address := start + target.Address(offset)
		inst, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			return result, fmt.Errorf("decode at %#x: %w", address, err)
		}
		if inst.Op == 0 || inst.Len <= 0 || inst.Len > len(code)-offset {
			return result, fmt.Errorf("decode at %#x: incomplete or unrecognized instruction: %w", address, target.ErrUnavailable)
		}
		result = append(result, Instruction{
			Address: address,
			Bytes:   slices.Clone(code[offset : offset+inst.Len]),
			Text:    x86asm.IntelSyntax(inst, uint64(address), nil),
		})
		offset += inst.Len
	}
	return result, nil
}
