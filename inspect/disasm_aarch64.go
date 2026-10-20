package inspect

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"fastdbg2/target"
	"golang.org/x/arch/arm64/arm64asm"
)

var aarch64DecodeMu sync.Mutex

const aarch64InstructionSize = 4

func disassembleAArch64(start target.Address, code []byte, limit int) ([]Instruction, error) {
	if start%aarch64InstructionSize != 0 {
		return nil, fmt.Errorf("AArch64 instruction address %#x must be 4-byte aligned: %w", start, target.ErrInvalidArgument)
	}
	var result []Instruction
	for offset := 0; offset < len(code) && (limit == 0 || len(result) < limit); offset += aarch64InstructionSize {
		address := start + target.Address(offset)
		if len(code)-offset < aarch64InstructionSize {
			return result, fmt.Errorf("decode at %#x: truncated AArch64 instruction: %w", address, target.ErrUnavailable)
		}
		encoded := code[offset : offset+aarch64InstructionSize]
		inst, err := func() (arm64asm.Inst, error) {
			aarch64DecodeMu.Lock()
			defer aarch64DecodeMu.Unlock()
			return arm64asm.Decode(encoded)
		}()
		if err != nil {
			return result, fmt.Errorf("decode at %#x: %w: %w", address, target.ErrUnavailable, err)
		}
		if inst.Op == 0 {
			return result, fmt.Errorf("decode at %#x: unrecognized AArch64 instruction: %w", address, target.ErrUnavailable)
		}
		result = append(result, Instruction{
			Address: address,
			Bytes:   slices.Clone(encoded),
			Text:    strings.TrimSpace(arm64asm.GNUSyntax(inst)),
		})
	}
	return result, nil
}
