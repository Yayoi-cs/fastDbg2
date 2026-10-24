package inspect

import (
	"fmt"
	"math"
	"slices"

	"fastdbg2/target"
	"golang.org/x/arch/x86/x86asm"
)

func disassembleX86(start target.Address, code []byte, limit int) ([]Instruction, error) {
	if start > math.MaxUint32 || len(code) > 0 && uint64(len(code)-1) > math.MaxUint32-uint64(start) {
		return nil, fmt.Errorf("32-bit disassembly address range: %w", target.ErrOverflow)
	}
	var result []Instruction
	for offset := 0; offset < len(code) && (limit == 0 || len(result) < limit); {
		address := start + target.Address(offset)
		if len(code)-offset >= 4 && code[offset] == 0xf3 && code[offset+1] == 0x0f && code[offset+2] == 0x1e && (code[offset+3] == 0xfb || code[offset+3] == 0xfa) {
			name := "endbr32"
			if code[offset+3] == 0xfa {
				name = "endbr64"
			}
			result = append(result, Instruction{Address: address, Bytes: slices.Clone(code[offset : offset+4]), Text: name})
			offset += 4
			continue
		}
		inst, err := x86asm.Decode(code[offset:], 32)
		if err != nil {
			return result, fmt.Errorf("decode at %#x: %w", address, err)
		}
		if inst.Op == 0 || inst.Len <= 0 || inst.Len > len(code)-offset {
			return result, fmt.Errorf("decode at %#x: incomplete or unrecognized instruction: %w", address, target.ErrUnavailable)
		}
		text, err := x86IntelSyntax(inst, address)
		if err != nil {
			return result, fmt.Errorf("format at %#x: %w", address, err)
		}
		result = append(result, Instruction{
			Address: address,
			Bytes:   slices.Clone(code[offset : offset+inst.Len]),
			Text:    text,
		})
		offset += inst.Len
	}
	return result, nil
}

func x86IntelSyntax(inst x86asm.Inst, address target.Address) (string, error) {
	for i, arg := range inst.Args {
		if relative, ok := arg.(x86asm.Rel); ok {
			if inst.DataSize != 16 && inst.DataSize != 32 {
				return "", fmt.Errorf("relative operand size %d: %w", inst.DataSize, target.ErrUnsupported)
			}
			destination := uint32(address) + uint32(inst.Len) + uint32(relative)
			switch inst.Op {
			case x86asm.CALL, x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
				x86asm.JE, x86asm.JNE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
				x86asm.JO, x86asm.JNO, x86asm.JP, x86asm.JNP, x86asm.JS, x86asm.JNS,
				x86asm.JCXZ, x86asm.JECXZ, x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
				if inst.DataSize == 16 {
					destination &= math.MaxUint16
				}
			case x86asm.XBEGIN:
			default:
				return "", fmt.Errorf("relative opcode %s: %w", inst.Op, target.ErrUnsupported)
			}
			inst.Args[i] = x86asm.Imm(destination)
		}
	}
	return x86asm.IntelSyntax(inst, uint64(address), nil), nil
}
