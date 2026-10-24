package inspect

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"fastdbg2/target"
)

type unwindBytes struct {
	data   []byte
	offset int
	err    error
}

func (r *unwindBytes) take(size int) []byte {
	if r.err != nil {
		return nil
	}
	if size < 0 || size > len(r.data)-r.offset {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	data := r.data[r.offset : r.offset+size]
	r.offset += size
	return data
}

func (r *unwindBytes) byte() byte {
	data := r.take(1)
	if data == nil {
		return 0
	}
	return data[0]
}

func (r *unwindBytes) fixed(size int) uint64 {
	data := r.take(size)
	if data == nil {
		return 0
	}
	switch size {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 8:
		return binary.LittleEndian.Uint64(data)
	default:
		r.err = target.ErrInvalidArgument
		return 0
	}
}

func (r *unwindBytes) uleb() uint64 {
	var result uint64
	for i := 0; i < 10; i++ {
		value := r.byte()
		if r.err != nil {
			return 0
		}
		if i == 9 && value > 1 {
			r.err = target.ErrOverflow
			return 0
		}
		result |= uint64(value&0x7f) << (i * 7)
		if value&0x80 == 0 {
			return result
		}
	}
	r.err = target.ErrOverflow
	return 0
}

func (r *unwindBytes) sleb() int64 {
	var result uint64
	for i := 0; i < 10; i++ {
		value := r.byte()
		if r.err != nil {
			return 0
		}
		if i == 9 && value != 0 && value != 0x7f {
			r.err = target.ErrOverflow
			return 0
		}
		result |= uint64(value&0x7f) << (i * 7)
		if value&0x80 == 0 {
			bits := (i + 1) * 7
			if bits < 64 && value&0x40 != 0 {
				result |= math.MaxUint64 << bits
			}
			return int64(result)
		}
	}
	r.err = target.ErrOverflow
	return 0
}

type unwindExpressionOp struct {
	opcode byte
	start  int
	end    int
	value  uint64
	delta  int64
	target int
}

func decodeUnwindExpression(ctx context.Context, data []byte, widths ...int) ([]unwindExpressionOp, error) {
	word := 8
	if len(widths) > 0 {
		word = widths[0]
	}
	if len(data) == 0 || len(data) > 4096 {
		return nil, fmt.Errorf("DWARF expression length %d: %w", len(data), target.ErrInvalidArgument)
	}
	reader := unwindBytes{data: data}
	var program []unwindExpressionOp
	boundaries := make(map[int]int)
	for reader.offset < len(data) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := reader.offset
		instruction := unwindExpressionOp{start: start, opcode: reader.byte(), target: -1}
		switch op := instruction.opcode; {
		case op == 0x03:
			instruction.value = reader.fixed(word)
		case op >= 0x08 && op <= 0x0f:
			size := 1 << ((op - 0x08) / 2)
			instruction.value = reader.fixed(int(size))
			if op&1 != 0 && size < 8 {
				shift := 64 - size*8
				instruction.value = uint64(int64(instruction.value<<shift) >> shift)
			}
		case op == 0x10 || op == 0x23:
			instruction.value = reader.uleb()
		case op == 0x11:
			instruction.value = uint64(reader.sleb())
		case op == 0x15 || op == 0x94:
			instruction.value = uint64(reader.byte())
		case op == 0x28 || op == 0x2f:
			instruction.delta = int64(int16(reader.fixed(2)))
		case op >= 0x30 && op <= 0x4f:
			instruction.value = uint64(op - 0x30)
		case op >= 0x70 && op <= 0x8f:
			instruction.value = uint64(op - 0x70)
			instruction.delta = reader.sleb()
		case op == 0x92:
			instruction.value, instruction.delta = reader.uleb(), reader.sleb()
		case op == 0x06 || op >= 0x12 && op <= 0x14 || op == 0x16 || op == 0x17 || op >= 0x19 && op <= 0x22 || op >= 0x24 && op <= 0x27 || op >= 0x29 && op <= 0x2e || op == 0x96:
		default:
			return nil, fmt.Errorf("CFI DWARF expression opcode %#x at %d: %w", op, instruction.start, target.ErrUnsupported)
		}
		if reader.err != nil {
			return nil, fmt.Errorf("DWARF expression operand at %d: %w", instruction.start, reader.err)
		}
		instruction.end = reader.offset
		boundaries[instruction.start] = len(program)
		program = append(program, instruction)
	}
	boundaries[len(data)] = len(program)
	for i := range program {
		instruction := &program[i]
		if instruction.opcode != 0x28 && instruction.opcode != 0x2f {
			continue
		}
		position := int64(instruction.end) + instruction.delta
		if position < 0 || position > int64(len(data)) {
			return nil, fmt.Errorf("DWARF expression branch outside block: %w", target.ErrInvalidArgument)
		}
		index, exists := boundaries[int(position)]
		if !exists {
			return nil, fmt.Errorf("DWARF expression branch inside operand: %w", target.ErrInvalidArgument)
		}
		instruction.target = index
	}
	return program, nil
}

func evaluateUnwindExpression(ctx context.Context, expression []byte, registers AMD64UnwindRegisters, cfa *uint64, metadata *CFIFrame, budget *unwindBudget) (uint64, error) {
	if err := budget.charge(ctx, len(expression)); err != nil {
		return 0, err
	}
	program, err := decodeUnwindExpression(ctx, expression, unwindABIFor(budget.arch).word)
	if err != nil {
		return 0, err
	}
	stack := make([]uint64, 0, 64)
	if cfa != nil {
		stack = append(stack, *cfa)
	}
	steps := 0
	for pc := 0; pc < len(program); {
		if steps == 4096 {
			return 0, fmt.Errorf("DWARF expression execution limit: %w", target.ErrOverflow)
		}
		steps++
		if err := budget.operation(ctx); err != nil {
			return 0, err
		}
		instruction := program[pc]
		pc++
		op := instruction.opcode
		require := 0
		switch {
		case op == 0x12 || op == 0x13 || op == 0x15 || op == 0x06 || op == 0x94 || op == 0x19 || op == 0x1f || op == 0x20 || op == 0x23 || op == 0x28:
			require = 1
		case op == 0x14 || op == 0x16 || op >= 0x1a && op <= 0x1e || op == 0x21 || op == 0x22 || op >= 0x24 && op <= 0x27 || op >= 0x29 && op <= 0x2e:
			require = 2
		case op == 0x17:
			require = 3
		}
		if len(stack) < require {
			return 0, fmt.Errorf("DWARF expression stack underflow at %d: %w", instruction.start, target.ErrInvalidArgument)
		}
		push := func(value uint64) error {
			if len(stack) == 64 {
				return fmt.Errorf("DWARF expression stack depth: %w", target.ErrOverflow)
			}
			if unwindABIFor(budget.arch).word == 4 {
				value = uint64(uint32(value))
			}
			stack = append(stack, value)
			return nil
		}
		switch {
		case op == 0x03:
			value := instruction.value
			if metadata.debug {
				if metadata.loadBias > math.MaxUint64-value {
					return 0, target.ErrOverflow
				}
				value += metadata.loadBias
			}
			err = push(value)
		case op >= 0x08 && op <= 0x11 || op >= 0x30 && op <= 0x4f:
			err = push(instruction.value)
		case op >= 0x70 && op <= 0x8f || op == 0x92:
			value, e := unwindRegisterValue(registers, instruction.value)
			if e != nil {
				return 0, e
			}
			value, e = unwindSignedAdd(value, instruction.delta)
			if e != nil {
				return 0, e
			}
			err = push(value)
		case op == 0x06 || op == 0x94:
			size := unwindABIFor(budget.arch).word
			if op == 0x94 {
				size = int(instruction.value)
			}
			stack[len(stack)-1], err = budget.value(ctx, target.Address(stack[len(stack)-1]), size)
		case op == 0x12:
			err = push(stack[len(stack)-1])
		case op == 0x13:
			stack = stack[:len(stack)-1]
		case op == 0x14:
			err = push(stack[len(stack)-2])
		case op == 0x15:
			if instruction.value >= uint64(len(stack)) {
				return 0, fmt.Errorf("DWARF expression pick underflow: %w", target.ErrInvalidArgument)
			}
			err = push(stack[len(stack)-int(instruction.value)-1])
		case op == 0x16:
			last := len(stack) - 1
			stack[last], stack[last-1] = stack[last-1], stack[last]
		case op == 0x17:
			last := len(stack) - 1
			stack[last], stack[last-1], stack[last-2] = stack[last-1], stack[last-2], stack[last]
		case op == 0x19 || op == 0x1f || op == 0x20 || op == 0x23:
			last := len(stack) - 1
			switch op {
			case 0x19:
				if unwindABIFor(budget.arch).word == 4 {
					if int32(stack[last]) == math.MinInt32 {
						return 0, target.ErrOverflow
					}
					stack[last] = uint64(int64(int32(stack[last])))
				}
				if int64(stack[last]) == math.MinInt64 {
					return 0, fmt.Errorf("undefined DWARF absolute value: %w", target.ErrOverflow)
				}
				if int64(stack[last]) < 0 {
					stack[last] = -stack[last]
				}
			case 0x1f:
				stack[last] = -stack[last]
			case 0x20:
				stack[last] = ^stack[last]
			case 0x23:
				stack[last] += instruction.value
			}
		case op >= 0x1a && op <= 0x1e || op == 0x21 || op == 0x22 || op >= 0x24 && op <= 0x27 || op >= 0x29 && op <= 0x2e:
			a, b := stack[len(stack)-2], stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			value, e := unwindExpressionBinary(op, a, b)
			if unwindABIFor(budget.arch).word == 4 {
				value, e = unwindExpressionBinary32(op, a, b)
			}
			if e != nil {
				return 0, e
			}
			stack[len(stack)-1] = value
		case op == 0x28:
			value := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if value != 0 {
				pc = instruction.target
			}
		case op == 0x2f:
			pc = instruction.target
		case op == 0x96:
		}
		if unwindABIFor(budget.arch).word == 4 && len(stack) > 0 {
			stack[len(stack)-1] = uint64(uint32(stack[len(stack)-1]))
		}
		if err != nil {
			return 0, err
		}
	}
	if len(stack) == 0 {
		return 0, fmt.Errorf("empty DWARF expression result: %w", target.ErrInvalidArgument)
	}
	return stack[len(stack)-1], nil
}

func unwindExpressionBinary(op byte, a, b uint64) (uint64, error) {
	truth := func(value bool) uint64 {
		if value {
			return 1
		}
		return 0
	}
	switch op {
	case 0x1a:
		return a & b, nil
	case 0x1b:
		if b == 0 || int64(a) == math.MinInt64 && int64(b) == -1 {
			return 0, fmt.Errorf("invalid DWARF signed division: %w", target.ErrInvalidArgument)
		}
		return uint64(int64(a) / int64(b)), nil
	case 0x1c:
		return a - b, nil
	case 0x1d:
		if b == 0 {
			return 0, fmt.Errorf("invalid DWARF modulus: %w", target.ErrInvalidArgument)
		}
		return a % b, nil
	case 0x1e:
		return a * b, nil
	case 0x21:
		return a | b, nil
	case 0x22:
		return a + b, nil
	case 0x24, 0x25, 0x26:
		if b >= 64 {
			return 0, fmt.Errorf("DWARF shift count %d: %w", b, target.ErrInvalidArgument)
		}
		if op == 0x24 {
			return a << b, nil
		}
		if op == 0x25 {
			return a >> b, nil
		}
		return uint64(int64(a) >> b), nil
	case 0x27:
		return a ^ b, nil
	case 0x29:
		return truth(a == b), nil
	case 0x2a:
		return truth(int64(a) >= int64(b)), nil
	case 0x2b:
		return truth(int64(a) > int64(b)), nil
	case 0x2c:
		return truth(int64(a) <= int64(b)), nil
	case 0x2d:
		return truth(int64(a) < int64(b)), nil
	case 0x2e:
		return truth(a != b), nil
	default:
		return 0, target.ErrUnsupported
	}
}

func unwindExpressionBinary32(op byte, a, b uint64) (uint64, error) {
	a, b = uint64(uint32(a)), uint64(uint32(b))
	if op >= 0x24 && op <= 0x26 && b >= 32 {
		return 0, target.ErrInvalidArgument
	}
	if op == 0x1b && uint32(a) == 0x80000000 && uint32(b) == 0xffffffff {
		return 0, target.ErrInvalidArgument
	}
	if op == 0x1b || op >= 0x2a && op <= 0x2d {
		a, b = uint64(int64(int32(a))), uint64(int64(int32(b)))
	} else if op == 0x26 {
		a = uint64(int64(int32(a)))
	}
	value, err := unwindExpressionBinary(op, a, b)
	return uint64(uint32(value)), err
}
