package inspect

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"fastdbg2/target"
)

type AMD64UnwindRegisters = UnwindRegisters
type UnwindRegisters struct {
	Architecture target.Architecture
	Values       [17]uint64
	Known        uint32
}

type AMD64UnwindProfile = UnwindProfile
type UnwindProfile uint8

const (
	UnwindStrictCFI AMD64UnwindProfile = iota
	UnwindSysVAMD64
	UnwindSysVX86
)

type AMD64UnwindRequest = UnwindRequest
type UnwindRequest struct {
	Profile   AMD64UnwindProfile
	Registers AMD64UnwindRegisters
	PC        target.Address
	Find      func(context.Context, target.Address) (*CFIFrame, error)
	Read      CFIReader
	MaxFrames int
}

type UnwindResult struct {
	Frames   []UnwindFrame
	Complete bool
	Limited  bool
}

type UnwindFrame struct {
	MetadataKind  string
	CFARule       string
	PC            target.Address
	RawPC         target.Address
	LookupPC      target.Address
	ReturnPC      bool
	Registers     AMD64UnwindRegisters
	CFA           target.Address
	CFAKnown      bool
	CFARegister   uint64
	CFAOffset     int64
	CFAExpression bool
	Source        string
	FDE           target.Address
	Start         target.Address
	End           target.Address
	Signal        bool
	Saved         []UnwindSavedRegister
}

type UnwindSavedRegister struct {
	Register       uint64
	Rule           string
	Provenance     string
	SourceRegister uint64
	Offset         int64
	Address        target.Address
	AddressKnown   bool
	Value          uint64
	Available      bool
}

type UnwindLimitError struct {
	Limit int
}

func (e *UnwindLimitError) Error() string {
	return fmt.Sprintf("unwind reached the explicit %d-frame limit: %v", e.Limit, target.ErrPartial)
}

func (e *UnwindLimitError) Is(err error) bool { return err == target.ErrPartial }

var amd64UnwindNames = [...]string{"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}

func AMD64UnwindRegistersFromTarget(registers []target.Register) (AMD64UnwindRegisters, error) {
	return UnwindRegistersFromTarget(target.AMD64, registers)
}

func UnwindRegistersFromTarget(arch target.Architecture, registers []target.Register) (AMD64UnwindRegisters, error) {
	names := amd64UnwindNames[:]
	word := 8
	if arch == target.X86 {
		names = x86UnwindNames[:]
		word = 4
	} else if arch != target.AMD64 {
		return AMD64UnwindRegisters{}, target.ErrUnsupported
	}
	var result AMD64UnwindRegisters
	if arch == target.X86 {
		result.Architecture = arch
	}
	var seen uint32
	for _, register := range registers {
		for number, name := range names {
			if register.Name != name {
				continue
			}
			bit := uint32(1) << number
			if seen&bit != 0 {
				return AMD64UnwindRegisters{}, fmt.Errorf("duplicate register %s: %w", name, target.ErrInvalidArgument)
			}
			seen |= bit
			if !register.Available {
				break
			}
			if register.Bits != word*8 || len(register.Data) != word {
				return AMD64UnwindRegisters{}, fmt.Errorf("invalid AMD64 register %s: %w", name, target.ErrInvalidArgument)
			}
			var data [8]byte
			copy(data[:], register.Data)
			result.Values[number] = binary.LittleEndian.Uint64(data[:])
			result.Known |= bit
			break
		}
	}
	return result, nil
}

type unwindBudget struct {
	arch       target.Architecture
	operations int
	bytes      int
	read       CFIReader
	profile    AMD64UnwindProfile
}

func (b *unwindBudget) operation(ctx context.Context) error {
	return b.charge(ctx, 1)
}

func (b *unwindBudget) charge(ctx context.Context, cost int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cost < 0 || cost > b.operations {
		return fmt.Errorf("unwind operation budget: %w", target.ErrOverflow)
	}
	b.operations -= cost
	return nil
}

func (b *unwindBudget) memory(ctx context.Context, address target.Address, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.arch == target.X86 && (address > math.MaxUint32 || len(data) > 0 && uint64(len(data)-1) > math.MaxUint32-uint64(address)) {
		return target.ErrOverflow
	}
	if len(data) > b.bytes || len(data) != 0 && uint64(len(data)-1) > math.MaxUint64-uint64(address) {
		return fmt.Errorf("unwind memory budget or range: %w", target.ErrOverflow)
	}
	if b.read == nil {
		return fmt.Errorf("unwind memory reader: %w", target.ErrUnavailable)
	}
	b.bytes -= len(data)
	n, err := b.read(ctx, address, data)
	err = errors.Join(err, ctx.Err())
	if n < 0 || n > len(data) {
		return errors.Join(fmt.Errorf("invalid unwind read count %d: %w", n, target.ErrInvalidArgument), err)
	}
	if err != nil {
		return err
	}
	if n != len(data) {
		return &target.PartialError{Op: "unwind memory", Completed: n, Total: len(data), Err: io.ErrUnexpectedEOF}
	}
	return ctx.Err()
}

func (b *unwindBudget) value(ctx context.Context, address target.Address, size int) (uint64, error) {
	if size < 1 || size > 8 {
		return 0, target.ErrInvalidArgument
	}
	var data [8]byte
	if err := b.memory(ctx, address, data[:size]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

func unwindFatal(err error) bool {
	return errors.Is(err, target.ErrStale) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func unwindError(result UnwindResult, err error) (UnwindResult, error) {
	if unwindFatal(err) {
		return UnwindResult{}, err
	}
	return result, err
}

func UnwindAMD64(ctx context.Context, request AMD64UnwindRequest) (UnwindResult, error) {
	return Unwind(ctx, request)
}

func Unwind(ctx context.Context, request UnwindRequest) (result UnwindResult, err error) {
	if ctx == nil {
		return UnwindResult{}, target.ErrInvalidArgument
	}
	defer func() {
		if contextErr := ctx.Err(); contextErr != nil {
			err = errors.Join(err, contextErr)
		}
		if unwindFatal(err) {
			result = UnwindResult{}
		}
	}()
	abi := unwindABIFor(request.Registers.Architecture)
	if abi.word == 4 && request.PC > math.MaxUint32 {
		return result, target.ErrOverflow
	}
	if request.Find == nil || request.MaxFrames < 1 || request.MaxFrames > 256 || request.Registers.Known>>abi.count != 0 || request.Profile > UnwindSysVX86 {
		return UnwindResult{}, target.ErrInvalidArgument
	}
	if request.Registers.Architecture != "" && request.Registers.Architecture != target.AMD64 && request.Registers.Architecture != target.X86 || request.Profile == UnwindSysVX86 && abi.word != 4 || request.Profile == UnwindSysVAMD64 && abi.word != 8 {
		return UnwindResult{}, target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return UnwindResult{}, err
	}
	if request.Registers.Known&(1<<abi.pc) == 0 {
		return UnwindResult{}, fmt.Errorf("initial RIP: %w", target.ErrUnavailable)
	}
	type identity struct {
		registers AMD64UnwindRegisters
		pc        target.Address
		isReturn  bool
	}
	seen := make(map[identity]struct{})
	registers, pc, isReturn := request.Registers, request.PC, false
	budget := &unwindBudget{operations: 1 << 20, bytes: 1 << 20, read: request.Read, profile: request.Profile, arch: request.Registers.Architecture}
	for {
		if err := budget.operation(ctx); err != nil {
			return unwindError(result, err)
		}
		key := identity{registers, pc, isReturn}
		if _, exists := seen[key]; exists {
			return unwindError(result, fmt.Errorf("repeated complete unwind state at %#x: %w", pc, target.ErrInvalidState))
		}
		seen[key] = struct{}{}
		lookup := pc
		if isReturn {
			if lookup == 0 {
				return unwindError(result, fmt.Errorf("zero recovered return PC has no call-site address: %w", target.ErrUnavailable))
			}
			lookup--
		}
		result.Frames = append(result.Frames, UnwindFrame{PC: pc, RawPC: target.Address(registers.Values[abi.pc]), LookupPC: lookup, ReturnPC: isReturn, Registers: registers})
		frame := &result.Frames[len(result.Frames)-1]
		metadata, err := request.Find(ctx, lookup)
		if err != nil {
			return unwindError(result, fmt.Errorf("CFI at %#x: %w", lookup, err))
		}
		if metadata == nil || lookup < metadata.start || lookup >= metadata.end {
			return unwindError(result, fmt.Errorf("CFI does not cover %#x: %w", lookup, target.ErrInvalidArgument))
		}
		frame.Source, frame.FDE, frame.Start, frame.End, frame.Signal = metadata.source, metadata.entry, metadata.start, metadata.end, metadata.cie.signal
		row, err := evaluateCFIRow(ctx, metadata, lookup, budget)
		if err != nil {
			return unwindError(result, err)
		}
		evaluation := registers
		if len(result.Frames) == 1 {
			evaluation.Values[abi.pc] = uint64(pc)
		}
		next, complete, err := recoverCFIFrame(ctx, metadata, row, evaluation, frame, budget)
		if err != nil {
			return unwindError(result, err)
		}
		if err := ctx.Err(); err != nil {
			return UnwindResult{}, err
		}
		if complete {
			result.Complete = true
			return result, nil
		}
		if len(result.Frames) == request.MaxFrames {
			result.Limited = true
			return result, &UnwindLimitError{Limit: request.MaxFrames}
		}
		registers, pc, isReturn = next, target.Address(next.Values[abi.pc]), !metadata.cie.signal
	}
}

type unwindRuleKind uint8

const (
	unwindUndefined unwindRuleKind = iota
	unwindSame
	unwindOffset
	unwindValueOffset
	unwindRegister
	unwindExpression
	unwindValueExpression
)

type unwindRule struct {
	kind       unwindRuleKind
	register   uint64
	offset     int64
	expression []byte
	explicit   bool
}

type unwindCFA struct {
	defined    bool
	register   uint64
	offset     int64
	expression []byte
}

type unwindRow struct {
	cfa   unwindCFA
	rules map[uint64]unwindRule
}

func initialAMD64Row(profile AMD64UnwindProfile) unwindRow {
	row := unwindRow{rules: make(map[uint64]unwindRule)}
	if profile == UnwindSysVX86 {
		for _, r := range []uint64{3, 5, 6, 7} {
			row.rules[r] = unwindRule{kind: unwindSame}
		}
		row.rules[4] = unwindRule{kind: unwindValueOffset}
		return row
	}
	if profile != UnwindSysVAMD64 {
		return row
	}
	for _, reg := range []uint64{3, 6, 12, 13, 14, 15} {
		row.rules[reg] = unwindRule{kind: unwindSame}
	}
	row.rules[7] = unwindRule{kind: unwindValueOffset}
	return row
}

func cloneUnwindRow(row unwindRow) unwindRow {
	cloned := unwindRow{cfa: row.cfa, rules: make(map[uint64]unwindRule, len(row.rules))}
	for register, rule := range row.rules {
		cloned.rules[register] = rule
	}
	return cloned
}

func evaluateCFIRow(ctx context.Context, frame *CFIFrame, pc target.Address, budget *unwindBudget) (unwindRow, error) {
	if int(frame.cie.addressSize) != unwindABIFor(budget.arch).word || frame.cie.returnRegister != uint64(unwindABIFor(budget.arch).pc) || frame.cie.codeAlign == 0 {
		return unwindRow{}, fmt.Errorf("unsupported CIE address/return-register/alignment for target ABI: %w", target.ErrUnsupported)
	}
	initial := initialAMD64Row(budget.profile)
	initial, err := runCFIProgram(ctx, frame, frame.cie.initial, cloneUnwindRow(initial), initial, frame.start, pc, true, budget)
	if err != nil {
		return unwindRow{}, err
	}
	if err := budget.charge(ctx, len(initial.rules)+1); err != nil {
		return unwindRow{}, err
	}
	return runCFIProgram(ctx, frame, frame.program, cloneUnwindRow(initial), initial, frame.start, pc, false, budget)
}

func unwindSignedAdd(value uint64, delta int64) (uint64, error) {
	if delta >= 0 {
		if uint64(delta) > math.MaxUint64-value {
			return 0, target.ErrOverflow
		}
		return value + uint64(delta), nil
	}
	abs := uint64(-(delta + 1)) + 1
	if abs > value {
		return 0, target.ErrOverflow
	}
	return value - abs, nil
}

func unwindFactored(value, factor int64) (int64, error) {
	if value == 0 || factor == 0 {
		return 0, nil
	}
	if value == math.MinInt64 && factor == -1 || factor == math.MinInt64 && value == -1 {
		return 0, target.ErrOverflow
	}
	result := value * factor
	if result/factor != value {
		return 0, target.ErrOverflow
	}
	return result, nil
}

func unwindUnsignedFactored(value uint64, factor int64) (int64, error) {
	if value == 0 || factor == 0 {
		return 0, nil
	}
	if factor > 0 {
		if value > uint64(math.MaxInt64)/uint64(factor) {
			return 0, target.ErrOverflow
		}
		return int64(value * uint64(factor)), nil
	}
	abs := uint64(-(factor + 1)) + 1
	if value > (uint64(1)<<63)/abs {
		return 0, target.ErrOverflow
	}
	return -int64(value * abs), nil
}

func runCFIProgram(ctx context.Context, frame *CFIFrame, program cfiProgram, row, initial unwindRow, location, pc target.Address, cie bool, budget *unwindBudget) (unwindRow, error) {
	reader := unwindBytes{data: program.data}
	var states []unwindRow
	var err error
	for reader.offset < len(reader.data) {
		if err := budget.operation(ctx); err != nil {
			return unwindRow{}, err
		}
		op := reader.byte()
		var register uint64
		var rule unwindRule
		var next target.Address
		advance := false
		setRule := false
		readRegister := func() uint64 {
			value := reader.uleb()
			if value >= 1024 && reader.err == nil {
				reader.err = fmt.Errorf("CFI register %d: %w", value, target.ErrUnsupported)
			}
			return value
		}
		readFactored := func(signed bool) int64 {
			var value int64
			if signed {
				value = reader.sleb()
				value, err = unwindFactored(value, frame.cie.dataAlign)
			} else {
				value, err = unwindUnsignedFactored(reader.uleb(), frame.cie.dataAlign)
			}
			if err != nil && reader.err == nil {
				reader.err = err
			}
			return value
		}
		readExpression := func() []byte {
			size := reader.uleb()
			if size > 4096 {
				reader.err = fmt.Errorf("CFI expression length: %w", target.ErrOverflow)
				return nil
			}
			return reader.take(int(size))
		}
		advanceBy := func(delta uint64) {
			advance = true
			if delta > math.MaxUint64/frame.cie.codeAlign || delta*frame.cie.codeAlign > math.MaxUint64-uint64(location) {
				reader.err = target.ErrOverflow
				return
			}
			next = location + target.Address(delta*frame.cie.codeAlign)
		}
		switch op & 0xc0 {
		case 0x40:
			advanceBy(uint64(op & 0x3f))
		case 0x80:
			register, setRule = uint64(op&0x3f), true
			rule = unwindRule{kind: unwindOffset, offset: readFactored(false), explicit: true}
		case 0xc0:
			register, setRule = uint64(op&0x3f), true
			rule = initial.rules[register]
		default:
			switch op {
			case 0x00:
			case 0x01:
				advance = true
				if frame.debug {
					value := reader.fixed(unwindABIFor(budget.arch).word)
					if frame.loadBias > math.MaxUint64-value {
						reader.err = target.ErrOverflow
					} else {
						next = target.Address(value + frame.loadBias)
					}
				} else {
					function := uint64(frame.start)
					value, e := cfiDecodePointer(ctx, reader.data, &reader.offset, program.address, frame.cie.pointerEncoding, cfiPointerBases{word: unwindABIFor(budget.arch).word, function: &function}, func(ctx context.Context, address target.Address, data []byte) (int, error) {
						if e := budget.memory(ctx, address, data); e != nil {
							return 0, e
						}
						return len(data), nil
					})
					reader.err = e
					next = target.Address(value)
				}
			case 0x02, 0x03, 0x04:
				advanceBy(reader.fixed(1 << (op - 2)))
			case 0x05, 0x11, 0x14, 0x15, 0x2f:
				register, setRule = readRegister(), true
				rule = unwindRule{kind: unwindOffset, offset: readFactored(op == 0x11 || op == 0x15), explicit: true}
				if op == 0x14 || op == 0x15 {
					rule.kind = unwindValueOffset
				}
				if op == 0x2f {
					if rule.offset == math.MinInt64 {
						reader.err = target.ErrOverflow
					} else {
						rule.offset = -rule.offset
					}
				}
			case 0x06:
				register, setRule = readRegister(), true
				rule = initial.rules[register]
			case 0x07, 0x08:
				register, setRule = readRegister(), true
				rule = unwindRule{kind: unwindUndefined, explicit: true}
				if op == 0x08 {
					rule.kind = unwindSame
				}
			case 0x09:
				register, setRule = readRegister(), true
				rule = unwindRule{kind: unwindRegister, register: readRegister(), explicit: true}
			case 0x0a:
				if len(states) == 64 {
					reader.err = fmt.Errorf("CFI remember-state depth: %w", target.ErrOverflow)
				} else if err := budget.charge(ctx, len(row.rules)+1); err != nil {
					reader.err = err
				} else {
					states = append(states, cloneUnwindRow(row))
				}
			case 0x0b:
				if len(states) == 0 {
					reader.err = fmt.Errorf("CFI restore-state without saved state: %w", target.ErrInvalidArgument)
				} else {
					row = states[len(states)-1]
					states = states[:len(states)-1]
				}
			case 0x0c, 0x12:
				register = readRegister()
				var offset int64
				if op == 0x12 {
					offset = readFactored(true)
				} else {
					value := reader.uleb()
					if value > math.MaxInt64 {
						reader.err = target.ErrOverflow
					}
					offset = int64(value)
				}
				row.cfa = unwindCFA{defined: true, register: register, offset: offset}
			case 0x0d, 0x0e, 0x13:
				if !row.cfa.defined || row.cfa.expression != nil {
					reader.err = fmt.Errorf("CFI CFA register/offset update without register CFA: %w", target.ErrInvalidArgument)
				}
				if op == 0x0d {
					row.cfa.register = readRegister()
				} else if op == 0x13 {
					row.cfa.offset = readFactored(true)
				} else {
					value := reader.uleb()
					if value > math.MaxInt64 {
						reader.err = target.ErrOverflow
					}
					row.cfa.offset = int64(value)
				}
			case 0x0f:
				row.cfa = unwindCFA{defined: true, expression: readExpression()}
				if row.cfa.expression == nil && reader.err == nil {
					reader.err = target.ErrInvalidArgument
				}
			case 0x10, 0x16:
				register, setRule = readRegister(), true
				rule = unwindRule{kind: unwindExpression, expression: readExpression(), explicit: true}
				if op == 0x16 {
					rule.kind = unwindValueExpression
				}
			case 0x2e:
				reader.uleb()
			default:
				reader.err = fmt.Errorf("CFI opcode %#x: %w", op, target.ErrUnsupported)
			}
		}
		if reader.err != nil {
			return unwindRow{}, fmt.Errorf("CFI instruction at %#x+%#x: %w", program.address, reader.offset, reader.err)
		}
		if setRule {
			row.rules[register] = rule
		}
		if advance {
			if cie || next < location || next > frame.end || op == 0x01 && next == location {
				return unwindRow{}, fmt.Errorf("invalid CFI row location %#x: %w", next, target.ErrInvalidArgument)
			}
			if next > pc {
				return row, nil
			}
			location = next
		}
	}
	return row, nil
}

func unwindRegisterValue(registers AMD64UnwindRegisters, number uint64) (uint64, error) {
	if number >= uint64(len(registers.Values)) {
		return 0, fmt.Errorf("required DWARF register %d: %w", number, target.ErrUnsupported)
	}
	if registers.Known&(1<<number) == 0 {
		return 0, fmt.Errorf("DWARF register %d (%s): %w", number, unwindName(registers.Architecture, number), target.ErrUnavailable)
	}
	return registers.Values[number], nil
}

func recoverCFIFrame(ctx context.Context, metadata *CFIFrame, row unwindRow, registers AMD64UnwindRegisters, frame *UnwindFrame, budget *unwindBudget) (AMD64UnwindRegisters, bool, error) {
	var next AMD64UnwindRegisters
	next.Architecture = registers.Architecture
	abi := unwindABIFor(registers.Architecture)
	returnRule := row.rules[uint64(abi.pc)]
	complete := returnRule.kind == unwindUndefined && returnRule.explicit
	if !row.cfa.defined {
		if complete {
			return next, true, nil
		}
		return next, false, fmt.Errorf("CFI has no CFA rule: %w", target.ErrUnavailable)
	}
	var cfa uint64
	var err error
	if row.cfa.expression != nil {
		frame.CFAExpression = true
		cfa, err = evaluateUnwindExpression(ctx, row.cfa.expression, registers, nil, metadata, budget)
	} else {
		frame.CFARegister, frame.CFAOffset = row.cfa.register, row.cfa.offset
		cfa, err = unwindRegisterValue(registers, row.cfa.register)
		if err == nil {
			cfa, err = unwindSignedAdd(cfa, row.cfa.offset)
		}
	}
	if err != nil {
		return next, false, fmt.Errorf("CFA at %#x: %w", frame.LookupPC, err)
	}
	if abi.word == 4 && cfa > math.MaxUint32 {
		return next, false, target.ErrOverflow
	}
	frame.CFA, frame.CFAKnown = target.Address(cfa), true
	for number := uint64(0); number < uint64(abi.count); number++ {
		if err := budget.operation(ctx); err != nil {
			return next, false, err
		}
		rule := row.rules[number]
		saved := UnwindSavedRegister{Register: number, SourceRegister: rule.register, Offset: rule.offset, Provenance: "unavailable"}
		if rule.explicit {
			saved.Provenance = "cfi"
		} else if rule.kind != unwindUndefined {
			saved.Provenance = "abi:sysv-amd64"
			if abi.word == 4 {
				saved.Provenance = "abi:sysv-x86"
			}
		}
		var value uint64
		var available bool
		switch rule.kind {
		case unwindUndefined:
			saved.Rule = "undefined"
			if !rule.explicit {
				saved.Rule = "unavailable"
			}
		case unwindSame:
			saved.Rule = "same_value"
			value, available = registers.Values[number], registers.Known&(1<<number) != 0
		case unwindOffset, unwindValueOffset:
			saved.Rule = "offset"
			value, err = unwindSignedAdd(cfa, rule.offset)
			if err == nil && rule.kind == unwindOffset {
				saved.Address, saved.AddressKnown = target.Address(value), true
				value, err = budget.value(ctx, saved.Address, abi.word)
			} else if rule.kind == unwindValueOffset {
				saved.Rule = "val_offset"
			}
			available = err == nil
		case unwindRegister:
			saved.Rule = "register"
			value, err = unwindRegisterValue(registers, rule.register)
			available = err == nil
		case unwindExpression, unwindValueExpression:
			saved.Rule = "expression"
			value, err = evaluateUnwindExpression(ctx, rule.expression, registers, &cfa, metadata, budget)
			if err == nil && rule.kind == unwindExpression {
				saved.Address, saved.AddressKnown = target.Address(value), true
				value, err = budget.value(ctx, saved.Address, abi.word)
			} else if rule.kind == unwindValueExpression {
				saved.Rule = "val_expression"
			}
			available = err == nil
		}
		if available && abi.word == 4 && value > math.MaxUint32 {
			return next, false, target.ErrOverflow
		}
		saved.Value, saved.Available = value, available
		frame.Saved = append(frame.Saved, saved)
		if err != nil {
			return next, false, fmt.Errorf("recover DWARF register %d: %w", number, err)
		}
		if available {
			next.Values[number], next.Known = value, next.Known|(1<<number)
		}
	}
	if complete {
		return next, true, nil
	}
	if next.Known&(1<<abi.pc) == 0 {
		return next, false, fmt.Errorf("CFI return address is unavailable: %w", target.ErrUnavailable)
	}
	return next, false, nil
}

var x86UnwindNames = [...]string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"}

type unwindABI struct{ word, pc, count int }

func unwindABIFor(arch target.Architecture) unwindABI {
	if arch == target.X86 {
		return unwindABI{4, 8, 9}
	}
	return unwindABI{8, 16, 17}
}
func unwindName(arch target.Architecture, n uint64) string {
	if arch == target.X86 {
		if n < 9 {
			return x86UnwindNames[n]
		}
		return fmt.Sprintf("register%d", n)
	}
	return amd64UnwindNames[n]
}
