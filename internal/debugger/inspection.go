package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
)

const maxDisplayInstructions = 256

type lazyInspectionResolver struct {
	controller *Controller
	ctx        context.Context
	snapshot   target.Snapshot
	thread     target.ThreadInfo
	ready      bool
	registers  []target.Register
	readRegs   bool
	symbols    *stoppedSymbolResolver
}

func (resolver *lazyInspectionResolver) initialize() error {
	if err := contextReady(resolver.ctx); err != nil {
		return err
	}
	if resolver.ready {
		return nil
	}
	if resolver.controller == nil {
		return target.ErrInvalidState
	}
	snapshot, thread, err := resolver.controller.stopped()
	if err != nil {
		return err
	}
	if err := validateImageSnapshot(snapshot, thread); err != nil {
		return err
	}
	if err := contextReady(resolver.ctx); err != nil {
		return err
	}
	resolver.snapshot, resolver.thread, resolver.ready = snapshot, thread, true
	return nil
}

func (resolver *lazyInspectionResolver) ResolveRegister(name string) (uint64, error) {
	if err := resolver.initialize(); err != nil {
		return 0, err
	}
	if !resolver.readRegs {
		registers, err := resolver.controller.session.ReadThreadRegisters(resolver.thread.Token)
		if err != nil {
			return 0, err
		}
		resolver.registers, resolver.readRegs = registers, true
	}
	if err := contextReady(resolver.ctx); err != nil {
		return 0, err
	}
	return (expressionResolver{registers: resolver.registers}).ResolveRegister(name)
}

func (resolver *lazyInspectionResolver) ResolveSymbol(name string) (uint64, error) {
	if err := resolver.initialize(); err != nil {
		return 0, err
	}
	if resolver.symbols == nil {
		resolver.symbols = resolver.controller.newStoppedSymbolResolver(resolver.ctx, resolver.snapshot, resolver.thread)
	}
	return resolver.symbols.Resolve(name)
}

func (c *Controller) showPrint(ctx context.Context, format, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if format != "" && (len(format) != 1 || !strings.ContainsRune("xduot", rune(format[0]))) {
		return fmt.Errorf("print format must be x, d, u, o or t: %w", target.ErrInvalidArgument)
	}
	if strings.TrimSpace(rawArgs) == "" {
		return fmt.Errorf("usage: print[/FORMAT] EXPR: %w", target.ErrInvalidArgument)
	}
	resolver := &lazyInspectionResolver{controller: c, ctx: ctx}
	value, err := inspect.EvalExpression(rawArgs, resolver)
	if err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if format == "" {
		return c.writef("HEX: %s DEC: %s OCT: %s BIN: %s\n",
			c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%x", value)),
			c.renderer.Text(display.StyleCyan, fmt.Sprint(value)),
			c.renderer.Text(display.StyleCyan, fmt.Sprintf("%o", value)),
			c.renderer.Text(display.StyleCyan, fmt.Sprintf("%b", value)))
	}
	if format == "x" {
		return c.writef("0x%x\n", value)
	}
	if format == "t" {
		return c.writef("%b\n", value)
	}
	return c.writef("%s\n", inspectionNumber(value, 8, format[0]))
}

func inspectionCountArguments(rawArgs string, defaultCount, maximum int, command string) (string, int, error) {
	expression := strings.TrimSpace(rawArgs)
	count := defaultCount
	first, rest := takeMemoryArgument(expression)
	if first == "--count" {
		number, remaining := takeMemoryArgument(rest)
		value, err := positiveInt(number, command+" count")
		if err != nil || value > maximum {
			return "", 0, fmt.Errorf("%s count must be between 1 and %d: %w", command, maximum, target.ErrInvalidArgument)
		}
		count, expression = value, remaining
	}
	return expression, count, nil
}

func inspectionRange(address target.Address, size int) error {
	if size <= 0 {
		return target.ErrInvalidArgument
	}
	if uint64(size-1) > math.MaxUint64-uint64(address) {
		return fmt.Errorf("display range at %#x with %d bytes: %w", address, size, target.ErrOverflow)
	}
	return nil
}

func inspectionConfirmedBytes(data []byte, n int, err error) ([]byte, error) {
	data, err = confirmedContextBytes(data, n, err)
	if errors.Is(err, target.ErrStale) {
		return nil, err
	}
	return data, err
}

func (c *Controller) showDisassemble(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if first, rest := takeMemoryArgument(rawArgs); first == "f" || first == "func" || first == "F" || first == "FUNC" {
		return c.showFunctionDisassemble(ctx, rest)
	}
	expression, count, err := inspectionCountArguments(rawArgs, contextInstructionCount, maxDisplayInstructions, "disassemble")
	if err != nil {
		return err
	}
	if first, rest := takeMemoryArgument(rawArgs); first != "--count" {
		if parsedExpression, parsedCount, ok, parseErr := legacyDisassembleArguments(first, rest); ok || parseErr != nil {
			if parseErr != nil {
				return parseErr
			}
			expression, count = parsedExpression, parsedCount
		}
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	location, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil {
		return err
	}
	if location.Breakpoint != nil && *location.Breakpoint != location.InstructionPC {
		return fmt.Errorf("code location disagrees with breakpoint: %w", target.ErrStale)
	}
	address := location.InstructionPC
	if expression != "" {
		address, err = c.evaluate(ctx, expression, snapshot, thread)
		if err != nil {
			return err
		}
	}
	return c.showInstructionRange(ctx, snapshot.Memory, address, count, &location, expression == "")
}

func (c *Controller) showInstructionRange(ctx context.Context, token target.MemoryToken, address target.Address, count int, location *native.CodeLocation, showLocation bool) error {
	if err := inspectionRange(address, count); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, contextReadSize(address, count*15))
	n, readErr := c.session.ReadCodeMemory(token, address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	if errors.Is(readErr, target.ErrStale) {
		return readErr
	}
	instructions, decodeErr := inspect.Disassemble(c.abi().arch, address, data, count)
	if len(instructions) < count && decodeErr == nil && readErr == nil {
		decodeErr = fmt.Errorf("decoded %d of %d requested instructions: %w", len(instructions), count, io.ErrUnexpectedEOF)
	}
	view := contextOutput{arch: c.abi().arch, writef: c.writef, renderer: c.renderer, width: display.OutputWidth(c.out)}
	if err := view.heading("disassembly"); err != nil {
		return err
	}
	if err := c.instructionRows(instructions, location); err != nil {
		return err
	}
	return errors.Join(readErr, decodeErr)
}

func (c *Controller) instructionRows(instructions []inspect.Instruction, location *native.CodeLocation) error {
	byteWidth := 0
	for _, instruction := range instructions {
		byteWidth = max(byteWidth, 2*len(instruction.Bytes))
	}
	width := display.OutputWidth(c.out)
	for _, instruction := range instructions {
		address, err := (display.Renderer{}).Address(c.abi().arch, instruction.Address, display.AddressUnknown)
		address = c.renderer.Text(display.StyleBlue, address)
		if err != nil {
			return err
		}
		marker := "  "
		if location != nil && instruction.Address == location.InstructionPC {
			marker = c.renderer.Text(display.StyleCurrent, "=>")
		}
		line := fmt.Sprintf("%s %s  %-*x  %s\n", marker, address, byteWidth, instruction.Bytes, c.renderer.Text(display.StylePurple, contextEscapedText(instruction.Text)))
		if err := c.writef("%s", display.Wrap(line, width, 4)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) showStack(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	count := contextStackBytes / 8
	if strings.TrimSpace(rawArgs) != "" {
		value, err := positiveInt(rawArgs, "stack count")
		if err != nil || value > maxMemoryBytes/c.abi().word {
			return fmt.Errorf("stack count must be between 1 and %d: %w", maxMemoryBytes/c.abi().word, target.ErrInvalidArgument)
		}
		count = value
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	registers, err := c.session.ReadThreadRegisters(thread.Token)
	if err != nil {
		return err
	}
	sp, err := contextRegisterValue(registers, c.abi().sp)
	if err != nil {
		return err
	}
	address := target.Address(sp)
	if err := inspectionRange(address, count*c.abi().word); err != nil {
		return err
	}
	walker, viewErr := c.newAddressView(ctx, snapshot, thread, registers)
	if addressWalkFatal(viewErr) {
		return viewErr
	}
	if walker != nil {
		body, readErr := walker.Rows(ctx, address, count, defaultAddressWalkDepth)
		if addressWalkFatal(readErr) {
			return errors.Join(viewErr, readErr)
		}
		if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
			return errors.Join(viewErr, readErr, err)
		}
		return c.publishAddressWalk(ctx, "stack", body, errors.Join(viewErr, readErr))
	}
	if viewErr != nil {
		return viewErr
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, count*c.abi().word)
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	view := contextOutput{arch: c.abi().arch, writef: c.writef, renderer: c.renderer}
	if err := view.heading("stack"); err != nil {
		return err
	}
	if err := view.rawMemory(address, data, c.abi().word, display.AddressStack, true); err != nil {
		return err
	}
	return readErr
}

func hexdumpUnitSize(unit string) (int, error) {
	switch unit {
	case "byte":
		return 1, nil
	case "word":
		return 2, nil
	case "dword":
		return 4, nil
	case "qword":
		return 8, nil
	default:
		return 0, fmt.Errorf("hexdump unit must be byte, word, dword or qword: %w", target.ErrInvalidArgument)
	}
}

func (c *Controller) showHexdump(ctx context.Context, unit, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if unit == "" {
		unit, rawArgs = takeMemoryArgument(rawArgs)
	}
	size, err := hexdumpUnitSize(unit)
	if err != nil {
		return err
	}
	expression, count, err := inspectionCountArguments(rawArgs, defaultMemoryBytes/size, maxMemoryBytes/size, "hexdump")
	if err != nil {
		return err
	}
	if expression == "" {
		return fmt.Errorf("usage: hexdump UNIT [--count N] EXPR: %w", target.ErrInvalidArgument)
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	address, err := c.evaluate(ctx, expression, snapshot, thread)
	if err != nil {
		return err
	}
	if err := inspectionRange(address, count*size); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, count*size)
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	view := contextOutput{arch: c.abi().arch, writef: c.writef, renderer: c.renderer, width: display.OutputWidth(c.out)}
	if err := view.heading("memory"); err != nil {
		return err
	}
	if err := c.hexRows(address, data, size); err != nil {
		return err
	}
	return readErr
}

func (c *Controller) hexRows(address target.Address, data []byte, unit int) error {
	perUnit := unit*3 + 3
	if unit == 1 {
		perUnit = 4
	}
	units := max(1, min(16/unit, (display.OutputWidth(c.out)-22)/perUnit))
	rowBytes := units * unit
	for offset := 0; offset < len(data); offset += rowBytes {
		row := data[offset:min(offset+rowBytes, len(data))]
		addressText, err := (display.Renderer{}).Address(c.abi().arch, address+target.Address(offset), display.AddressUnknown)
		addressText = c.renderer.Text(display.StyleBlue, addressText)
		if err != nil {
			return err
		}
		var values []string
		for i := 0; i < len(row); i += unit {
			part := row[i:min(i+unit, len(row))]
			if len(part) != unit {
				values = append(values, "["+display.FormatBytes(part)+"]")
				continue
			}
			if unit == 1 {
				values = append(values, fmt.Sprintf("%02x", part[0]))
			} else {
				values = append(values, c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%0*x", unit*2, inspectionWord(part))))
			}
		}
		width := units*(unit*2+3) - 1
		if unit == 1 {
			width = units*3 - 1
		}
		ascii := make([]byte, len(row))
		for i, value := range row {
			ascii[i] = '.'
			if value >= 0x20 && value <= 0x7e {
				ascii[i] = value
			}
		}
		if err := c.writef("%s: %s |%s|\n", addressText, display.Pad(strings.Join(values, " "), width), ascii); err != nil {
			return err
		}
	}
	return nil
}

func inspectionWord(data []byte) uint64 {
	var padded [8]byte
	copy(padded[:], data)
	return binary.LittleEndian.Uint64(padded[:])
}

func inspectionNumber(value uint64, size int, format byte) string {
	switch format {
	case 'x':
		return fmt.Sprintf("0x%0*x", size*2, value)
	case 'd':
		shift := uint(64 - size*8)
		return strconv.FormatInt(int64(value<<shift)>>shift, 10)
	case 'u':
		return strconv.FormatUint(value, 10)
	case 'o':
		return fmt.Sprintf("%#o", value)
	case 't':
		return fmt.Sprintf("%0*b", size*8, value)
	case 'c':
		text := strconv.QuoteRuneToASCII(rune(value))
		if value >= 0x80 {
			text = fmt.Sprintf("'\\x%02x'", value)
		}
		return fmt.Sprintf("%d %s", value, text)
	}
	return ""
}
