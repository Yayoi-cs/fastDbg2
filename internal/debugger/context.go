package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/native/amd64"
	"fastdbg2/target"
)

const (
	contextInstructionCount = 8
	contextCodeBytes        = 120
	contextStackBytes       = 64
	defaultMemoryBytes      = 64
	maxMemoryBytes          = 4096
)

type contextReader interface {
	PID() int
	ReadThreadRegisters(target.ThreadToken) ([]target.Register, error)
	ReadCodeLocation(target.ThreadToken) (native.CodeLocation, error)
	ReadCodeMemory(target.MemoryToken, target.Address, []byte) (int, error)
	ReadSpaceMemory(target.MemoryToken, target.Address, []byte) (int, error)
}

type contextOutput struct {
	writef    func(string, ...any) error
	renderer  display.Renderer
	width     int
	ctx       context.Context
	walker    *addressWalker
	prepare   func([]target.Register) (*addressWalker, error)
	compare   func([]target.Register) map[string]bool
	changed   map[string]bool
	observed  *[]target.Register
	simple    bool
	requested bool
}

type contextCode struct {
	location     *native.CodeLocation
	instructions []inspect.Instruction
	err          error
}

type contextPanes struct {
	registers bool
	stack     bool
	code      bool
	threads   bool
}

func defaultContextPanes() contextPanes {
	return contextPanes{registers: true, stack: true, code: true, threads: true}
}

func parseContextPanes(rawArgs string) (contextPanes, error) {
	arguments := strings.Fields(rawArgs)
	if len(arguments) == 0 {
		return defaultContextPanes(), nil
	}
	var panes contextPanes
	for _, argument := range arguments {
		var selected *bool
		switch argument {
		case "regs", "registers":
			selected = &panes.registers
		case "stack":
			selected = &panes.stack
		case "code":
			selected = &panes.code
		case "threads":
			selected = &panes.threads
		default:
			return contextPanes{}, fmt.Errorf("unknown context pane %q: %w", argument, target.ErrInvalidArgument)
		}
		if *selected {
			return contextPanes{}, fmt.Errorf("duplicate context pane %q: %w", argument, target.ErrInvalidArgument)
		}
		*selected = true
	}
	return panes, nil
}

func (c *Controller) showContext(ctx context.Context, arguments ...string) error {
	return c.showContextWithPrefix(ctx, "", nil, arguments...)
}

func (c *Controller) showContextWithPrefix(ctx context.Context, prefix string, expected *target.Snapshot, arguments ...string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if len(arguments) > 1 {
		return target.ErrInvalidArgument
	}
	var rawArgs string
	if len(arguments) == 1 {
		rawArgs = strings.TrimSpace(arguments[0])
	}
	if rawArgs == "on" || rawArgs == "off" {
		c.contextDisabled = rawArgs == "off"
		return c.writef("Context is %s.\n", rawArgs)
	}
	panes, err := parseContextPanes(rawArgs)
	if err != nil {
		return err
	}
	if c.contextDisabled {
		return nil
	}
	if panes.threads && !panes.registers && !panes.stack && !panes.code {
		return c.showThreads()
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if expected != nil && (!sameContextSnapshot(*expected, snapshot) || validateImageSnapshot(*expected, thread) != nil) {
		return fmt.Errorf("stop snapshot changed before context rendering: %w", target.ErrStale)
	}
	var output bytes.Buffer
	output.WriteString(prefix)
	var observed []target.Register
	view := c.contextUIView(ctx, snapshot, thread, &output)
	view.observed = &observed
	readErr := view.renderContext(ctx, c.session, snapshot, thread, panes)
	if uiDisplayFatal(readErr) {
		return readErr
	}
	if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
		return errors.Join(readErr, err)
	}
	if err := c.publishContext(output.String(), rawArgs == ""); err != nil {
		return errors.Join(readErr, err)
	}
	if panes.registers && len(observed) != 0 {
		c.rememberRegisters(snapshot, thread, observed)
	}
	return readErr
}

func registerArguments(rawArgs string) ([]string, error) {
	arguments := strings.Fields(rawArgs)
	if len(arguments) > 0 && (arguments[0] == "-s" || arguments[0] == "--simple") {
		arguments = arguments[1:]
	}
	var names []string
	seen := make(map[string]bool, len(arguments))
	profile := amd64.Descriptor()
	for _, argument := range arguments {
		name := strings.TrimPrefix(argument, "$")
		if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "$'\"`\\") {
			return nil, fmt.Errorf("invalid register name %q: %w", argument, target.ErrInvalidArgument)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate register name %q: %w", name, target.ErrInvalidArgument)
		}
		if _, ok := profile.Register(name); !ok {
			return nil, fmt.Errorf("unknown AMD64 general register %q: %w", name, target.ErrNotFound)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}

func selectRegisters(registers []target.Register, names []string) ([]target.Register, error) {
	if len(names) == 0 {
		return registers, nil
	}
	selected := make([]target.Register, 0, len(names))
	for _, name := range names {
		found := -1
		for index, register := range registers {
			if register.Name != name {
				continue
			}
			if found >= 0 {
				return nil, fmt.Errorf("register %q: %w", name, target.ErrAmbiguous)
			}
			found = index
		}
		if found < 0 {
			return nil, fmt.Errorf("register %q: %w", name, target.ErrNotFound)
		}
		selected = append(selected, registers[found])
	}
	return selected, nil
}

func (c *Controller) showRegisters(ctx context.Context, arguments ...string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if len(arguments) > 1 {
		return target.ErrInvalidArgument
	}
	var rawArgs string
	if len(arguments) == 1 {
		rawArgs = arguments[0]
	}
	names, err := registerArguments(rawArgs)
	if err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if snapshot.Architecture != target.AMD64 {
		return fmt.Errorf("register display requires amd64: %w", target.ErrUnsupported)
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	registers, readErr := c.session.ReadThreadRegisters(thread.Token)
	if err := contextReady(ctx); err != nil {
		return errors.Join(readErr, err)
	}
	if readErr == nil && len(registers) == 0 {
		readErr = fmt.Errorf("general registers: %w", target.ErrUnavailable)
	}
	allRegisters := registers
	if readErr == nil {
		registers, err = selectRegisters(registers, names)
		if err != nil {
			return err
		}
	}
	if uiDisplayFatal(readErr) {
		return readErr
	}
	var output bytes.Buffer
	view := c.contextUIView(ctx, snapshot, thread, &output)
	first, _ := takeMemoryArgument(rawArgs)
	view.simple = first == "-s" || first == "--simple"
	view.requested = len(names) != 0
	view.changed = c.changedRegisters(snapshot, thread, allRegisters)
	var decorationErr error
	if readErr == nil && !view.simple {
		view.walker, decorationErr = c.newAddressView(ctx, snapshot, thread, allRegisters)
		if uiDisplayFatal(decorationErr) {
			return decorationErr
		}
	}
	valueErr, outputErr := view.registers(registers, readErr)
	combined := errors.Join(readErr, decorationErr, valueErr, outputErr)
	if uiDisplayFatal(combined) {
		return combined
	}
	if !view.simple {
		if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
			return errors.Join(combined, err)
		}
	}
	if err := c.writef("%s", output.String()); err != nil {
		return errors.Join(combined, err)
	}
	if readErr == nil {
		c.rememberRegisters(snapshot, thread, allRegisters)
	}
	return combined
}

func (c *Controller) showMemory(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	expression, count, err := memoryArguments(rawArgs)
	if err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	address, err := c.evaluate(ctx, expression, snapshot, thread)
	if err != nil {
		return err
	}
	if uint64(count-1) > math.MaxUint64-uint64(address) {
		return fmt.Errorf("memory display range: %w", target.ErrOverflow)
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, count)
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	data, readErr = confirmedContextBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return errors.Join(readErr, err)
	}
	view := contextOutput{writef: c.writef, renderer: c.renderer, width: display.OutputWidth(c.out)}
	if err := view.heading("memory"); err != nil {
		return errors.Join(readErr, err)
	}
	if err := view.rawMemory(address, data, 16, display.AddressUnknown, false); err != nil {
		return errors.Join(readErr, err)
	}
	if readErr != nil {
		return errors.Join(readErr, view.unavailable(readErr))
	}
	return nil
}

func contextReady(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required: %w", target.ErrInvalidArgument)
	}
	return ctx.Err()
}

func (view contextOutput) context(ctx context.Context, reader contextReader, snapshot target.Snapshot, thread target.ThreadInfo) error {
	return view.renderContext(ctx, reader, snapshot, thread, defaultContextPanes())
}

func (view contextOutput) renderContext(ctx context.Context, reader contextReader, snapshot target.Snapshot, thread target.ThreadInfo, panes contextPanes) (err error) {
	var readErrors []error
	defer func() { err = errors.Join(append(readErrors, err)...) }()
	if err := contextReady(ctx); err != nil {
		return err
	}
	if snapshot.Architecture != target.AMD64 {
		return fmt.Errorf("context display requires amd64: %w", target.ErrUnsupported)
	}
	view.ctx = ctx
	if err := view.writef("Thread #%d (TID %d) %q — %s: %s\n", thread.Ref.ID, thread.TID, thread.Name, thread.State, thread.Stop.Reason); err != nil {
		return err
	}
	if thread.Stop.Reason == target.StopSignal && thread.Stop.Signal.Number != 0 {
		if err := view.writef("Signal %s:%d\n", contextEscapedText(string(thread.Stop.Signal.Domain)), thread.Stop.Signal.Number); err != nil {
			return err
		}
	}
	if panes.registers {
		if err := view.legend(); err != nil {
			return err
		}
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	var registers []target.Register
	var registerErr error
	if panes.registers || panes.stack || panes.code {
		registers, registerErr = reader.ReadThreadRegisters(thread.Token)
		if registerErr == nil && len(registers) == 0 {
			registerErr = fmt.Errorf("general registers: %w", target.ErrUnavailable)
		}
		readErrors = append(readErrors, registerErr)
	}
	if registerErr == nil && len(registers) != 0 {
		if view.observed != nil {
			*view.observed = registers
		}
		if view.compare != nil {
			view.changed = view.compare(registers)
		}
		if view.prepare != nil {
			var decorationErr error
			view.walker, decorationErr = view.prepare(registers)
			readErrors = append(readErrors, decorationErr)
			if uiDisplayFatal(decorationErr) {
				return decorationErr
			}
		}
	}
	if panes.registers {
		readErr, outputErr := view.registers(registers, registerErr)
		readErrors = append(readErrors, readErr)
		if outputErr != nil || uiDisplayFatal(readErr) {
			return errors.Join(readErr, outputErr)
		}
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	code := contextCode{err: registerErr}
	if panes.code && !errors.Is(registerErr, target.ErrStale) {
		code = readContextCode(reader, snapshot.Memory, thread.Token, registers, registerErr)
		readErrors = append(readErrors, code.err)
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if panes.stack {
		stackErr := registerErr
		if errors.Is(code.err, target.ErrStale) {
			stackErr = errors.Join(stackErr, code.err)
		}
		readErr, outputErr := view.stack(reader, snapshot.Memory, registers, stackErr)
		readErrors = append(readErrors, readErr)
		if errors.Is(readErr, target.ErrStale) {
			code = contextCode{err: readErr}
		}
		if outputErr != nil {
			return outputErr
		}
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if panes.code {
		if err := view.code(code); err != nil {
			return err
		}
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if panes.threads {
		return writeThreadSnapshot(view.writef, snapshot, thread.Ref, threadDisplayOptions{view.renderer, view.width})
	}
	return nil
}

func (view contextOutput) stack(reader contextReader, memory target.MemoryToken, registers []target.Register, registerErr error) (error, error) {
	if err := view.heading("stack"); err != nil {
		return nil, err
	}
	if registerErr != nil {
		return nil, view.unavailable(registerErr)
	}
	sp, err := contextRegisterValue(registers, "rsp")
	if err != nil {
		return err, view.unavailable(err)
	}
	address := target.Address(sp)
	if view.walker != nil {
		rows, err := view.walker.Rows(view.ctx, address, contextStackBytes/8, defaultAddressWalkDepth)
		if uiDisplayFatal(err) {
			return err, nil
		}
		return err, view.writef("%s", rows)
	}
	data := make([]byte, contextReadSize(address, contextStackBytes))
	n, readErr := reader.ReadSpaceMemory(memory, address, data)
	data, readErr = confirmedContextBytes(data, n, readErr)
	if err := view.rawStackRows(registers, address, data); err != nil {
		return readErr, err
	}
	if readErr != nil {
		return readErr, view.unavailable(readErr)
	}
	return nil, nil
}

func (view contextOutput) heading(name string) error {
	return view.writef("%s\n", view.renderer.Section(name, view.width))
}

func (view contextOutput) unavailable(err error) error {
	return view.writef("  %s\n", view.renderer.Text(display.StyleError, "unavailable: "+contextEscapedText(err.Error())))
}

func contextEscapedText(text string) string {
	quoted := strconv.QuoteToGraphic(text)
	return quoted[1 : len(quoted)-1]
}

func (view contextOutput) registers(registers []target.Register, readErr error) (error, error) {
	if err := view.heading("registers"); err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, view.unavailable(readErr)
	}
	if len(registers) == 0 {
		err := fmt.Errorf("general registers: %w", target.ErrUnavailable)
		return err, view.unavailable(err)
	}
	if !view.requested {
		registers = uiOrderedRegisters(registers)
	}
	var failures []error
	var segments []string
	ctx := view.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for _, register := range registers {
		if err := contextReady(ctx); err != nil {
			return errors.Join(append(failures, err)...), nil
		}
		value, scalarErr := contextScalar(register)
		if !view.requested && uiSegment(register.Name) && scalarErr == nil {
			segments = append(segments, fmt.Sprintf("%s: 0x%04x", view.registerName(register), value))
			continue
		}
		text := "<unavailable>"
		if register.Available {
			if scalarErr != nil {
				text = fmt.Sprintf("<invalid %d-bit value>", register.Bits)
			} else {
				text = fmt.Sprintf("0x%0*x", register.Bits/4, value)
				if register.Name == "eflags" {
					text += " " + view.flags(value)
				} else if !view.simple && view.walker != nil && register.Bits == 64 && !uiSegment(register.Name) && register.Name != "orig_rax" {
					var chainErr error
					text, chainErr = view.walker.Value(ctx, value, defaultAddressWalkDepth)
					if uiDisplayFatal(chainErr) {
						return chainErr, nil
					}
					failures = append(failures, chainErr)
				}
			}
		}
		padding := strings.Repeat(" ", max(0, 7-utf8.RuneCountInString("$"+contextEscapedText(register.Name))))
		if err := view.writef("%s%s: %s\n", view.registerName(register), padding, text); err != nil {
			return errors.Join(failures...), err
		}
	}
	if len(segments) != 0 {
		if err := view.writef("%s\n", strings.Join(segments, " ")); err != nil {
			return errors.Join(failures...), err
		}
	}
	return errors.Join(failures...), nil
}

func contextRegisterText(register target.Register) string {
	name := contextEscapedText(register.Name)
	if !register.Available {
		return fmt.Sprintf("$%-6s: <unavailable>", name)
	}
	value, err := contextScalar(register)
	if err != nil {
		return fmt.Sprintf("$%-6s: <invalid %d-bit value>", name, register.Bits)
	}
	return fmt.Sprintf("$%-6s: 0x%0*x", name, register.Bits/4, value)
}

func contextScalar(register target.Register) (uint64, error) {
	if !register.Available {
		return 0, fmt.Errorf("register %q: %w", register.Name, target.ErrUnavailable)
	}
	if register.Bits <= 0 || register.Bits > 64 || register.Bits%8 != 0 || len(register.Data) != register.Bits/8 {
		return 0, fmt.Errorf("register %q has invalid %d-bit data: %w", register.Name, register.Bits, target.ErrUnavailable)
	}
	var data [8]byte
	copy(data[:], register.Data)
	return binary.LittleEndian.Uint64(data[:]), nil
}

func contextRegisterValue(registers []target.Register, name string) (uint64, error) {
	var found *target.Register
	for i := range registers {
		if registers[i].Name != name {
			continue
		}
		if found != nil {
			return 0, fmt.Errorf("duplicate register %q: %w", name, target.ErrAmbiguous)
		}
		found = &registers[i]
	}
	if found == nil {
		return 0, fmt.Errorf("register %q: %w", name, target.ErrUnavailable)
	}
	if found.Bits != 64 {
		return 0, fmt.Errorf("register %q is not 64-bit: %w", name, target.ErrUnavailable)
	}
	return contextScalar(*found)
}

func readContextCode(reader contextReader, memory target.MemoryToken, thread target.ThreadToken, registers []target.Register, registerErr error) contextCode {
	location, err := reader.ReadCodeLocation(thread)
	if err != nil {
		return contextCode{err: err}
	}
	if registerErr == nil {
		pc, err := contextRegisterValue(registers, "rip")
		if err == nil && target.Address(pc) != location.RawPC {
			return contextCode{err: fmt.Errorf("code location disagrees with raw rip: %w", target.ErrStale)}
		}
	}
	if location.Breakpoint != nil && *location.Breakpoint != location.InstructionPC {
		return contextCode{err: fmt.Errorf("code location disagrees with breakpoint: %w", target.ErrStale)}
	}
	data := make([]byte, contextReadSize(location.InstructionPC, contextCodeBytes))
	n, readErr := reader.ReadCodeMemory(memory, location.InstructionPC, data)
	data, readErr = confirmedContextBytes(data, n, readErr)
	instructions, decodeErr := inspect.Disassemble(target.AMD64, location.InstructionPC, data, contextInstructionCount)
	return contextCode{location: &location, instructions: instructions, err: errors.Join(readErr, decodeErr)}
}

func (view contextOutput) code(code contextCode) error {
	if err := view.heading("code"); err != nil {
		return err
	}
	byteWidth := 0
	for _, instruction := range code.instructions {
		byteWidth = max(byteWidth, 2*min(len(instruction.Bytes), 15))
	}
	for _, instruction := range code.instructions {
		address, err := view.renderer.Address(target.AMD64, instruction.Address, display.AddressCode)
		if view.walker != nil {
			address, err = view.walker.Address(instruction.Address)
		}
		if err != nil {
			return err
		}
		marker := "   "
		if code.location != nil && instruction.Address == code.location.InstructionPC {
			marker = " ->"
			if code.location.Breakpoint != nil {
				marker = "*->"
			}
			marker = view.renderer.Text(display.StyleCurrent, marker)
		}
		label := ""
		if view.walker != nil && view.walker.symbol != nil {
			if name := view.walker.symbol(instruction.Address); name != "" {
				label = view.renderer.Text(display.StyleSymbol, "<"+contextEscapedText(name)+"> ")
			}
		}
		if err := view.writef("%s %s  %-*x %s%s\n", marker, address, byteWidth, instruction.Bytes, label, view.instructionText(instruction)); err != nil {
			return err
		}
	}
	if code.location != nil && code.location.Breakpoint != nil && code.location.RawPC != code.location.InstructionPC {
		if err := view.writef("  %s\n", view.renderer.Text(display.StyleMuted, fmt.Sprintf("breakpoint instruction 0x%016x; raw $rip = 0x%016x", code.location.InstructionPC, code.location.RawPC))); err != nil {
			return err
		}
	}
	if code.err != nil {
		return view.unavailable(code.err)
	}
	return nil
}

func (view contextOutput) rawMemory(start target.Address, data []byte, width int, kind display.AddressKind, words bool) error {
	for offset := 0; offset < len(data); offset += width {
		end := min(offset+width, len(data))
		row := data[offset:end]
		address, err := view.renderer.Address(target.AMD64, start+target.Address(offset), kind)
		if err != nil {
			return err
		}
		if words && len(row) == 8 {
			if err := view.writef("%s  %-23s  0x%016x\n", address, display.FormatBytes(row), binary.LittleEndian.Uint64(row)); err != nil {
				return err
			}
			continue
		}
		if err := view.writef("%s  %s\n", address, display.FormatBytes(row)); err != nil {
			return err
		}
	}
	return nil
}

func contextReadSize(address target.Address, limit int) int {
	if uint64(limit-1) > math.MaxUint64-uint64(address) {
		return int(math.MaxUint64-uint64(address)) + 1
	}
	return limit
}

func confirmedContextBytes(data []byte, n int, err error) ([]byte, error) {
	if n < 0 || n > len(data) {
		return nil, fmt.Errorf("invalid memory read count %d/%d: %w", n, len(data), errors.Join(target.ErrUnknown, err))
	}
	if errors.Is(err, target.ErrStale) {
		return nil, err
	}
	if err == nil && n != len(data) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil && n > 0 && n < len(data) && !errors.Is(err, target.ErrPartial) {
		err = &target.PartialError{Op: "read display memory", Completed: n, Total: len(data), Err: err}
	}
	return data[:n], err
}

func memoryArguments(rawArgs string) (string, int, error) {
	expression := strings.TrimSpace(rawArgs)
	count := defaultMemoryBytes
	first, rest := takeMemoryArgument(expression)
	if first == "--count" {
		number, remaining := takeMemoryArgument(rest)
		value, err := strconv.ParseUint(number, 10, 32)
		if err != nil || value == 0 || value > maxMemoryBytes {
			return "", 0, fmt.Errorf("memory count must be between 1 and %d: %w", maxMemoryBytes, target.ErrInvalidArgument)
		}
		count = int(value)
		expression = strings.TrimSpace(remaining)
	}
	if expression == "" {
		return "", 0, fmt.Errorf("usage: memory [--count N] EXPR: %w", target.ErrInvalidArgument)
	}
	return expression, count, nil
}

func takeMemoryArgument(text string) (string, string) {
	text = strings.TrimSpace(text)
	index := strings.IndexAny(text, " \t\r\n\v\f")
	if index < 0 {
		return text, ""
	}
	return text[:index], strings.TrimSpace(text[index:])
}
