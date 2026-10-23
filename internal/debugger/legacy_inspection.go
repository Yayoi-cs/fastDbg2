package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/internal/cli"
	"fastdbg2/native"
	"fastdbg2/target"
)

const (
	maxFunctionBytes        = 64 << 10
	maxFunctionInstructions = 4096
)

type executableSymbolRange struct {
	address target.Address
	size    uint64
}

func (span executableSymbolRange) contains(address target.Address) bool {
	return address >= span.address && uint64(address-span.address) < span.size
}

type moduleSymbolFacts struct {
	id         string
	path       string
	proof      string
	metadata   string
	header     metadataModuleHeader
	symbols    []inspect.Symbol
	executable []executableSymbolRange
	err        error
}

func legacyDisassembleArguments(first, rest string) (string, int, bool, error) {
	second, remaining := takeMemoryArgument(rest)
	if remaining != "" || first == "" || second == "" {
		return "", 0, false, nil
	}
	for _, token := range []string{first, second} {
		if token[0] < '0' || token[0] > '9' {
			return "", 0, false, nil
		}
		for _, char := range token {
			if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z') {
				return "", 0, false, nil
			}
		}
	}
	if _, err := inspect.EvalExpression(first, nil); err != nil {
		return "", 0, true, err
	}
	count, err := inspect.EvalExpression(second, nil)
	if err != nil || count == 0 || count > maxDisplayInstructions {
		return "", 0, true, fmt.Errorf("disassemble count must be between 1 and %d: %w", maxDisplayInstructions, errors.Join(target.ErrInvalidArgument, err))
	}
	return first, int(count), true, nil
}

func readMappedSymbolFacts(ctx context.Context, module *mappedELF) moduleSymbolFacts {
	if module.Runtime != nil {
		facts := readRuntimeSymbolFacts(ctx, module)
		facts.header = newMetadataModuleHeader(module)
		return facts
	}
	facts := moduleSymbolFacts{id: module.ID, path: module.Path, proof: module.Proof, metadata: mappedELFSourceDescription(module), header: newMetadataModuleHeader(module)}
	for _, program := range module.File.Progs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 || program.Memsz == 0 {
			continue
		}
		if module.LoadBias > math.MaxUint64-program.Vaddr || program.Memsz-1 > math.MaxUint64-(module.LoadBias+program.Vaddr) {
			facts.err = fmt.Errorf("executable segment in module %q: %w", module.ID, target.ErrOverflow)
			return facts
		}
		facts.executable = append(facts.executable, executableSymbolRange{target.Address(module.LoadBias + program.Vaddr), program.Memsz})
	}
	index, err := inspect.LoadSymbols(ctx, []inspect.Module{{
		ID: module.ID, Path: fmt.Sprintf("/proc/self/fd/%d", module.Source.Fd()), LoadBias: module.LoadBias,
	}}, 1)
	if err != nil {
		facts.err = err
		return facts
	}
	facts.symbols, facts.err = index.Symbols(module.ID)
	return facts
}

func (c *Controller) mappedSymbolFacts(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, selection elfModuleSelection) ([]moduleSymbolFacts, error) {
	var facts []moduleSymbolFacts
	err := c.withELFModules(ctx, snapshot, thread, selection, func(modules []*mappedELF) error {
		for _, module := range modules {
			if err := contextReady(ctx); err != nil {
				return err
			}
			facts = append(facts, readMappedSymbolFacts(ctx, module))
		}
		return contextReady(ctx)
	})
	if !mappedELFResultUsable(err) {
		return nil, err
	}
	return facts, err
}

func (c *Controller) showSymbols(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	args, err := cli.ParseArgs(rawArgs)
	if err != nil || len(args) > 1 {
		return fmt.Errorf("usage: sym [FILTER]: %w", errors.Join(target.ErrInvalidArgument, err))
	}
	filter := ""
	if len(args) == 1 {
		filter = args[0]
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	facts, err := c.mappedSymbolFacts(ctx, snapshot, thread, elfModuleSelection{All: true})
	if !mappedELFResultUsable(err) {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	var mappings []procMap
	if source, ok := c.session.(addressWalkMapSource); ok {
		var mapErr error
		mappings, mapErr = source.addressWalkMaps(ctx, snapshot, thread)
		if addressWalkFatal(mapErr) || contextReady(ctx) != nil {
			return errors.Join(err, mapErr, contextReady(ctx))
		}
		if mapErr != nil {
			mappings = nil
		}
	}
	var output strings.Builder
	renderErr := c.renderSymbolFactsMapped(ctx, facts, filter, mappings, func(format string, args ...any) error {
		_, err := fmt.Fprintf(&output, format, args...)
		return err
	})
	if addressWalkFatal(renderErr) {
		return errors.Join(err, renderErr)
	}
	if err != nil {
		view := c.metadataView()
		view.unavailable("Scope", err)
		view.note("Module scan incomplete; only proven module records are shown.", metadataPartial)
		output.WriteString(view.output.String())
	}
	if currentErr := c.displaySnapshotCurrent(ctx, snapshot, thread); currentErr != nil {
		return errors.Join(err, renderErr, currentErr)
	}
	return errors.Join(err, renderErr, c.publishPaged(ctx, output.String()))
}

func (c *Controller) renderSymbolFacts(facts []moduleSymbolFacts, filter string) error {
	return c.renderSymbolFactsWith(context.Background(), facts, filter, c.writef)
}

func (c *Controller) renderSymbolFactsWith(ctx context.Context, facts []moduleSymbolFacts, filter string, writef func(string, ...any) error) error {
	return c.renderSymbolFactsMapped(ctx, facts, filter, nil, writef)
}

func (c *Controller) renderSymbolFactsMapped(ctx context.Context, facts []moduleSymbolFacts, filter string, mappings []procMap, writef func(string, ...any) error) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	view := c.metadataView()
	view.heading("symbols")
	if err := writef("%s", view.output.String()); err != nil {
		return err
	}
	filter = strings.ToLower(filter)
	var failures []error
	count := 0
	hidden := 0
	unavailable := 0
	for _, module := range facts {
		if err := contextReady(ctx); err != nil {
			return errors.Join(append(failures, err)...)
		}
		var matching []int
		if module.err == nil {
			for index, symbol := range module.symbols {
				if err := contextReady(ctx); err != nil {
					return errors.Join(append(failures, err)...)
				}
				if strings.Contains(strings.ToLower(symbol.Name), filter) {
					matching = append(matching, index)
				}
			}
			if filter != "" && len(matching) == 0 {
				hidden++
				continue
			}
		}
		view.output.Reset()
		if module.header.present {
			view.moduleHeader("", module.header)
			if module.header.runtime {
				view.note("Runtime dynamic symbols only; static symbols and debug metadata unavailable.", metadataUnknown)
			}
		} else {
			view.field("Module", strconv.QuoteToGraphic(module.id), metadataPlain)
			view.field("File", strconv.QuoteToGraphic(module.path), metadataPlain)
			view.field("Source proof", strconv.QuoteToGraphic(module.proof), metadataPlain)
			if module.metadata != "" {
				view.field("Metadata", strconv.QuoteToGraphic(module.metadata), metadataPlain)
			}
		}
		if module.err != nil {
			unavailable++
			failures = append(failures, fmt.Errorf("module %q: %w", module.id, module.err))
			view.unavailable("Symbols", module.err)
			if err := writef("%s", view.output.String()); err != nil {
				return errors.Join(append(failures, err)...)
			}
			continue
		}
		if err := writef("%s", view.output.String()); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := writef("%s\n", c.renderer.Text(display.StyleHeading, fmt.Sprintf("%-18s %6s %-10s %-10s %s", "ADDRESS / VALUE", "SIZE", "TYPE", "BIND", "NAME"))); err != nil {
			return errors.Join(append(failures, err)...)
		}
		for _, index := range matching {
			if err := contextReady(ctx); err != nil {
				return errors.Join(append(failures, err)...)
			}
			symbol := module.symbols[index]
			address := c.renderer.Text(display.StyleMuted, "<unavailable>")
			if symbol.AddressKnown {
				address = fmt.Sprintf("0x%016x", symbol.Address)
				if symbol.Section != elf.SHN_ABS {
					address = view.address(symbol.Address, mappings)
				}
			}
			kind := c.renderer.Text(display.StyleHeading, display.Pad(symbol.Type.String(), 10))
			name := c.renderer.Text(display.StyleSymbol, strconv.QuoteToGraphic(symbol.Name))
			detail := fmt.Sprintf("version=%q value=%#x section=%s module=%q", symbol.Version, symbol.Value, symbolSectionText(symbol.Section), symbol.ModuleID)
			if symbol.Section == elf.SHN_ABS {
				detail += " (absolute scalar)"
			}
			if err := writef("%s %6d %s %-10s %s %s\n", display.Pad(address, 18), symbol.Size, kind, symbol.Binding, name, detail); err != nil {
				return errors.Join(append(failures, err)...)
			}
			count++
		}
	}
	if err := contextReady(ctx); err != nil {
		return errors.Join(append(failures, err)...)
	}
	view.output.Reset()
	view.note(fmt.Sprintf("%d symbol(s); names are literal ELF symbols, unavailable addresses are not inferred.", count), metadataUnknown)
	if filter != "" {
		view.note(fmt.Sprintf("Scope: %d module record(s); %d healthy no-match module(s) hidden; %d symbol table(s) unavailable.", len(facts), hidden, unavailable), metadataUnknown)
	}
	if err := writef("%s", view.output.String()); err != nil {
		return errors.Join(append(failures, err)...)
	}
	return errors.Join(failures...)
}

func symbolSectionText(section elf.SectionIndex) string {
	if section == elf.SHN_UNDEF || section >= elf.SHN_LORESERVE && section <= elf.SHN_XINDEX {
		return section.String()
	}
	return strconv.Itoa(int(section))
}

func telescopeArguments(rawArgs string) (string, int, int, error) {
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return "", 0, 0, fmt.Errorf("telescope arguments: %w", errors.Join(target.ErrInvalidArgument, err))
	}
	depth := defaultAddressWalkDepth
	if len(args) != 0 && args[0] == "--depth" {
		if len(args) < 2 {
			return "", 0, 0, fmt.Errorf("telescope --depth requires 1..16: %w", target.ErrInvalidArgument)
		}
		depth, err = positiveInt(args[1], "telescope depth")
		if err != nil || depth > 16 {
			return "", 0, 0, fmt.Errorf("telescope depth must be between 1 and 16: %w", target.ErrInvalidArgument)
		}
		args = args[2:]
	}
	if len(args) < 1 || len(args) > 2 {
		return "", 0, 0, fmt.Errorf("usage: telescope [--depth N] ADDR [COUNT]; quote expressions containing spaces: %w", target.ErrInvalidArgument)
	}
	count := 128
	if len(args) == 2 {
		value, err := strconv.ParseUint(args[1], 0, 32)
		if err != nil || value == 0 || value > maxMemoryBytes/8 {
			return "", 0, 0, fmt.Errorf("telescope count must be between 1 and %d: %w", maxMemoryBytes/8, target.ErrInvalidArgument)
		}
		count = int(value)
	}
	return args[0], count, depth, nil
}

func (c *Controller) showTelescope(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	expression, count, depth, err := telescopeArguments(rawArgs)
	if err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	address, registers, err := c.addressWalkExpression(ctx, expression, snapshot, thread)
	if err != nil {
		return err
	}
	if err := inspectionRange(address, count*8); err != nil {
		return err
	}
	walker, viewErr := c.newAddressView(ctx, snapshot, thread, registers)
	if addressWalkFatal(viewErr) {
		return viewErr
	}
	if walker != nil {
		body, readErr := walker.Rows(ctx, address, count, depth)
		if addressWalkFatal(readErr) {
			return errors.Join(viewErr, readErr)
		}
		if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
			return errors.Join(viewErr, readErr, err)
		}
		return c.publishPagedAddressWalk(ctx, "telescope", body, errors.Join(viewErr, readErr))
	}
	if viewErr != nil {
		return viewErr
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, count*8)
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	if errors.Is(readErr, target.ErrStale) {
		return readErr
	}
	var output strings.Builder
	output.WriteString("[telescope]\n")
	for offset := 0; offset < len(data); offset += 8 {
		row := data[offset:min(offset+8, len(data))]
		addressText, err := c.renderer.Address(target.AMD64, address+target.Address(offset), display.AddressUnknown)
		if err != nil {
			return err
		}
		value := "<partial bytes: " + display.FormatBytes(row) + ">"
		if len(row) == 8 {
			value = fmt.Sprintf("0x%016x", inspectionWord(row))
		}
		fmt.Fprintf(&output, "%s:+0x%03x(+0x%02x)|%s\n", addressText, offset, offset/8, value)
	}
	if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
		return errors.Join(readErr, err)
	}
	return errors.Join(readErr, c.publishPaged(ctx, output.String()))
}

func (c *Controller) showFSBase(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(rawArgs) != "" {
		return fmt.Errorf("fs takes no arguments: %w", target.ErrInvalidArgument)
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
	base, err := contextRegisterValue(registers, "fs_base")
	if err != nil {
		return err
	}
	if err := inspectionRange(target.Address(base), 128); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, 128)
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, target.Address(base), data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	if errors.Is(readErr, target.ErrStale) {
		return readErr
	}
	if err := c.writef("[fs dump]\nfs_base = 0x%016x\n", base); err != nil {
		return err
	}
	if err := c.hexRows(target.Address(base), data, 8); err != nil {
		return err
	}
	return readErr
}

func exactFunctionSymbol(facts []moduleSymbolFacts, address target.Address) (inspect.Symbol, error) {
	var candidates []inspect.Symbol
	var failures []error
	for _, module := range facts {
		contains := false
		for _, span := range module.executable {
			contains = contains || span.contains(address)
		}
		if !contains {
			continue
		}
		if module.err != nil {
			failures = append(failures, fmt.Errorf("module %q: %w", module.id, module.err))
			continue
		}
		for _, symbol := range module.symbols {
			if symbol.Type != elf.STT_FUNC || !symbol.AddressKnown || address < symbol.Address ||
				(address != symbol.Address && uint64(address-symbol.Address) >= symbol.Size) {
				continue
			}
			candidates = append(candidates, symbol)
		}
	}
	if len(failures) != 0 {
		return inspect.Symbol{}, errors.Join(failures...)
	}
	if len(candidates) == 0 {
		return inspect.Symbol{}, fmt.Errorf("no exact ELF function contains %#x: %w", address, target.ErrNotFound)
	}
	if len(candidates) != 1 {
		return inspect.Symbol{}, &inspect.AmbiguousSymbolError{Candidates: candidates}
	}
	symbol := candidates[0]
	if symbol.Size == 0 {
		return inspect.Symbol{}, fmt.Errorf("function %q has no declared size: %w", symbol.Name, target.ErrUnavailable)
	}
	if symbol.Size-1 > math.MaxUint64-uint64(symbol.Address) {
		return inspect.Symbol{}, target.ErrOverflow
	}
	last := symbol.Address + target.Address(symbol.Size-1)
	for _, module := range facts {
		if module.id == symbol.ModuleID {
			for _, span := range module.executable {
				if span.contains(symbol.Address) && span.contains(last) {
					return symbol, nil
				}
			}
		}
	}
	return inspect.Symbol{}, fmt.Errorf("function %q is outside a proven executable segment: %w", symbol.Name, target.ErrUnavailable)
}

func functionDisassembleArguments(rawArgs string) (elfModuleSelection, string, error) {
	first, rest := takeMemoryArgument(rawArgs)
	if first != "--module" {
		return elfModuleSelection{}, strings.TrimSpace(rawArgs), nil
	}
	name, expression, err := takeInspectionCLIArgument(rest)
	if err != nil || name == "" {
		return elfModuleSelection{}, "", fmt.Errorf("disassemble func --module requires an exact module name: %w", errors.Join(target.ErrInvalidArgument, err))
	}
	return elfModuleSelection{Name: name}, expression, nil
}

func takeInspectionCLIArgument(input string) (string, string, error) {
	input = strings.TrimSpace(input)
	end := len(input)
	var quote rune
	escaped := false
	for index, char := range input {
		switch {
		case quote == '\'':
			if char == quote {
				quote = 0
			}
		case escaped:
			escaped = false
		case char == '\\':
			escaped = true
		case quote == '"':
			if char == quote {
				quote = 0
			}
		case char == '\'' || char == '"':
			quote = char
		case unicode.IsSpace(char):
			end = index
		}
		if end != len(input) {
			break
		}
	}
	args, err := cli.ParseArgs(input[:end])
	if err != nil || len(args) != 1 {
		return "", "", errors.Join(target.ErrInvalidArgument, err)
	}
	return args[0], strings.TrimSpace(input[end:]), nil
}

func (c *Controller) showFunctionDisassemble(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	selection, expression, err := functionDisassembleArguments(rawArgs)
	if err != nil {
		return err
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
	if strings.TrimSpace(expression) != "" {
		address, err = c.evaluate(ctx, expression, snapshot, thread)
		if err != nil {
			return err
		}
	}
	facts, err := c.mappedSymbolFacts(ctx, snapshot, thread, selection)
	if err != nil {
		return err
	}
	symbol, err := exactFunctionSymbol(facts, address)
	if err != nil {
		return err
	}
	return c.showFunctionCode(ctx, snapshot.Memory, symbol, location)
}

func (c *Controller) showFunctionCode(ctx context.Context, token target.MemoryToken, symbol inspect.Symbol, location native.CodeLocation) error {
	if symbol.Size == 0 || symbol.Size > maxFunctionBytes {
		return fmt.Errorf("function size must be between 1 and %d bytes: %w", maxFunctionBytes, target.ErrInvalidArgument)
	}
	if err := inspectionRange(symbol.Address, int(symbol.Size)); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	data := make([]byte, int(symbol.Size))
	n, readErr := c.session.ReadCodeMemory(token, symbol.Address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return err
	}
	if errors.Is(readErr, target.ErrStale) {
		return readErr
	}
	instructions, decodeErr := inspect.Disassemble(target.AMD64, symbol.Address, data, maxFunctionInstructions)
	consumed := 0
	for _, instruction := range instructions {
		consumed += len(instruction.Bytes)
	}
	if decodeErr == nil && consumed < len(data) {
		decodeErr = fmt.Errorf("function display stopped after %d instructions: %w", maxFunctionInstructions, target.ErrPartial)
	}
	view := c.metadataView()
	view.heading("disassembly")
	view.field("Function", strconv.QuoteToGraphic(symbol.Name), metadataPlain)
	view.field("Module", strconv.QuoteToGraphic(symbol.ModuleID), metadataPlain)
	view.field("Address", fmt.Sprintf("0x%016x", symbol.Address), metadataPlain)
	view.field("Extent", fmt.Sprintf("%d bytes (ELF STT_FUNC extent)", symbol.Size), metadataPlain)
	if err := c.writef("%s", view.output.String()); err != nil {
		return err
	}
	if err := c.instructionRows(instructions, &location); err != nil {
		return err
	}
	return errors.Join(readErr, decodeErr)
}
