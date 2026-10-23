package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

const maxELFCommandMetadata = 64 << 20

type elfDynamicFacts struct {
	present bool
	values  map[elf.DynTag][]uint64
}

type elfSecurityFacts struct {
	kind        elf.Type
	pieFlag     bool
	stackKnown  bool
	stackExec   bool
	relro       bool
	bindNow     bool
	dynamic     bool
	static      bool
	staticKnown bool
	runtimeOnly bool
	symbols     bool
	canary      []string
	fortify     []string
	rwx         [][2]uint64
}

type elfPointerRelocation struct {
	section string
	symbol  string
	kind    elf.R_X86_64
	offset  uint64
	address target.Address
}

func elfCommandSectionData(section *elf.Section) ([]byte, error) {
	if section == nil || section.Size > maxELFCommandMetadata {
		return nil, fmt.Errorf("ELF metadata exceeds %d bytes: %w", maxELFCommandMetadata, target.ErrUnsupported)
	}
	if section.Flags&elf.SHF_COMPRESSED != 0 || section.Type == elf.SHT_NOBITS {
		return nil, fmt.Errorf("ELF metadata section %q encoding: %w", section.Name, target.ErrUnsupported)
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != section.Size {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func elfCommandSymbolTable(file *elf.File, sectionIndex int) ([]elf.Symbol, error) {
	if file == nil || sectionIndex < 0 || sectionIndex >= len(file.Sections) {
		return nil, target.ErrInvalidArgument
	}
	section := file.Sections[sectionIndex]
	if section.Type != elf.SHT_SYMTAB && section.Type != elf.SHT_DYNSYM {
		return nil, fmt.Errorf("section %q is not a symbol table: %w", section.Name, target.ErrInvalidArgument)
	}
	if section.Entsize != 24 || section.Size%24 != 0 || section.Size == 0 || int(section.Link) >= len(file.Sections) {
		return nil, fmt.Errorf("invalid symbol table %q: %w", section.Name, target.ErrInvalidArgument)
	}
	stringsSection := file.Sections[section.Link]
	if stringsSection.Type != elf.SHT_STRTAB {
		return nil, fmt.Errorf("invalid symbol strings for %q: %w", section.Name, target.ErrInvalidArgument)
	}
	data, err := elfCommandSectionData(section)
	if err != nil {
		return nil, err
	}
	stringsData, err := elfCommandSectionData(stringsSection)
	if err != nil {
		return nil, err
	}
	var result []elf.Symbol
	for offset := 0; offset < len(data); offset += 24 {
		entry := data[offset : offset+24]
		nameOffset := binary.LittleEndian.Uint32(entry[:4])
		if uint64(nameOffset) >= uint64(len(stringsData)) {
			return nil, fmt.Errorf("symbol string offset %d: %w", nameOffset, target.ErrInvalidArgument)
		}
		nameEnd := bytes.IndexByte(stringsData[nameOffset:], 0)
		if nameEnd < 0 {
			return nil, fmt.Errorf("unterminated symbol name: %w", target.ErrInvalidArgument)
		}
		section := elf.SectionIndex(binary.LittleEndian.Uint16(entry[6:8]))
		if section == elf.SHN_XINDEX {
			return nil, fmt.Errorf("extended symbol section indices: %w", target.ErrUnsupported)
		}
		result = append(result, elf.Symbol{
			Name: string(stringsData[int(nameOffset) : int(nameOffset)+nameEnd]), Info: entry[4], Other: entry[5], Section: section,
			Value: binary.LittleEndian.Uint64(entry[8:16]), Size: binary.LittleEndian.Uint64(entry[16:24]),
		})
	}
	return result, nil
}

func elfCommandDynamic(file *elf.File) (elfDynamicFacts, error) {
	facts := elfDynamicFacts{values: make(map[elf.DynTag][]uint64)}
	for _, program := range file.Progs {
		if program.Type != elf.PT_DYNAMIC {
			continue
		}
		if facts.present {
			return elfDynamicFacts{}, fmt.Errorf("multiple PT_DYNAMIC headers: %w", target.ErrAmbiguous)
		}
		facts.present = true
		if program.Filesz == 0 || program.Filesz%16 != 0 || program.Filesz > maxELFCommandMetadata {
			return elfDynamicFacts{}, fmt.Errorf("invalid PT_DYNAMIC size: %w", target.ErrInvalidArgument)
		}
		data := make([]byte, int(program.Filesz))
		if _, err := io.ReadFull(program.Open(), data); err != nil {
			return elfDynamicFacts{}, err
		}
		terminated := false
		for offset := 0; offset < len(data); offset += 16 {
			tag := elf.DynTag(int64(binary.LittleEndian.Uint64(data[offset : offset+8])))
			value := binary.LittleEndian.Uint64(data[offset+8 : offset+16])
			if tag == elf.DT_NULL {
				terminated = true
				break
			}
			facts.values[tag] = append(facts.values[tag], value)
		}
		if !terminated {
			return elfDynamicFacts{}, fmt.Errorf("unterminated PT_DYNAMIC: %w", target.ErrInvalidArgument)
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_FLAGS, elf.DT_FLAGS_1, elf.DT_BIND_NOW} {
		if len(facts.values[tag]) > 1 {
			return elfDynamicFacts{}, fmt.Errorf("duplicate %s: %w", tag, target.ErrAmbiguous)
		}
	}
	return facts, nil
}

func elfHasDynamicFlag(dynamic elfDynamicFacts, tag elf.DynTag, mask uint64) bool {
	for _, value := range dynamic.values[tag] {
		if value&mask != 0 {
			return true
		}
	}
	return false
}

func inspectELFSecurity(file *elf.File) (elfSecurityFacts, error) {
	if err := validateAMD64ELF(file); err != nil {
		return elfSecurityFacts{}, err
	}
	dynamic, err := elfCommandDynamic(file)
	if err != nil {
		return elfSecurityFacts{}, err
	}
	facts := elfSecurityFacts{
		kind: file.Type, dynamic: dynamic.present, staticKnown: true,
		pieFlag: elfHasDynamicFlag(dynamic, elf.DT_FLAGS_1, uint64(elf.DF_1_PIE)),
		bindNow: len(dynamic.values[elf.DT_BIND_NOW]) != 0 || elfHasDynamicFlag(dynamic, elf.DT_FLAGS, uint64(elf.DF_BIND_NOW)) || elfHasDynamicFlag(dynamic, elf.DT_FLAGS_1, uint64(elf.DF_1_NOW)),
	}
	for _, program := range file.Progs {
		switch program.Type {
		case elf.PT_GNU_STACK:
			if facts.stackKnown {
				return elfSecurityFacts{}, fmt.Errorf("multiple PT_GNU_STACK headers: %w", target.ErrAmbiguous)
			}
			facts.stackKnown, facts.stackExec = true, program.Flags&elf.PF_X != 0
		case elf.PT_GNU_RELRO:
			facts.relro = true
		case elf.PT_LOAD:
			if program.Memsz > math.MaxUint64-program.Vaddr {
				return elfSecurityFacts{}, target.ErrOverflow
			}
			if program.Flags&(elf.PF_R|elf.PF_W|elf.PF_X) == elf.PF_R|elf.PF_W|elf.PF_X {
				facts.rwx = append(facts.rwx, [2]uint64{program.Vaddr, program.Vaddr + program.Memsz})
			}
		}
	}
	canary, fortify := make(map[string]bool), make(map[string]bool)
	for index, section := range file.Sections {
		if section.Type != elf.SHT_SYMTAB && section.Type != elf.SHT_DYNSYM {
			continue
		}
		facts.symbols = true
		facts.static = facts.static || section.Type == elf.SHT_SYMTAB
		symbols, err := elfCommandSymbolTable(file, index)
		if err != nil {
			return elfSecurityFacts{}, err
		}
		for _, symbol := range symbols {
			if symbol.Name == "__stack_chk_fail" || symbol.Name == "__stack_chk_fail_local" {
				canary[symbol.Name] = true
			}
			if strings.HasPrefix(symbol.Name, "__") && strings.HasSuffix(symbol.Name, "_chk") {
				fortify[symbol.Name] = true
			}
		}
	}
	for name := range canary {
		facts.canary = append(facts.canary, name)
	}
	for name := range fortify {
		facts.fortify = append(facts.fortify, name)
	}
	slices.Sort(facts.canary)
	slices.Sort(facts.fortify)
	return facts, nil
}

func elfContainsLoadRange(file *elf.File, address, size uint64) bool {
	if size == 0 || size > math.MaxUint64-address {
		return false
	}
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Memsz > math.MaxUint64-program.Vaddr || address < program.Vaddr {
			continue
		}
		if address+size <= program.Vaddr+program.Memsz {
			return true
		}
	}
	return false
}

func elfPointerRelocations(file *elf.File, bias uint64) ([]elfPointerRelocation, error) {
	if err := validateAMD64ELF(file); err != nil {
		return nil, err
	}
	dynamic, err := elfCommandDynamic(file)
	if err != nil {
		return nil, err
	}
	if err := validateELFDynamicRelocations(file, dynamic); err != nil {
		return nil, err
	}
	var relocations []elfPointerRelocation
	tables := make(map[uint32][]elf.Symbol)
	seen := make(map[uint64]bool)
	for _, section := range file.Sections {
		if section.Type != elf.SHT_RELA && section.Type != elf.SHT_REL || section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		entrySize := uint64(24)
		if section.Type == elf.SHT_REL {
			entrySize = 16
		}
		if section.Entsize != entrySize || section.Size%entrySize != 0 || int(section.Link) >= len(file.Sections) {
			return nil, fmt.Errorf("invalid relocation section %q: %w", section.Name, target.ErrInvalidArgument)
		}
		data, err := elfCommandSectionData(section)
		if err != nil {
			return nil, err
		}
		for offset := 0; offset < len(data); offset += int(entrySize) {
			address := binary.LittleEndian.Uint64(data[offset : offset+8])
			info := binary.LittleEndian.Uint64(data[offset+8 : offset+16])
			kind, symbolIndex := elf.R_X86_64(uint32(info)), uint32(info>>32)
			if kind != elf.R_X86_64_GLOB_DAT && kind != elf.R_X86_64_JMP_SLOT && kind != elf.R_X86_64_IRELATIVE {
				continue
			}
			if !elfContainsLoadRange(file, address, 8) {
				return nil, fmt.Errorf("relocation slot %#x is outside PT_LOAD: %w", address, target.ErrInvalidArgument)
			}
			if address > math.MaxUint64-bias || 7 > math.MaxUint64-(address+bias) {
				return nil, target.ErrOverflow
			}
			if seen[address] {
				return nil, fmt.Errorf("duplicate pointer relocation at %#x: %w", address, target.ErrAmbiguous)
			}
			seen[address] = true
			name := ""
			if symbolIndex != 0 {
				symbols, ok := tables[section.Link]
				if !ok {
					symbols, err = elfCommandSymbolTable(file, int(section.Link))
					if err != nil {
						return nil, err
					}
					tables[section.Link] = symbols
				}
				if uint64(symbolIndex) >= uint64(len(symbols)) {
					return nil, fmt.Errorf("relocation symbol index %d: %w", symbolIndex, target.ErrInvalidArgument)
				}
				name = symbols[symbolIndex].Name
			}
			relocations = append(relocations, elfPointerRelocation{section.Name, name, kind, address, target.Address(address + bias)})
		}
	}
	return relocations, nil
}

func validateELFDynamicRelocations(file *elf.File, dynamic elfDynamicFacts) error {
	for _, table := range []struct {
		address elf.DynTag
		size    elf.DynTag
		entry   elf.DynTag
		kind    elf.SectionType
	}{
		{elf.DT_RELA, elf.DT_RELASZ, elf.DT_RELAENT, elf.SHT_RELA},
		{elf.DT_REL, elf.DT_RELSZ, elf.DT_RELENT, elf.SHT_REL},
		{elf.DT_JMPREL, elf.DT_PLTRELSZ, elf.DT_PLTREL, elf.SHT_NULL},
	} {
		addresses, sizes, entries := dynamic.values[table.address], dynamic.values[table.size], dynamic.values[table.entry]
		if len(addresses) == 0 && len(sizes) == 0 {
			continue
		}
		if len(addresses) > 1 || len(sizes) > 1 || len(entries) > 1 {
			return fmt.Errorf("duplicate dynamic relocation metadata for %s: %w", table.address, target.ErrAmbiguous)
		}
		if len(addresses) != 1 || len(sizes) != 1 || len(entries) != 1 {
			return fmt.Errorf("incomplete dynamic relocation metadata for %s: %w", table.address, target.ErrUnavailable)
		}
		kind := table.kind
		entrySize := uint64(24)
		if kind == elf.SHT_NULL {
			switch elf.DynTag(entries[0]) {
			case elf.DT_RELA:
				kind = elf.SHT_RELA
			case elf.DT_REL:
				kind = elf.SHT_REL
			default:
				return fmt.Errorf("DT_PLTREL value %#x: %w", entries[0], target.ErrUnsupported)
			}
		}
		if kind == elf.SHT_REL {
			entrySize = 16
		}
		if table.kind != elf.SHT_NULL && entries[0] != entrySize || sizes[0]%entrySize != 0 {
			return fmt.Errorf("dynamic relocation entry size for %s: %w", table.address, target.ErrInvalidArgument)
		}
		if sizes[0] > math.MaxUint64-addresses[0] {
			return target.ErrOverflow
		}
		end := addresses[0] + sizes[0]
		for cursor := addresses[0]; cursor < end; {
			next := cursor
			for _, section := range file.Sections {
				if section.Type != kind || section.Flags&elf.SHF_ALLOC == 0 || section.Entsize != entrySize || section.Size > math.MaxUint64-section.Addr || cursor < section.Addr || cursor >= section.Addr+section.Size {
					continue
				}
				if (cursor-section.Addr)%entrySize != 0 || section.Size%entrySize != 0 {
					continue
				}
				sectionEnd := min(end, section.Addr+section.Size)
				if err := elfSectionFileBacked(file, section, cursor, sectionEnd); err != nil {
					return fmt.Errorf("dynamic relocation section %q: %w", section.Name, err)
				}
				next = max(next, sectionEnd)
			}
			if next == cursor {
				return fmt.Errorf("dynamic relocation table %s at %#x lacks matching section metadata: %w", table.address, cursor, target.ErrUnavailable)
			}
			cursor = next
		}
	}
	return nil
}

func elfSectionFileBacked(file *elf.File, section *elf.Section, start, end uint64) error {
	for cursor := start; cursor < end; {
		next := end
		var offset uint64
		found := false
		for _, program := range file.Progs {
			if program.Type != elf.PT_LOAD || program.Filesz > math.MaxUint64-program.Vaddr || program.Filesz > math.MaxUint64-program.Off {
				continue
			}
			if program.Vaddr > cursor {
				next = min(next, program.Vaddr)
				continue
			}
			if cursor >= program.Vaddr+program.Filesz {
				continue
			}
			actual := program.Off + cursor - program.Vaddr
			if found && offset != actual {
				return fmt.Errorf("overlapping PT_LOAD file offsets at %#x: %w", cursor, target.ErrAmbiguous)
			}
			found, offset = true, actual
			next = min(next, program.Vaddr+program.Filesz)
		}
		if !found || cursor < section.Addr || cursor-section.Addr > math.MaxUint64-section.Offset || section.Offset+cursor-section.Addr != offset {
			return fmt.Errorf("section/file offset at %#x disagrees with PT_LOAD: %w", cursor, target.ErrUnavailable)
		}
		cursor = next
	}
	return nil
}

func (c *Controller) showChecksec(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	arguments, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return err
	}
	selection, path, err := parseELFModuleArguments(arguments, true)
	if err != nil {
		return err
	}
	if path == "" && len(arguments) == 0 && (c.session == nil || c.session.State() == target.StateExited) {
		path = c.path
		if path == "" {
			return fmt.Errorf("no configured executable; use checksec --file PATH: %w", target.ErrUnavailable)
		}
	}
	view := c.metadataView()
	var scanErr, metadataErr error
	if path != "" {
		source, err := openRegularELFSource(ctx, path)
		if err != nil {
			return err
		}
		file, parseErr := elf.NewFile(source)
		if parseErr == nil {
			var facts elfSecurityFacts
			facts, parseErr = inspectELFSecurity(file)
			if parseErr == nil {
				view.heading("checksec")
				view.field("File", fmt.Sprintf("%q", path), metadataPlain)
				view.security(facts)
			}
		}
		if err := errors.Join(parseErr, source.Close(), contextReady(ctx)); err != nil {
			return err
		}
	} else {
		snapshot, thread, err := c.stopped()
		if err != nil {
			return err
		}
		scanErr = c.withELFModules(ctx, snapshot, thread, selection, func(modules []*mappedELF) error {
			for _, module := range modules {
				facts, err := inspectMappedELFSecurity(module)
				if err != nil {
					metadataErr = errors.Join(metadataErr, fmt.Errorf("module %q: %w", module.ID, err))
					view.module("checksec", module)
					view.unavailable("Security", err)
					continue
				}
				view.module("checksec", module)
				view.security(facts)
			}
			return nil
		})
	}
	return c.publishMetadata(ctx, view, scanErr, metadataErr)
}

func (c *Controller) publishELFResults(output *bytes.Buffer, scanErr, detailErr error) error {
	if !mappedELFResultUsable(scanErr) {
		return scanErr
	}
	if scanErr != nil {
		if err := c.writef("Mapped ELF scan incomplete; only verified metadata is shown: %q\n", scanErr.Error()); err != nil {
			return errors.Join(err, scanErr, detailErr)
		}
	}
	return errors.Join(c.writef("%s", output.String()), scanErr, detailErr)
}

func (c *Controller) printELFSecurity(path string, facts elfSecurityFacts) error {
	view := c.metadataView()
	view.heading("checksec")
	label := "File"
	if facts.runtimeOnly {
		label = "Runtime"
	}
	view.field(label, fmt.Sprintf("%q", path), metadataPlain)
	view.security(facts)
	return c.writef("%s", view.output.String())
}

func (c *Controller) showGOT(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	arguments, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return err
	}
	selection, _, err := parseELFModuleArguments(arguments, false)
	if err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	mappings, err := c.readProcessMaps(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	view := c.metadataView()
	var readErrors error
	err = c.withELFModules(ctx, snapshot, thread, selection, func(modules []*mappedELF) error {
		for _, module := range modules {
			relocations, err := mappedELFPointerRelocations(module)
			if err != nil {
				readErrors = errors.Join(readErrors, fmt.Errorf("module %q: %w", module.ID, err))
				view.module("got", module)
				view.unavailable("Relocations", err)
				continue
			}
			view.module("got", module)
			view.field("Load bias", fmt.Sprintf("%#x", module.LoadBias), metadataPlain)
			view.note("Slot               Raw value          Relocation             Symbol / section", metadataPlain)
			for _, relocation := range relocations {
				if err := contextReady(ctx); err != nil {
					return err
				}
				data := make([]byte, 8)
				n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, relocation.address, data)
				data, readErr = inspectionConfirmedBytes(data, n, readErr)
				if errors.Is(readErr, target.ErrStale) {
					return readErr
				}
				var value uint64
				if len(data) == 8 {
					value = binary.LittleEndian.Uint64(data)
				}
				view.relocation(relocation, value, len(data) == 8, mappings)
				if readErr != nil {
					readErrors = errors.Join(readErrors, fmt.Errorf("slot %#x: %w", relocation.address, readErr))
				}
			}
			if len(relocations) == 0 {
				view.note("No JUMP_SLOT, GLOB_DAT or IRELATIVE relocation slots.", metadataUnknown)
			}
		}
		return nil
	})
	return c.publishMetadata(ctx, view, err, readErrors)
}

func elfStdioObject(module *mappedELF, name string) (target.Address, uint64, error) {
	if module.Runtime != nil {
		return runtimeStdioObject(module, name)
	}
	var matches []elf.Symbol
	seen := make(map[elf.Symbol]bool)
	for index, section := range module.File.Sections {
		if section.Type != elf.SHT_DYNSYM && section.Type != elf.SHT_SYMTAB {
			continue
		}
		symbols, err := elfCommandSymbolTable(module.File, index)
		if err != nil {
			return 0, 0, err
		}
		for _, symbol := range symbols {
			if symbol.Name != name || symbol.Section == elf.SHN_UNDEF || seen[symbol] {
				continue
			}
			seen[symbol] = true
			matches = append(matches, symbol)
		}
	}
	if len(matches) == 0 {
		return 0, 0, target.ErrNotFound
	}
	if len(matches) != 1 {
		return 0, 0, fmt.Errorf("symbol %q has %d definitions: %w", name, len(matches), target.ErrAmbiguous)
	}
	symbol := matches[0]
	if elf.ST_TYPE(symbol.Info) != elf.STT_OBJECT || symbol.Section >= elf.SHN_LORESERVE || int(symbol.Section) >= len(module.File.Sections) || module.File.Sections[symbol.Section].Flags&elf.SHF_ALLOC == 0 {
		return 0, 0, fmt.Errorf("symbol %q is not an allocated object: %w", name, target.ErrUnsupported)
	}
	if symbol.Size == 0 || symbol.Size > maxMemoryBytes {
		return 0, 0, fmt.Errorf("symbol %q declared size %d is outside 1..%d: %w", name, symbol.Size, maxMemoryBytes, target.ErrUnsupported)
	}
	section := module.File.Sections[symbol.Section]
	if section.Size > math.MaxUint64-section.Addr || symbol.Value < section.Addr || symbol.Value > section.Addr+section.Size || symbol.Size > section.Addr+section.Size-symbol.Value {
		return 0, 0, fmt.Errorf("symbol %q exceeds its declared section: %w", name, target.ErrInvalidArgument)
	}
	if !elfContainsLoadRange(module.File, symbol.Value, symbol.Size) {
		return 0, 0, fmt.Errorf("symbol %q is outside PT_LOAD: %w", name, target.ErrInvalidArgument)
	}
	if symbol.Value > math.MaxUint64-module.LoadBias || symbol.Size-1 > math.MaxUint64-(symbol.Value+module.LoadBias) {
		return 0, 0, target.ErrOverflow
	}
	return target.Address(symbol.Value + module.LoadBias), symbol.Size, nil
}

func (c *Controller) showStdio(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	arguments, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return err
	}
	selection := elfModuleSelection{All: true}
	if len(arguments) != 0 {
		if len(arguments) != 2 || arguments[0] != "--module" {
			return fmt.Errorf("usage: stdio [--module EXACT]: %w", target.ErrInvalidArgument)
		}
		selection, _, err = parseELFModuleArguments(arguments, false)
		if err != nil {
			return err
		}
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	var output bytes.Buffer
	view := *c
	view.out = &output
	var readErrors error
	var symbolErrors error
	var missing []string
	err = c.withELFModules(ctx, snapshot, thread, selection, func(modules []*mappedELF) error {
		type object struct {
			name    string
			module  *mappedELF
			address target.Address
			size    uint64
		}
		var objects []object
		for _, name := range []string{"_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"} {
			var matches []object
			for _, module := range modules {
				address, size, err := elfStdioObject(module, name)
				if errors.Is(err, target.ErrNotFound) {
					continue
				}
				if err != nil {
					symbolErrors = errors.Join(symbolErrors, fmt.Errorf("module %q: %w", module.ID, err))
					continue
				}
				matches = append(matches, object{name, module, address, size})
			}
			if len(matches) == 0 {
				missing = append(missing, name)
				continue
			}
			if len(matches) != 1 {
				symbolErrors = errors.Join(symbolErrors, fmt.Errorf("stdio symbol %q occurs in %d mapped ELF images; use --module EXACT: %w", name, len(matches), target.ErrAmbiguous))
				continue
			}
			objects = append(objects, matches[0])
		}
		for _, object := range objects {
			if err := contextReady(ctx); err != nil {
				return err
			}
			data := make([]byte, int(object.size))
			n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, object.address, data)
			data, readErr = inspectionConfirmedBytes(data, n, readErr)
			if errors.Is(readErr, target.ErrStale) {
				return readErr
			}
			if err := view.writef("[stdio] %s module=%q %s=%q address=%#x declared-size=%d %s\nRaw object bytes; FILE member offsets are not inferred.\n", object.name, object.module.ID, mappedELFPathLabel(object.module), object.module.Path, object.address, object.size, mappedELFSourceDescription(object.module)); err != nil {
				return err
			}
			if err := view.hexRows(object.address, data, 1); err != nil {
				return err
			}
			if readErr != nil {
				readErrors = errors.Join(readErrors, fmt.Errorf("stdio symbol %q: %w", object.name, readErr))
			}
		}
		return nil
	})
	if !mappedELFResultUsable(err) {
		return err
	}
	if err != nil || symbolErrors != nil {
		if writeErr := c.writef("Stdio symbol scan incomplete; displayed definitions are not proven unique across all mapped images.\n"); writeErr != nil {
			return errors.Join(writeErr, err, symbolErrors, readErrors)
		}
	}
	for _, name := range missing {
		missingErr := target.ErrNotFound
		if err != nil || symbolErrors != nil {
			missingErr = target.ErrUnavailable
		}
		readErrors = errors.Join(readErrors, fmt.Errorf("stdio symbol %q: %w", name, missingErr))
	}
	return c.publishELFResults(&output, err, errors.Join(readErrors, symbolErrors))
}
