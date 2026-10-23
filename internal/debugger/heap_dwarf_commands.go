package debugger

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func heapMainArenaSymbol(file *elf.File) (elf.Symbol, error) {
	var result elf.Symbol
	if file == nil {
		return result, target.ErrInvalidArgument
	}
	found := false
	for index, section := range file.Sections {
		if section.Type != elf.SHT_SYMTAB && section.Type != elf.SHT_DYNSYM {
			continue
		}
		symbols, err := elfCommandSymbolTable(file, index)
		if err != nil {
			return result, err
		}
		for _, symbol := range symbols {
			if symbol.Name != "main_arena" || symbol.Section == elf.SHN_UNDEF {
				continue
			}
			if elf.ST_TYPE(symbol.Info) != elf.STT_OBJECT || symbol.Section >= elf.SHN_LORESERVE || int(symbol.Section) >= len(file.Sections) {
				return result, fmt.Errorf("main_arena is not a section-defined ELF object: %w", target.ErrUnsupported)
			}
			owner := file.Sections[symbol.Section]
			if owner.Flags&elf.SHF_ALLOC == 0 || symbol.Size == 0 || symbol.Value < owner.Addr || symbol.Value-owner.Addr > owner.Size || symbol.Size > owner.Size-(symbol.Value-owner.Addr) {
				return result, fmt.Errorf("main_arena ELF object range is not contained in its allocated section: %w", target.ErrInvalidArgument)
			}
			if found && (result.Value != symbol.Value || result.Size != symbol.Size || result.Section != symbol.Section) {
				return result, fmt.Errorf("multiple main_arena ELF object definitions: %w", target.ErrAmbiguous)
			}
			result, found = symbol, true
		}
	}
	if !found {
		return result, fmt.Errorf("selected ELF has no main_arena object symbol; provide matching debug information or an explicit layout and address: %w", target.ErrNotFound)
	}
	return result, nil
}

func heapDWARFData(file *elf.File) (*dwarf.Data, error) {
	if file == nil {
		return nil, target.ErrInvalidArgument
	}
	var total uint64
	sections := make(map[string]bool)
	for _, section := range file.Sections {
		if strings.HasPrefix(section.Name, ".zdebug_") {
			return nil, fmt.Errorf("legacy compressed DWARF sections are not supported for heap layouts: %w", target.ErrUnsupported)
		}
		if !strings.HasPrefix(section.Name, ".debug_") {
			continue
		}
		if sections[section.Name] {
			return nil, fmt.Errorf("duplicate DWARF section %q: %w", section.Name, target.ErrAmbiguous)
		}
		sections[section.Name] = true
		if section.Size > maxELFCommandMetadata-total {
			return nil, fmt.Errorf("DWARF metadata exceeds %d bytes: %w", maxELFCommandMetadata, target.ErrUnsupported)
		}
		total += section.Size
	}
	if !sections[".debug_info"] || !sections[".debug_abbrev"] {
		return nil, fmt.Errorf("selected ELF has no complete DWARF information: %w", target.ErrUnavailable)
	}
	return file.DWARF()
}

func heapMainArenaType(ctx context.Context, data *dwarf.Data, symbol elf.Symbol) (dwarf.Offset, error) {
	if data == nil {
		return 0, target.ErrInvalidArgument
	}
	reader := data.Reader()
	var variables []*dwarf.Entry
	byOffset := make(map[dwarf.Offset]*dwarf.Entry)
	for count := 0; ; count++ {
		if count == 1<<20 {
			return 0, fmt.Errorf("heap DWARF lookup reached its entry limit: %w", target.ErrUnavailable)
		}
		if count%256 == 0 {
			if err := contextReady(ctx); err != nil {
				return 0, err
			}
		}
		entry, err := reader.Next()
		if err != nil {
			return 0, err
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagVariable {
			continue
		}
		seen := make(map[dwarf.Attr]bool)
		for _, field := range entry.Field {
			if seen[field.Attr] {
				return 0, fmt.Errorf("duplicate DWARF variable attribute %s: %w", field.Attr, target.ErrInvalidArgument)
			}
			seen[field.Attr] = true
		}
		if reader.AddressSize() != 8 {
			return 0, fmt.Errorf("heap DWARF variable uses a non-AMD64 address size: %w", target.ErrUnsupported)
		}
		variables = append(variables, entry)
		byOffset[entry.Offset] = entry
	}
	var result dwarf.Offset
	found := false
	for index, entry := range variables {
		if index%256 == 0 {
			if err := contextReady(ctx); err != nil {
				return 0, err
			}
		}
		name, err := heapDWARFVariableName(entry, byOffset, make(map[dwarf.Offset]bool))
		if err != nil {
			return 0, err
		}
		if name != "main_arena" || entry.Val(dwarf.AttrDeclaration) == true {
			continue
		}
		if entry.Val(dwarf.AttrSpecification) != nil || entry.Val(dwarf.AttrAbstractOrigin) != nil {
			return 0, fmt.Errorf("main_arena DWARF specification and abstract-origin definitions are not supported: %w", target.ErrUnsupported)
		}
		location, ok := entry.Val(dwarf.AttrLocation).([]byte)
		if !ok || len(location) != 9 || location[0] != 0x03 {
			return 0, fmt.Errorf("main_arena DWARF location must be one exact AMD64 DW_OP_addr: %w", target.ErrUnsupported)
		}
		if binary.LittleEndian.Uint64(location[1:]) != symbol.Value {
			return 0, fmt.Errorf("main_arena DWARF location differs from its ELF object definition: %w", target.ErrInvalidArgument)
		}
		typeOffset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			return 0, fmt.Errorf("main_arena DWARF type reference is unavailable: %w", target.ErrUnsupported)
		}
		if found && result != typeOffset {
			return 0, fmt.Errorf("main_arena has multiple DWARF type definitions: %w", target.ErrAmbiguous)
		}
		result, found = typeOffset, true
	}
	if !found {
		return 0, fmt.Errorf("main_arena DWARF variable definition is unavailable: %w", target.ErrNotFound)
	}
	return result, nil
}

func heapDWARFVariableName(entry *dwarf.Entry, entries map[dwarf.Offset]*dwarf.Entry, visiting map[dwarf.Offset]bool) (string, error) {
	if entry == nil || len(visiting) >= 32 || visiting[entry.Offset] {
		return "", fmt.Errorf("cyclic or excessive DWARF variable name inheritance: %w", target.ErrUnsupported)
	}
	if name := entry.Val(dwarf.AttrName); name != nil {
		if text, ok := name.(string); ok {
			return text, nil
		}
		return "", fmt.Errorf("DWARF variable name is not a string: %w", target.ErrInvalidArgument)
	}
	visiting[entry.Offset] = true
	defer delete(visiting, entry.Offset)
	var name string
	for _, attribute := range []dwarf.Attr{dwarf.AttrSpecification, dwarf.AttrAbstractOrigin} {
		if value := entry.Val(attribute); value != nil {
			offset, ok := value.(dwarf.Offset)
			if !ok || entries[offset] == nil {
				return "", fmt.Errorf("DWARF variable name inheritance has no exact variable definition: %w", target.ErrUnsupported)
			}
			inherited, err := heapDWARFVariableName(entries[offset], entries, visiting)
			if err != nil {
				return "", err
			}
			if name != "" && inherited != "" && name != inherited {
				return "", fmt.Errorf("ambiguous inherited DWARF variable name: %w", target.ErrAmbiguous)
			}
			if inherited != "" {
				name = inherited
			}
		}
	}
	return name, nil
}

func (c *Controller) withHeapDWARFInput(ctx context.Context, arguments heapGraphArguments, visit func(heapGraphInput) error) error {
	resolver := &lazyInspectionResolver{controller: c, ctx: ctx}
	if err := resolver.initialize(); err != nil {
		return err
	}
	var inspectionErr error
	proofErr := c.withELFModules(ctx, resolver.snapshot, resolver.thread, elfModuleSelection{Name: arguments.module}, func(modules []*mappedELF) (err error) {
		if len(modules) != 1 {
			return fmt.Errorf("heap inspection needs exactly one proven ELF module: %w", target.ErrAmbiguous)
		}
		module := modules[0]
		if module.File == nil {
			return fmt.Errorf("selected module has runtime metadata only, without an exact ELF/DWARF source: %w", target.ErrUnavailable)
		}
		file := module.File
		proof := fmt.Sprintf("module=%q metadata-proof=%q", module.ID, module.Proof)
		if arguments.debugFile != "" {
			association, err := associateELFDebugFile(ctx, module, arguments.debugFile)
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, association.Source.Close()) }()
			file = association.File
			proof += fmt.Sprintf(" debug-file=%q debug-proof=%q", association.Path, association.Proof)
		}
		if err := validateAMD64ELF(file); err != nil {
			return err
		}
		symbol, err := heapMainArenaSymbol(file)
		if err != nil {
			return err
		}
		data, err := heapDWARFData(file)
		if err != nil {
			return err
		}
		typeOffset, err := heapMainArenaType(ctx, data, symbol)
		if err != nil {
			return err
		}
		layout, err := inspect.HeapLayoutFromDWARF(data, typeOffset, arguments.fastLink)
		if err != nil {
			return err
		}
		if symbol.Size != layout.Arena.Size {
			return fmt.Errorf("main_arena ELF object size %d differs from its DWARF type size %d: %w", symbol.Size, layout.Arena.Size, target.ErrInvalidArgument)
		}
		if symbol.Value > math.MaxUint64-module.LoadBias {
			return fmt.Errorf("main_arena relocated address overflows: %w", target.ErrOverflow)
		}
		address := symbol.Value + module.LoadBias
		proof += " arena-address=main_arena-symbol+DWARF"
		if arguments.expression != "" {
			address, err = inspect.EvalExpression(arguments.expression, resolver)
			if err != nil {
				return err
			}
			proof += fmt.Sprintf(" explicit-address-expression=%q", arguments.expression)
		}
		inspectionErr = visit(heapGraphInput{layout: layout, address: target.Address(address), proof: proof, reader: newHeapGraphReader(ctx, c.session, resolver.snapshot.Memory)})
		return nil
	})
	if proofErr != nil {
		return &heapGraphProofError{errors.Join(proofErr, inspectionErr)}
	}
	return inspectionErr
}
