package debugger

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"reflect"

	"fastdbg2/target"
)

type stdioField struct {
	name               string
	offset, size       int
	bit, bits          int
	pointer, aggregate bool
}

type stdioRecord struct {
	size   int
	fields []stdioField
}

type stdioLayout struct {
	file, jump, wide stdioRecord
}

func stdioBase(t dwarf.Type) (dwarf.Type, error) {
	for i := 0; i < 32 && t != nil; i++ {
		switch v := t.(type) {
		case *dwarf.TypedefType:
			t = v.Type
		case *dwarf.QualType:
			t = v.Type
		default:
			return t, nil
		}
	}
	return nil, fmt.Errorf("stdio type chain: %w", target.ErrUnsupported)
}

func stdioStruct(t dwarf.Type) (*dwarf.StructType, error) {
	t, err := stdioBase(t)
	if err != nil {
		return nil, err
	}
	s, ok := t.(*dwarf.StructType)
	if !ok || s.Incomplete || s.Kind != "struct" || s.Size() <= 0 || s.Size() > maxMemoryBytes || len(s.Field) == 0 || len(s.Field) > 128 {
		return nil, fmt.Errorf("stdio structure: %w", target.ErrUnsupported)
	}
	return s, nil
}

func stdioMember(s *dwarf.StructType, name string) (dwarf.Type, error) {
	for _, f := range s.Field {
		if f.Name == name {
			return f.Type, nil
		}
	}
	return nil, fmt.Errorf("stdio member %q: %w", name, target.ErrUnavailable)
}

func stdioPointee(t dwarf.Type) (*dwarf.StructType, error) {
	t, err := stdioBase(t)
	if err != nil {
		return nil, err
	}
	p, ok := t.(*dwarf.PtrType)
	if !ok || (p.Size() != 4 && p.Size() != 8) {
		return nil, fmt.Errorf("stdio pointer type: %w", target.ErrUnsupported)
	}
	return stdioStruct(p.Type)
}

func stdioRecordType(s *dwarf.StructType) (stdioRecord, error) {
	result := stdioRecord{size: int(s.Size())}
	used := make([]bool, result.size*8)
	names := make(map[string]bool)
	for _, f := range s.Field {
		if f.Name == "" || names[f.Name] {
			return result, fmt.Errorf("stdio duplicate or unnamed field: %w", target.ErrAmbiguous)
		}
		names[f.Name] = true
		t, err := stdioBase(f.Type)
		if err != nil {
			return result, err
		}
		size, offset := t.Size(), f.ByteOffset
		field := stdioField{name: f.Name}
		start, bits := offset*8, size*8
		if f.BitSize != 0 {
			bits = f.BitSize
			if bits <= 0 || bits > 64 {
				return result, target.ErrUnsupported
			}
			if f.DataBitOffset != 0 {
				start = f.DataBitOffset
			} else {
				start += size*8 - f.BitOffset - bits
			}
			offset = start / 8
			size = (start%8 + bits + 7) / 8
			if size > 8 {
				return result, target.ErrUnsupported
			}
			field.bit, field.bits = int(start%8), int(bits)
		}
		if offset < 0 || size <= 0 || offset > s.Size() || size > s.Size()-offset || start < 0 || bits <= 0 || start > int64(len(used)) || bits > int64(len(used))-start {
			return result, fmt.Errorf("stdio field %q range: %w", f.Name, target.ErrInvalidArgument)
		}
		for i := start; i < start+bits; i++ {
			if used[i] {
				return result, fmt.Errorf("stdio overlapping field %q: %w", f.Name, target.ErrInvalidArgument)
			}
			used[i] = true
		}
		field.offset, field.size = int(offset), int(size)
		switch v := t.(type) {
		case *dwarf.PtrType:
			if size != 4 && size != 8 {
				return result, target.ErrUnsupported
			}
			field.pointer = true
		case *dwarf.ArrayType:
			element, err := stdioBase(v.Type)
			if err != nil {
				return result, err
			}
			_, character := element.(*dwarf.CharType)
			_, integer := element.(*dwarf.IntType)
			field.aggregate = v.Count != 1 || (!character && !integer) || size > 8
		case *dwarf.StructType:
			field.aggregate = size > 8
		case *dwarf.UnspecifiedType:
			field.aggregate = true
		default:
			field.aggregate = size > 8
		}
		result.fields = append(result.fields, field)
	}
	return result, nil
}

func stdioTypeLayout(t dwarf.Type) (stdioLayout, error) {
	var result stdioLayout
	plus, err := stdioStruct(t)
	if err != nil {
		return result, err
	}
	if len(plus.Field) != 2 || plus.Field[0].Name != "file" || plus.Field[0].ByteOffset != 0 || plus.Field[1].Name != "vtable" {
		return result, target.ErrUnsupported
	}
	file, err := stdioStruct(plus.Field[0].Type)
	if err != nil {
		return result, err
	}
	result.file, err = stdioRecordType(file)
	if err != nil {
		return result, err
	}
	outer, err := stdioRecordType(plus)
	if err != nil {
		return result, err
	}
	if outer.fields[1].offset < result.file.size || !outer.fields[1].pointer {
		return result, target.ErrInvalidArgument
	}
	result.file.size = outer.size
	result.file.fields = append(result.file.fields, outer.fields[1])
	jump, err := stdioPointee(plus.Field[1].Type)
	if err != nil {
		return result, err
	}
	result.jump, err = stdioRecordType(jump)
	if err != nil {
		return result, err
	}
	wideType, err := stdioMember(file, "_wide_data")
	if err != nil {
		return result, err
	}
	wide, err := stdioPointee(wideType)
	if err != nil {
		return result, err
	}
	result.wide, err = stdioRecordType(wide)
	if err != nil {
		return result, err
	}
	wideJumpType, err := stdioMember(wide, "_wide_vtable")
	if err != nil {
		return result, err
	}
	wideJump, err := stdioPointee(wideJumpType)
	if err != nil {
		return result, err
	}
	wideRecord, err := stdioRecordType(wideJump)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(result.jump, wideRecord) {
		return result, target.ErrAmbiguous
	}
	return result, nil
}

func stdioVariableAttr(e *dwarf.Entry, entries map[dwarf.Offset]*dwarf.Entry, attr dwarf.Attr) (any, error) {
	seen := make(map[dwarf.Offset]bool)
	for i := 0; i < 32 && e != nil; i++ {
		if seen[e.Offset] {
			return nil, target.ErrInvalidArgument
		}
		seen[e.Offset] = true
		if v := e.Val(attr); v != nil {
			return v, nil
		}
		ref := e.Val(dwarf.AttrSpecification)
		if ref == nil {
			ref = e.Val(dwarf.AttrAbstractOrigin)
		}
		if ref == nil {
			return nil, nil
		}
		off, ok := ref.(dwarf.Offset)
		if !ok || entries[off] == nil {
			return nil, target.ErrInvalidArgument
		}
		e = entries[off]
	}
	return nil, target.ErrInvalidArgument
}

func stdioDWARFLayouts(ctx context.Context, data *dwarf.Data, objects []stdioObject) ([]stdioLayout, error) {
	if len(objects) == 0 {
		return nil, target.ErrInvalidArgument
	}
	arch, err := nativeELFArchitecture(objects[0].module.File)
	if err != nil {
		return nil, err
	}
	word := abiFor(arch).word
	entries := make(map[dwarf.Offset]*dwarf.Entry)
	reader := data.Reader()
	for count := 0; ; count++ {
		if count >= 1<<20 {
			return nil, target.ErrUnsupported
		}
		if count%256 == 0 {
			if err := contextReady(ctx); err != nil {
				return nil, err
			}
		}
		e, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagVariable {
			continue
		}
		if reader.AddressSize() != word {
			return nil, target.ErrUnsupported
		}
		seen := make(map[dwarf.Attr]bool)
		for _, f := range e.Field {
			if seen[f.Attr] {
				return nil, target.ErrInvalidArgument
			}
			seen[f.Attr] = true
		}
		entries[e.Offset] = e
	}
	result := make([]stdioLayout, len(objects))
	found := make([]bool, len(objects))
	for _, e := range entries {
		if e.Val(dwarf.AttrLocation) == nil || e.Val(dwarf.AttrDeclaration) == true {
			continue
		}
		name, err := stdioVariableAttr(e, entries, dwarf.AttrName)
		if err != nil {
			return nil, err
		}
		for i, object := range objects {
			if name != object.name {
				continue
			}
			location, ok := e.Val(dwarf.AttrLocation).([]byte)
			if !ok || len(location) != word+1 || location[0] != 3 {
				return nil, fmt.Errorf("stdio variable location: %w", target.ErrUnsupported)
			}
			if inspectionWord(location[1:]) != uint64(object.address)-object.module.LoadBias {
				return nil, fmt.Errorf("stdio ELF/DWARF address mismatch: %w", target.ErrInvalidArgument)
			}
			ref, err := stdioVariableAttr(e, entries, dwarf.AttrType)
			if err != nil {
				return nil, err
			}
			off, ok := ref.(dwarf.Offset)
			if !ok {
				return nil, target.ErrUnavailable
			}
			t, err := data.Type(off)
			if err != nil {
				return nil, err
			}
			layout, err := stdioTypeLayout(t)
			if err != nil {
				return nil, err
			}
			for _, field := range layout.file.fields {
				if field.pointer && field.size != word {
					return nil, target.ErrInvalidArgument
				}
			}
			if uint64(layout.file.size) != object.size {
				return nil, fmt.Errorf("stdio ELF/DWARF size mismatch: %w", target.ErrInvalidArgument)
			}
			if found[i] && !reflect.DeepEqual(layout, result[i]) {
				return nil, target.ErrAmbiguous
			}
			result[i], found[i] = layout, true
		}
	}
	for i, ok := range found {
		if !ok {
			return nil, fmt.Errorf("%s FILE type definition: %w", objects[i].name, target.ErrUnavailable)
		}
	}
	return result, nil
}

func stdioModuleLayouts(ctx context.Context, module *mappedELF, objects []stdioObject, labels map[target.Address]string) ([]stdioLayout, error) {
	if module.File == nil {
		return nil, target.ErrUnavailable
	}
	file := module.File
	if file.Section(".debug_info") == nil {
		debug, err := findELFDebugFile(ctx, nil, module)
		if err != nil {
			return nil, err
		}
		defer debug.Source.Close()
		file = debug.File
	}
	data, err := heapDWARFData(file)
	if err != nil {
		return nil, err
	}
	layouts, err := stdioDWARFLayouts(ctx, data, objects)
	if err != nil {
		return nil, err
	}
	var symbols []elf.Symbol
	for index, section := range file.Sections {
		if section.Type != elf.SHT_SYMTAB {
			continue
		}
		table, err := elfCommandSymbolTable(file, index)
		if err != nil {
			return nil, err
		}
		symbols = append(symbols, table...)
	}

	for _, symbol := range symbols {
		if symbol.Name == "" || symbol.Section == elf.SHN_UNDEF || symbol.Section >= elf.SHN_LORESERVE || !elfContainsLoadRange(module.File, symbol.Value, 1) {
			continue
		}
		if symbol.Value > ^uint64(0)-module.LoadBias {
			continue
		}
		address := target.Address(symbol.Value + module.LoadBias)
		old := labels[address]
		if old == "" || uiCompareSymbolLabels(symbol.Name, old) < 0 {
			labels[address] = symbol.Name
		}
	}
	return layouts, nil
}
