package debugger

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

const (
	maxRuntimeVDSOSymbols  = 65536
	maxRuntimeVDSOStrings  = 1 << 20
	maxRuntimeVDSOVersions = 4096
	runtimeDTSymtabSize    = elf.DynTag(39)
)

type runtimeVDSOVersionDefinition struct {
	Index uint16
	Flags uint16
	Hash  uint32
	Names []string
}

type runtimeVDSOMetadata struct {
	Header              elf.FileHeader
	HeaderFlags         uint32
	Programs            []elf.ProgHeader
	Dynamic             elfDynamicFacts
	Symbols             []elf.Symbol
	SymbolsComplete     bool
	SymbolCountSource   string
	VersionDefinitions  []runtimeVDSOVersionDefinition
	PointerRelocations  []elfPointerRelocation
	RelocationsDeclared bool
	LoadBias            uint64
	Loads               []runtimeELFSpan
}

type runtimeVDSOReader struct {
	memory *runtimeELFMemory
	module *runtimeELFModule
}

func (reader runtimeVDSOReader) bytes(offset, size uint64) ([]byte, error) {
	if offset > math.MaxUint64-reader.module.LoadBias {
		return nil, target.ErrOverflow
	}
	address := target.Address(reader.module.LoadBias + offset)
	if !runtimeELFLoaded(reader.module, address, size) {
		return nil, fmt.Errorf("vDSO metadata %#x+%#x is outside PT_LOAD: %w", offset, size, target.ErrUnavailable)
	}
	return reader.memory.bytes(address, size)
}

func readRuntimeVDSO(view *runtimeELFView, module *runtimeELFModule) (*runtimeVDSOMetadata, error) {
	if view == nil || view.Memory == nil || module == nil {
		return nil, target.ErrInvalidArgument
	}
	if module.AuxiliaryTag != 33 || module.AuxiliaryAddress == 0 || module.AuxiliaryAddress != module.Header || uint64(module.Header) != module.LoadBias {
		return nil, fmt.Errorf("runtime image lacks the exact AT_SYSINFO_EHDR anchor: %w", target.ErrUnsupported)
	}
	verified, err := runtimeELFZeroOrigin(view.Memory, module.Header, &module.Dynamic.Address)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(verified.Programs, module.Programs) || !slices.Equal(verified.Loads, module.Loads) || verified.Dynamic != module.Dynamic {
		return nil, fmt.Errorf("vDSO runtime headers changed: %w", target.ErrStale)
	}
	loads, dynamics := 0, 0
	for _, program := range verified.Programs {
		switch program.Type {
		case elf.PT_LOAD:
			loads++
			if program.Off != 0 || program.Vaddr != 0 || program.Filesz != program.Memsz || program.Flags != elf.PF_R|elf.PF_X {
				return nil, fmt.Errorf("vDSO requires a read-only zero-origin PT_LOAD: %w", target.ErrUnsupported)
			}
		case elf.PT_DYNAMIC:
			dynamics++
			if program.Flags != elf.PF_R || program.Filesz != program.Memsz || program.Off != program.Vaddr {
				return nil, fmt.Errorf("vDSO requires read-only ELF-relative dynamic metadata: %w", target.ErrUnsupported)
			}
		case elf.PT_TLS, elf.PT_INTERP:
			return nil, fmt.Errorf("unsupported vDSO program %s: %w", program.Type, target.ErrUnsupported)
		}
	}
	if loads != 1 || dynamics != 1 {
		return nil, fmt.Errorf("vDSO requires one PT_LOAD and one PT_DYNAMIC: %w", target.ErrUnsupported)
	}
	for _, mapping := range view.Memory.mappings {
		load := verified.Loads[0]
		if mapping.Start < load.Address+target.Address(load.Size) && mapping.End > load.Address && (!mapping.Read || mapping.Write || !mapping.Execute) {
			return nil, fmt.Errorf("vDSO PT_LOAD is not mapped read-only executable: %w", target.ErrUnsupported)
		}
	}
	reader := runtimeVDSOReader{view.Memory, verified}
	header, err := reader.bytes(0, 64)
	if err != nil {
		return nil, err
	}
	if header[elf.EI_OSABI] != byte(elf.ELFOSABI_NONE) && header[elf.EI_OSABI] != byte(elf.ELFOSABI_LINUX) || header[elf.EI_ABIVERSION] != 0 || binary.LittleEndian.Uint32(header[48:]) != 0 {
		return nil, fmt.Errorf("unsupported vDSO ELF ABI: %w", target.ErrUnsupported)
	}
	metadata := &runtimeVDSOMetadata{
		Header: elf.FileHeader{
			Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB, Version: elf.EV_CURRENT,
			OSABI: elf.OSABI(header[elf.EI_OSABI]), ABIVersion: header[elf.EI_ABIVERSION], ByteOrder: binary.LittleEndian,
			Type: elf.ET_DYN, Machine: elf.EM_X86_64, Entry: binary.LittleEndian.Uint64(header[24:]),
		},
		HeaderFlags: binary.LittleEndian.Uint32(header[48:]), Programs: slices.Clone(verified.Programs),
		LoadBias: verified.LoadBias, Loads: slices.Clone(verified.Loads),
	}
	metadata.Dynamic, err = readRuntimeVDSODynamic(reader)
	if err != nil {
		return nil, err
	}
	metadata.RelocationsDeclared, err = runtimeVDSORelocations(metadata.Dynamic)
	if err != nil {
		return nil, err
	}
	stringsOffset, err := runtimeVDSORequiredTag(metadata.Dynamic, elf.DT_STRTAB)
	if err != nil {
		return nil, err
	}
	stringsSize, err := runtimeVDSORequiredTag(metadata.Dynamic, elf.DT_STRSZ)
	if err != nil {
		return nil, err
	}
	if stringsSize == 0 || stringsSize > maxRuntimeVDSOStrings {
		return nil, fmt.Errorf("vDSO DT_STRSZ %d is unsupported: %w", stringsSize, target.ErrUnsupported)
	}
	stringsBytes, err := reader.bytes(stringsOffset, stringsSize)
	if err != nil {
		return nil, err
	}
	if stringsBytes[0] != 0 || stringsBytes[len(stringsBytes)-1] != 0 {
		return nil, fmt.Errorf("vDSO dynamic string table lacks boundary NUL: %w", target.ErrInvalidArgument)
	}
	stringsData := runtimeVDSOStrings{data: string(stringsBytes)}
	for offset := 0; offset < len(stringsData.data); {
		end := offset + strings.IndexByte(stringsData.data[offset:], 0)
		stringsData.ends = append(stringsData.ends, uint32(end))
		offset = end + 1
	}
	for _, tag := range []elf.DynTag{elf.DT_SONAME, elf.DT_NEEDED, elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_AUXILIARY, elf.DT_FILTER} {
		for _, offset := range metadata.Dynamic.values[tag] {
			if _, err := runtimeVDSOString(stringsData, offset); err != nil {
				return nil, fmt.Errorf("vDSO %s: %w", tag, err)
			}
		}
	}
	metadata.Symbols, metadata.SymbolCountSource, err = readRuntimeVDSOSymbols(reader, metadata.Dynamic, stringsData)
	if err != nil {
		return nil, err
	}
	metadata.VersionDefinitions, err = readRuntimeVDSOVersions(reader, metadata.Dynamic, stringsData, metadata.Symbols)
	if err != nil {
		return nil, err
	}
	metadata.SymbolsComplete = true
	return metadata, nil
}

func readRuntimeVDSODynamic(reader runtimeVDSOReader) (elfDynamicFacts, error) {
	span := reader.module.Dynamic
	if span.Size == 0 || span.Size%16 != 0 || span.Size > maxRuntimeELFNotes {
		return elfDynamicFacts{}, fmt.Errorf("invalid vDSO PT_DYNAMIC size: %w", target.ErrInvalidArgument)
	}
	data, err := reader.bytes(uint64(span.Address)-reader.module.LoadBias, span.Size)
	if err != nil {
		return elfDynamicFacts{}, err
	}
	facts := elfDynamicFacts{present: true, values: make(map[elf.DynTag][]uint64)}
	for offset := 0; offset < len(data); offset += 16 {
		tag := elf.DynTag(int64(binary.LittleEndian.Uint64(data[offset:])))
		if tag == elf.DT_NULL {
			return facts, nil
		}
		switch tag {
		case elf.DT_NEEDED, elf.DT_PLTRELSZ, elf.DT_PLTGOT, elf.DT_HASH, elf.DT_STRTAB, elf.DT_SYMTAB,
			elf.DT_RELA, elf.DT_RELASZ, elf.DT_RELAENT, elf.DT_STRSZ, elf.DT_SYMENT, elf.DT_INIT, elf.DT_FINI,
			elf.DT_SONAME, elf.DT_RPATH, elf.DT_SYMBOLIC, elf.DT_REL, elf.DT_RELSZ, elf.DT_RELENT, elf.DT_PLTREL,
			elf.DT_DEBUG, elf.DT_TEXTREL, elf.DT_JMPREL, elf.DT_BIND_NOW, elf.DT_INIT_ARRAY, elf.DT_FINI_ARRAY,
			elf.DT_INIT_ARRAYSZ, elf.DT_FINI_ARRAYSZ, elf.DT_RUNPATH, elf.DT_FLAGS, elf.DT_PREINIT_ARRAY,
			elf.DT_PREINIT_ARRAYSZ, elf.DT_SYMTAB_SHNDX, elf.DT_GNU_HASH, elf.DT_VERSYM, elf.DT_RELACOUNT,
			elf.DT_RELCOUNT, elf.DT_FLAGS_1, elf.DT_VERDEF, elf.DT_VERDEFNUM, elf.DT_VERNEED, elf.DT_VERNEEDNUM,
			elf.DT_AUXILIARY, elf.DT_FILTER, 35, 36, 37, runtimeDTSymtabSize,
			0x6000000f, 0x60000010, 0x60000011, 0x60000012, 0x6fffe000, 0x6fffe001, 0x6fffe003:
		default:
			return elfDynamicFacts{}, fmt.Errorf("vDSO dynamic tag %s is outside the supported ABI: %w", tag, target.ErrUnsupported)
		}
		if len(facts.values[tag]) != 0 && tag != elf.DT_NEEDED && tag != elf.DT_AUXILIARY && tag != elf.DT_FILTER {
			return elfDynamicFacts{}, fmt.Errorf("duplicate vDSO %s: %w", tag, target.ErrAmbiguous)
		}
		value := binary.LittleEndian.Uint64(data[offset+8:])
		if tag == elf.DT_FLAGS && value&^uint64(0x1f) != 0 || tag == elf.DT_FLAGS_1 && value&^uint64(0x7fffffff) != 0 {
			return elfDynamicFacts{}, fmt.Errorf("unknown vDSO flags in %s: %w", tag, target.ErrUnsupported)
		}
		facts.values[tag] = append(facts.values[tag], value)
	}
	return elfDynamicFacts{}, fmt.Errorf("vDSO PT_DYNAMIC lacks DT_NULL: %w", target.ErrInvalidArgument)
}

func runtimeVDSORequiredTag(facts elfDynamicFacts, tag elf.DynTag) (uint64, error) {
	values := facts.values[tag]
	if len(values) != 1 {
		return 0, fmt.Errorf("vDSO requires one %s: %w", tag, target.ErrUnavailable)
	}
	return values[0], nil
}

func runtimeVDSORelocations(facts elfDynamicFacts) (bool, error) {
	declared := false
	for _, table := range []struct {
		address elf.DynTag
		size    elf.DynTag
		entry   elf.DynTag
		width   uint64
	}{
		{elf.DT_REL, elf.DT_RELSZ, elf.DT_RELENT, 16},
		{elf.DT_RELA, elf.DT_RELASZ, elf.DT_RELAENT, 24},
		{elf.DT_JMPREL, elf.DT_PLTRELSZ, elf.DT_PLTREL, 0},
		{elf.DynTag(36), elf.DynTag(35), elf.DynTag(37), 8},
	} {
		addresses, sizes, entries := facts.values[table.address], facts.values[table.size], facts.values[table.entry]
		if len(addresses)+len(sizes)+len(entries) == 0 {
			continue
		}
		declared = true
		if len(addresses) != 1 || len(sizes) != 1 || len(entries) != 1 {
			return declared, fmt.Errorf("incomplete vDSO relocation metadata for %s: %w", table.address, target.ErrUnsupported)
		}
		if table.width == 0 {
			if elf.DynTag(entries[0]) != elf.DT_REL && elf.DynTag(entries[0]) != elf.DT_RELA {
				return declared, fmt.Errorf("unsupported vDSO DT_PLTREL: %w", target.ErrUnsupported)
			}
		} else if entries[0] != table.width {
			return declared, fmt.Errorf("invalid vDSO relocation entry width: %w", target.ErrInvalidArgument)
		}
		if sizes[0] != 0 {
			return declared, fmt.Errorf("vDSO dynamic relocations are outside the supported kernel ABI: %w", target.ErrUnsupported)
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_TEXTREL, elf.DT_RELCOUNT, elf.DT_RELACOUNT, 0x6000000f, 0x60000010, 0x60000011, 0x60000012, 0x6fffe000, 0x6fffe001, 0x6fffe003} {
		if len(facts.values[tag]) != 0 {
			return true, fmt.Errorf("unsupported vDSO relocation declaration %s: %w", tag, target.ErrUnsupported)
		}
	}
	if elfHasDynamicFlag(facts, elf.DT_FLAGS, uint64(elf.DF_TEXTREL)) {
		return true, fmt.Errorf("vDSO text relocations are outside the supported kernel ABI: %w", target.ErrUnsupported)
	}
	return declared, nil
}

type runtimeVDSOStrings struct {
	data string
	ends []uint32
}

func runtimeVDSOString(data runtimeVDSOStrings, offset uint64) (string, error) {
	if offset >= uint64(len(data.data)) {
		return "", fmt.Errorf("vDSO string offset %#x is outside DT_STRSZ: %w", offset, target.ErrInvalidArgument)
	}
	index := sort.Search(len(data.ends), func(index int) bool { return uint64(data.ends[index]) >= offset })
	if index == len(data.ends) {
		return "", fmt.Errorf("unterminated vDSO string: %w", target.ErrInvalidArgument)
	}
	return data.data[offset:data.ends[index]], nil
}

type runtimeVDSOSysVHash struct {
	buckets []uint32
	chains  []uint32
}

func readRuntimeVDSOSysVHash(reader runtimeVDSOReader, offset uint64) (*runtimeVDSOSysVHash, error) {
	header, err := reader.bytes(offset, 8)
	if err != nil {
		return nil, err
	}
	buckets, chains := uint64(binary.LittleEndian.Uint32(header)), uint64(binary.LittleEndian.Uint32(header[4:]))
	if buckets == 0 || buckets > maxRuntimeVDSOSymbols || chains == 0 || chains > maxRuntimeVDSOSymbols {
		return nil, fmt.Errorf("invalid vDSO DT_HASH geometry: %w", target.ErrUnsupported)
	}
	data, err := reader.bytes(offset, 8+4*(buckets+chains))
	if err != nil {
		return nil, err
	}
	hash := &runtimeVDSOSysVHash{buckets: make([]uint32, buckets), chains: make([]uint32, chains)}
	for index := range hash.buckets {
		hash.buckets[index] = binary.LittleEndian.Uint32(data[8+index*4:])
		if uint64(hash.buckets[index]) >= chains {
			return nil, fmt.Errorf("vDSO DT_HASH bucket exceeds nchain: %w", target.ErrInvalidArgument)
		}
	}
	for index := range hash.chains {
		hash.chains[index] = binary.LittleEndian.Uint32(data[8+int(buckets)*4+index*4:])
		if uint64(hash.chains[index]) >= chains {
			return nil, fmt.Errorf("vDSO DT_HASH chain exceeds nchain: %w", target.ErrInvalidArgument)
		}
	}
	if hash.chains[0] != 0 {
		return nil, fmt.Errorf("vDSO DT_HASH symbol-zero chain is nonzero: %w", target.ErrInvalidArgument)
	}
	return hash, nil
}

type runtimeVDSOGNUHash struct {
	buckets []uint32
	chains  []uint32
	bloom   []uint64
	shift   uint32
	first   uint32
	count   uint32
}

func readRuntimeVDSOGNUHash(reader runtimeVDSOReader, offset uint64, count uint32) (*runtimeVDSOGNUHash, error) {
	header, err := reader.bytes(offset, 16)
	if err != nil {
		return nil, err
	}
	buckets := uint64(binary.LittleEndian.Uint32(header))
	first := binary.LittleEndian.Uint32(header[4:])
	bloom := uint64(binary.LittleEndian.Uint32(header[8:]))
	shift := binary.LittleEndian.Uint32(header[12:])
	if buckets == 0 || buckets > maxRuntimeVDSOSymbols || first == 0 || first > maxRuntimeVDSOSymbols || bloom == 0 || bloom > maxRuntimeVDSOSymbols || bloom&(bloom-1) != 0 || shift >= 32 || count != 0 && first > count {
		return nil, fmt.Errorf("invalid vDSO DT_GNU_HASH geometry: %w", target.ErrUnsupported)
	}
	size := 16 + 8*bloom + 4*buckets
	data, err := reader.bytes(offset, size)
	if err != nil {
		return nil, err
	}
	hash := &runtimeVDSOGNUHash{buckets: make([]uint32, buckets), bloom: make([]uint64, bloom), shift: shift, first: first}
	for index := range hash.bloom {
		hash.bloom[index] = binary.LittleEndian.Uint64(data[16+index*8:])
	}
	var starts []uint32
	for index := range hash.buckets {
		value := binary.LittleEndian.Uint32(data[16+int(bloom)*8+index*4:])
		hash.buckets[index] = value
		if value == 0 {
			continue
		}
		if value < first || value >= maxRuntimeVDSOSymbols || count != 0 && value >= count {
			return nil, fmt.Errorf("vDSO DT_GNU_HASH bucket is outside dynsym: %w", target.ErrInvalidArgument)
		}
		starts = append(starts, value)
	}
	if len(starts) == 0 {
		if count == 0 {
			return nil, fmt.Errorf("empty DT_GNU_HASH cannot prove dynamic symbol count: %w", target.ErrUnavailable)
		}
		hash.count = count
		return hash, nil
	}
	slices.Sort(starts)
	if starts[0] != first {
		return nil, fmt.Errorf("vDSO DT_GNU_HASH leaves an unaccounted symbol prefix: %w", target.ErrInvalidArgument)
	}
	if size > math.MaxUint64-offset {
		return nil, target.ErrOverflow
	}
	chainOffset := offset + size
	if count == 0 {
		var cache []byte
		var cacheStart uint64
		for index := uint64(starts[len(starts)-1]); index < maxRuntimeVDSOSymbols; index++ {
			relative := (index - uint64(first)) * 4
			if relative > math.MaxUint64-chainOffset {
				return nil, target.ErrOverflow
			}
			position := chainOffset + relative
			if len(cache) == 0 || position < cacheStart || position-cacheStart >= uint64(len(cache)) {
				load := reader.module.Loads[0]
				if position > load.Size || load.Size-position < 4 {
					return nil, fmt.Errorf("unterminated vDSO GNU hash chain: %w", target.ErrInvalidArgument)
				}
				readSize := min(uint64(1024), load.Size-position, (maxRuntimeVDSOSymbols-index)*4) &^ 3
				cache, err = reader.bytes(position, readSize)
				if err != nil {
					return nil, err
				}
				cacheStart = position
			}
			if binary.LittleEndian.Uint32(cache[position-cacheStart:])&1 != 0 {
				count = uint32(index + 1)
				break
			}
		}
		if count == 0 {
			return nil, fmt.Errorf("vDSO GNU hash chain exceeds symbol limit: %w", target.ErrUnsupported)
		}
	}
	chainData, err := reader.bytes(chainOffset, uint64(count-first)*4)
	if err != nil {
		return nil, err
	}
	hash.chains = make([]uint32, count-first)
	for index := range hash.chains {
		hash.chains[index] = binary.LittleEndian.Uint32(chainData[index*4:])
	}
	for index, start := range starts {
		end := count
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		if start >= end {
			return nil, fmt.Errorf("overlapping vDSO GNU hash buckets: %w", target.ErrInvalidArgument)
		}
		for symbol := start; symbol < end; symbol++ {
			if (hash.chains[symbol-first]&1 != 0) != (symbol == end-1) {
				return nil, fmt.Errorf("vDSO GNU hash chain does not exactly partition dynsym: %w", target.ErrInvalidArgument)
			}
		}
	}
	hash.count = count
	return hash, nil
}

func readRuntimeVDSOSymbols(reader runtimeVDSOReader, facts elfDynamicFacts, stringsData runtimeVDSOStrings) ([]elf.Symbol, string, error) {
	offset, err := runtimeVDSORequiredTag(facts, elf.DT_SYMTAB)
	if err != nil {
		return nil, "", err
	}
	width, err := runtimeVDSORequiredTag(facts, elf.DT_SYMENT)
	if err != nil {
		return nil, "", err
	}
	if width != 24 {
		return nil, "", fmt.Errorf("vDSO DT_SYMENT %d: %w", width, target.ErrUnsupported)
	}
	count := uint32(0)
	source := ""
	if sizes := facts.values[runtimeDTSymtabSize]; len(sizes) != 0 {
		if sizes[0] == 0 || sizes[0]%24 != 0 || sizes[0]/24 > maxRuntimeVDSOSymbols {
			return nil, "", fmt.Errorf("invalid vDSO DT_SYMTABSZ: %w", target.ErrInvalidArgument)
		}
		count, source = uint32(sizes[0]/24), "DT_SYMTABSZ"
	}
	var sysv *runtimeVDSOSysVHash
	if offsets := facts.values[elf.DT_HASH]; len(offsets) != 0 {
		sysv, err = readRuntimeVDSOSysVHash(reader, offsets[0])
		if err != nil {
			return nil, "", err
		}
		if count != 0 && int(count) != len(sysv.chains) {
			return nil, "", fmt.Errorf("vDSO symbol count declarations disagree: %w", target.ErrInvalidArgument)
		}
		count, source = uint32(len(sysv.chains)), "DT_HASH.nchain"
	}
	var gnu *runtimeVDSOGNUHash
	if offsets := facts.values[elf.DT_GNU_HASH]; len(offsets) != 0 {
		gnu, err = readRuntimeVDSOGNUHash(reader, offsets[0], count)
		if err != nil {
			return nil, "", err
		}
		if source == "" {
			source = "DT_GNU_HASH checked chains"
		}
		count = gnu.count
	}
	if count == 0 {
		return nil, "", fmt.Errorf("vDSO has no exact dynamic symbol count: %w", target.ErrUnavailable)
	}
	data, err := reader.bytes(offset, uint64(count)*24)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(data[:24], make([]byte, 24)) {
		return nil, "", fmt.Errorf("vDSO symbol zero is not STN_UNDEF: %w", target.ErrInvalidArgument)
	}
	symbols := make([]elf.Symbol, count)
	nameBytes := uint64(0)
	for index := range symbols {
		entry := data[index*24:]
		name, err := runtimeVDSOString(stringsData, uint64(binary.LittleEndian.Uint32(entry)))
		if err != nil {
			return nil, "", err
		}
		nameBytes += uint64(len(name))
		if nameBytes > maxRuntimeELFRead {
			return nil, "", fmt.Errorf("vDSO symbol name budget exhausted: %w", target.ErrOverflow)
		}
		section := elf.SectionIndex(binary.LittleEndian.Uint16(entry[6:]))
		if section == elf.SHN_XINDEX {
			return nil, "", fmt.Errorf("vDSO extended symbol section index: %w", target.ErrUnsupported)
		}
		symbols[index] = elf.Symbol{Name: name, Info: entry[4], Other: entry[5], Section: section, Value: binary.LittleEndian.Uint64(entry[8:]), Size: binary.LittleEndian.Uint64(entry[16:])}
	}
	if sysv != nil {
		seen := make([]bool, len(symbols))
		for bucket, first := range sysv.buckets {
			for index := first; index != 0; index = sysv.chains[index] {
				if seen[index] {
					return nil, "", fmt.Errorf("cyclic or overlapping vDSO DT_HASH chains: %w", target.ErrInvalidArgument)
				}
				seen[index] = true
				if runtimeVDSOELFHash(symbols[index].Name)%uint32(len(sysv.buckets)) != uint32(bucket) {
					return nil, "", fmt.Errorf("vDSO DT_HASH symbol is in the wrong bucket: %w", target.ErrInvalidArgument)
				}
			}
		}
	}
	if gnu != nil {
		for bucket, first := range gnu.buckets {
			if first == 0 {
				continue
			}
			for index := first; ; index++ {
				hash := uint32(5381)
				for _, ch := range []byte(symbols[index].Name) {
					hash = hash*33 + uint32(ch)
				}
				chain := gnu.chains[index-gnu.first]
				bits := uint64(1)<<(hash%64) | uint64(1)<<((hash>>gnu.shift)%64)
				if hash%uint32(len(gnu.buckets)) != uint32(bucket) || hash&^1 != chain&^1 || gnu.bloom[(hash/64)%uint32(len(gnu.bloom))]&bits != bits {
					return nil, "", fmt.Errorf("vDSO GNU hash symbol or bloom mismatch: %w", target.ErrInvalidArgument)
				}
				if chain&1 != 0 {
					break
				}
			}
		}
	}
	return symbols, source, nil
}

func runtimeVDSOELFHash(name string) uint32 {
	var hash uint32
	for _, ch := range []byte(name) {
		hash = hash<<4 + uint32(ch)
		high := hash & 0xf0000000
		hash ^= high >> 24
		hash &^= high
	}
	return hash
}

func readRuntimeVDSOVersions(reader runtimeVDSOReader, facts elfDynamicFacts, stringsData runtimeVDSOStrings, symbols []elf.Symbol) ([]runtimeVDSOVersionDefinition, error) {
	if len(facts.values[elf.DT_VERNEED])+len(facts.values[elf.DT_VERNEEDNUM]) != 0 {
		return nil, fmt.Errorf("vDSO external version requirements: %w", target.ErrUnsupported)
	}
	offsets, counts := facts.values[elf.DT_VERDEF], facts.values[elf.DT_VERDEFNUM]
	if (len(offsets) == 0) != (len(counts) == 0) {
		return nil, fmt.Errorf("incomplete vDSO version definitions: %w", target.ErrInvalidArgument)
	}
	var definitions []runtimeVDSOVersionDefinition
	byIndex := make(map[uint16]int)
	var spans []runtimeELFSpan
	auxiliaryCount, nameBytes := uint64(0), uint64(0)
	if len(offsets) != 0 {
		if counts[0] == 0 || counts[0] > maxRuntimeVDSOVersions {
			return nil, fmt.Errorf("invalid vDSO DT_VERDEFNUM: %w", target.ErrUnsupported)
		}
		offset := offsets[0]
		for index := uint64(0); index < counts[0]; index++ {
			data, err := reader.bytes(offset, 20)
			if err != nil {
				return nil, err
			}
			version, flags := binary.LittleEndian.Uint16(data), binary.LittleEndian.Uint16(data[2:])
			id, count := binary.LittleEndian.Uint16(data[4:]), binary.LittleEndian.Uint16(data[6:])
			hash := binary.LittleEndian.Uint32(data[8:])
			aux, next := uint64(binary.LittleEndian.Uint32(data[12:])), uint64(binary.LittleEndian.Uint32(data[16:]))
			if version != 1 || id == 0 || id&0x8000 != 0 || count == 0 || count > maxRuntimeVDSOVersions || aux < 20 || aux%4 != 0 || (index+1 < counts[0]) != (next != 0) || next != 0 && (next < 20 || next%4 != 0) {
				return nil, fmt.Errorf("invalid vDSO version definition: %w", target.ErrInvalidArgument)
			}
			auxiliaryCount += uint64(count)
			if auxiliaryCount > maxRuntimeVDSOSymbols {
				return nil, fmt.Errorf("vDSO version auxiliary count exceeds limit: %w", target.ErrOverflow)
			}
			if _, exists := byIndex[id]; exists {
				return nil, fmt.Errorf("duplicate vDSO version index: %w", target.ErrAmbiguous)
			}
			if aux > math.MaxUint64-offset || next > math.MaxUint64-offset {
				return nil, target.ErrOverflow
			}
			spans = append(spans, runtimeELFSpan{target.Address(offset), 20})
			definition := runtimeVDSOVersionDefinition{Index: id, Flags: flags, Hash: hash}
			auxOffset := offset + aux
			for ordinal := uint16(0); ordinal < count; ordinal++ {
				entry, err := reader.bytes(auxOffset, 8)
				if err != nil {
					return nil, err
				}
				name, err := runtimeVDSOString(stringsData, uint64(binary.LittleEndian.Uint32(entry)))
				if err != nil {
					return nil, err
				}
				nameBytes += uint64(len(name))
				if nameBytes > maxRuntimeELFRead {
					return nil, fmt.Errorf("vDSO version name budget exhausted: %w", target.ErrOverflow)
				}
				jump := uint64(binary.LittleEndian.Uint32(entry[4:]))
				if name == "" || (ordinal+1 < count) != (jump != 0) || jump != 0 && (jump < 8 || jump%4 != 0) {
					return nil, fmt.Errorf("invalid vDSO version auxiliary entry: %w", target.ErrInvalidArgument)
				}
				spans = append(spans, runtimeELFSpan{target.Address(auxOffset), 8})
				definition.Names = append(definition.Names, name)
				if jump > math.MaxUint64-auxOffset {
					return nil, target.ErrOverflow
				}
				auxOffset += jump
			}
			if runtimeVDSOELFHash(definition.Names[0]) != hash {
				return nil, fmt.Errorf("vDSO version name hash mismatch: %w", target.ErrInvalidArgument)
			}
			byIndex[id] = len(definitions)
			definitions = append(definitions, definition)
			offset += next
		}
	}
	slices.SortFunc(spans, func(a, b runtimeELFSpan) int {
		if a.Address < b.Address {
			return -1
		}
		if a.Address > b.Address {
			return 1
		}
		return 0
	})
	for index := 1; index < len(spans); index++ {
		if uint64(spans[index].Address-spans[index-1].Address) < spans[index-1].Size {
			return nil, fmt.Errorf("overlapping vDSO version records: %w", target.ErrInvalidArgument)
		}
	}
	versions := facts.values[elf.DT_VERSYM]
	if len(versions) == 0 {
		if len(definitions) != 0 {
			return nil, fmt.Errorf("vDSO definitions lack DT_VERSYM: %w", target.ErrUnavailable)
		}
		return nil, nil
	}
	data, err := reader.bytes(versions[0], uint64(len(symbols))*2)
	if err != nil {
		return nil, err
	}
	for index := range symbols {
		version := binary.LittleEndian.Uint16(data[index*2:])
		id := version & 0x7fff
		if index == 0 && version != 0 || id <= 1 && version&0x8000 != 0 {
			return nil, fmt.Errorf("invalid vDSO reserved symbol version: %w", target.ErrInvalidArgument)
		}
		symbols[index].HasVersion, symbols[index].VersionIndex = true, elf.VersionIndex(version)
		if id <= 1 {
			continue
		}
		definition, exists := byIndex[id]
		if !exists {
			return nil, fmt.Errorf("undefined vDSO version index %d: %w", id, target.ErrInvalidArgument)
		}
		symbols[index].Version = definitions[definition].Names[0]
	}
	return definitions, nil
}

func runtimeVDSOSymbol(metadata *runtimeVDSOMetadata, moduleID string, raw elf.Symbol) (inspect.Symbol, error) {
	symbol := inspect.Symbol{
		ModuleID: moduleID, Name: raw.Name, Version: raw.Version, Value: raw.Value, Size: raw.Size,
		Type: elf.ST_TYPE(raw.Info), Binding: elf.ST_BIND(raw.Info), Section: raw.Section,
	}
	if metadata == nil || !metadata.SymbolsComplete {
		return symbol, target.ErrInvalidArgument
	}
	if raw.Section == elf.SHN_UNDEF {
		return symbol, target.ErrUnavailable
	}
	switch symbol.Type {
	case elf.STT_NOTYPE, elf.STT_OBJECT, elf.STT_FUNC:
	default:
		return symbol, target.ErrUnsupported
	}
	address := raw.Value
	if raw.Section != elf.SHN_ABS {
		if raw.Section >= elf.SHN_LORESERVE {
			return symbol, target.ErrUnsupported
		}
		if address > math.MaxUint64-metadata.LoadBias {
			return symbol, target.ErrOverflow
		}
		address += metadata.LoadBias
		module := runtimeELFModule{Loads: metadata.Loads}
		if !runtimeELFLoaded(&module, target.Address(address), max(raw.Size, 1)) {
			return symbol, fmt.Errorf("vDSO symbol %q is outside PT_LOAD: %w", raw.Name, target.ErrUnavailable)
		}
	}
	if raw.Size > 0 && raw.Size-1 > math.MaxUint64-address {
		return symbol, target.ErrOverflow
	}
	symbol.Address, symbol.AddressKnown = target.Address(address), true
	return symbol, nil
}
