package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"fastdbg2/target"
)

type runtimeVDSOTestFixture struct {
	data   []byte
	view   *runtimeELFView
	module *runtimeELFModule
	names  map[string]uint32
}

func (fixture runtimeVDSOTestFixture) tag(tag elf.DynTag, value uint64) {
	for offset := 0x800; offset < 0xa00; offset += 16 {
		current := elf.DynTag(binary.LittleEndian.Uint64(fixture.data[offset:]))
		if current == tag || current == elf.DT_NULL {
			binary.LittleEndian.PutUint64(fixture.data[offset:], uint64(tag))
			binary.LittleEndian.PutUint64(fixture.data[offset+8:], value)
			return
		}
	}
	panic("fixture dynamic table full")
}

func (fixture runtimeVDSOTestFixture) removeTag(tag elf.DynTag) {
	for offset := 0x800; offset < 0xa00; offset += 16 {
		if elf.DynTag(binary.LittleEndian.Uint64(fixture.data[offset:])) == tag {
			copy(fixture.data[offset:0xa00-16], fixture.data[offset+16:0xa00])
			clear(fixture.data[0xa00-16 : 0xa00])
			return
		}
	}
}

func runtimeVDSOTestImage(t *testing.T) runtimeVDSOTestFixture {
	t.Helper()
	const base = target.Address(0x700000)
	data := make([]byte, 0x3000)
	programs := []elf.Prog64{
		{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Filesz: uint64(len(data)), Memsz: uint64(len(data)), Align: 0x1000},
		{Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R), Off: 0x800, Vaddr: 0x800, Filesz: 0x200, Memsz: 0x200, Align: 8},
	}
	header := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: uint16(len(programs))}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS], header.Ident[elf.EI_DATA], header.Ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	var encoded bytes.Buffer
	for _, item := range []any{header, programs} {
		if err := binary.Write(&encoded, binary.LittleEndian, item); err != nil {
			t.Fatal(err)
		}
	}
	copy(data, encoded.Bytes())
	names := make(map[string]uint32)
	var stringData []byte
	for _, name := range []string{"", "__vdso_clock_gettime", "absolute", "kernel.so", "LINUX_TEST", "unsafe\x1b[31m\n"} {
		names[name] = uint32(len(stringData))
		stringData = append(stringData, name...)
		stringData = append(stringData, 0)
	}
	copy(data[0x1000:], stringData)
	for index, symbol := range []elf.Sym64{
		{},
		{Name: names["__vdso_clock_gettime"], Info: byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)), Shndx: 1, Value: 0x2000, Size: 8},
		{Name: names["absolute"], Info: byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT)), Shndx: uint16(elf.SHN_ABS), Value: 0, Size: 0},
	} {
		encoded.Reset()
		if err := binary.Write(&encoded, binary.LittleEndian, symbol); err != nil {
			t.Fatal(err)
		}
		copy(data[0x1200+index*24:], encoded.Bytes())
	}
	for index, word := range []uint32{1, 3, 1, 0, 2, 0} {
		binary.LittleEndian.PutUint32(data[0x1400+index*4:], word)
	}
	for index, word := range []uint32{1, 1, 1, 5} {
		binary.LittleEndian.PutUint32(data[0x1500+index*4:], word)
	}
	var bloom uint64
	for index, name := range []string{"__vdso_clock_gettime", "absolute"} {
		hash := uint32(5381)
		for _, ch := range []byte(name) {
			hash = hash*33 + uint32(ch)
		}
		bloom |= uint64(1)<<(hash%64) | uint64(1)<<((hash>>5)%64)
		value := hash &^ 1
		if index == 1 {
			value |= 1
		}
		binary.LittleEndian.PutUint32(data[0x151c+index*4:], value)
	}
	binary.LittleEndian.PutUint64(data[0x1510:], bloom)
	binary.LittleEndian.PutUint32(data[0x1518:], 1)
	binary.LittleEndian.PutUint16(data[0x1602:], 2)
	binary.LittleEndian.PutUint16(data[0x1604:], 0x8002)
	binary.LittleEndian.PutUint16(data[0x1700:], 1)
	binary.LittleEndian.PutUint16(data[0x1704:], 2)
	binary.LittleEndian.PutUint16(data[0x1706:], 1)
	binary.LittleEndian.PutUint32(data[0x1708:], runtimeVDSOELFHash("LINUX_TEST"))
	binary.LittleEndian.PutUint32(data[0x170c:], 20)
	binary.LittleEndian.PutUint32(data[0x1714:], names["LINUX_TEST"])
	fixture := runtimeVDSOTestFixture{data: data, names: names}
	for _, entry := range []struct {
		tag   elf.DynTag
		value uint64
	}{
		{elf.DT_HASH, 0x1400}, {elf.DT_GNU_HASH, 0x1500}, {elf.DT_STRTAB, 0x1000}, {elf.DT_STRSZ, uint64(len(stringData))},
		{elf.DT_SYMTAB, 0x1200}, {elf.DT_SYMENT, 24}, {elf.DT_SONAME, uint64(names["kernel.so"])},
		{elf.DT_VERSYM, 0x1600}, {elf.DT_VERDEF, 0x1700}, {elf.DT_VERDEFNUM, 1}, {elf.DT_FLAGS, uint64(elf.DF_SYMBOLIC)},
	} {
		fixture.tag(entry.tag, entry.value)
	}
	memory := runtimeELFTestMemory(t, runtimeELFTestRegion{base, data})
	memory.mappings[0].Execute = true
	module, err := runtimeELFZeroOrigin(memory, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	module.AuxiliaryTag, module.AuxiliaryAddress = 33, base
	fixture.module, fixture.view = module, &runtimeELFView{Memory: memory, Modules: []*runtimeELFModule{module}}
	return fixture
}

func TestRuntimeVDSOExactDynamicMetadataWithoutSections(t *testing.T) {
	for _, hash := range []string{"both", "sysv", "gnu", "explicit"} {
		t.Run(hash, func(t *testing.T) {
			fixture := runtimeVDSOTestImage(t)
			if hash == "gnu" || hash == "explicit" {
				fixture.removeTag(elf.DT_HASH)
			}
			if hash == "sysv" || hash == "explicit" {
				fixture.removeTag(elf.DT_GNU_HASH)
			}
			if hash == "explicit" {
				fixture.tag(runtimeDTSymtabSize, 3*24)
			}
			metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Header.Type != elf.ET_DYN || metadata.Header.Machine != elf.EM_X86_64 || metadata.HeaderFlags != 0 || len(metadata.Programs) != 2 || !metadata.SymbolsComplete || len(metadata.Symbols) != 3 || metadata.SymbolCountSource == "" || !metadata.Dynamic.present || metadata.RelocationsDeclared || len(metadata.PointerRelocations) != 0 || len(metadata.VersionDefinitions) != 1 {
				t.Fatalf("metadata=%+v", metadata)
			}
			if metadata.Symbols[0].Name != "" || metadata.Symbols[0].Section != elf.SHN_UNDEF || metadata.Symbols[1].Version != "LINUX_TEST" || !metadata.Symbols[1].HasVersion || metadata.Symbols[1].VersionIndex.Index() != 2 || !metadata.Symbols[2].VersionIndex.IsHidden() {
				t.Fatalf("symbols=%+v", metadata.Symbols)
			}
			for index, want := range map[int]target.Address{1: 0x702000, 2: 0} {
				symbol, err := runtimeVDSOSymbol(metadata, "vdso", metadata.Symbols[index])
				if err != nil || !symbol.AddressKnown || symbol.Address != want || symbol.ModuleID != "vdso" || symbol.Version != "LINUX_TEST" {
					t.Fatalf("symbol=%+v error=%v", symbol, err)
				}
			}
		})
	}
}

func TestRuntimeVDSORejectsMissingOrInconsistentProof(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(runtimeVDSOTestFixture)
		kind error
	}{
		{"name_is_not_anchor", func(f runtimeVDSOTestFixture) { f.module.AuxiliaryTag = 0; f.module.Name = "linux-vdso.so.1" }, target.ErrUnsupported},
		{"interpreter_anchor", func(f runtimeVDSOTestFixture) { f.module.AuxiliaryTag = 7 }, target.ErrUnsupported},
		{"other_aux_address", func(f runtimeVDSOTestFixture) { f.module.AuxiliaryAddress++ }, target.ErrUnsupported},
		{"other_bias", func(f runtimeVDSOTestFixture) { f.module.LoadBias++ }, target.ErrUnsupported},
		{"changed_program", func(f runtimeVDSOTestFixture) { f.module.Programs[0].Align = 0x2000 }, target.ErrStale},
		{"changed_load", func(f runtimeVDSOTestFixture) { f.module.Loads[0].Size-- }, target.ErrStale},
		{"changed_dynamic", func(f runtimeVDSOTestFixture) { f.module.Dynamic.Size -= 16 }, target.ErrStale},
		{"writable_mapping", func(f runtimeVDSOTestFixture) { f.view.Memory.mappings[0].Write = true }, target.ErrUnsupported},
		{"nonexecutable_mapping", func(f runtimeVDSOTestFixture) { f.view.Memory.mappings[0].Execute = false }, target.ErrUnsupported},
		{"nonreadable_mapping", func(f runtimeVDSOTestFixture) { f.view.Memory.mappings[0].Read = false }, target.ErrUnavailable},
		{"class", func(f runtimeVDSOTestFixture) { f.data[elf.EI_CLASS] = byte(elf.ELFCLASS32) }, target.ErrUnsupported},
		{"machine", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint16(f.data[18:], uint16(elf.EM_AARCH64)) }, target.ErrUnsupported},
		{"abi", func(f runtimeVDSOTestFixture) { f.data[elf.EI_ABIVERSION] = 1 }, target.ErrUnsupported},
		{"osabi", func(f runtimeVDSOTestFixture) { f.data[elf.EI_OSABI] = byte(elf.ELFOSABI_FREEBSD) }, target.ErrUnsupported},
		{"header_flags", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[48:], 1) }, target.ErrUnsupported},
		{"stale_memory", func(f runtimeVDSOTestFixture) {
			f.view.Memory.read = func(target.Address, []byte) (int, error) { return 0, target.ErrStale }
		}, target.ErrStale},
		{"short_read", func(f runtimeVDSOTestFixture) {
			f.view.Memory.read = func(target.Address, []byte) (int, error) { return 0, nil }
		}, io.ErrUnexpectedEOF},
		{"read_budget", func(f runtimeVDSOTestFixture) { f.view.Memory.remaining = 63 }, target.ErrOverflow},
		{"cancelled", func(f runtimeVDSOTestFixture) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			f.view.Memory.ctx = ctx
		}, context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := runtimeVDSOTestImage(t)
			test.edit(fixture)
			metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
			if metadata != nil || !errors.Is(err, test.kind) {
				t.Fatalf("metadata=%+v error=%v want=%v", metadata, err, test.kind)
			}
		})
	}
}

func TestRuntimeVDSORejectsMalformedDynamicMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(runtimeVDSOTestFixture)
		kind error
	}{
		{"no_count", func(f runtimeVDSOTestFixture) { f.removeTag(elf.DT_HASH); f.removeTag(elf.DT_GNU_HASH) }, target.ErrUnavailable},
		{"unknown_dynamic_tag", func(f runtimeVDSOTestFixture) { f.tag(0x7000ffff, 0x1800) }, target.ErrUnsupported},
		{"unknown_flags", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_FLAGS, 0x20) }, target.ErrUnsupported},
		{"unknown_flags_1", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_FLAGS_1, 0x80000000) }, target.ErrUnsupported},
		{"symbol_width", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_SYMENT, 16) }, target.ErrUnsupported},
		{"symbol_count_conflict", func(f runtimeVDSOTestFixture) { f.tag(runtimeDTSymtabSize, 4*24) }, target.ErrInvalidArgument},
		{"symbol_count_fraction", func(f runtimeVDSOTestFixture) { f.tag(runtimeDTSymtabSize, 25) }, target.ErrInvalidArgument},
		{"symbol_count_zero", func(f runtimeVDSOTestFixture) { f.tag(runtimeDTSymtabSize, 0) }, target.ErrInvalidArgument},
		{"symbol_zero", func(f runtimeVDSOTestFixture) { f.data[0x1200] = 1 }, target.ErrInvalidArgument},
		{"extended_section", func(f runtimeVDSOTestFixture) {
			binary.LittleEndian.PutUint16(f.data[0x1200+24+6:], uint16(elf.SHN_XINDEX))
		}, target.ErrUnsupported},
		{"absolute_dynamic_pointer", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_SYMTAB, uint64(f.module.Header)+0x1200) }, target.ErrUnavailable},
		{"symbol_pointer_overflow", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_SYMTAB, math.MaxUint64) }, target.ErrOverflow},
		{"symbol_range", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_SYMTAB, 0x2ff0) }, target.ErrUnavailable},
		{"strsz_zero", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_STRSZ, 0) }, target.ErrUnsupported},
		{"strsz_limit", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_STRSZ, maxRuntimeVDSOStrings+1) }, target.ErrUnsupported},
		{"first_string_boundary", func(f runtimeVDSOTestFixture) { f.data[0x1000] = 'x' }, target.ErrInvalidArgument},
		{"last_string_boundary", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_STRSZ, uint64(f.names["unsafe\x1b[31m\n"])+1) }, target.ErrInvalidArgument},
		{"name_outside_strsz", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1200+24:], 0xffffffff) }, target.ErrInvalidArgument},
		{"soname_outside_strsz", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_SONAME, 0xffffffff) }, target.ErrInvalidArgument},
		{"missing_symbol_tag", func(f runtimeVDSOTestFixture) { f.removeTag(elf.DT_SYMTAB) }, target.ErrUnavailable},
		{"duplicate_tag", func(f runtimeVDSOTestFixture) {
			f.tag(elf.DT_DEBUG, 7)
			for offset := 0x800; offset < 0xa00; offset += 16 {
				if elf.DynTag(binary.LittleEndian.Uint64(f.data[offset:])) == elf.DT_DEBUG {
					binary.LittleEndian.PutUint64(f.data[offset:], uint64(elf.DT_SYMTAB))
					break
				}
			}
		}, target.ErrAmbiguous},
		{"unterminated_dynamic", func(f runtimeVDSOTestFixture) {
			for offset := 0x800; offset < 0xa00; offset += 16 {
				binary.LittleEndian.PutUint64(f.data[offset:], uint64(elf.DT_NEEDED))
				binary.LittleEndian.PutUint64(f.data[offset+8:], 0)
			}
		}, target.ErrInvalidArgument},
		{"sysv_nchain_zero", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1404:], 0) }, target.ErrUnsupported},
		{"sysv_nchain_limit", func(f runtimeVDSOTestFixture) {
			binary.LittleEndian.PutUint32(f.data[0x1404:], maxRuntimeVDSOSymbols+1)
		}, target.ErrUnsupported},
		{"sysv_bucket_oob", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1408:], 3) }, target.ErrInvalidArgument},
		{"sysv_chain_oob", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1410:], 3) }, target.ErrInvalidArgument},
		{"sysv_chain_cycle", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1410:], 1) }, target.ErrInvalidArgument},
		{"gnu_bloom_geometry", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1508:], 3) }, target.ErrUnsupported},
		{"gnu_shift", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x150c:], 32) }, target.ErrUnsupported},
		{"gnu_bucket_oob", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1518:], 3) }, target.ErrInvalidArgument},
		{"gnu_unaccounted_prefix", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1518:], 2) }, target.ErrInvalidArgument},
		{"gnu_early_termination", func(f runtimeVDSOTestFixture) { f.data[0x151c] |= 1 }, target.ErrInvalidArgument},
		{"gnu_unterminated", func(f runtimeVDSOTestFixture) { f.data[0x1520] &^= 1 }, target.ErrInvalidArgument},
		{"gnu_hash_name", func(f runtimeVDSOTestFixture) { f.data[0x151c] ^= 2 }, target.ErrInvalidArgument},
		{"gnu_bloom_bits", func(f runtimeVDSOTestFixture) { clear(f.data[0x1510:0x1518]) }, target.ErrInvalidArgument},
		{"gnu_empty_no_exact_count", func(f runtimeVDSOTestFixture) {
			f.removeTag(elf.DT_HASH)
			binary.LittleEndian.PutUint32(f.data[0x1518:], 0)
		}, target.ErrUnavailable},
		{"gnu_only_unterminated", func(f runtimeVDSOTestFixture) { f.removeTag(elf.DT_HASH); clear(f.data[0x151c:]) }, target.ErrInvalidArgument},
		{"verdef_missing_count", func(f runtimeVDSOTestFixture) { f.removeTag(elf.DT_VERDEFNUM) }, target.ErrInvalidArgument},
		{"versym_missing", func(f runtimeVDSOTestFixture) { f.removeTag(elf.DT_VERSYM) }, target.ErrUnavailable},
		{"verdef_limit", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_VERDEFNUM, maxRuntimeVDSOVersions+1) }, target.ErrUnsupported},
		{"verdef_format", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint16(f.data[0x1700:], 2) }, target.ErrInvalidArgument},
		{"verdef_next_count", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1710:], 28) }, target.ErrInvalidArgument},
		{"verdef_hash", func(f runtimeVDSOTestFixture) { f.data[0x1708] ^= 1 }, target.ErrInvalidArgument},
		{"verdef_aux_in_header", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x170c:], 16) }, target.ErrInvalidArgument},
		{"verdef_aux_next", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1718:], 8) }, target.ErrInvalidArgument},
		{"verdef_name_oob", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint32(f.data[0x1714:], 0xffffffff) }, target.ErrInvalidArgument},
		{"versym_unknown", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint16(f.data[0x1602:], 3) }, target.ErrInvalidArgument},
		{"versym_zero", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint16(f.data[0x1600:], 1) }, target.ErrInvalidArgument},
		{"versym_reserved_hidden", func(f runtimeVDSOTestFixture) { binary.LittleEndian.PutUint16(f.data[0x1602:], 0x8001) }, target.ErrInvalidArgument},
		{"verneed_external", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_VERNEED, 0x1800) }, target.ErrUnsupported},
		{"rela", func(f runtimeVDSOTestFixture) {
			f.tag(elf.DT_RELA, 0x1800)
			f.tag(elf.DT_RELASZ, 24)
			f.tag(elf.DT_RELAENT, 24)
		}, target.ErrUnsupported},
		{"partial_rela", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_RELA, 0x1800) }, target.ErrUnsupported},
		{"relr", func(f runtimeVDSOTestFixture) { f.tag(36, 0x1800); f.tag(35, 8); f.tag(37, 8) }, target.ErrUnsupported},
		{"android_rel", func(f runtimeVDSOTestFixture) { f.tag(0x6000000f, 0x1800) }, target.ErrUnsupported},
		{"textrel", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_TEXTREL, 0) }, target.ErrUnsupported},
		{"textrel_flag", func(f runtimeVDSOTestFixture) { f.tag(elf.DT_FLAGS, uint64(elf.DF_TEXTREL)) }, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := runtimeVDSOTestImage(t)
			test.edit(fixture)
			metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
			if metadata != nil || !errors.Is(err, test.kind) {
				t.Fatalf("metadata=%+v error=%v want=%v", metadata, err, test.kind)
			}
		})
	}
}

func TestRuntimeVDSOExplicitEmptyRelocationsAndUnversionedSymbols(t *testing.T) {
	fixture := runtimeVDSOTestImage(t)
	for _, tag := range []elf.DynTag{elf.DT_VERSYM, elf.DT_VERDEF, elf.DT_VERDEFNUM} {
		fixture.removeTag(tag)
	}
	fixture.tag(elf.DT_RELA, 0)
	fixture.tag(elf.DT_RELASZ, 0)
	fixture.tag(elf.DT_RELAENT, 24)
	metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
	if err != nil || !metadata.RelocationsDeclared || len(metadata.PointerRelocations) != 0 || len(metadata.VersionDefinitions) != 0 {
		t.Fatalf("metadata=%+v error=%v", metadata, err)
	}
	for _, symbol := range metadata.Symbols {
		if symbol.HasVersion || symbol.Version != "" {
			t.Fatalf("invented symbol version %+v", symbol)
		}
	}
}

func TestRuntimeVDSOCheckedMultipleGNUHashBuckets(t *testing.T) {
	for _, corruption := range []string{"", "overlap", "gap", "wrong_bucket"} {
		t.Run(corruption, func(t *testing.T) {
			fixture := runtimeVDSOTestImage(t)
			fixture.removeTag(elf.DT_HASH)
			first := binary.LittleEndian.Uint32(fixture.data[0x151c:])
			last := binary.LittleEndian.Uint32(fixture.data[0x1520:])
			binary.LittleEndian.PutUint32(fixture.data[0x1500:], 3)
			for index, value := range []uint32{0, 1, 2, first | 1, last} {
				binary.LittleEndian.PutUint32(fixture.data[0x1518+index*4:], value)
			}
			switch corruption {
			case "overlap":
				binary.LittleEndian.PutUint32(fixture.data[0x1520:], 1)
			case "gap":
				binary.LittleEndian.PutUint32(fixture.data[0x1520:], 3)
			case "wrong_bucket":
				binary.LittleEndian.PutUint32(fixture.data[0x151c:], 2)
				binary.LittleEndian.PutUint32(fixture.data[0x1520:], 1)
			}
			metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
			if corruption == "" {
				if err != nil || len(metadata.Symbols) != 3 || metadata.SymbolCountSource != "DT_GNU_HASH checked chains" {
					t.Fatalf("metadata=%+v error=%v", metadata, err)
				}
			} else if metadata != nil || !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("metadata=%+v error=%v", metadata, err)
			}
		})
	}
}

func TestRuntimeVDSOVersionDefinitionLinkedRecords(t *testing.T) {
	for _, corruption := range []string{"", "duplicate_index", "overlapping_auxiliary", "truncated_count"} {
		t.Run(corruption, func(t *testing.T) {
			fixture := runtimeVDSOTestImage(t)
			copy(fixture.data[0x1740:0x175c], fixture.data[0x1700:0x171c])
			fixture.tag(elf.DT_VERDEFNUM, 2)
			binary.LittleEndian.PutUint16(fixture.data[0x1704:], 1)
			binary.LittleEndian.PutUint16(fixture.data[0x1702:], 1)
			binary.LittleEndian.PutUint32(fixture.data[0x1708:], runtimeVDSOELFHash("kernel.so"))
			binary.LittleEndian.PutUint32(fixture.data[0x1714:], fixture.names["kernel.so"])
			binary.LittleEndian.PutUint32(fixture.data[0x1710:], 0x40)
			switch corruption {
			case "duplicate_index":
				binary.LittleEndian.PutUint16(fixture.data[0x1744:], 1)
			case "overlapping_auxiliary":
				binary.LittleEndian.PutUint32(fixture.data[0x170c:], 0x54)
				binary.LittleEndian.PutUint32(fixture.data[0x1708:], runtimeVDSOELFHash("LINUX_TEST"))
			case "truncated_count":
				fixture.tag(elf.DT_VERDEFNUM, 3)
			}
			metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
			if corruption == "" {
				if err != nil || len(metadata.VersionDefinitions) != 2 || metadata.VersionDefinitions[0].Names[0] != "kernel.so" {
					t.Fatalf("metadata=%+v error=%v", metadata, err)
				}
			} else if metadata != nil || !errors.Is(err, target.ErrInvalidArgument) && !errors.Is(err, target.ErrAmbiguous) {
				t.Fatalf("metadata=%+v error=%v", metadata, err)
			}
		})
	}
}

func TestRuntimeVDSORejectsUnsupportedKernelProgramLayout(t *testing.T) {
	for _, kind := range []string{"writable_load", "split_load", "bss", "writable_dynamic", "tls", "interpreter"} {
		t.Run(kind, func(t *testing.T) {
			fixture := runtimeVDSOTestImage(t)
			switch kind {
			case "writable_load":
				binary.LittleEndian.PutUint32(fixture.data[64+4:], uint32(elf.PF_R|elf.PF_W|elf.PF_X))
			case "split_load":
				binary.LittleEndian.PutUint16(fixture.data[56:], 3)
				copy(fixture.data[64+2*56:], fixture.data[64:64+56])
			case "bss":
				binary.LittleEndian.PutUint64(fixture.data[64+32:], 0x2000)
			case "writable_dynamic":
				binary.LittleEndian.PutUint32(fixture.data[64+56+4:], uint32(elf.PF_R|elf.PF_W))
			case "tls", "interpreter":
				binary.LittleEndian.PutUint16(fixture.data[56:], 3)
				program := elf.PT_TLS
				if kind == "interpreter" {
					program = elf.PT_INTERP
				}
				binary.LittleEndian.PutUint32(fixture.data[64+2*56:], uint32(program))
			}
			module, err := runtimeELFZeroOrigin(fixture.view.Memory, fixture.module.Header, nil)
			if err != nil {
				t.Fatal(err)
			}
			module.AuxiliaryTag, module.AuxiliaryAddress = 33, module.Header
			metadata, err := readRuntimeVDSO(fixture.view, module)
			if metadata != nil || !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("metadata=%+v error=%v", metadata, err)
			}
		})
	}
}

func TestRuntimeVDSOSymbolAddressSemantics(t *testing.T) {
	fixture := runtimeVDSOTestImage(t)
	metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		symbol  elf.Symbol
		address target.Address
		kind    error
	}{
		{"undefined", elf.Symbol{Name: "missing", Info: byte(elf.STT_FUNC), Section: elf.SHN_UNDEF, Value: 0x2000}, 0, target.ErrUnavailable},
		{"absolute_zero", elf.Symbol{Name: "constant", Info: byte(elf.STT_OBJECT), Section: elf.SHN_ABS}, 0, nil},
		{"function", elf.Symbol{Name: "function", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x2000, Size: 8}, 0x702000, nil},
		{"tls_offset", elf.Symbol{Name: "tls", Info: byte(elf.STT_TLS), Section: 1, Value: 0x20}, 0, target.ErrUnsupported},
		{"ifunc_resolver", elf.Symbol{Name: "resolver", Info: byte(elf.STT_GNU_IFUNC), Section: 1, Value: 0x2000}, 0, target.ErrUnsupported},
		{"common", elf.Symbol{Name: "common", Info: byte(elf.STT_OBJECT), Section: elf.SHN_COMMON, Value: 8}, 0, target.ErrUnsupported},
		{"reserved", elf.Symbol{Name: "reserved", Info: byte(elf.STT_OBJECT), Section: elf.SHN_XINDEX}, 0, target.ErrUnsupported},
		{"not_in_load", elf.Symbol{Name: "external", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x3000}, 0, target.ErrUnavailable},
		{"range_overflow", elf.Symbol{Name: "range", Info: byte(elf.STT_OBJECT), Section: elf.SHN_ABS, Value: math.MaxUint64, Size: 2}, 0, target.ErrOverflow},
		{"bias_overflow", elf.Symbol{Name: "bias", Info: byte(elf.STT_OBJECT), Section: 1, Value: math.MaxUint64}, 0, target.ErrOverflow},
	} {
		t.Run(test.name, func(t *testing.T) {
			symbol, err := runtimeVDSOSymbol(metadata, "vdso", test.symbol)
			if !errors.Is(err, test.kind) || symbol.AddressKnown != (test.kind == nil) || symbol.Address != test.address || symbol.Name != test.symbol.Name || symbol.Value != test.symbol.Value || symbol.Section != test.symbol.Section {
				t.Fatalf("symbol=%+v error=%v", symbol, err)
			}
		})
	}
}

func TestRuntimeVDSORetainsUntrustedNamesWithoutTerminalEscapes(t *testing.T) {
	fixture := runtimeVDSOTestImage(t)
	fixture.removeTag(elf.DT_GNU_HASH)
	binary.LittleEndian.PutUint32(fixture.data[0x1200+24:], fixture.names["unsafe\x1b[31m\n"])
	metadata, err := readRuntimeVDSO(fixture.view, fixture.module)
	if err != nil || metadata.Symbols[1].Name != "unsafe\x1b[31m\n" {
		t.Fatalf("metadata=%+v error=%v", metadata, err)
	}
	metadata.Symbols[1].Value = 0x4000
	_, err = runtimeVDSOSymbol(metadata, "vdso", metadata.Symbols[1])
	if !errors.Is(err, target.ErrUnavailable) || strings.ContainsAny(err.Error(), "\x1b\n") || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("unsafe error %q", err)
	}
}

func TestRuntimeVDSOLiveSelfMatchesDeclaredDynamicSymbols(t *testing.T) {
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		t.Fatal(err)
	}
	auxiliary, err := runtimeAuxiliary(auxv)
	if err != nil || auxiliary[33] == 0 {
		t.Fatalf("auxiliary=%v error=%v", auxiliary, err)
	}
	mapData, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := parseProcMaps(mapData)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	memory, err := newRuntimeELFMemory(context.Background(), mappings, func(address target.Address, data []byte) (int, error) {
		if uint64(address) > math.MaxInt64 {
			return 0, target.ErrOverflow
		}
		return source.ReadAt(data, int64(address))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(memory.close)
	anchor := target.Address(auxiliary[33])
	module, err := runtimeELFZeroOrigin(memory, anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	module.AuxiliaryTag, module.AuxiliaryAddress = 33, anchor
	metadata, err := readRuntimeVDSO(&runtimeELFView{Memory: memory, Modules: []*runtimeELFModule{module}}, module)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.SymbolsComplete || len(metadata.Symbols) < 2 || metadata.RelocationsDeclared || len(metadata.PointerRelocations) != 0 {
		t.Fatalf("metadata=%+v", metadata)
	}
	var image []byte
	for _, mapping := range mappings {
		if mapping.Start <= anchor && mapping.End > anchor {
			image, err = memory.bytes(anchor, uint64(mapping.End-anchor))
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	oracle, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	want, err := oracle.DynamicSymbols()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(metadata.Symbols[1:], want) {
		t.Fatalf("runtime symbols=%+v\nsection-declared symbols=%+v", metadata.Symbols[1:], want)
	}
	for _, symbol := range metadata.Symbols[1:] {
		if symbol.Section != elf.SHN_UNDEF && slices.Contains([]elf.SymType{elf.STT_FUNC, elf.STT_OBJECT, elf.STT_NOTYPE}, elf.ST_TYPE(symbol.Info)) {
			resolved, err := runtimeVDSOSymbol(metadata, "vdso", symbol)
			if err != nil || !resolved.AddressKnown {
				t.Fatalf("symbol=%+v resolved=%+v error=%v", symbol, resolved, err)
			}
		}
	}
	t.Logf("AT_SYSINFO_EHDR=%#x symbols=%d count-proof=%s versions=%d no dynamic relocations; independent section-table oracle equal", anchor, len(metadata.Symbols), metadata.SymbolCountSource, len(metadata.VersionDefinitions))
}
