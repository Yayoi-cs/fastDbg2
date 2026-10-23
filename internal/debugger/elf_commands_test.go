package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fastdbg2/target"
)

func elfCommandTestELF(t *testing.T, symbols []elf.Symbol, relocations []elf.Rela64, dynamic []elf.Dyn64) (*elf.File, []byte) {
	t.Helper()
	type section struct {
		name   string
		header elf.Section64
		data   []byte
	}
	stringData := []byte{0}
	var symbolData bytes.Buffer
	imageTestWrite(t, &symbolData, elf.Sym64{})
	for _, symbol := range symbols {
		name := len(stringData)
		stringData = append(stringData, symbol.Name...)
		stringData = append(stringData, 0)
		imageTestWrite(t, &symbolData, elf.Sym64{Name: uint32(name), Info: symbol.Info, Other: symbol.Other, Shndx: uint16(symbol.Section), Value: symbol.Value, Size: symbol.Size})
	}
	var relocationData, dynamicData bytes.Buffer
	for _, relocation := range relocations {
		imageTestWrite(t, &relocationData, relocation)
	}
	for _, entry := range dynamic {
		imageTestWrite(t, &dynamicData, entry)
	}
	sections := []section{
		{},
		{".data", elf.Section64{Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Addr: 0x400800, Addralign: 8}, make([]byte, 512)},
		{".dynstr", elf.Section64{Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_ALLOC), Addralign: 1}, stringData},
		{".dynsym", elf.Section64{Type: uint32(elf.SHT_DYNSYM), Flags: uint64(elf.SHF_ALLOC), Link: 2, Info: 1, Entsize: 24, Addralign: 8}, symbolData.Bytes()},
		{".rela.plt", elf.Section64{Type: uint32(elf.SHT_RELA), Flags: uint64(elf.SHF_ALLOC), Link: 3, Info: 1, Entsize: 24, Addralign: 8}, relocationData.Bytes()},
		{".dynamic", elf.Section64{Type: uint32(elf.SHT_DYNAMIC), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Link: 2, Entsize: 16, Addralign: 8}, dynamicData.Bytes()},
	}
	names := []byte{0}
	for index := 1; index < len(sections); index++ {
		sections[index].header.Name = uint32(len(names))
		names = append(names, sections[index].name...)
		names = append(names, 0)
	}
	shstrIndex := len(sections)
	shstrName := len(names)
	names = append(names, ".shstrtab\x00"...)
	sections = append(sections, section{".shstrtab", elf.Section64{Name: uint32(shstrName), Type: uint32(elf.SHT_STRTAB), Addralign: 1}, names})
	var data bytes.Buffer
	data.Write(make([]byte, 0x800))
	for index := 1; index < len(sections); index++ {
		for data.Len()%8 != 0 {
			data.WriteByte(0)
		}
		sections[index].header.Off = uint64(data.Len())
		sections[index].header.Size = uint64(len(sections[index].data))
		data.Write(sections[index].data)
	}
	for data.Len()%8 != 0 {
		data.WriteByte(0)
	}
	shoff := data.Len()
	for _, section := range sections {
		imageTestWrite(t, &data, section.header)
	}
	programs := []elf.Prog64{
		{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W), Vaddr: 0x400000, Filesz: uint64(data.Len()), Memsz: uint64(data.Len()) + 0x1000, Align: 0x1000},
		{Type: uint32(elf.PT_GNU_STACK), Flags: uint32(elf.PF_R | elf.PF_W), Align: 16},
	}
	if dynamic != nil {
		programs = append(programs, elf.Prog64{Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R | elf.PF_W), Off: sections[5].header.Off, Vaddr: 0x400000 + sections[5].header.Off, Filesz: uint64(dynamicData.Len()), Memsz: uint64(dynamicData.Len()), Align: 8})
	}
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Entry: 0x400800, Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: uint16(len(programs)), Shoff: uint64(shoff), Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: uint16(shstrIndex)}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	var headers bytes.Buffer
	imageTestWrite(t, &headers, header)
	for _, program := range programs {
		imageTestWrite(t, &headers, program)
	}
	copy(data.Bytes(), headers.Bytes())
	file, err := elf.NewFile(bytes.NewReader(data.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return file, data.Bytes()
}

func TestELFSecurityFactsAreEvidenceNotProtectionGuesses(t *testing.T) {
	file, _ := elfCommandTestELF(t, []elf.Symbol{
		{Name: "__stack_chk_fail", Section: elf.SHN_UNDEF},
		{Name: "__memcpy_chk", Section: elf.SHN_UNDEF},
		{Name: "not_fortified", Section: 1},
	}, nil, []elf.Dyn64{{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_PIE | elf.DF_1_NOW)}, {Tag: 0}})
	file.Type = elf.ET_DYN
	file.Progs = append(file.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_GNU_RELRO}})
	facts, err := inspectELFSecurity(file)
	if err != nil || !facts.pieFlag || !facts.bindNow || !facts.relro || !facts.stackKnown || facts.stackExec || facts.static || !facts.symbols {
		t.Fatalf("facts=%+v error=%v", facts, err)
	}
	var output bytes.Buffer
	controller := &Controller{out: &output}
	if err := controller.printELFSecurity("file\n\x1b[31m", facts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"declared (DF_1_PIE)", "full declarations", "Stack-check symbols: [\"__stack_chk_fail\"]", "Fortify-name symbols (__*_chk): [\"__memcpy_chk\"]", "does not establish instrumentation", "file\\n\\x1b[31m"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %q", want, output.String())
		}
	}
	if strings.ContainsRune(output.String(), '\x1b') || strings.Contains(output.String(), "Canary   : Enabled") {
		t.Fatal(output.String())
	}
}

func TestELFSecurityETDYNWithoutPIEFlagAndMissingMetadata(t *testing.T) {
	file, _ := elfCommandTestELF(t, nil, nil, nil)
	file.Type, file.Progs, file.Sections = elf.ET_DYN, file.Progs[:1], nil
	facts, err := inspectELFSecurity(file)
	if err != nil || facts.pieFlag || facts.stackKnown || facts.symbols {
		t.Fatalf("facts=%+v error=%v", facts, err)
	}
	var output bytes.Buffer
	if err := (&Controller{out: &output}).printELFSecurity("x", facts); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ET_DYN alone does not establish PIE", "unknown (no PT_GNU_STACK)", "unknown (no symbol tables)"} {
		if !strings.Contains(output.String(), want) {
			t.Fatal(output.String())
		}
	}
}

func TestELFSecurityBindNowDeclarationForms(t *testing.T) {
	for _, entry := range []elf.Dyn64{
		{Tag: int64(elf.DT_BIND_NOW)},
		{Tag: int64(elf.DT_FLAGS), Val: uint64(elf.DF_BIND_NOW)},
		{Tag: int64(elf.DT_FLAGS_1), Val: uint64(elf.DF_1_NOW)},
	} {
		file, _ := elfCommandTestELF(t, nil, nil, []elf.Dyn64{entry, {Tag: 0}})
		facts, err := inspectELFSecurity(file)
		if err != nil || !facts.bindNow || facts.relro {
			t.Fatalf("entry=%+v facts=%+v error=%v", entry, facts, err)
		}
	}
}

func TestELFSecurityRejectsAmbiguousOrMalformedMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*elf.File)
		err  error
	}{
		{"stack duplicate", func(f *elf.File) { f.Progs = append(f.Progs, f.Progs[1]) }, target.ErrAmbiguous},
		{"dynamic duplicate", func(f *elf.File) { f.Progs = append(f.Progs, f.Progs[2]) }, target.ErrAmbiguous},
		{"dynamic size", func(f *elf.File) { f.Progs[2].Filesz = 17 }, target.ErrInvalidArgument},
		{"load overflow", func(f *elf.File) { f.Progs[0].Vaddr = math.MaxUint64 }, target.ErrOverflow},
		{"symbol entry size", func(f *elf.File) { f.Sections[3].Entsize = 1 }, target.ErrInvalidArgument},
		{"symbol link", func(f *elf.File) { f.Sections[3].Link = 999 }, target.ErrInvalidArgument},
		{"symbol string kind", func(f *elf.File) { f.Sections[2].Type = elf.SHT_PROGBITS }, target.ErrInvalidArgument},
		{"compressed symbol", func(f *elf.File) { f.Sections[3].Flags |= elf.SHF_COMPRESSED }, target.ErrUnsupported},
		{"large symbol", func(f *elf.File) { f.Sections[3].Size = (maxELFCommandMetadata/24 + 1) * 24 }, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, _ := elfCommandTestELF(t, nil, nil, []elf.Dyn64{{Tag: 0}})
			test.edit(file)
			if _, err := inspectELFSecurity(file); !errors.Is(err, test.err) {
				t.Fatal(err)
			}
		})
	}
	for _, dynamic := range [][]elf.Dyn64{
		{{Tag: int64(elf.DT_FLAGS_1)}, {Tag: int64(elf.DT_FLAGS_1)}, {Tag: 0}},
		{{Tag: int64(elf.DT_FLAGS_1)}},
	} {
		file, _ := elfCommandTestELF(t, nil, nil, dynamic)
		if _, err := inspectELFSecurity(file); err == nil {
			t.Fatal("invalid dynamic metadata accepted")
		}
	}
}

func TestELFPointerRelocationExactIndexAndOffset(t *testing.T) {
	file, _ := elfCommandTestELF(t, []elf.Symbol{{Name: "puts"}}, []elf.Rela64{
		{Off: 0x400810, Info: 1<<32 | uint64(elf.R_X86_64_JMP_SLOT)},
		{Off: 0x400818, Info: uint64(elf.R_X86_64_IRELATIVE)},
		{Off: 0x400820, Info: uint64(elf.R_X86_64_RELATIVE)},
	}, nil)
	relocations, err := elfPointerRelocations(file, 0x70000000)
	if err != nil || len(relocations) != 2 || relocations[0].symbol != "puts" || relocations[0].address != 0x70400810 || relocations[1].kind != elf.R_X86_64_IRELATIVE || relocations[1].symbol != "" {
		t.Fatalf("relocations=%+v error=%v", relocations, err)
	}
}

func TestELFPointerRelocationRejectsFalseSlotsAndIndices(t *testing.T) {
	for _, test := range []struct {
		name string
		rela []elf.Rela64
		bias uint64
		err  error
	}{
		{"symbol out of bounds", []elf.Rela64{{Off: 0x400810, Info: 99<<32 | uint64(elf.R_X86_64_JMP_SLOT)}}, 0, target.ErrInvalidArgument},
		{"slot outside load", []elf.Rela64{{Off: 0x1234, Info: uint64(elf.R_X86_64_IRELATIVE)}}, 0, target.ErrInvalidArgument},
		{"slot overflow", []elf.Rela64{{Off: math.MaxUint64 - 1, Info: uint64(elf.R_X86_64_IRELATIVE)}}, 0, target.ErrInvalidArgument},
		{"bias overflow", []elf.Rela64{{Off: 0x400810, Info: uint64(elf.R_X86_64_IRELATIVE)}}, math.MaxUint64, target.ErrOverflow},
		{"duplicate slots", []elf.Rela64{{Off: 0x400810, Info: uint64(elf.R_X86_64_IRELATIVE)}, {Off: 0x400810, Info: uint64(elf.R_X86_64_IRELATIVE)}}, 0, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, _ := elfCommandTestELF(t, []elf.Symbol{{Name: "puts"}}, test.rela, nil)
			if _, err := elfPointerRelocations(file, test.bias); !errors.Is(err, test.err) {
				t.Fatal(err)
			}
		})
	}
}

func TestELFPointerRelocationSectionlessIsUnavailable(t *testing.T) {
	file, _ := elfCommandTestELF(t, nil, nil, []elf.Dyn64{{Tag: int64(elf.DT_JMPREL), Val: 0x400900}, {Tag: 0}})
	file.Sections = nil
	if _, err := elfPointerRelocations(file, 0); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestELFPointerRelocationRequiresEveryDynamicTable(t *testing.T) {
	file, _ := elfCommandTestELF(t, []elf.Symbol{{Name: "puts"}}, []elf.Rela64{{Off: 0x400810, Info: 1<<32 | uint64(elf.R_X86_64_JMP_SLOT)}}, nil)
	file.Sections[4].Addr = 0x400000 + file.Sections[4].Offset
	first := file.Sections[4].Addr
	dynamic := elfDynamicFacts{present: true, values: map[elf.DynTag][]uint64{
		elf.DT_RELA: {first}, elf.DT_RELASZ: {24}, elf.DT_RELAENT: {24},
		elf.DT_JMPREL: {first + 0x40}, elf.DT_PLTRELSZ: {24}, elf.DT_PLTREL: {uint64(elf.DT_RELA)},
	}}
	if err := validateELFDynamicRelocations(file, dynamic); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("missing second table accepted: %v", err)
	}
	other := *file.Sections[4]
	other.Addr, other.Offset = first+0x40, other.Offset+0x40
	file.Sections = append(file.Sections, &other)
	if err := validateELFDynamicRelocations(file, dynamic); err != nil {
		t.Fatal(err)
	}
	other.Type = elf.SHT_PROGBITS
	if err := validateELFDynamicRelocations(file, dynamic); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("wrong type accepted: %v", err)
	}
}

func TestELFDynamicRelocationsRequireMatchingFileOffsets(t *testing.T) {
	file, _ := elfCommandTestELF(t, nil, []elf.Rela64{{Off: 0x400810, Info: uint64(elf.R_X86_64_IRELATIVE)}}, nil)
	section := file.Sections[4]
	section.Addr = 0x400000 + section.Offset
	dynamic := elfDynamicFacts{present: true, values: map[elf.DynTag][]uint64{
		elf.DT_JMPREL: {section.Addr}, elf.DT_PLTRELSZ: {24}, elf.DT_PLTREL: {uint64(elf.DT_RELA)},
	}}
	if err := validateELFDynamicRelocations(file, dynamic); err != nil {
		t.Fatal(err)
	}
	section.Offset++
	if err := validateELFDynamicRelocations(file, dynamic); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("section offset mismatch accepted: %v", err)
	}
	section.Offset--
	file.Progs = append(file.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: section.Offset + 1, Vaddr: section.Addr, Filesz: 24, Memsz: 24}})
	if err := validateELFDynamicRelocations(file, dynamic); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("overlapping inconsistent program offsets accepted: %v", err)
	}
}

func TestELFPointerRelocationDynamicTableMetadataIsExact(t *testing.T) {
	for _, test := range []struct {
		values map[elf.DynTag][]uint64
		err    error
	}{
		{map[elf.DynTag][]uint64{elf.DT_RELA: {0x400b00}, elf.DT_RELASZ: {24}}, target.ErrUnavailable},
		{map[elf.DynTag][]uint64{elf.DT_RELA: {0x400b00}, elf.DT_RELASZ: {24}, elf.DT_RELAENT: {16}}, target.ErrInvalidArgument},
		{map[elf.DynTag][]uint64{elf.DT_RELA: {0x400b00, 0x400b00}, elf.DT_RELASZ: {24}, elf.DT_RELAENT: {24}}, target.ErrAmbiguous},
		{map[elf.DynTag][]uint64{elf.DT_RELA: {0x400b00}, elf.DT_RELASZ: {48}, elf.DT_RELAENT: {24}}, target.ErrUnavailable},
		{map[elf.DynTag][]uint64{elf.DT_RELA: {0x400b01}, elf.DT_RELASZ: {24}, elf.DT_RELAENT: {24}}, target.ErrUnavailable},
		{map[elf.DynTag][]uint64{elf.DT_RELA: {math.MaxUint64 - 1}, elf.DT_RELASZ: {24}, elf.DT_RELAENT: {24}}, target.ErrOverflow},
		{map[elf.DynTag][]uint64{elf.DT_JMPREL: {0x400b00}, elf.DT_PLTRELSZ: {24}, elf.DT_PLTREL: {999}}, target.ErrUnsupported},
	} {
		file, _ := elfCommandTestELF(t, nil, []elf.Rela64{{Off: 0x400810, Info: uint64(elf.R_X86_64_IRELATIVE)}}, nil)
		file.Sections[4].Addr = 0x400b00
		if err := validateELFDynamicRelocations(file, elfDynamicFacts{present: true, values: test.values}); !errors.Is(err, test.err) {
			t.Fatalf("%+v: %v", test.values, err)
		}
	}
}

func TestELFStdioObjectUsesOnlySymbolDeclaredSize(t *testing.T) {
	name := "_IO_2_1_stdout_"
	file, _ := elfCommandTestELF(t, []elf.Symbol{{Name: name, Info: byte(elf.STT_OBJECT), Section: 1, Value: 0x400820, Size: 23}}, nil, nil)
	module := &mappedELF{File: file, LoadBias: 0x70000000}
	address, size, err := elfStdioObject(module, name)
	if err != nil || address != 0x70400820 || size != 23 {
		t.Fatalf("address=%#x size=%d error=%v", address, size, err)
	}
	file.Sections = append(file.Sections, file.Sections[3])
	if _, _, err := elfStdioObject(module, name); err != nil {
		t.Fatalf("identical duplicate symbol rejected: %v", err)
	}
}

func TestELFStdioObjectRejectsUnsupportedOrAmbiguousSymbols(t *testing.T) {
	name := "_IO_2_1_stdout_"
	base := elf.Symbol{Name: name, Info: byte(elf.STT_OBJECT), Section: 1, Value: 0x400820, Size: 32}
	for _, test := range []struct {
		name string
		edit func(*elf.Symbol)
		err  error
	}{
		{"undefined", func(s *elf.Symbol) { s.Section = elf.SHN_UNDEF }, target.ErrNotFound},
		{"unknown size", func(s *elf.Symbol) { s.Size = 0 }, target.ErrUnsupported},
		{"large size", func(s *elf.Symbol) { s.Size = maxMemoryBytes + 1 }, target.ErrUnsupported},
		{"function", func(s *elf.Symbol) { s.Info = byte(elf.STT_FUNC) }, target.ErrUnsupported},
		{"absolute", func(s *elf.Symbol) { s.Section = elf.SHN_ABS }, target.ErrUnsupported},
		{"section index", func(s *elf.Symbol) { s.Section = 999 }, target.ErrUnsupported},
		{"not allocated", func(s *elf.Symbol) { s.Section = 6 }, target.ErrUnsupported},
		{"outside section", func(s *elf.Symbol) { s.Value = 0x400fff }, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			symbol := base
			test.edit(&symbol)
			file, _ := elfCommandTestELF(t, []elf.Symbol{symbol}, nil, nil)
			if _, _, err := elfStdioObject(&mappedELF{File: file}, name); !errors.Is(err, test.err) {
				t.Fatal(err)
			}
		})
	}
	other := base
	other.Value++
	file, _ := elfCommandTestELF(t, []elf.Symbol{base, other}, nil, nil)
	if _, _, err := elfStdioObject(&mappedELF{File: file}, name); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
}

func TestChecksecConfiguredAndExplicitFileWithoutTarget(t *testing.T) {
	_, data := elfCommandTestELF(t, nil, nil, nil)
	path := filepath.Join(t.TempDir(), "a b")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		var output bytes.Buffer
		controller := &Controller{out: &output, path: path}
		args := ""
		if explicit {
			args = "--file " + "\"" + path + "\""
			controller.path = ""
		}
		if err := controller.showChecksec(context.Background(), args); err != nil || !strings.Contains(output.String(), "[checksec]") {
			t.Fatalf("error=%v output=%q", err, output.String())
		}
	}
}

func TestELFCommandInvalidArgumentsHaveNoSideEffects(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	for _, command := range []func(context.Context, string) error{controller.showChecksec, controller.showGOT, controller.showStdio} {
		for _, arg := range []string{"unknown", "--module", "--module \"\"", "--module '\x00'", "all extra"} {
			if err := command(context.Background(), arg); err == nil {
				t.Fatalf("accepted %q", arg)
			}
		}
		if err := command(nil, ""); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := command(ctx, ""); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if fixture.snapshotReads != 0 || output.Len() != 0 {
		t.Fatalf("reads=%d output=%q", fixture.snapshotReads, output.String())
	}
}

func TestELFOutputOnlyPublishesProvenPartialResults(t *testing.T) {
	for _, test := range []struct {
		err     error
		publish bool
	}{
		{nil, true},
		{&mappedELFPartialError{Err: target.ErrUnavailable}, true},
		{&mappedELFPartialError{Err: target.ErrStale}, false},
		{&mappedELFPartialError{Err: context.Canceled}, false},
		{errors.Join(&mappedELFPartialError{Err: target.ErrUnavailable}, target.ErrStale), false},
		{errors.Join(&mappedELFPartialError{Err: target.ErrUnavailable}, errors.New("identity read failed")), false},
		{target.ErrUnavailable, false},
	} {
		var output bytes.Buffer
		controller := &Controller{out: &output}
		err := controller.publishELFResults(bytes.NewBufferString("confirmed result\n"), test.err, nil)
		if strings.Contains(output.String(), "confirmed result") != test.publish || !errors.Is(err, test.err) {
			t.Fatalf("input=%v returned=%v output=%q", test.err, err, output.String())
		}
	}
}

func TestELFSymbolTableBadNameAndExtendedIndices(t *testing.T) {
	file, data := elfCommandTestELF(t, []elf.Symbol{{Name: "x", Section: 1}}, nil, nil)
	offset := file.Sections[3].Offset + 24
	for _, test := range []struct {
		edit func([]byte)
		err  error
	}{
		{func(data []byte) { binary.LittleEndian.PutUint32(data[offset:offset+4], 9999) }, target.ErrInvalidArgument},
		{func(data []byte) { binary.LittleEndian.PutUint16(data[offset+6:offset+8], uint16(elf.SHN_XINDEX)) }, target.ErrUnsupported},
	} {
		copyData := bytes.Clone(data)
		test.edit(copyData)
		modified, err := elf.NewFile(bytes.NewReader(copyData))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := elfCommandSymbolTable(modified, 3); !errors.Is(err, test.err) {
			t.Fatal(err)
		}
	}
}
