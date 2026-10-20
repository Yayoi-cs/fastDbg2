package inspect_test

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
	"sync"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestSymbolsExplicitDefinitionAddresses(t *testing.T) {
	path := symbolTestELF(t, elf.ET_DYN, []elf.Symbol{
		symbolTestEntry("work", 0x1010, 16, elf.STT_FUNC, 1),
		symbolTestEntry("global", 0x1040, 8, elf.STT_OBJECT, 1),
	}, nil)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x700000}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := index.ResolveName("main", "work")
	if err != nil {
		t.Fatal(err)
	}
	if symbol.ModuleID != "main" || symbol.Value != 0x1010 || symbol.Address != 0x701010 || !symbol.AddressKnown || symbol.Size != 16 || symbol.Type != elf.STT_FUNC {
		t.Fatalf("unexpected symbol: %+v", symbol)
	}
	match, err := index.ResolveAddress("main", 0x70101f)
	if err != nil || match.Symbol != symbol || match.Offset != 15 {
		t.Fatalf("match=%+v err=%v", match, err)
	}
	for _, address := range []target.Address{0x70100f, 0x701020, 0x701030} {
		if _, err := index.ResolveAddress("main", address); !errors.Is(err, target.ErrNotFound) {
			t.Fatalf("address %#x: %v", address, err)
		}
	}
	for _, name := range []string{"wor", "WORK"} {
		if _, err := index.ResolveName("main", name); !errors.Is(err, target.ErrNotFound) {
			t.Fatalf("name %q: %v", name, err)
		}
	}
	index, err = inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "same-file", Path: path}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err = index.ResolveName("same-file", "work")
	if err != nil || symbol.Address != 0x1010 {
		t.Fatalf("zero explicit bias: %+v, %v", symbol, err)
	}
}

func TestSymbolsZeroSizeAndAbsolute(t *testing.T) {
	path := symbolTestELF(t, elf.ET_EXEC, []elf.Symbol{
		symbolTestEntry("marker", 0x1010, 0, elf.STT_NOTYPE, 1),
		symbolTestEntry("absolute", 0x42, 0, elf.STT_NOTYPE, elf.SHN_ABS),
	}, nil)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x2000}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := index.ResolveName("main", "marker")
	if err != nil || marker.Size != 0 || marker.Address != 0x3010 {
		t.Fatalf("marker=%+v err=%v", marker, err)
	}
	if _, err := index.ResolveAddress("main", 0x3010); err != nil {
		t.Fatal(err)
	}
	if _, err := index.ResolveAddress("main", 0x3011); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("size zero must not imply a range: %v", err)
	}
	absolute, err := index.ResolveName("main", "absolute")
	if err != nil || absolute.Address != 0x42 || absolute.Value != 0x42 {
		t.Fatalf("absolute=%+v err=%v", absolute, err)
	}
}

func TestSymbolsLastRepresentableAddress(t *testing.T) {
	for _, test := range []struct {
		value uint64
		size  uint64
	}{
		{math.MaxUint64, 0},
		{math.MaxUint64, 1},
		{math.MaxUint64 - 1, 2},
	} {
		path := symbolTestELF(t, elf.ET_EXEC, []elf.Symbol{symbolTestEntry("last", test.value, test.size, elf.STT_OBJECT, elf.SHN_ABS)}, nil)
		index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: math.MaxUint64}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		match, err := index.ResolveAddress("main", target.Address(math.MaxUint64))
		if err != nil || match.Symbol.Address != target.Address(test.value) || match.Offset != math.MaxUint64-test.value {
			t.Fatalf("case=%+v match=%+v err=%v", test, match, err)
		}
	}
}

func TestSymbolsAmbiguityAndImmutableCandidates(t *testing.T) {
	path := symbolTestELF(t, elf.ET_DYN, []elf.Symbol{symbolTestEntry("work", 0x1000, 16, elf.STT_FUNC, 1)}, nil)
	modules := []inspect.Module{{ID: "z", Path: path}, {ID: "a", Path: path}}
	index, err := inspect.LoadSymbols(context.Background(), modules, 8)
	if err != nil {
		t.Fatal(err)
	}
	modules[1].ID = "changed"
	_, err = index.ResolveName("", "work")
	var ambiguous *inspect.AmbiguousSymbolError
	if !errors.Is(err, target.ErrAmbiguous) || !errors.As(err, &ambiguous) {
		t.Fatalf("expected ambiguity: %v", err)
	}
	if len(ambiguous.Candidates) != 2 || ambiguous.Candidates[0].ModuleID != "a" || ambiguous.Candidates[1].ModuleID != "z" {
		t.Fatalf("nondeterministic candidates: %+v", ambiguous.Candidates)
	}
	ambiguous.Candidates[0].Address = 0
	symbol, err := index.ResolveName("a", "work")
	if err != nil || symbol.Address != 0x1000 {
		t.Fatalf("mutated index: %+v, %v", symbol, err)
	}
	symbol.Address = 0
	if _, err := index.ResolveAddress("", 0x1000); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("expected address ambiguity: %v", err)
	}
	if _, err := index.ResolveAddress("a", 0x1000); err != nil {
		t.Fatal(err)
	}
	if _, err := index.ResolveName("changed", "work"); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("unknown module: %v", err)
	}
}

func TestSymbolsOverlapsDoNotPreferClosestOrExact(t *testing.T) {
	path := symbolTestELF(t, elf.ET_EXEC, []elf.Symbol{
		symbolTestEntry("outer", 0x1000, 0x30, elf.STT_FUNC, 1),
		symbolTestEntry("inner", 0x1010, 0x10, elf.STT_FUNC, 1),
		symbolTestEntry("alias", 0x1000, 0x30, elf.STT_FUNC, 1),
	}, nil)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []target.Address{0x1000, 0x1010, 0x1015} {
		if _, err := index.ResolveAddress("main", address); !errors.Is(err, target.ErrAmbiguous) {
			t.Fatalf("address %#x must remain ambiguous: %v", address, err)
		}
	}
}

func TestSymbolsTablesDeduplicateOnlyIdenticalEntries(t *testing.T) {
	symbol := symbolTestEntry("work", 0x1000, 16, elf.STT_FUNC, 1)
	path := symbolTestELF(t, elf.ET_DYN, []elf.Symbol{symbol}, []elf.Symbol{symbol})
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.ResolveName("main", "work"); err != nil {
		t.Fatalf("same definition in two tables: %v", err)
	}
	path = symbolTestELF(t, elf.ET_DYN, nil, []elf.Symbol{symbol})
	index, err = inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "dyn", Path: path}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.ResolveName("dyn", "work"); err != nil {
		t.Fatal(err)
	}
}

func TestSymbolsVersionsRemainAmbiguous(t *testing.T) {
	first := symbolTestEntry("work", 0x1000, 8, elf.STT_FUNC, 1)
	first.Version = "VERSION_1"
	second := symbolTestEntry("work", 0x1020, 8, elf.STT_FUNC, 1)
	second.Version = "VERSION_2"
	path := symbolTestELF(t, elf.ET_DYN, nil, []elf.Symbol{second, first})
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "lib", Path: path}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = index.ResolveName("lib", "work")
	var ambiguous *inspect.AmbiguousSymbolError
	if !errors.As(err, &ambiguous) || len(ambiguous.Candidates) != 2 {
		t.Fatalf("version ambiguity: %v", err)
	}
	if ambiguous.Candidates[0].Version != "VERSION_1" || ambiguous.Candidates[1].Version != "VERSION_2" {
		t.Fatalf("lost versions: %+v", ambiguous.Candidates)
	}
}

func TestSymbolsUndefinedDoesNotGuessRuntimeBinding(t *testing.T) {
	reference := symbolTestEntry("imported", 0, 0, elf.STT_FUNC, elf.SHN_UNDEF)
	exe := symbolTestELF(t, elf.ET_EXEC, nil, []elf.Symbol{reference})
	lib := symbolTestELF(t, elf.ET_DYN, nil, []elf.Symbol{symbolTestEntry("imported", 0x1010, 8, elf.STT_FUNC, 1)})
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{
		{ID: "exe", Path: exe}, {ID: "lib", Path: lib, LoadBias: 0x500000},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.ResolveName("exe", "imported"); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("unbound reference: %v", err)
	}
	symbol, err := index.ResolveName("", "imported")
	if err != nil || symbol.ModuleID != "lib" || symbol.Address != 0x501010 {
		t.Fatalf("explicit definition: %+v, %v", symbol, err)
	}
	if _, err := index.ResolveAddress("exe", 0); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("undefined symbol must not have address zero: %v", err)
	}
}

func TestSymbolsUnsupportedMetadataDoesNotBecomeAnAddress(t *testing.T) {
	cases := []struct {
		name    string
		kind    elf.SymType
		section elf.SectionIndex
	}{
		{"tls", elf.STT_TLS, 1},
		{"ifunc", elf.STT_GNU_IFUNC, 1},
		{"common-kind", elf.STT_COMMON, 1},
		{"common-section", elf.STT_OBJECT, elf.SHN_COMMON},
		{"file", elf.STT_FILE, elf.SHN_ABS},
		{"not-allocated", elf.STT_OBJECT, 2},
		{"extended-section", elf.STT_FUNC, elf.SHN_XINDEX},
	}
	var symbols []elf.Symbol
	for _, test := range cases {
		symbols = append(symbols, symbolTestEntry(test.name, 0x20, 4, test.kind, test.section))
	}
	path := symbolTestELF(t, elf.ET_DYN, symbols, nil)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x10000}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			symbol, err := index.ResolveName("main", test.name)
			if !errors.Is(err, target.ErrUnsupported) || symbol.AddressKnown || symbol.Value != 0x20 {
				t.Fatalf("symbol=%+v err=%v", symbol, err)
			}
		})
	}
	if _, err := index.ResolveAddress("main", 0x10020); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("unsupported symbols must not acquire an address: %v", err)
	}
}

func TestLoadSymbolsErrors(t *testing.T) {
	valid := symbolTestELF(t, elf.ET_EXEC, []elf.Symbol{symbolTestEntry("work", 0x1000, 8, elf.STT_FUNC, 1)}, nil)
	validModule := inspect.Module{ID: "main", Path: valid}
	cases := []struct {
		name    string
		modules []inspect.Module
		workers int
		want    error
	}{
		{"negative-workers", []inspect.Module{validModule}, -1, target.ErrInvalidArgument},
		{"empty-ID", []inspect.Module{{Path: valid}}, 1, target.ErrInvalidArgument},
		{"empty-path", []inspect.Module{{ID: "main"}}, 1, target.ErrInvalidArgument},
		{"duplicate-ID", []inspect.Module{validModule, validModule}, 2, target.ErrInvalidArgument},
		{"relocatable", []inspect.Module{{ID: "rel", Path: symbolTestELF(t, elf.ET_REL, nil, nil)}}, 1, target.ErrUnsupported},
		{"no-tables", []inspect.Module{{ID: "none", Path: symbolTestELF(t, elf.ET_EXEC, nil, nil)}}, 1, target.ErrUnavailable},
		{"bias-overflow", []inspect.Module{{ID: "overflow", Path: valid, LoadBias: math.MaxUint64}}, 1, target.ErrOverflow},
		{"range-overflow", []inspect.Module{{ID: "range", Path: symbolTestELF(t, elf.ET_EXEC, []elf.Symbol{symbolTestEntry("bad", math.MaxUint64-1, 3, elf.STT_FUNC, elf.SHN_ABS)}, nil)}}, 1, target.ErrOverflow},
		{"invalid-section", []inspect.Module{{ID: "section", Path: symbolTestELF(t, elf.ET_EXEC, []elf.Symbol{symbolTestEntry("bad", 0x1000, 4, elf.STT_FUNC, 100)}, nil)}}, 1, target.ErrInvalidArgument},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			index, err := inspect.LoadSymbols(context.Background(), test.modules, test.workers)
			if !errors.Is(err, test.want) || index != nil {
				t.Fatalf("index=%v err=%v want=%v", index, err, test.want)
			}
		})
	}
	if _, err := inspect.LoadSymbols(nil, nil, 1); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspect.LoadSymbols(ctx, []inspect.Module{validModule}, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	index, err := inspect.LoadSymbols(context.Background(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.ResolveName("", "missing"); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("empty index: %v", err)
	}
	if _, err := index.ResolveName("", ""); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("empty name: %v", err)
	}
	var nilIndex *inspect.SymbolIndex
	if _, err := nilIndex.ResolveAddress("", 0); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("nil index: %v", err)
	}
}

func TestLoadSymbolsErrorsHaveDeterministicModuleOrder(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.elf")
	for range 8 {
		_, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "z", Path: missing}, {ID: "a", Path: missing}}, 2)
		if err == nil || !strings.HasPrefix(err.Error(), "module \"a\":") {
			t.Fatalf("unexpected first error: %v", err)
		}
	}
}

func TestSymbolsConcurrentReadOnlyLookups(t *testing.T) {
	path := symbolTestELF(t, elf.ET_DYN, []elf.Symbol{symbolTestEntry("work", 0x1000, 16, elf.STT_FUNC, 1)}, nil)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x700000}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				symbol, err := index.ResolveName("main", "work")
				if err != nil || symbol.Address != 0x701000 {
					t.Errorf("symbol=%+v err=%v", symbol, err)
					return
				}
				match, err := index.ResolveAddress("main", 0x701008)
				if err != nil || match.Offset != 8 {
					t.Errorf("match=%+v err=%v", match, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

type symbolTestSection struct {
	name   string
	header elf.Section64
	data   []byte
}

func symbolTestEntry(name string, value, size uint64, kind elf.SymType, section elf.SectionIndex) elf.Symbol {
	return elf.Symbol{Name: name, Info: byte(elf.STB_GLOBAL)<<4 | byte(kind), Section: section, Value: value, Size: size}
}

func symbolTestELF(t *testing.T, kind elf.Type, static, dynamic []elf.Symbol) string {
	t.Helper()
	sections := []symbolTestSection{
		{},
		{name: ".text", header: elf.Section64{Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x1000, Addralign: 16}, data: bytes.Repeat([]byte{0x90}, 256)},
	}
	for i, symbols := range [][]elf.Symbol{static, dynamic} {
		if symbols == nil {
			continue
		}
		stringName, symbolName, symbolType := ".strtab", ".symtab", elf.SHT_SYMTAB
		if i == 1 {
			stringName, symbolName, symbolType = ".dynstr", ".dynsym", elf.SHT_DYNSYM
		}
		stringsData := []byte{0}
		var symbolsData bytes.Buffer
		symbolTestWrite(t, &symbolsData, elf.Sym64{})
		for _, symbol := range symbols {
			nameOffset := len(stringsData)
			stringsData = append(stringsData, symbol.Name...)
			stringsData = append(stringsData, 0)
			symbolTestWrite(t, &symbolsData, elf.Sym64{Name: uint32(nameOffset), Info: symbol.Info, Other: symbol.Other, Shndx: uint16(symbol.Section), Value: symbol.Value, Size: symbol.Size})
		}
		stringIndex := len(sections)
		symbolIndex := stringIndex + 1
		sections = append(sections,
			symbolTestSection{name: stringName, header: elf.Section64{Type: uint32(elf.SHT_STRTAB), Addralign: 1}},
			symbolTestSection{name: symbolName, header: elf.Section64{Type: uint32(symbolType), Link: uint32(stringIndex), Info: 1, Addralign: 8, Entsize: 24}, data: symbolsData.Bytes()},
		)
		if i == 1 {
			versions := make(map[string]uint16)
			var versionNames []string
			var versionSymbols bytes.Buffer
			symbolTestWrite(t, &versionSymbols, uint16(0))
			for _, symbol := range symbols {
				version := uint16(1)
				if symbol.Version != "" {
					var found bool
					version, found = versions[symbol.Version]
					if !found {
						version = uint16(len(versions) + 2)
						versions[symbol.Version] = version
						versionNames = append(versionNames, symbol.Version)
					}
				}
				symbolTestWrite(t, &versionSymbols, version)
			}
			if len(versionNames) > 0 {
				var definitions bytes.Buffer
				for j, name := range versionNames {
					next := uint32(28)
					if j == len(versionNames)-1 {
						next = 0
					}
					nameOffset := len(stringsData)
					stringsData = append(stringsData, name...)
					stringsData = append(stringsData, 0)
					symbolTestWrite(t, &definitions, []uint16{1, 0, versions[name], 1})
					symbolTestWrite(t, &definitions, []uint32{0, 20, next, uint32(nameOffset), 0})
				}
				sections = append(sections,
					symbolTestSection{name: ".gnu.version", header: elf.Section64{Type: uint32(elf.SHT_GNU_VERSYM), Link: uint32(symbolIndex), Addralign: 2, Entsize: 2}, data: versionSymbols.Bytes()},
					symbolTestSection{name: ".gnu.version_d", header: elf.Section64{Type: uint32(elf.SHT_GNU_VERDEF), Link: uint32(stringIndex), Info: uint32(len(versionNames)), Addralign: 4}, data: definitions.Bytes()},
				)
			}
		}
		sections[stringIndex].data = stringsData
	}
	sectionNamesIndex := len(sections)
	sections = append(sections, symbolTestSection{name: ".shstrtab", header: elf.Section64{Type: uint32(elf.SHT_STRTAB), Addralign: 1}})
	sectionNames := []byte{0}
	for i := 1; i < len(sections); i++ {
		sections[i].header.Name = uint32(len(sectionNames))
		sectionNames = append(sectionNames, sections[i].name...)
		sectionNames = append(sectionNames, 0)
	}
	sections[sectionNamesIndex].data = sectionNames
	var output bytes.Buffer
	output.Write(make([]byte, 64))
	for i := 1; i < len(sections); i++ {
		for output.Len()%8 != 0 {
			output.WriteByte(0)
		}
		sections[i].header.Off = uint64(output.Len())
		sections[i].header.Size = uint64(len(sections[i].data))
		output.Write(sections[i].data)
	}
	for output.Len()%8 != 0 {
		output.WriteByte(0)
	}
	sectionOffset := uint64(output.Len())
	for _, section := range sections {
		symbolTestWrite(t, &output, section.header)
	}
	header := elf.Header64{Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: 1, Shoff: sectionOffset, Ehsize: 64, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: uint16(sectionNamesIndex)}
	copy(header.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	var headerData bytes.Buffer
	symbolTestWrite(t, &headerData, header)
	copy(output.Bytes(), headerData.Bytes())
	path := filepath.Join(t.TempDir(), "module.elf")
	if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func symbolTestWrite(t *testing.T, buffer *bytes.Buffer, value any) {
	t.Helper()
	if err := binary.Write(buffer, binary.LittleEndian, value); err != nil {
		t.Fatal(err)
	}
}
