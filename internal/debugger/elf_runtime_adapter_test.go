package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"strings"
	"testing"

	"fastdbg2/target"
)

func elfRuntimeAdapterFixture() *mappedELF {
	return &mappedELF{
		ID: "vdso", Path: "runtime image", LoadBias: 0x700000, Proof: "auxv-vdso+runtime-dynamic-metadata", Scope: "loader/runtime-dynamic",
		Runtime: &runtimeVDSOMetadata{
			Header:   elf.FileHeader{Type: elf.ET_DYN, Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Data: elf.ELFDATA2LSB},
			Programs: []elf.ProgHeader{{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Filesz: 0x1000, Memsz: 0x1000}},
			Dynamic:  elfDynamicFacts{present: true, values: map[elf.DynTag][]uint64{}}, SymbolsComplete: true,
			LoadBias: 0x700000, Loads: []runtimeELFSpan{{Address: 0x700000, Size: 0x1000}},
			Symbols: []elf.Symbol{{}, {Name: "clock", Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Section: 1, Value: 0x100, Size: 16, Version: "LINUX_TEST"}},
		},
	}
}

func TestELFRuntimeAdapterDoesNotInventFileOrStaticMetadata(t *testing.T) {
	module := elfRuntimeAdapterFixture()
	facts, err := inspectMappedELFSecurity(module)
	if err != nil || facts.staticKnown || !facts.runtimeOnly || facts.static || !facts.symbols || !facts.dynamic {
		t.Fatalf("facts=%+v error=%v", facts, err)
	}
	var output bytes.Buffer
	controller := &Controller{out: &output}
	if err := controller.printELFSecurity(module.Path, facts); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Runtime", "SYMTAB     : unknown (runtime dynamic metadata only)", "no PT_GNU_STACK"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("missing %q: %q", text, output.String())
		}
	}
	if module.File != nil || module.Source != nil || strings.Contains(mappedELFSourceDescription(module), "metadata-file=") {
		t.Fatal("runtime image was represented as an associated file")
	}
	relocations, err := mappedELFPointerRelocations(module)
	if err != nil || len(relocations) != 0 {
		t.Fatalf("relocations=%v error=%v", relocations, err)
	}
}

func TestELFRuntimeAdapterPreservesExactDynamicSymbolFacts(t *testing.T) {
	module := elfRuntimeAdapterFixture()
	module.Runtime.Symbols = append(module.Runtime.Symbols,
		elf.Symbol{Name: "resolver", Info: byte(elf.STT_GNU_IFUNC), Section: 1, Value: 0x200, Size: 32},
		elf.Symbol{Name: "undefined", Section: elf.SHN_UNDEF},
	)
	facts := readMappedSymbolFacts(context.Background(), module)
	if facts.err != nil || len(facts.symbols) != 3 || facts.symbols[0].Address != 0x700100 || !facts.symbols[0].AddressKnown || facts.symbols[0].Version != "LINUX_TEST" || facts.symbols[1].AddressKnown || facts.symbols[2].AddressKnown || len(facts.executable) != 1 {
		t.Fatalf("facts=%+v", facts)
	}
	if !strings.Contains(facts.metadata, "static symbols and debug metadata unavailable") {
		t.Fatal(facts.metadata)
	}
	if _, _, err := elfStdioObject(module, "_IO_2_1_stdout_"); !errors.Is(err, target.ErrNotFound) {
		t.Fatal(err)
	}
	module.Runtime.SymbolsComplete = false
	if _, _, err := elfStdioObject(module, "_IO_2_1_stdout_"); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestELFRuntimeAdapterObjectExtentAndAmbiguity(t *testing.T) {
	module := elfRuntimeAdapterFixture()
	object := elf.Symbol{Name: "_IO_2_1_stdout_", Info: byte(elf.STT_OBJECT), Section: 1, Value: 0x300, Size: 29}
	module.Runtime.Symbols = append(module.Runtime.Symbols, object)
	address, size, err := elfStdioObject(module, object.Name)
	if err != nil || address != 0x700300 || size != 29 {
		t.Fatalf("address=%#x size=%d error=%v", address, size, err)
	}
	object.Value++
	module.Runtime.Symbols = append(module.Runtime.Symbols, object)
	if _, _, err := elfStdioObject(module, object.Name); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
}

func TestELFLoaderMembershipUsesPublishedAddressesNotNames(t *testing.T) {
	file, _ := elfCommandTestELF(t, nil, nil, []elf.Dyn64{{Tag: 0}})
	main := &mappedELF{File: file, Main: true}
	mainDynamic, err := mappedELFDynamicAddress(main)
	if err != nil {
		t.Fatal(err)
	}
	maps := []procMap{
		{Start: 0x400000, End: 0x401000, Inode: 1},
		{Start: 0x700000, End: 0x701000, Inode: 2, Path: "/not-a-library-name"},
		{Start: 0x800000, End: 0x801000, Inode: 3, Path: "/libc.so.6"},
	}
	view := &runtimeELFView{LoaderComplete: true, Loader: []runtimeLinkMap{
		{dynamic: mainDynamic}, {bias: 0x700000, dynamic: 0x700100, name: "arbitrary loader label"},
	}}
	groups, err := loaderELFMembership(view, maps, main)
	if err != nil || len(groups) != 1 || len(groups[elfMapIdentity(maps[1])]) != 1 || len(groups[elfMapIdentity(maps[2])]) != 0 {
		t.Fatalf("groups=%v error=%v", groups, err)
	}
	view.Loader = append(view.Loader, runtimeLinkMap{namespace: 123, bias: 0x700000, dynamic: 0x700100, name: "same physical image"})
	groups, err = loaderELFMembership(view, maps, main)
	if err != nil || len(groups[elfMapIdentity(maps[1])]) != 1 {
		t.Fatalf("shared namespace image=%v error=%v", groups, err)
	}
	links := append(groups[elfMapIdentity(maps[1])], runtimeLinkMap{bias: 0x900000, dynamic: 0x900100})
	if err := validateELFLoaderMembership(main, links, view); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("distinct loader instances were collapsed: %v", err)
	}
}

func TestELFLoaderMembershipRuntimeAnchorCannotBeSpoofedByName(t *testing.T) {
	view := &runtimeELFView{Modules: []*runtimeELFModule{{Name: "linux-vdso.so.1", Header: 0x700000, LoadBias: 0x700000, Dynamic: runtimeELFSpan{Address: 0x700200, Size: 16}}}}
	link := runtimeLinkMap{bias: 0x700000, dynamic: 0x700200, name: "linux-vdso.so.1"}
	if runtimeVDSOLoaderAnchor(view, link) {
		t.Fatal("vDSO identity inferred from a name")
	}
	view.Modules[0].AuxiliaryTag, view.Modules[0].AuxiliaryAddress = 33, 0x700000
	if !runtimeVDSOLoaderAnchor(view, link) {
		t.Fatal("exact auxiliary anchor rejected")
	}
	link.dynamic++
	if runtimeVDSOLoaderAnchor(view, link) {
		t.Fatal("mismatching loader dynamic address accepted")
	}
}
