package inspect_test

import (
	"context"
	"debug/elf"
	"errors"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestSymbolListIsImmutableAndDeterministic(t *testing.T) {
	entry := symbolTestEntry("work", 0x1010, 16, elf.STT_FUNC, 1)
	path := symbolTestELF(t, elf.ET_DYN, []elf.Symbol{entry}, []elf.Symbol{entry})
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "z", Path: path}, {ID: "a", Path: path, LoadBias: 0x700000}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := index.Symbols("")
	if err != nil || len(symbols) != 2 || symbols[0].ModuleID != "a" || symbols[1].ModuleID != "z" || symbols[0].Address != 0x701010 {
		t.Fatalf("symbols=%+v error=%v", symbols, err)
	}
	symbols[0].Name, symbols[0].Address = "changed", 0
	listed, err := index.Symbols("a")
	if err != nil || len(listed) != 1 || listed[0].Name != "work" || listed[0].Address != 0x701010 {
		t.Fatalf("mutation reached index: %+v %v", listed, err)
	}
	if _, err := index.ResolveName("a", "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := index.Symbols("missing"); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("unknown module: %v", err)
	}
	if _, err := (*inspect.SymbolIndex)(nil).Symbols(""); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("nil index: %v", err)
	}
}

func TestSymbolListPreservesUnsupportedAndAmbiguousFacts(t *testing.T) {
	path := symbolTestELF(t, elf.ET_DYN, []elf.Symbol{
		symbolTestEntry("overlap", 0x1010, 16, elf.STT_FUNC, 1),
		symbolTestEntry("overlap", 0x1020, 8, elf.STT_FUNC, 1),
		symbolTestEntry("tls", 0x1030, 8, elf.STT_TLS, 1),
		symbolTestEntry("undefined", 0, 0, elf.STT_FUNC, elf.SHN_UNDEF),
		symbolTestEntry("zero", 0x1040, 0, elf.STT_FUNC, 1),
	}, nil)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x700000}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := index.Symbols("main")
	if err != nil || len(symbols) != 5 {
		t.Fatalf("symbols=%+v error=%v", symbols, err)
	}
	if symbols[0].Name != "overlap" || symbols[1].Name != "overlap" || symbols[0].Address == symbols[1].Address ||
		symbols[2].Name != "tls" || symbols[2].AddressKnown || symbols[2].Type != elf.STT_TLS ||
		symbols[3].Name != "undefined" || symbols[3].AddressKnown || symbols[3].Section != elf.SHN_UNDEF ||
		symbols[4].Name != "zero" || !symbols[4].AddressKnown || symbols[4].Size != 0 {
		t.Fatalf("facts lost: %+v", symbols)
	}
	if _, err := index.ResolveName("main", "overlap"); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("listing changed ambiguity: %v", err)
	}
}
