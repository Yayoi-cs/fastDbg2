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
	"strings"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
)

func TestTelescopeArguments(t *testing.T) {
	for _, test := range []struct {
		input string
		expr  string
		count int
	}{
		{"$rsp", "$rsp", 128},
		{"0x1000 2", "0x1000", 2},
		{"'$rsp + 8' 0x10", "$rsp + 8", 16},
		{"\"`symbol with spaces`\" 512", "`symbol with spaces`", 512},
	} {
		expression, count, depth, err := telescopeArguments(test.input)
		if err != nil || expression != test.expr || count != test.count || depth != defaultAddressWalkDepth {
			t.Fatalf("%q: expression=%q count=%d depth=%d error=%v", test.input, expression, count, depth, err)
		}
	}
	for _, input := range []string{"", "0x1000 0", "0x1000 513", "0x1000 -1", "0x1000 1 2", "$rsp + 8", "'unfinished"} {
		if _, _, _, err := telescopeArguments(input); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func TestLegacyDisassembleCountDoesNotChangeExpressionParsing(t *testing.T) {
	for _, input := range []string{"0x401000 2", "0x401000 0x2"} {
		controller, fixture, output := newInspectionTestController()
		if err := controller.showDisassemble(context.Background(), input); err != nil || len(fixture.codeCalls) != 1 || fixture.codeCalls[0].address != 0x401000 || fixture.codeCalls[0].size != 30 || strings.Count(output.String(), "  nop\n") != 2 {
			t.Fatalf("legacy count %q: error=%v output=%q calls=%+v", input, err, output.String(), fixture.codeCalls)
		}
	}
	for _, input := range []string{"0x401000 +8", "$rip +8"} {
		controller, fixture, _ := newInspectionTestController()
		if err := controller.showDisassemble(context.Background(), input); err != nil || fixture.codeCalls[0].size != 120 {
			t.Fatalf("changed expression %q: error=%v calls=%+v", input, err, fixture.codeCalls)
		}
	}
	for _, input := range []string{"0x401000 0", "0x401000 257", "0x401000 2 3"} {
		controller, fixture, output := newInspectionTestController()
		if err := controller.showDisassemble(context.Background(), input); err == nil || len(fixture.codeCalls) != 0 || output.Len() != 0 {
			t.Fatalf("invalid %q: error=%v calls=%+v output=%q", input, err, fixture.codeCalls, output.String())
		}
	}
}

func TestFunctionDisassembleArgumentsKeepModuleScopeExplicit(t *testing.T) {
	for _, test := range []struct {
		input      string
		module     string
		expression string
	}{
		{"", "", ""},
		{" $rip + 8 ", "", "$rip + 8"},
		{"--module main", "main", ""},
		{"--module main  `two  spaces` + 8", "main", "`two  spaces` + 8"},
		{"--module '/mapped path/lib.so' $rip + 8", "/mapped path/lib.so", "$rip + 8"},
		{"--module /mapped\\ path/lib.so 0x401000", "/mapped path/lib.so", "0x401000"},
		{"--module '日本語 lib.so' `odd  symbol`", "日本語 lib.so", "`odd  symbol`"},
	} {
		selection, expression, err := functionDisassembleArguments(test.input)
		if err != nil || selection.All || selection.Name != test.module || expression != test.expression {
			t.Fatalf("%q: selection=%+v expression=%q error=%v", test.input, selection, expression, err)
		}
	}
	for _, input := range []string{"--module", "--module ''", "--module \"unfinished", "--module unfinished\\", "--module bad\x00name"} {
		controller, fixture, output := newInspectionTestController()
		if err := controller.showFunctionDisassemble(context.Background(), input); !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || output.Len() != 0 {
			t.Fatalf("invalid module %q: error=%v snapshots=%d output=%q", input, err, fixture.snapshotReads, output.String())
		}
	}
}

func TestTelescopeOnlyReadsRawQwords(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	fixture.stack = []byte("abcdefghABCDEFGH")
	fixture.rawBase = 0x401001
	if err := controller.showTelescope(context.Background(), "$rip 2"); err != nil {
		t.Fatal(err)
	}
	want := controller.renderer.Section("telescope", 100) + "\n          0x0000000000401001|+0x0000|+000: 0x6867666564636261\n          0x0000000000401009|+0x0008|+001: 0x4847464544434241\n"
	if output.String() != want || len(fixture.stackCalls) != 3 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x401001, 8}) ||
		fixture.stackCalls[1] != (contextMemoryCall{fixture.snapshot.Memory, 0x401009, 32}) || fixture.stackCalls[2] != (contextMemoryCall{fixture.snapshot.Memory, 0x401009, 8}) ||
		fixture.mapCalls != 1 ||
		len(fixture.registerTokens) != 1 || len(fixture.codeCalls) != 0 || len(fixture.locationTokens) != 0 {
		t.Fatalf("telescope inferred contents: output=%q fixture=%+v", output.String(), fixture)
	}
}

func TestTelescopePartialAndStaleRead(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	fixture.stack = fixture.stack[:10]
	err := controller.showTelescope(context.Background(), "$rsp 2")
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(output.String(), "<partial 2/8: 08 09>\n") || strings.Contains(output.String(), "0x0000000000000908") {
		t.Fatalf("partial qword padded: error=%v output=%q", err, output.String())
	}
	controller, fixture, output = newAddressWalkTestController()
	fixture.stackErr = target.ErrStale
	if err := controller.showTelescope(context.Background(), "$rsp 2"); !errors.Is(err, target.ErrStale) || output.Len() != 0 || len(fixture.stackCalls) != 1 {
		t.Fatalf("stale read used: error=%v output=%q fixture=%+v", err, output.String(), fixture)
	}
}

func TestTelescopeBounds(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	if err := controller.showTelescope(context.Background(), "0xffffffffffffffff"); !errors.Is(err, target.ErrOverflow) || output.Len() != 0 || len(fixture.stackCalls) != 0 {
		t.Fatalf("wrapped range: error=%v output=%q", err, output.String())
	}
	controller, fixture, _ = newAddressWalkTestController()
	fixture.stack = make([]byte, maxMemoryBytes)
	if err := controller.showTelescope(context.Background(), "$rsp 512"); err != nil || len(fixture.stackCalls) != 512 || fixture.stackCalls[0].size != 8 || fixture.stackCalls[511].address != 0x70000000+511*8 {
		t.Fatalf("maximum count: error=%v calls=%+v", err, fixture.stackCalls)
	}
}

func TestTelescopeExplicitDepthArguments(t *testing.T) {
	expression, count, depth, err := telescopeArguments("--depth 16 '$rsp + 8' 0x10")
	if err != nil || expression != "$rsp + 8" || count != 16 || depth != 16 {
		t.Fatalf("expression=%q count=%d depth=%d error=%v", expression, count, depth, err)
	}
	for _, input := range []string{"--depth", "--depth 0 $rsp", "--depth 17 $rsp", "--depth +1 $rsp", "--depth -1 $rsp", "--depth 1"} {
		if _, _, _, err := telescopeArguments(input); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func TestTelescopeExplicitDepthReadsOnlyRequestedEdges(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	words := map[target.Address]uint64{0x1000: 0x2000, 0x2000: 0x3000, 0x3000: 0x4142434445464748}
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if address == 0x3008 && len(dst) == 32 {
			return 0, target.ErrUnavailable
		}
		value, ok := words[address]
		if !ok || len(dst) != 8 {
			t.Fatalf("unexpected dereference at %#x size=%d", address, len(dst))
		}
		binary.LittleEndian.PutUint64(dst, value)
		return 8, nil
	}
	if err := controller.showTelescope(context.Background(), "--depth 2 0x1000 1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(output.String()), " "), "0x0000000000002000 -> 0x0000000000003000 -> 0x4142434445464748") ||
		len(fixture.stackCalls) != 4 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x1000, 8}) ||
		fixture.stackCalls[1] != (contextMemoryCall{fixture.snapshot.Memory, 0x2000, 8}) || fixture.stackCalls[2] != (contextMemoryCall{fixture.snapshot.Memory, 0x3000, 8}) ||
		fixture.stackCalls[3] != (contextMemoryCall{fixture.snapshot.Memory, 0x3008, 32}) || strings.Contains(output.String(), "ABCDEFGH") || len(fixture.codeCalls) != 0 {
		t.Fatalf("wrong explicit edges: %q calls=%+v", output.String(), fixture.stackCalls)
	}
	for _, call := range fixture.stackCalls {
		if call.token != fixture.snapshot.Memory {
			t.Fatalf("token changed: %+v", call)
		}
	}
}

func TestTelescopeExplicitDepthReportsExactCycle(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if address != 0x1000 && address != 0x2000 {
			t.Fatalf("unexpected cyclic read %#x", address)
		}
		value := uint64(0x2000)
		if address == 0x2000 {
			value = 0x1000
		}
		binary.LittleEndian.PutUint64(dst, value)
		return 8, nil
	}
	if err := controller.showTelescope(context.Background(), "--depth 16 0x1000 1"); err != nil || len(fixture.stackCalls) != 2 || !strings.Contains(output.String(), "[loop detected]") {
		t.Fatalf("cycle not exact: error=%v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
	}
}

func TestTelescopeDepthPartialStaleAndOverflowStopReads(t *testing.T) {
	for _, state := range []string{"partial", "stale", "overflow"} {
		t.Run(state, func(t *testing.T) {
			controller, fixture, output := newAddressWalkTestController()
			fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
				if address == 0x1008 && state == "overflow" {
					clear(dst)
					return len(dst), nil
				}
				if address == 0x1000 {
					value := uint64(0x2000)
					if state == "overflow" {
						value = math.MaxUint64
					}
					binary.LittleEndian.PutUint64(dst, value)
					return len(dst), nil
				}
				if address != 0x2000 {
					t.Fatalf("unexpected address %#x", address)
				}
				copy(dst, []byte{1, 2, 3})
				if state == "stale" {
					return 3, target.ErrStale
				}
				return 3, io.ErrUnexpectedEOF
			}
			err := controller.showTelescope(context.Background(), "--depth 16 0x1000 2")
			switch state {
			case "partial":
				if !errors.Is(err, target.ErrPartial) || len(fixture.stackCalls) != 2 || !strings.Contains(output.String(), "<partial 3/8: 01 02 03>") {
					t.Fatalf("partial chain: error=%v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
				}
			case "stale":
				if !errors.Is(err, target.ErrStale) || len(fixture.stackCalls) != 2 || output.Len() != 0 {
					t.Fatalf("stale chain: error=%v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
				}
			case "overflow":
				if err != nil || len(fixture.stackCalls) != 2 || fixture.stackCalls[1].address != 0x1008 || !strings.Contains(output.String(), "0xffffffffffffffff") {
					t.Fatalf("overflow chain: error=%v calls=%+v", err, fixture.stackCalls)
				}
			}
		})
	}
}

func TestFSBaseReadsSelectedRegisterWithoutTLSAssumptions(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.registers = append(fixture.registers, contextTestRegister("fs_base", 0x60000000))
	fixture.stack = make([]byte, 128)
	fixture.stack[40] = 0x12
	fixture.stack[48] = 0x34
	if err := controller.showFSBase(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "fs_base = 0x0000000060000000") || strings.Contains(output.String(), "canary") || strings.Contains(output.String(), "mangling") ||
		len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x60000000, 128}) ||
		len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != fixture.snapshot.Threads[0].Token || len(fixture.locationTokens) != 0 {
		t.Fatalf("FS assumptions or wrong scope: output=%q fixture=%+v", output.String(), fixture)
	}
}

func TestFSBaseRejectsMissingMalformedAndOverflowingRegisters(t *testing.T) {
	for _, state := range []string{"missing", "duplicate", "wrong-width", "overflow", "stale"} {
		t.Run(state, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			if state != "missing" {
				fixture.registers = append(fixture.registers, contextTestRegister("fs_base", 0x60000000))
			}
			switch state {
			case "duplicate":
				fixture.registers = append(fixture.registers, contextTestRegister("fs_base", 0x70000000))
			case "wrong-width":
				fixture.registers[len(fixture.registers)-1].Bits = 32
			case "overflow":
				fixture.registers[len(fixture.registers)-1] = contextTestRegister("fs_base", math.MaxUint64)
			case "stale":
				fixture.registerErr = target.ErrStale
			}
			if err := controller.showFSBase(context.Background(), ""); err == nil || output.Len() != 0 || len(fixture.stackCalls) != 0 {
				t.Fatalf("invalid FS read: error=%v output=%q", err, output.String())
			}
		})
	}
}

func TestMappedSymbolFactsReuseExactSymbolAddressRules(t *testing.T) {
	path := imageTestELF(t, elf.ET_DYN, []elf.Symbol{
		{Name: "function", Value: 0x1010, Size: 4, Info: byte(elf.STT_FUNC), Section: 1},
		{Name: "tls", Value: 0x1040, Size: 8, Info: byte(elf.STT_TLS), Section: 1},
	})
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	file, err := elf.NewFile(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	file.Progs = []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: 0x1000, Memsz: 0x100}}}
	module := &mappedELF{ID: "module", Path: path, Source: source, File: file, LoadBias: 0x700000}
	facts := readMappedSymbolFacts(context.Background(), module)
	if facts.err != nil || len(facts.symbols) != 2 || len(facts.executable) != 1 ||
		facts.symbols[0].Address != 0x701010 || !facts.symbols[0].AddressKnown || facts.symbols[1].AddressKnown ||
		!facts.executable[0].contains(0x701000) || facts.executable[0].contains(0x701100) {
		t.Fatalf("wrong mapped facts: %+v", facts)
	}
	module.LoadBias = math.MaxUint64
	if got := readMappedSymbolFacts(context.Background(), module); !errors.Is(got.err, target.ErrOverflow) {
		t.Fatalf("overflowing module: %+v", got)
	}
}

func legacyFunctionFacts() []moduleSymbolFacts {
	return []moduleSymbolFacts{{
		id: "main", path: "/fixture",
		executable: []executableSymbolRange{{address: 0x401000, size: 0x100}},
		symbols:    []inspect.Symbol{{ModuleID: "main", Name: "work", Type: elf.STT_FUNC, Address: 0x401010, AddressKnown: true, Size: 4}},
	}}
}

func TestExactFunctionSymbolRequiresDeclaredUniqueExecutableExtent(t *testing.T) {
	for _, address := range []target.Address{0x401010, 0x401011, 0x401013} {
		symbol, err := exactFunctionSymbol(legacyFunctionFacts(), address)
		if err != nil || symbol.Address != 0x401010 || symbol.Size != 4 {
			t.Fatalf("address %#x: %+v %v", address, symbol, err)
		}
	}
	for _, test := range []struct {
		name string
		edit func([]moduleSymbolFacts)
		err  error
	}{
		{"zero-size", func(f []moduleSymbolFacts) { f[0].symbols[0].Size = 0 }, target.ErrUnavailable},
		{"unknown-address", func(f []moduleSymbolFacts) { f[0].symbols[0].AddressKnown = false }, target.ErrNotFound},
		{"not-function", func(f []moduleSymbolFacts) { f[0].symbols[0].Type = elf.STT_OBJECT }, target.ErrNotFound},
		{"alias", func(f []moduleSymbolFacts) { f[0].symbols = append(f[0].symbols, f[0].symbols[0]) }, target.ErrAmbiguous},
		{"outside-executable", func(f []moduleSymbolFacts) { f[0].symbols[0].Size = 0x100 }, target.ErrUnavailable},
		{"symbol-error", func(f []moduleSymbolFacts) { f[0].err = target.ErrUnavailable }, target.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := legacyFunctionFacts()
			test.edit(facts)
			if _, err := exactFunctionSymbol(facts, 0x401010); !errors.Is(err, test.err) {
				t.Fatalf("got %v want %v", err, test.err)
			}
		})
	}
	for _, address := range []target.Address{0x40100f, 0x401014, 0x400000} {
		if _, err := exactFunctionSymbol(legacyFunctionFacts(), address); !errors.Is(err, target.ErrNotFound) {
			t.Fatalf("guessed extent at %#x: %v", address, err)
		}
	}
}

func TestExactFunctionDoesNotFailOnUnrelatedStrippedModule(t *testing.T) {
	facts := append(legacyFunctionFacts(), moduleSymbolFacts{id: "other", executable: []executableSymbolRange{{address: 0x70000000, size: 4096}}, err: target.ErrUnavailable})
	if _, err := exactFunctionSymbol(facts, 0x401010); err != nil {
		t.Fatal(err)
	}
	if _, err := exactFunctionSymbol(facts, 0x70000000); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("ignored missing relevant symbols: %v", err)
	}
}

func TestFunctionDisassemblyReadsOnlyELFExtentIncludingAfterRet(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.code = []byte{0x90, 0xc3, 0x90, 0xc3, 0xcc}
	symbol := legacyFunctionFacts()[0].symbols[0]
	location := native.CodeLocation{RawPC: 0x401012, InstructionPC: 0x401012}
	if err := controller.showFunctionCode(context.Background(), fixture.snapshot.Memory, symbol, location); err != nil {
		t.Fatal(err)
	}
	if len(fixture.codeCalls) != 1 || fixture.codeCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, symbol.Address, 4}) ||
		len(fixture.stackCalls) != 0 || strings.Count(output.String(), "  nop\n") != 2 || strings.Count(output.String(), "  ret\n") != 2 ||
		strings.Contains(output.String(), "int3") || !strings.Contains(output.String(), "=> 0x0000000000401012") {
		t.Fatalf("function extent inferred: output=%q calls=%+v", output.String(), fixture.codeCalls)
	}
}

func TestFunctionDisassemblyRejectsInvalidOrHugeExtentBeforeRead(t *testing.T) {
	for _, size := range []uint64{0, maxFunctionBytes + 1, math.MaxUint64} {
		controller, fixture, output := newInspectionTestController()
		symbol := legacyFunctionFacts()[0].symbols[0]
		symbol.Size = size
		if err := controller.showFunctionCode(context.Background(), fixture.snapshot.Memory, symbol, native.CodeLocation{}); err == nil || output.Len() != 0 || len(fixture.codeCalls) != 0 {
			t.Fatalf("invalid function size %d: error=%v output=%q", size, err, output.String())
		}
	}
}

func TestFunctionDisassemblyPartialAndInstructionLimit(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixture.code = []byte{0x90, 0x48, 0x89}
		fixture.codeErr = io.ErrUnexpectedEOF
		err := controller.showFunctionCode(context.Background(), fixture.snapshot.Memory, legacyFunctionFacts()[0].symbols[0], native.CodeLocation{})
		if !errors.Is(err, target.ErrPartial) || strings.Count(output.String(), "  nop\n") != 1 || strings.Contains(output.String(), "0x0000000000401013") {
			t.Fatalf("partial function: error=%v output=%q", err, output.String())
		}
	})
	t.Run("instruction-limit", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixture.code = bytes.Repeat([]byte{0x90}, maxFunctionInstructions+1)
		symbol := legacyFunctionFacts()[0].symbols[0]
		symbol.Size = maxFunctionInstructions + 1
		err := controller.showFunctionCode(context.Background(), fixture.snapshot.Memory, symbol, native.CodeLocation{})
		if !errors.Is(err, target.ErrPartial) || strings.Count(output.String(), "  nop\n") != maxFunctionInstructions {
			t.Fatalf("instruction cap: error=%v count=%d", err, strings.Count(output.String(), "  nop\n"))
		}
	})
	t.Run("stale", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixture.codeErr = target.ErrStale
		err := controller.showFunctionCode(context.Background(), fixture.snapshot.Memory, legacyFunctionFacts()[0].symbols[0], native.CodeLocation{})
		if !errors.Is(err, target.ErrStale) || output.Len() != 0 || len(fixture.codeCalls) != 1 {
			t.Fatalf("stale function: error=%v output=%q", err, output.String())
		}
	})
}

func TestSymbolListingFilterAndUnknownAddresses(t *testing.T) {
	controller, _, output := newInspectionTestController()
	facts := legacyFunctionFacts()
	facts[0].symbols = append(facts[0].symbols, inspect.Symbol{ModuleID: "main", Name: "WORK\x1b[31m\n", Type: elf.STT_TLS, Value: 0x40, Size: 8})
	if err := controller.renderSymbolFacts(facts, "WoRk"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"0x0000000000401010", "<unavailable>", `WORK\x1b[31m\n`, "2 symbol(s)", "value=0x40"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %q", want, output.String())
		}
	}
	if strings.Contains(output.String(), "\x1b") || strings.Contains(output.String(), "0x0000000000000000") {
		t.Fatalf("unknown symbol address fabricated or text unsafe: %q", output.String())
	}
	output.Reset()
	if err := controller.renderSymbolFacts(facts, "absent"); err != nil || !strings.Contains(output.String(), "0 symbol(s)") {
		t.Fatalf("empty filter: error=%v output=%q", err, output.String())
	}
}

func TestSymbolListingPreservesPerModuleFailure(t *testing.T) {
	controller, _, output := newInspectionTestController()
	facts := append(legacyFunctionFacts(), moduleSymbolFacts{id: "missing", path: "bad\x1b[31m", err: target.ErrUnavailable})
	err := controller.renderSymbolFacts(facts, "")
	if !errors.Is(err, target.ErrUnavailable) || !strings.Contains(output.String(), "0x0000000000401010") ||
		!strings.Contains(output.String(), "unavailable:") || strings.Contains(output.String(), "\x1b") {
		t.Fatalf("module failure hidden: error=%v output=%q", err, output.String())
	}
}
