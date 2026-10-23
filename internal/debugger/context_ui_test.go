package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
)

type uiReadFixture struct {
	*contextReadFixture
	maps        []procMap
	symbols     []inspect.Symbol
	memory      map[target.Address][]byte
	mapErr      error
	mapCalls    int
	symbolCalls int
	readError   error
}

func (fixture *uiReadFixture) addressWalkMaps(context.Context, target.Snapshot, target.ThreadInfo) ([]procMap, error) {
	fixture.mapCalls++
	return fixture.maps, fixture.mapErr
}

func (fixture *uiReadFixture) addressWalkSymbols(context.Context, target.Snapshot, target.ThreadInfo) ([]inspect.Symbol, error) {
	fixture.symbolCalls++
	return fixture.symbols, nil
}

func (fixture *uiReadFixture) ReadSpaceMemory(token target.MemoryToken, address target.Address, destination []byte) (int, error) {
	fixture.stackCalls = append(fixture.stackCalls, contextMemoryCall{token, address, len(destination)})
	if fixture.readError != nil {
		return 0, fixture.readError
	}
	for start, data := range fixture.memory {
		if address < start || uint64(address-start) >= uint64(len(data)) {
			continue
		}
		n := copy(destination, data[int(address-start):])
		if n != len(destination) {
			return n, io.ErrUnexpectedEOF
		}
		return n, nil
	}
	return 0, target.ErrUnavailable
}

func newUIFixture() (*uiReadFixture, target.ThreadInfo) {
	base, _, thread := newContextFixture()
	fixture := &uiReadFixture{
		contextReadFixture: base,
		maps: []procMap{
			{Start: 0x400000, End: 0x402000, Read: true, Execute: true},
			{Start: 0x500000, End: 0x501000, Read: true, Write: true},
			{Start: 0x600000, End: 0x601000, Read: true},
			{Start: 0x70000000, End: 0x70001000, Read: true, Write: true},
		},
		symbols: []inspect.Symbol{
			{Name: "ui_probe", Address: 0x401000, AddressKnown: true, Size: 16, Type: elf.STT_FUNC},
			{Name: "writable_value", Address: 0x500000, AddressKnown: true, Size: 8, Type: elf.STT_OBJECT},
			{Name: "readonly_value", Address: 0x600000, AddressKnown: true, Size: 8, Type: elf.STT_OBJECT},
		},
		memory: map[target.Address][]byte{
			0x401000: bytes.Repeat([]byte{0x90}, 64),
			0x500000: make([]byte, 8), 0x600000: make([]byte, 8), 0x70000000: make([]byte, 64),
		},
	}
	binary.LittleEndian.PutUint64(fixture.memory[0x500000], 0x600000)
	binary.LittleEndian.PutUint64(fixture.memory[0x600000], 0x500000)
	binary.LittleEndian.PutUint64(fixture.memory[0x70000000], 0x500000)
	binary.LittleEndian.PutUint64(fixture.memory[0x70000000][8:], 0x401000)
	fixture.registers = []target.Register{
		contextTestRegister("rip", 0x401001), contextTestRegister("rax", 0x500000),
		contextTestRegister("rsp", 0x70000000), contextTestRegister("rbp", 0x70000008),
		contextTestRegister("r12", 0x1234), contextTestRegister("eflags", 0x202),
		contextTestRegister("cs", 0x33), contextTestRegister("ss", 0x2b), contextTestRegister("fs_base", 0),
	}
	return fixture, thread
}

func TestUIRegistersUseGEFOrderFlagsAndSegments(t *testing.T) {
	fixture, thread := newUIFixture()
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := c.showRegisters(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	last := -1
	for _, name := range []string{"$rax", "$rsp", "$rbp", "$rip", "$r12", "$fs_base", "$eflags", "$cs"} {
		position := strings.Index(text, name)
		if position <= last {
			t.Fatalf("register order %s: %s", name, text)
		}
		last = position
	}
	for _, want := range []string{"$rax   :", "[loop detected]", "<writable_value>", "<readonly_value>", "<ui_probe+0x1>", " IF ", "IOPL=0]", "$cs: 0x0033 $ss: 0x002b"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing UI register detail %q: %s", want, text)
		}
	}
	if fixture.mapCalls != 1 || fixture.symbolCalls != 1 || len(fixture.registerTokens) != 1 {
		t.Fatalf("unexpected register decoration reads: %+v", fixture)
	}
}

func TestUISimpleRegistersDoNotReadMappingsSymbolsOrPointers(t *testing.T) {
	fixture, thread := newUIFixture()
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := c.showRegisters(context.Background(), "-s rax rip"); err != nil {
		t.Fatal(err)
	}
	if fixture.mapCalls != 0 || fixture.symbolCalls != 0 || len(fixture.stackCalls) != 0 || len(fixture.registerTokens) != 1 || fixture.snapshotReads != 1 {
		t.Fatalf("simple view decorated values: %+v", fixture)
	}
	if strings.Contains(output.String(), " -> ") || strings.Contains(output.String(), "<ui_") || !strings.Contains(output.String(), "$rip   : 0x0000000000401001") {
		t.Fatalf("simple view changed raw RIP: %s", output.String())
	}
}

func TestUIDecorationsUseVerifiedPermissionsAndExactSymbols(t *testing.T) {
	fixture, thread := newUIFixture()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output, renderer: renderer}
	if err := c.showContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"\x1b[36m0x0000000000500000\x1b[0m", "\x1b[34m0x0000000000600000\x1b[0m", "\x1b[31m0x0000000000401000\x1b[0m",
		"$rsp>", "$rbp>", "|+0x0008|+001:", "<ui_probe>", "*->", "breakpoint instruction 0x0000000000401000; raw $rip = 0x0000000000401001",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing permission/label/location %q: %q", want, text)
		}
	}
	for _, read := range fixture.stackCalls {
		if read.token != fixture.snapshot.Memory {
			t.Fatalf("wrong decoration token: %+v", read)
		}
	}
}

func TestUIChangedRegistersDoNotCrossThreadOrAddressSpace(t *testing.T) {
	fixture, _, thread := newContextFixture()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output, renderer: renderer}
	check := func(want bool) {
		t.Helper()
		output.Reset()
		if err := c.showRegisters(context.Background(), "-s rax"); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(output.String(), "\x1b[1;31m$rax\x1b[0m"); got != want {
			t.Fatalf("changed register marker=%t want %t: %q", got, want, output.String())
		}
	}
	check(false)
	fixture.registers[0] = contextTestRegister("rax", 2)
	fixture.snapshot.Threads[0].Token.Registers++
	check(true)
	check(true)
	fixture.snapshot.Threads[0].Token.Stop++
	fixture.registers[0] = contextTestRegister("rax", 3)
	check(true)
	check(true)
	fixture.snapshot.Memory.Space.ID++
	check(false)
	fixture.snapshot.Threads[0].Ref.ID++
	fixture.snapshot.Threads[0].Token.Thread = fixture.snapshot.Threads[0].Ref
	c.selected = fixture.snapshot.Threads[0].Ref
	check(false)
}

func TestUIStaleDecorationsDiscardTheWholeBufferedView(t *testing.T) {
	for _, failure := range []string{"maps", "memory"} {
		fixture, thread := newUIFixture()
		if failure == "maps" {
			fixture.mapErr = target.ErrStale
		} else {
			fixture.readError = target.ErrStale
		}
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output}
		if err := c.showContext(context.Background()); !errors.Is(err, target.ErrStale) || output.Len() != 0 || len(c.registerHistory) != 0 {
			t.Fatalf("stale %s view was published: %v %q", failure, err, output.String())
		}
	}
}

func TestUIOutputFailureDoesNotContinueReadingOrCommitHistory(t *testing.T) {
	fixture, thread := newUIFixture()
	want := errors.New("UI output failed")
	readsAtFailure := -1
	c := &Controller{session: fixture, selected: thread.Ref, out: controllerTestWriter(func([]byte) (int, error) {
		readsAtFailure = len(fixture.stackCalls)
		return 0, want
	})}
	err := c.showContext(context.Background())
	var outputErr *OutputError
	if !errors.Is(err, want) || !errors.As(err, &outputErr) || readsAtFailure < 0 || len(fixture.stackCalls) != readsAtFailure || len(c.registerHistory) != 0 {
		t.Fatalf("failed UI output continued reads or committed history: %v reads=%d/%d history=%d", err, len(fixture.stackCalls), readsAtFailure, len(c.registerHistory))
	}
}

func TestUIExactSymbolAmbiguityIsNotGuessed(t *testing.T) {
	fixture, thread := newUIFixture()
	fixture.symbols = append(fixture.symbols, inspect.Symbol{Name: "other_symbol", Address: 0x500000, AddressKnown: true, Size: 8})
	var output bytes.Buffer
	c := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := c.showRegisters(context.Background(), "rax"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "<other_symbol | writable_value>") || !strings.Contains(output.String(), "0x0000000000500000") {
		t.Fatalf("true symbol candidates were hidden or presented as unique: %s", output.String())
	}
}

func TestUIAddressSymbolCandidatesAreDeduplicatedOrderedAndBounded(t *testing.T) {
	fixture, thread := newUIFixture()
	fixture.symbols = []inspect.Symbol{
		{Name: "probe", Address: 0x401000, AddressKnown: true, Size: 32, Type: elf.STT_FUNC},
		{Name: "probe_call", Address: 0x401004, AddressKnown: true, Type: elf.STT_NOTYPE},
		{Name: "probe_call", Address: 0x401004, AddressKnown: true, Type: elf.STT_NOTYPE},
	}
	c := &Controller{session: fixture, selected: thread.Ref, out: io.Discard}
	walker, err := c.newAddressView(context.Background(), fixture.snapshot, thread, fixture.registers)
	if err != nil {
		t.Fatal(err)
	}
	if got := walker.symbol(0x401004); got != "probe_call | probe+0x4" {
		t.Fatalf("exact label/containing function candidates: %q", got)
	}
	for _, name := range []string{"c_label", "a_label", "b_label"} {
		fixture.symbols = append(fixture.symbols, inspect.Symbol{Name: name, Address: 0x401004, AddressKnown: true})
	}
	if err := c.addAddressSymbols(context.Background(), fixture.snapshot, thread, walker); err != nil {
		t.Fatal(err)
	}
	if got := walker.symbol(0x401004); got != "a_label | b_label | c_label | +2 more" {
		t.Fatalf("candidate order/dedup/bound: %q", got)
	}
}

func TestUIContextPlainAndColorArtifacts(t *testing.T) {
	directory := filepath.Join("..", "..", ".cache", "context-ui")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []display.ColorMode{display.ColorNever, display.ColorAlways} {
		fixture, thread := newUIFixture()
		renderer, err := display.NewRenderer(display.Options{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		c := &Controller{session: fixture, selected: thread.Ref, out: &output, renderer: renderer}
		if err := c.showContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		name := "plain-context.txt"
		if mode == display.ColorAlways {
			name = "color-context.ansi"
		}
		if strings.ContainsRune(output.String(), '\x1b') != (mode == display.ColorAlways) {
			t.Fatal("color policy was not preserved")
		}
		if err := os.WriteFile(filepath.Join(directory, name), output.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUINativeMainSymbolCacheReusesVerifiedAddressSpace(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	session, err := native.Launch(executable, "-test.run=^$")
	if session != nil {
		defer func() {
			if err := session.Close(); err != nil {
				t.Errorf("native UI fixture cleanup: %v", err)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	adapter := &nativeSession{Session: session}
	c := &Controller{session: adapter, out: io.Discard}
	if err := c.initializeSelection(); err != nil {
		t.Fatal(err)
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.addressWalkSymbols(context.Background(), snapshot, thread)
	if err != nil && !onlyLoaderPublicationPending(err) {
		t.Fatal(err)
	}
	if !adapter.uiSymbols.ready || adapter.uiSymbols.key != newUISymbolCacheKey(snapshot, thread) || len(first) == 0 {
		t.Fatal("verified symbol facts were not retained by stopped-snapshot identity")
	}
	storage := &adapter.uiSymbols.symbols[0]
	second, err := adapter.addressWalkSymbols(context.Background(), snapshot, thread)
	if err != nil && !onlyLoaderPublicationPending(err) || &adapter.uiSymbols.symbols[0] != storage || len(first) != len(second) {
		t.Fatalf("same stopped snapshot was reparsed: err=%v first=%d second=%d", err, len(first), len(second))
	}
}

func TestUIDirectBranchAnnotationUsesOnlyDecodedRelativeOperand(t *testing.T) {
	walker := &addressWalker{symbol: func(address target.Address) string {
		if address == 0x401100 {
			return "leaf"
		}
		return ""
	}}
	view := contextOutput{walker: walker}
	for _, test := range []struct {
		bytes []byte
		text  string
		want  string
	}{
		{[]byte{0xe8, 0xfb, 0, 0, 0}, "call 0x401100", "call 0x401100 <leaf>"},
		{[]byte{0xe9, 0xfb, 0, 0, 0}, "jmp 0x401100", "jmp 0x401100 <leaf>"},
		{[]byte{0xff, 0xd0}, "call rax", "call rax"},
		{[]byte{0xe8}, "incomplete", "incomplete"},
	} {
		got := view.instructionText(inspect.Instruction{Address: 0x401000, Bytes: test.bytes, Text: test.text})
		if got != test.want {
			t.Fatalf("branch %x: %q want %q", test.bytes, got, test.want)
		}
	}
}
