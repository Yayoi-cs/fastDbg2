package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

type addressWalkTestSession struct {
	*inspectionReadFixture
	mappings []procMap
	mapErr   error
	mapCalls int
	rawBase  target.Address
}

func (fixture *addressWalkTestSession) addressWalkMaps(_ context.Context, snapshot target.Snapshot, thread target.ThreadInfo) ([]procMap, error) {
	fixture.mapCalls++
	if snapshot.Memory != fixture.snapshot.Memory || thread.Token != fixture.snapshot.Threads[0].Token {
		return nil, target.ErrStale
	}
	return fixture.mappings, fixture.mapErr
}

func (fixture *addressWalkTestSession) ReadSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	if fixture.readRaw != nil {
		return fixture.inspectionReadFixture.ReadSpaceMemory(token, address, data)
	}
	fixture.stackCalls = append(fixture.stackCalls, contextMemoryCall{token, address, len(data)})
	if address < fixture.rawBase || uint64(address-fixture.rawBase) >= uint64(len(fixture.stack)) {
		return 0, io.EOF
	}
	n := copy(data, fixture.stack[int(address-fixture.rawBase):])
	if fixture.stackCount != nil {
		n = *fixture.stackCount
	}
	return n, fixture.stackErr
}

func newAddressWalkTestController() (*Controller, *addressWalkTestSession, *bytes.Buffer) {
	controller, base, output := newInspectionTestController()
	fixture := &addressWalkTestSession{
		inspectionReadFixture: base, rawBase: 0x70000000,
		mappings: []procMap{
			{Start: 0x1000, End: 0x4000, Read: true, Write: true, Private: true},
			{Start: 0x401000, End: 0x402000, Read: true, Execute: true, Private: true},
			{Start: 0x70000000, End: 0x70001000, Read: true, Write: true, Private: true},
		},
	}
	controller.session = fixture
	return controller, fixture, output
}

func addressWalkTestWords(fixture *addressWalkTestSession, words map[target.Address]uint64) {
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
		value, ok := words[address]
		if !ok || len(data) != 8 {
			return 0, fmt.Errorf("fixture read at %#x/%d: %w", address, len(data), target.ErrUnavailable)
		}
		binary.LittleEndian.PutUint64(data, value)
		return len(data), nil
	}
}

func addressWalkTestView(t *testing.T, fixture *addressWalkTestSession, renderer display.Renderer) *addressWalker {
	t.Helper()
	walker, err := newAddressWalker(fixture, fixture.snapshot.Memory, fixture.mappings, fixture.registers, renderer)
	if err != nil {
		t.Fatal(err)
	}
	return walker
}

func TestAddressWalkConstructorRejectsInvalidMappingsAndTokens(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	for _, mappings := range [][]procMap{
		{{Start: 0x1000, End: 0x1000}},
		{{Start: 0x2000, End: 0x3000}, {Start: 0x1000, End: 0x2000}},
		{{Start: 0x1000, End: 0x3000}, {Start: 0x2000, End: 0x4000}},
	} {
		if _, err := newAddressWalker(fixture, fixture.snapshot.Memory, mappings, nil, display.Renderer{}); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("invalid maps accepted: %v", err)
		}
	}
	if _, err := newAddressWalker(fixture, target.MemoryToken{}, nil, nil, display.Renderer{}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("invalid token: %v", err)
	}
	if _, err := newAddressWalker(nil, fixture.snapshot.Memory, nil, nil, display.Renderer{}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil reader: %v", err)
	}
}

func TestAddressWalkDefaultDepthAndExactRawPointerInterpretation(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 0x1010, 0x1010: 0x1020, 0x1020: 0x1030, 0x1030: 0x1040, 0x1040: 0x1050})
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	text, err := walker.Value(context.Background(), 0x1000, defaultAddressWalkDepth)
	want := "0x0000000000001000 -> 0x0000000000001010 -> 0x0000000000001020 -> 0x0000000000001030 -> 0x0000000000001040 -> ..."
	if err != nil || text != want || len(fixture.stackCalls) != 4 {
		t.Fatalf("default chain: error=%v text=%q reads=%+v", err, text, fixture.stackCalls)
	}
	for _, call := range fixture.stackCalls {
		if call.token != fixture.snapshot.Memory || call.size != 8 {
			t.Fatalf("changed token/width: %+v", call)
		}
	}
	if _, err := walker.Value(context.Background(), 0x1000, defaultAddressWalkDepth); err != nil || len(fixture.stackCalls) != 4 {
		t.Fatalf("cache reread memory: error=%v calls=%+v", err, fixture.stackCalls)
	}
}

func TestAddressWalkScalarTerminalsAreNormalAndCompact(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	fixture.mappings = []procMap{{Start: 0x1000, End: 0x1004, Read: true}, {Start: 0x2000, End: 0x2100, Execute: true}}
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	reads := 0
	for _, value := range []uint64{0, 1, 0x1000, 0x2000, 0xdeadbeef, math.MaxUint64} {
		text, err := walker.Value(context.Background(), value, 4)
		if value == 0x1000 {
			reads++
		}
		if err != nil || text != fmt.Sprintf("0x%016x", value) || len(fixture.stackCalls) != reads {
			t.Fatalf("terminal scalar %#x: error=%v text=%q calls=%+v", value, err, text, fixture.stackCalls)
		}
	}
	if fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x1000, 4}) {
		t.Fatalf("guard preview used a fabricated qword: %+v", fixture.stackCalls)
	}
}

func TestAddressWalkReadsMappedZeroAndUnalignedAddressesWithoutGuessing(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	fixture.mappings = []procMap{{Start: 0, End: 8, Read: true}, {Start: 0x1000, End: 0x1005, Read: true}, {Start: 0x1005, End: 0x1010, Read: true}}
	addressWalkTestWords(fixture, map[target.Address]uint64{0: 42, 0x1001: 43})
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	for _, value := range []uint64{0, 0x1001} {
		text, err := walker.Value(context.Background(), value, 4)
		if err != nil || !strings.Contains(text, " -> ") {
			t.Fatalf("mapped address %#x was guessed null/unaligned: error=%v text=%q", value, err, text)
		}
	}
	if len(fixture.stackCalls) != 2 || fixture.stackCalls[0].address != 0 || fixture.stackCalls[1].address != 0x1001 {
		t.Fatalf("wrong exact reads: %+v", fixture.stackCalls)
	}
}

func TestAddressWalkCycleDetectionAndViewSharedCache(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 0x2000, 0x2000: 0x1000, 0x1008: 0x1000})
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	text, err := walker.Value(context.Background(), 0x1000, 16)
	if err != nil || text != "0x0000000000001000 -> 0x0000000000002000 -> [loop detected]" || len(fixture.stackCalls) != 2 {
		t.Fatalf("cycle: error=%v text=%q calls=%+v", err, text, fixture.stackCalls)
	}
	rows, err := walker.Rows(context.Background(), 0x1000, 2, 4)
	if err != nil || strings.Count(rows, "[loop detected]") != 2 || len(fixture.stackCalls) != 3 {
		t.Fatalf("rows did not share cache: error=%v rows=%q calls=%+v", err, rows, fixture.stackCalls)
	}
}

func TestAddressWalkRowsUseExactRegisterLabelsAndOffsets(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	fixture.registers = []target.Register{contextTestRegister("rsp", 0x1000), contextTestRegister("rbp", 0x1010), contextTestRegister("rax", 0x1008)}
	addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 1, 0x1008: 2, 0x1010: 3})
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	rows, err := walker.Rows(context.Background(), 0x1000, 3, 4)
	if err != nil || !strings.Contains(rows, "$rsp>     0x0000000000001000|+0x0000|+000: 0x0000000000000001") ||
		!strings.Contains(rows, "0x0000000000001008|+0x0008|+001: 0x0000000000000002") ||
		!strings.Contains(rows, "$rbp>     0x0000000000001010|+0x0010|+002: 0x0000000000000003") || strings.Contains(rows, "$rax") {
		t.Fatalf("labels/offsets: error=%v rows=%q", err, rows)
	}
}

func TestAddressWalkCoincidentStackRegistersKeepColumnsAndFixedOrder(t *testing.T) {
	for _, order := range [][]string{{"rsp", "rbp"}, {"rbp", "rsp"}} {
		_, fixture, _ := newAddressWalkTestController()
		fixture.registers = []target.Register{contextTestRegister(order[0], 0x1000), contextTestRegister(order[1], 0x1000)}
		addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 1, 0x1008: 2})
		walker := addressWalkTestView(t, fixture, display.Renderer{})
		rows, err := walker.Rows(context.Background(), 0x1000, 2, 4)
		if err != nil || !strings.HasPrefix(rows, "$rsp/rbp> 0x0000000000001000") || walker.Labels(0x1000) != "$rsp/rbp>" {
			t.Fatalf("order=%v error=%v rows=%q", order, err, rows)
		}
		for _, line := range strings.Split(strings.TrimSuffix(rows, "\n"), "\n") {
			if strings.Index(line, "0x") != 10 {
				t.Fatalf("unaligned address column for order=%v: %q", order, line)
			}
		}
	}
}

func TestAddressWalkNeverGuessesStringsOrInstructions(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	fixture.mappings = []procMap{{Start: 0x1000, End: 0x1010, Read: true, Execute: true}}
	addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 0x4847464544434241, 0x1008: 0x90909090909090cc})
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	rows, err := walker.Rows(context.Background(), 0x1000, 2, 4)
	if err != nil || !strings.Contains(rows, "0x4847464544434241") || !strings.Contains(rows, "0x90909090909090cc") || strings.Contains(rows, "ABCDEFGH") || strings.Contains(rows, "nop") || len(fixture.codeCalls) != 0 {
		t.Fatalf("content guessed: error=%v rows=%q", err, rows)
	}
}

func TestAddressWalkPermissionsAndExactSymbols(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	walker := addressWalkTestView(t, fixture, renderer)
	for _, mapping := range fixture.mappings {
		got, err := walker.Address(mapping.Start)
		want, _ := renderer.AddressPermissions(target.AMD64, mapping.Start, mapping.Read, mapping.Write, mapping.Execute)
		if err != nil || got != want {
			t.Fatalf("wrong permission color: got=%q want=%q error=%v", got, want, err)
		}
	}
	walker = addressWalkTestView(t, fixture, display.Renderer{})
	calls := 0
	walker.symbol = func(address target.Address) string {
		calls++
		if address == 0x500000 {
			return "exact\x1b[31m\nname+0x8"
		}
		return ""
	}
	for range 2 {
		text, err := walker.Value(context.Background(), 0x500000, 4)
		if err != nil || !strings.Contains(text, `<exact\x1b[31m\nname+0x8>`) || strings.Contains(text, "\x1b") {
			t.Fatalf("symbol annotation: error=%v text=%q", err, text)
		}
	}
	if calls != 1 {
		t.Fatalf("symbol cache calls=%d", calls)
	}
}

func TestAddressWalkPartialRowsAndReadableBackendFailures(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	fixture.mappings = []procMap{{Start: 0x1000, End: 0x1004, Read: true}}
	fixture.readRaw = func(_ target.MemoryToken, _ target.Address, data []byte) (int, error) {
		copy(data, []byte{0xd4, 0xc3, 0xb2, 0xa1})
		return 4, io.ErrUnexpectedEOF
	}
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	rows, err := walker.Rows(context.Background(), 0x1000, 1, 4)
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(rows, "<partial 4/8: d4 c3 b2 a1>") || strings.Contains(rows, "0x00000000a1b2c3d4") || len(fixture.stackCalls) != 1 {
		t.Fatalf("partial explicit row: error=%v rows=%q calls=%+v", err, rows, fixture.stackCalls)
	}
	text, err := walker.Value(context.Background(), 0x1000, 4)
	if err != nil || text != "0x0000000000001000" || len(fixture.stackCalls) != 1 {
		t.Fatalf("automatic chain crossed boundary: error=%v text=%q calls=%+v", err, text, fixture.stackCalls)
	}
	fixture.mappings[0].End = 0x1008
	walker = addressWalkTestView(t, fixture, display.Renderer{})
	text, err = walker.Value(context.Background(), 0x1000, 4)
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(text, "<partial 4/8: d4 c3 b2 a1>") {
		t.Fatalf("readable backend failure hidden: error=%v text=%q", err, text)
	}
}

func TestAddressWalkStaleAndCancellationDiscardWholeRows(t *testing.T) {
	for _, state := range []string{"stale", "cancel"} {
		t.Run(state, func(t *testing.T) {
			_, fixture, _ := newAddressWalkTestController()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
				binary.LittleEndian.PutUint64(data, 1)
				if address == 0x1008 {
					if state == "cancel" {
						cancel()
						return 8, nil
					}
					return 8, target.ErrStale
				}
				return 8, nil
			}
			walker := addressWalkTestView(t, fixture, display.Renderer{})
			rows, err := walker.Rows(ctx, 0x1000, 2, 4)
			if !addressWalkFatal(err) || rows != "" || len(fixture.stackCalls) != 2 {
				t.Fatalf("unsafe prefix retained: error=%v rows=%q calls=%+v", err, rows, fixture.stackCalls)
			}
			if text, err := walker.Value(context.Background(), 0x1000, 4); !addressWalkFatal(err) || text != "" || len(fixture.stackCalls) != 2 {
				t.Fatalf("fatal walker reused cache: error=%v text=%q", err, text)
			}
		})
	}
}

func TestAddressWalkCancellationDuringAnnotationDiscardsEvenMapFallback(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	walker.mapErr = target.ErrUnavailable
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	walker.symbol = func(target.Address) string { cancel(); return "exact" }
	text, err := walker.Value(ctx, 0x1000, 4)
	if !errors.Is(err, context.Canceled) || text != "" || len(fixture.stackCalls) != 0 {
		t.Fatalf("canceled annotation committed: error=%v text=%q calls=%+v", err, text, fixture.stackCalls)
	}
}

func TestAddressWalkTotalBudgetAndCache(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	fixture.mappings = []procMap{{Start: 0x1000, End: 0x1000 + (maxAddressWalkReads+1)*8, Read: true}}
	fixture.readRaw = func(_ target.MemoryToken, _ target.Address, data []byte) (int, error) {
		clear(data)
		return len(data), nil
	}
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	for index := 0; index < maxAddressWalkReads; index++ {
		if _, err := walker.Value(context.Background(), 0x1000+uint64(index)*8, 4); err != nil {
			t.Fatal(err)
		}
	}
	text, err := walker.Value(context.Background(), 0x1000+maxAddressWalkReads*8, 4)
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(text, "[budget]") || len(fixture.stackCalls) != maxAddressWalkReads {
		t.Fatalf("budget: error=%v text=%q reads=%d", err, text, len(fixture.stackCalls))
	}
	if _, err := walker.Value(context.Background(), 0x1000, 4); err != nil || len(fixture.stackCalls) != maxAddressWalkReads {
		t.Fatalf("confirmed cache unavailable after budget: error=%v reads=%d", err, len(fixture.stackCalls))
	}
}

func TestAddressWalkControllerStackAndTelescopeShareDefaultBehavior(t *testing.T) {
	for _, command := range []struct{ name, args string }{{"stack", "1"}, {"telescope", "$rsp 1"}, {"tel", "$rsp 1"}} {
		controller, fixture, output := newAddressWalkTestController()
		fixture.registers[2] = contextTestRegister("rsp", 0x1000)
		addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 0x2000, 0x2000: 0x3000, 0x3000: 42})
		quit, err := controller.Execute(context.Background(), command.name, command.args)
		if err != nil || quit || !strings.Contains(output.String(), "$rsp>") || !strings.Contains(strings.Join(strings.Fields(output.String()), " "), "0x0000000000002000 -> 0x0000000000003000 -> 0x000000000000002a") ||
			!strings.Contains(output.String(), "|+0x0000|+000:") || fixture.mapCalls != 1 || len(fixture.stackCalls) != 3 || len(fixture.registerTokens) != 1 {
			t.Fatalf("%s %s: quit=%t error=%v output=%q fixture=%+v", command.name, command.args, quit, err, output.String(), fixture)
		}
	}
}

func TestAddressWalkControllerFinalSnapshotMismatchDiscardsOutput(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	fixture.readRaw = func(_ target.MemoryToken, _ target.Address, data []byte) (int, error) {
		clear(data)
		fixture.snapshot.Sequence++
		return len(data), nil
	}
	if err := controller.showTelescope(context.Background(), "$rsp 1"); !errors.Is(err, target.ErrStale) || output.Len() != 0 {
		t.Fatalf("changed snapshot output published: error=%v output=%q", err, output.String())
	}
}

func TestAddressWalkMapFailureDisablesAutomaticReadsAndIsShownOnce(t *testing.T) {
	controller, fixture, _ := newAddressWalkTestController()
	fixture.mapErr = target.ErrUnavailable
	walker, err := controller.newAddressView(context.Background(), fixture.snapshot, fixture.snapshot.Threads[0], fixture.registers)
	if !errors.Is(err, target.ErrUnavailable) || walker == nil {
		t.Fatalf("map fallback: walker=%v error=%v", walker, err)
	}
	first, firstErr := walker.Value(context.Background(), 0x1000, 4)
	second, secondErr := walker.Value(context.Background(), 0x2000, 4)
	if firstErr != nil || secondErr != nil || !strings.Contains(first, "[maps unavailable]") || strings.Contains(second, "[maps unavailable]") || len(fixture.stackCalls) != 0 {
		t.Fatalf("map fallback read/inflated notices: %q %q %v %v", first, second, firstErr, secondErr)
	}
}

func TestAddressWalkControllerOutputFailureAndInvalidArguments(t *testing.T) {
	controller, fixture, _ := newAddressWalkTestController()
	failure := errors.New("output stopped")
	controller.out = contextFailingWriter{err: failure}
	var outputErr *OutputError
	if err := controller.showTelescope(context.Background(), "$rsp 1"); !errors.Is(err, failure) || !errors.As(err, &outputErr) || len(fixture.stackCalls) != 1 {
		t.Fatalf("output failure: error=%v calls=%+v", err, fixture.stackCalls)
	}
	for _, raw := range []string{"--depth 0 $rsp", "--depth 17 $rsp", "$rsp 513", "0xffffffffffffffff"} {
		controller, fixture, output := newAddressWalkTestController()
		if err := controller.showTelescope(context.Background(), raw); err == nil || len(fixture.stackCalls) != 0 || output.Len() != 0 {
			t.Fatalf("invalid telescope %q read: error=%v output=%q", raw, err, output.String())
		}
	}
}
