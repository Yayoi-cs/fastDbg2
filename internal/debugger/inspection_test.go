package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"fastdbg2/native"
	"fastdbg2/target"
)

type inspectionReadFixture struct {
	*contextReadFixture
	readRaw  func(target.MemoryToken, target.Address, []byte) (int, error)
	readCode func(target.MemoryToken, target.Address, []byte) (int, error)
}

func (fixture *inspectionReadFixture) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	if fixture.readRaw == nil {
		return fixture.contextReadFixture.ReadSpaceMemory(token, address, dst)
	}
	fixture.stackCalls = append(fixture.stackCalls, contextMemoryCall{token, address, len(dst)})
	return fixture.readRaw(token, address, dst)
}

func (fixture *inspectionReadFixture) ReadCodeMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	if fixture.readCode == nil {
		return fixture.contextReadFixture.ReadCodeMemory(token, address, dst)
	}
	fixture.codeCalls = append(fixture.codeCalls, contextMemoryCall{token, address, len(dst)})
	return fixture.readCode(token, address, dst)
}

func newInspectionTestController() (*Controller, *inspectionReadFixture, *bytes.Buffer) {
	base, _, thread := newContextFixture()
	fixture := &inspectionReadFixture{contextReadFixture: base}
	var output bytes.Buffer
	controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
	return controller, fixture, &output
}

func TestPrintConstantsWithoutTarget(t *testing.T) {
	for _, test := range []struct {
		format     string
		expression string
		want       string
	}{
		{"", "(0x10 + 2) * 3", "HEX: 0x36 DEC: 54 OCT: 66 BIN: 110110\n"},
		{"x", "255", "0xff\n"},
		{"d", "0xffffffffffffffff", "-1\n"},
		{"d", "0x8000000000000000", "-9223372036854775808\n"},
		{"d", "0xffffffff", "4294967295\n"},
		{"u", "0xffffffffffffffff", "18446744073709551615\n"},
		{"o", "8", "010\n"},
		{"o", "0", "0\n"},
		{"t", "5", "101\n"},
		{"t", "0", "0\n"},
	} {
		t.Run(test.format+"/"+test.expression, func(t *testing.T) {
			var output bytes.Buffer
			controller := &Controller{out: &output}
			if err := controller.showPrint(context.Background(), test.format, test.expression); err != nil || output.String() != test.want {
				t.Fatalf("error=%v output=%q want=%q", err, output.String(), test.want)
			}
		})
	}
}

func TestPrintConstantsDoNotInspectExistingTarget(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.snapshotErr = target.ErrStale
	if err := controller.showPrint(context.Background(), "", "42"); err != nil {
		t.Fatal(err)
	}
	if fixture.snapshotReads != 0 || len(fixture.registerTokens) != 0 || len(fixture.stackCalls) != 0 || output.Len() == 0 {
		t.Fatalf("constant inspected target: %+v output=%q", fixture, output.String())
	}
}

func TestPrintRegisterResolverUsesOneSnapshotAndRawValues(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	if err := controller.showPrint(context.Background(), "x", "$rip + $rax + $rip"); err != nil {
		t.Fatal(err)
	}
	if output.String() != "0x803236\n" || fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 ||
		fixture.registerTokens[0] != fixture.snapshot.Threads[0].Token || len(fixture.locationTokens) != 0 ||
		len(fixture.stackCalls) != 0 || len(fixture.codeCalls) != 0 {
		t.Fatalf("unexpected print read: %q %+v", output.String(), fixture)
	}
}

func TestPrintSymbolResolutionDoesNotReadRegisters(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	resolver := &lazyInspectionResolver{
		controller: controller, ctx: context.Background(),
		symbols: &stoppedSymbolResolver{
			ctx:  context.Background(),
			load: func() (*stoppedSymbolScope, error) { return symbolResolutionFixture(), nil },
		},
	}
	_, err := resolver.ResolveSymbol("missing")
	if !errors.Is(err, target.ErrNotFound) || fixture.snapshotReads != 1 || len(fixture.registerTokens) != 0 || output.Len() != 0 {
		t.Fatalf("symbol resolution: error=%v output=%q fixture=%+v", err, output.String(), fixture)
	}
}

func TestPrintInvalidSyntaxAndFormats(t *testing.T) {
	for _, test := range []struct {
		format     string
		expression string
		err        error
	}{
		{"", "", target.ErrInvalidArgument},
		{"s", "1", target.ErrInvalidArgument},
		{"xx", "1", target.ErrInvalidArgument},
		{"", "-1", target.ErrInvalidArgument},
		{"", "0xffffffffffffffff + 1", target.ErrOverflow},
		{"", "1 2", target.ErrInvalidArgument},
		{"", "'main'", target.ErrInvalidArgument},
	} {
		t.Run(test.format+"/"+test.expression, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			err := controller.showPrint(context.Background(), test.format, test.expression)
			if !errors.Is(err, test.err) || fixture.snapshotReads != 0 || output.Len() != 0 {
				t.Fatalf("invalid print: error=%v output=%q snapshot reads=%d", err, output.String(), fixture.snapshotReads)
			}
		})
	}
}

func TestPrintStaleRegistersAreNotRetried(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.registerErr = target.ErrStale
	err := controller.showPrint(context.Background(), "", "$rip + $rax")
	if !errors.Is(err, target.ErrStale) || fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || output.Len() != 0 {
		t.Fatalf("stale registers: error=%v output=%q fixture=%+v", err, output.String(), fixture)
	}
}

func TestInspectionCountArguments(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		count int
	}{
		{"", "", 8},
		{"$rip + 8", "$rip + 8", 8},
		{"--count 2 $rip + 8", "$rip + 8", 2},
		{" --count\t256\t`a b` + 8 ", "`a b` + 8", 256},
		{"--count 1", "", 1},
	} {
		expression, count, err := inspectionCountArguments(test.input, 8, 256, "test")
		if expression != test.want || count != test.count || err != nil {
			t.Fatalf("%q: expression=%q count=%d error=%v", test.input, expression, count, err)
		}
	}
	for _, input := range []string{"--count", "--count 0", "--count -1", "--count +1", "--count 257", "--count 18446744073709551616"} {
		if _, _, err := inspectionCountArguments(input, 8, 256, "test"); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%q: %v", input, err)
		}
	}
}

func TestDisassembleUsesCurrentLogicalLocation(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	oldPC, oldBreakpoint := target.Address(0xdeadbeef), target.Address(0xdeadbeee)
	fixture.snapshot.Threads[0].Stop.RawPC, fixture.snapshot.Threads[0].Stop.Breakpoint = &oldPC, &oldBreakpoint
	if err := controller.showDisassemble(context.Background(), "--count 2"); err != nil {
		t.Fatal(err)
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 0 || len(fixture.locationTokens) != 1 ||
		fixture.locationTokens[0] != fixture.snapshot.Threads[0].Token || len(fixture.codeCalls) != 1 ||
		fixture.codeCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, fixture.location.InstructionPC, 30}) ||
		len(fixture.stackCalls) != 0 {
		t.Fatalf("unexpected disassembly calls: %+v", fixture)
	}
	for _, want := range []string{"[disassembly]", "=> 0x0000000000401000"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %q", want, output.String())
		}
	}
	if strings.Contains(output.String(), "deadbe") || strings.Count(output.String(), "  nop\n") != 2 {
		t.Fatalf("historical address or wrong instruction count: %q", output.String())
	}
}

func TestDisassembleExplicitExpressionUsesRawRIP(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	if err := controller.showDisassemble(context.Background(), "--count 1 $rip"); err != nil {
		t.Fatal(err)
	}
	if len(fixture.registerTokens) != 1 || len(fixture.codeCalls) != 1 || fixture.codeCalls[0].address != 0x401001 ||
		strings.Contains(output.String(), "=>") || strings.Contains(output.String(), "raw-pc=") {
		t.Fatalf("explicit expression was normalized: %q calls=%+v", output.String(), fixture.codeCalls)
	}
}

func TestDisassemblePartialAndInvalidReads(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
		data  []byte
		err   error
		want  error
		nop   bool
	}{
		{"partial", 3, []byte{0x90, 0x48, 0x89}, io.ErrUnexpectedEOF, target.ErrPartial, true},
		{"short", 1, []byte{0x90}, nil, io.ErrUnexpectedEOF, true},
		{"stale", 3, []byte{0x90, 0x90, 0x90}, target.ErrStale, target.ErrStale, false},
		{"negative", -1, nil, nil, target.ErrUnknown, false},
		{"too-large", 31, nil, nil, target.ErrUnknown, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			fixture.code, fixture.codeErr, fixture.codeCount = test.data, test.err, &test.count
			err := controller.showDisassemble(context.Background(), "--count 2")
			if !errors.Is(err, test.want) || strings.Contains(output.String(), "  nop\n") != test.nop ||
				len(fixture.codeCalls) != 1 || len(fixture.stackCalls) != 0 {
				t.Fatalf("error=%v output=%q fixture=%+v", err, output.String(), fixture)
			}
		})
	}
}

func TestDisassembleBoundsAndNoBackwardGuess(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.readCode = func(_ target.MemoryToken, _ target.Address, data []byte) (int, error) {
		for i := range data {
			data[i] = 0x90
		}
		return len(data), nil
	}
	if err := controller.showDisassemble(context.Background(), "--count 256 0x1000"); err != nil {
		t.Fatal(err)
	}
	if fixture.codeCalls[0].size != 3840 || fixture.codeCalls[0].address != 0x1000 || strings.Count(output.String(), "  nop\n") != 256 {
		t.Fatalf("wrong bound: calls=%+v", fixture.codeCalls)
	}
	controller, fixture, output = newInspectionTestController()
	fixture.location = native.CodeLocation{RawPC: math.MaxUint64, InstructionPC: math.MaxUint64}
	fixture.code = []byte{0x90}
	if err := controller.showDisassemble(context.Background(), "--count 1"); err != nil || len(fixture.codeCalls) != 1 || fixture.codeCalls[0].size != 1 {
		t.Fatalf("last address: error=%v calls=%+v output=%q", err, fixture.codeCalls, output.String())
	}
	for _, input := range []string{"--count 0", "--count 257", "--count -1", "0x1000 4 8", "--count 2 0xffffffffffffffff"} {
		controller, fixture, output = newInspectionTestController()
		if err := controller.showDisassemble(context.Background(), input); err == nil || len(fixture.codeCalls) != 0 || output.Len() != 0 {
			t.Fatalf("invalid %q: error=%v calls=%+v output=%q", input, err, fixture.codeCalls, output.String())
		}
	}
}

func TestStackUsesSelectedRawRegistersAndMemory(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	if err := controller.showStack(context.Background(), "2"); err != nil {
		t.Fatal(err)
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || len(fixture.stackCalls) != 1 ||
		fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x70000000, 16}) ||
		len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0 {
		t.Fatalf("wrong stack reads: %+v", fixture)
	}
	if !strings.Contains(output.String(), "0x0706050403020100") || !strings.Contains(output.String(), "0x0f0e0d0c0b0a0908") {
		t.Fatalf("wrong stack values: %q", output.String())
	}
}

func TestStackRejectsInvalidCountsAndRegisters(t *testing.T) {
	for _, input := range []string{"0", "513", "-1", "+1", "1 2", "--count 1"} {
		controller, fixture, output := newInspectionTestController()
		if err := controller.showStack(context.Background(), input); !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || output.Len() != 0 {
			t.Fatalf("%q: error=%v reads=%d output=%q", input, err, fixture.snapshotReads, output.String())
		}
	}
	for _, issue := range []string{"missing", "duplicate", "overflow"} {
		t.Run(issue, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			switch issue {
			case "missing":
				fixture.registers = fixture.registers[:2]
			case "duplicate":
				fixture.registers = append(fixture.registers, fixture.registers[2])
			case "overflow":
				fixture.registers[2] = contextTestRegister("rsp", math.MaxUint64)
			}
			if err := controller.showStack(context.Background(), ""); err == nil || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("invalid rsp: error=%v reads=%+v output=%q", err, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestHexdumpDefaultsAndUnitWidths(t *testing.T) {
	for _, test := range []struct {
		unit string
		want string
	}{
		{"byte", "00 01 02 03"},
		{"word", "0x0100 0x0302"},
		{"dword", "0x03020100 0x07060504"},
		{"qword", "0x0706050403020100 0x0f0e0d0c0b0a0908"},
	} {
		t.Run(test.unit, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			if err := controller.showHexdump(context.Background(), test.unit, "$rip"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), test.want) || len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 64 ||
				fixture.stackCalls[0].address != 0x401001 || len(fixture.codeCalls) != 0 || len(fixture.locationTokens) != 0 {
				t.Fatalf("wrong hexdump output=%q fixture=%+v", output.String(), fixture)
			}
		})
	}
}

func TestHexdumpExplicitUnitCountAndEscaping(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.stack = []byte{0x1b, '[', '3', '1', 'm', '\n', 0x7f, 0xff}
	if err := controller.showHexdump(context.Background(), "", "byte --count 8 $rsp + 8"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "1b 5b 33 31 6d 0a 7f ff") || !strings.Contains(output.String(), "|.[31m...|") ||
		strings.ContainsAny(output.String(), "\x1b\x7f") || fixture.stackCalls[0].address != 0x70000008 || fixture.stackCalls[0].size != 8 {
		t.Fatalf("wrong escaped hexdump: %q calls=%+v", output.String(), fixture.stackCalls)
	}
}

func TestHexdumpPartialUnitsAreNotPaddedIntoValues(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.stack = []byte{1, 2, 3, 4, 5, 6}
	fixture.stackErr = io.ErrUnexpectedEOF
	err := controller.showHexdump(context.Background(), "dword", "--count 2 $rsp")
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(output.String(), "0x04030201 [05 06]") ||
		strings.Contains(output.String(), "0x00000605") || !strings.Contains(output.String(), "|......|") {
		t.Fatalf("partial hexdump: error=%v output=%q", err, output.String())
	}
}

func TestHexdumpRejectsInvalidArgumentsBeforeMemory(t *testing.T) {
	for _, test := range []struct{ unit, args string }{
		{"", ""}, {"", "$rsp"}, {"bytes", "$rsp"}, {"byte", ""}, {"byte", "--count 4097 $rsp"},
		{"word", "--count 2049 $rsp"}, {"qword", "--count 513 $rsp"}, {"dword", "--count 0 $rsp"},
		{"byte", "$rsp 4"}, {"qword", "--count 1 0xffffffffffffffff"},
	} {
		t.Run(test.unit+"/"+test.args, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			if err := controller.showHexdump(context.Background(), test.unit, test.args); err == nil || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("invalid arguments: error=%v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
			}
		})
	}
}

func TestInspectionCommandCancellationAndOutputErrors(t *testing.T) {
	commands := []struct {
		name string
		run  func(*Controller, context.Context) error
	}{
		{"print", func(c *Controller, ctx context.Context) error { return c.showPrint(ctx, "", "$rip") }},
		{"disassemble", func(c *Controller, ctx context.Context) error { return c.showDisassemble(ctx, "--count 1 $rip") }},
		{"stack", func(c *Controller, ctx context.Context) error { return c.showStack(ctx, "1") }},
		{"hexdump", func(c *Controller, ctx context.Context) error { return c.showHexdump(ctx, "byte", "--count 1 $rip") }},
		{"examine", func(c *Controller, ctx context.Context) error { return c.showExamine(ctx, "1xb", "$rip") }},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := command.run(controller, ctx); !errors.Is(err, context.Canceled) || fixture.snapshotReads != 0 || output.Len() != 0 {
				t.Fatalf("canceled command read: error=%v fixture=%+v", err, fixture)
			}
			controller, fixture, output = newInspectionTestController()
			ctx, cancel = context.WithCancel(context.Background())
			defer cancel()
			fixture.onReadRegisters = cancel
			if err := command.run(controller, ctx); !errors.Is(err, context.Canceled) || len(fixture.stackCalls) != 0 || len(fixture.codeCalls) != 0 || output.Len() != 0 {
				t.Fatalf("continued after cancellation: error=%v output=%q fixture=%+v", err, output.String(), fixture)
			}
			controller, _, _ = newInspectionTestController()
			failure := errors.New("output stopped")
			controller.out = contextFailingWriter{err: failure}
			var outputErr *OutputError
			if err := command.run(controller, context.Background()); !errors.Is(err, failure) || !errors.As(err, &outputErr) {
				t.Fatalf("lost output error: %v", err)
			}
		})
	}
}

func TestInspectionNumericSignedWidths(t *testing.T) {
	for _, test := range []struct {
		value  uint64
		size   int
		format byte
		want   string
	}{
		{0x80, 1, 'd', "-128"}, {0xff, 1, 'd', "-1"}, {0x7f, 1, 'd', "127"},
		{0x8000, 2, 'd', "-32768"}, {0xffff, 2, 'd', "-1"},
		{0x80000000, 4, 'd', "-2147483648"}, {0xffffffff, 4, 'd', "-1"},
		{0x8000000000000000, 8, 'd', "-9223372036854775808"}, {math.MaxUint64, 8, 'd', "-1"},
		{math.MaxUint64, 8, 'u', "18446744073709551615"}, {1, 1, 't', "00000001"},
		{1, 2, 'x', "0x0001"}, {8, 1, 'o', "010"}, {0x1b, 1, 'c', "27 '\\x1b'"},
	} {
		t.Run(fmt.Sprintf("%x/%d/%c", test.value, test.size, test.format), func(t *testing.T) {
			if got := inspectionNumber(test.value, test.size, test.format); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
}
