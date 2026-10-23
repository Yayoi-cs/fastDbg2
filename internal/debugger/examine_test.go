package debugger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"fastdbg2/target"
)

func TestExamineFormatDefaultsAndOrdering(t *testing.T) {
	for _, test := range []struct {
		spec string
		want examineFormat
	}{
		{"", examineFormat{1, 'x', 4}},
		{"8", examineFormat{8, 'x', 4}},
		{"8gx", examineFormat{8, 'x', 8}},
		{"8xg", examineFormat{8, 'x', 8}},
		{"16bx", examineFormat{16, 'x', 1}},
		{"16xb", examineFormat{16, 'x', 1}},
		{"h", examineFormat{1, 'x', 2}},
		{"d", examineFormat{1, 'd', 4}},
		{"s", examineFormat{1, 's', 1}},
		{"2bs", examineFormat{2, 's', 1}},
		{"c", examineFormat{1, 'c', 1}},
		{"256ig", examineFormat{256, 'i', 8}},
		{"4096xb", examineFormat{4096, 'x', 1}},
		{"512gx", examineFormat{512, 'x', 8}},
		{"4096s", examineFormat{4096, 's', 1}},
	} {
		t.Run(test.spec, func(t *testing.T) {
			format, err := parseExamineFormat(test.spec)
			if err != nil || format != test.want {
				t.Fatalf("got %+v, %v; want %+v", format, err, test.want)
			}
		})
	}
}

func TestExamineRejectsUnsupportedAndAmbiguousFormats(t *testing.T) {
	for _, spec := range []string{
		"0x", "-1x", "+1x", "4097xb", "18446744073709551616x", "257i", "513gx", "1025xw",
		"xx", "xd", "gg", "bh", "1 x", "X", "a", "f", "z", "x1", "/1x", "hs", "wc", "wsg",
	} {
		t.Run(spec, func(t *testing.T) {
			if _, err := parseExamineFormat(spec); err == nil {
				t.Fatal("accepted invalid format")
			}
		})
	}
}

func TestExamineNumericUsesRawMemory(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.stack = []byte{0xcc, 0x48, 0x31, 0xc0}
	if err := controller.showExamine(context.Background(), "4xb", "$rip - 1"); err != nil {
		t.Fatal(err)
	}
	if output.String() != "0x0000000000401000:\t0xcc\t0x48\t0x31\t0xc0\n" || fixture.snapshotReads != 1 ||
		len(fixture.registerTokens) != 1 || len(fixture.stackCalls) != 1 ||
		fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x401000, 4}) ||
		len(fixture.codeCalls) != 0 || len(fixture.locationTokens) != 0 {
		t.Fatalf("raw memory was hidden: output=%q fixture=%+v", output.String(), fixture)
	}
}

func TestExamineValuesUseLittleEndianUnitWidths(t *testing.T) {
	for _, test := range []struct {
		spec string
		data []byte
		want string
	}{
		{"2dh", []byte{0, 0x80, 0xff, 0x7f}, "-32768\t32767"},
		{"2dw", []byte{0, 0, 0, 0x80, 0xff, 0xff, 0xff, 0xff}, "-2147483648\t-1"},
		{"2ub", []byte{0x80, 0xff}, "128\t255"},
		{"1ug", bytes.Repeat([]byte{0xff}, 8), "18446744073709551615"},
		{"1dg", bytes.Repeat([]byte{0xff}, 8), "-1"},
		{"1xg", []byte{1, 2, 3, 4, 5, 6, 7, 8}, "0x0807060504030201"},
		{"2ob", []byte{8, 0xff}, "010\t0377"},
		{"2tb", []byte{1, 0xff}, "00000001\t11111111"},
		{"2cb", []byte{'A', 0x1b}, "65 'A'\t27 '\\x1b'"},
	} {
		t.Run(test.spec, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			fixture.stack = test.data
			if err := controller.showExamine(context.Background(), test.spec, "$rsp"); err != nil {
				t.Fatal(err)
			}
			if output.String() != "0x0000000070000000:\t"+test.want+"\n" || strings.Contains(output.String(), "\x1b") {
				t.Fatalf("wrong units: %q", output.String())
			}
		})
	}
}

func TestExamineInstructionUsesLogicalCodeAndRawExpression(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.stack = []byte{0xcc}
	if err := controller.showExamine(context.Background(), "2i", "$rip"); err != nil {
		t.Fatal(err)
	}
	if len(fixture.codeCalls) != 1 || fixture.codeCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x401001, 30}) ||
		len(fixture.stackCalls) != 0 || len(fixture.locationTokens) != 1 ||
		strings.Count(output.String(), "  nop\n") != 2 || strings.Contains(output.String(), "=>") || strings.Contains(output.String(), "int3") {
		t.Fatalf("wrong instruction path: output=%q fixture=%+v", output.String(), fixture)
	}
	controller, fixture, output = newInspectionTestController()
	if err := controller.showExamine(context.Background(), "1i", "$rip - 1"); err != nil {
		t.Fatal(err)
	}
	if fixture.codeCalls[0].address != 0x401000 || !strings.Contains(output.String(), "=> 0x0000000000401000") {
		t.Fatalf("wrong current marker: output=%q fixture=%+v", output.String(), fixture)
	}
}

func TestExamineRequiresExplicitAddressAndBoundsBeforeReading(t *testing.T) {
	for _, test := range []struct{ spec, expression string }{
		{"", ""}, {"1i", ""}, {"s", " "}, {"4097xb", "$rsp"}, {"513gx", "$rsp"},
		{"1xg", "0xffffffffffffffff"}, {"2xb", "0xffffffffffffffff"}, {"1x", "$rsp 8"},
	} {
		t.Run(test.spec+"/"+test.expression, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			if err := controller.showExamine(context.Background(), test.spec, test.expression); err == nil ||
				len(fixture.stackCalls) != 0 || len(fixture.codeCalls) != 0 || output.Len() != 0 {
				t.Fatalf("invalid examine read: error=%v output=%q fixture=%+v", err, output.String(), fixture)
			}
		})
	}
}

func TestExaminePartialReadsNeverInventAUnit(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.stack = []byte{1, 2, 3, 4, 5, 6}
	fixture.stackErr = io.ErrUnexpectedEOF
	err := controller.showExamine(context.Background(), "2xw", "$rsp")
	if !errors.Is(err, target.ErrPartial) || output.String() != "0x0000000070000000:\t0x04030201\t<partial bytes: 05 06>\n" {
		t.Fatalf("partial units padded: error=%v output=%q", err, output.String())
	}
}

func TestExamineStaleAndInvalidReadCounts(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
		err   error
		want  error
	}{
		{"stale", 4, target.ErrStale, target.ErrStale},
		{"negative", -1, nil, target.ErrUnknown},
		{"too-large", 5, nil, target.ErrUnknown},
		{"empty", 0, nil, io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, fixture, output := newInspectionTestController()
			fixture.stackCount, fixture.stackErr = &test.count, test.err
			err := controller.showExamine(context.Background(), "1xw", "$rsp")
			if !errors.Is(err, test.want) || output.Len() != 0 || len(fixture.stackCalls) != 1 || fixture.snapshotReads != 1 {
				t.Fatalf("invalid count used: error=%v output=%q fixture=%+v", err, output.String(), fixture)
			}
		})
	}
}

func fixtureStringMemory(fixture *inspectionReadFixture, base target.Address, data []byte) {
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if address < base || uint64(address-base) >= uint64(len(data)) {
			return 0, io.EOF
		}
		return copy(dst, data[int(address-base):]), nil
	}
}

func TestExamineStringsAreExplicitAndNULTerminated(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixtureStringMemory(fixture, 0x1000, []byte{'A', '\n', 0x1b, 0xff, 0, 0, 'B', 0, 'X'})
	if err := controller.showExamine(context.Background(), "3s", "0x1000"); err != nil {
		t.Fatal(err)
	}
	want := "0x0000000000001000:\t\"A\\n\\x1b\\xff\"\n0x0000000000001005:\t\"\"\n0x0000000000001006:\t\"B\"\n"
	if output.String() != want || len(fixture.stackCalls) != 8 || len(fixture.codeCalls) != 0 || len(fixture.locationTokens) != 0 {
		t.Fatalf("wrong explicit string output: %q calls=%+v", output.String(), fixture.stackCalls)
	}
	for i, call := range fixture.stackCalls {
		if call.token != fixture.snapshot.Memory || call.address != 0x1000+target.Address(i) || call.size != 1 {
			t.Fatalf("string token/address changed: %+v", call)
		}
	}
}

func TestExamineStringsDoNotFollowPointers(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixtureStringMemory(fixture, 0x1000, []byte{0x20, 0x10, 0, 0, 0, 0, 0, 0})
	if err := controller.showExamine(context.Background(), "s", "0x1000"); err != nil {
		t.Fatal(err)
	}
	if output.String() != "0x0000000000001000:\t\" \\x10\"\n" || len(fixture.stackCalls) != 3 {
		t.Fatalf("string followed pointer: output=%q calls=%+v", output.String(), fixture.stackCalls)
	}
}

func TestExamineStringsIncompleteReadReturnsErrorAndPrefix(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixtureStringMemory(fixture, 0x1000, []byte("hello"))
	err := controller.showExamine(context.Background(), "s", "0x1000")
	if !errors.Is(err, io.EOF) || output.String() != "0x0000000000001000:\t\"hello\" <unterminated>\n" || len(fixture.stackCalls) != 6 {
		t.Fatalf("incomplete string: error=%v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
	}
}

func TestExamineStringReadErrorAfterConfirmedByte(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.readRaw = func(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
		dst[0] = 'X'
		return 1, io.ErrUnexpectedEOF
	}
	err := controller.showExamine(context.Background(), "s", "0x1000")
	if !errors.Is(err, io.ErrUnexpectedEOF) || output.String() != "0x0000000000001000:\t\"X\" <unterminated>\n" || len(fixture.stackCalls) != 1 {
		t.Fatalf("lost confirmed string byte: error=%v output=%q fixture=%+v", err, output.String(), fixture)
	}
}

func TestExamineStringLimitsAndAddressOverflow(t *testing.T) {
	t.Run("byte-limit", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixtureStringMemory(fixture, 0x1000, bytes.Repeat([]byte{'A'}, maxMemoryBytes+1))
		err := controller.showExamine(context.Background(), "s", "0x1000")
		if !errors.Is(err, target.ErrUnavailable) || len(fixture.stackCalls) != maxMemoryBytes ||
			strings.Count(output.String(), "A") != maxMemoryBytes || !strings.Contains(output.String(), "<unterminated>") {
			t.Fatalf("unbounded string: error=%v reads=%d output length=%d", err, len(fixture.stackCalls), output.Len())
		}
	})
	t.Run("nul-at-limit", func(t *testing.T) {
		controller, fixture, _ := newInspectionTestController()
		data := bytes.Repeat([]byte{'A'}, maxMemoryBytes)
		data[len(data)-1] = 0
		fixtureStringMemory(fixture, 0x1000, data)
		if err := controller.showExamine(context.Background(), "s", "0x1000"); err != nil || len(fixture.stackCalls) != maxMemoryBytes {
			t.Fatalf("bounded NUL string: error=%v reads=%d", err, len(fixture.stackCalls))
		}
	})
	t.Run("count-limit", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixtureStringMemory(fixture, 0x1000, make([]byte, maxMemoryBytes+1))
		if err := controller.showExamine(context.Background(), "4096s", "0x1000"); err != nil || len(fixture.stackCalls) != maxMemoryBytes || strings.Count(output.String(), ":\t\"\"\n") != maxMemoryBytes {
			t.Fatalf("bounded empty strings: error=%v reads=%d", err, len(fixture.stackCalls))
		}
	})
	t.Run("last-address", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixtureStringMemory(fixture, math.MaxUint64, []byte{'A'})
		err := controller.showExamine(context.Background(), "s", "0xffffffffffffffff")
		if !errors.Is(err, target.ErrOverflow) || len(fixture.stackCalls) != 1 || !strings.Contains(output.String(), "\"A\" <unterminated>") {
			t.Fatalf("address wrapped: error=%v reads=%+v output=%q", err, fixture.stackCalls, output.String())
		}
	})
	t.Run("last-address-nul", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		fixtureStringMemory(fixture, math.MaxUint64, []byte{0})
		if err := controller.showExamine(context.Background(), "s", "0xffffffffffffffff"); err != nil || len(fixture.stackCalls) != 1 || output.String() != "0xffffffffffffffff:\t\"\"\n" {
			t.Fatalf("last NUL: error=%v reads=%+v output=%q", err, fixture.stackCalls, output.String())
		}
	})
}

func TestExamineStringsStopOnStaleTokenWithoutShowingStalePrefix(t *testing.T) {
	controller, fixture, output := newInspectionTestController()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		dst[0] = 'A'
		if address == 0x1001 {
			return 1, target.ErrStale
		}
		return 1, nil
	}
	err := controller.showExamine(context.Background(), "s", "0x1000")
	if !errors.Is(err, target.ErrStale) || len(fixture.stackCalls) != 2 || output.Len() != 0 || fixture.snapshotReads != 1 {
		t.Fatalf("stale string continued: error=%v output=%q fixture=%+v", err, output.String(), fixture)
	}
}

func TestExamineStringsStopOnCancellationAndOutputFailure(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		controller, fixture, output := newInspectionTestController()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fixture.readRaw = func(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
			dst[0] = 'A'
			cancel()
			return 1, nil
		}
		if err := controller.showExamine(ctx, "s", "0x1000"); !errors.Is(err, context.Canceled) || len(fixture.stackCalls) != 1 || output.Len() != 0 {
			t.Fatalf("cancellation: error=%v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
		}
	})
	t.Run("output", func(t *testing.T) {
		controller, fixture, _ := newInspectionTestController()
		fixtureStringMemory(fixture, 0x1000, []byte{0, 0})
		want := errors.New("output stopped")
		controller.out = contextFailingWriter{err: want}
		var outputErr *OutputError
		err := controller.showExamine(context.Background(), "2s", "0x1000")
		if !errors.Is(err, want) || !errors.As(err, &outputErr) || len(fixture.stackCalls) != 1 {
			t.Fatalf("output failure continued: error=%v calls=%+v", err, fixture.stackCalls)
		}
	})
}
