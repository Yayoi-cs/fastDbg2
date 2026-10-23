package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"fastdbg2/display"
	"fastdbg2/target"
)

func addressTextFixture(t *testing.T, data []byte) (*addressWalker, *addressWalkTestSession) {
	t.Helper()
	_, fixture, _ := newAddressWalkTestController()
	fixture.rawBase = 0x1000
	fixture.stack = append([]byte(nil), data...)
	fixture.mappings = []procMap{{Start: 0x1000, End: 0x1000 + target.Address(len(data)), Read: true}}
	return addressWalkTestView(t, fixture, display.Renderer{}), fixture
}

func TestAddressTextStrictPredicateUsesTheReadWordSource(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{"shell", []byte("SHELL=/bin/bash\x00"), "'SHELL=/bin/bash'"},
		{"quotes", []byte("A'B\"C\\D\x00"), `'A\'B"C\\D'`},
		{"one", []byte{'A', 0, 255, 255, 255, 255, 255, 255}, "'A'"},
		{"space", []byte{' ', 0, 255, 255, 255, 255, 255, 255}, "' '"},
		{"utf8", []byte("日本語☃\x00"), "'日本語☃'"},
		{"split-utf8", []byte("abcdefg日本語\x00"), "'abcdefg日本語'"},
		{"empty", []byte{0, 255, 255, 255, 255, 255, 255, 255}, ""},
		{"invalid", []byte{'A', 255, 0, 0, 0, 0, 0, 0}, ""},
		{"incomplete", []byte{'A', 0xe3, 0x81, 0, 0, 0, 0, 0}, ""},
		{"control", []byte("A\tB\nC\x00ZZ"), ""},
		{"escape", []byte("AA\x1b[31mZ\x00"), ""},
		{"bidi", []byte("AB\u202eCD\x00"), ""},
		{"del", []byte{'A', 127, 0, 0, 0, 0, 0, 0}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			walker, fixture := addressTextFixture(t, test.data)
			text, err := walker.Value(context.Background(), 0x1000, 4)
			want := fmt.Sprintf("0x0000000000001000 -> 0x%016x", binary.LittleEndian.Uint64(test.data[:8]))
			if test.want != "" {
				want += " " + test.want
			}
			if err != nil || text != want || strings.ContainsAny(text, "\n\r\x1b") {
				t.Fatalf("text=%q want=%q error=%v", text, want, err)
			}
			if test.want == "" && len(fixture.stackCalls) != 1 {
				t.Fatalf("negative first qword caused extra reads: %+v", fixture.stackCalls)
			}
			calls := len(fixture.stackCalls)
			if repeated, err := walker.Value(context.Background(), 0x1000, 4); err != nil || repeated != text || len(fixture.stackCalls) != calls {
				t.Fatalf("source cache reread: text=%q error=%v calls=%+v", repeated, err, fixture.stackCalls)
			}
			for _, call := range fixture.stackCalls {
				if call.token != fixture.snapshot.Memory || call.address < 0x1000 || call.address+target.Address(call.size) > 0x1000+target.Address(len(test.data)) {
					t.Fatalf("text escaped map or memory token: %+v", call)
				}
			}
		})
	}
}

func TestAddressTextNeverInventsRegisterBytesOrReplacesPointerEdges(t *testing.T) {
	_, fixture, _ := newAddressWalkTestController()
	walker := addressWalkTestView(t, fixture, display.Renderer{})
	immediate := uint64(0x622f3d4c4c454853)
	text, err := walker.Value(context.Background(), immediate, 4)
	if err != nil || text != "0x622f3d4c4c454853" || len(fixture.stackCalls) != 0 {
		t.Fatalf("register immediate interpreted as memory text: %q %v %+v", text, err, fixture.stackCalls)
	}
	fixture.mappings = []procMap{{Start: 0x1000, End: 0x1008, Read: true}, {Start: 0x41414141, End: 0x41414149, Read: true}}
	addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 0x41414141, 0x41414141: 1})
	for _, depth := range []int{0, 1, 4} {
		fixture.stackCalls = nil
		walker = addressWalkTestView(t, fixture, display.Renderer{})
		text, err := walker.Value(context.Background(), 0x1000, depth)
		if err != nil || strings.Contains(text, "'") || walker.textCalls != 0 || len(fixture.stackCalls) != min(depth, 2) {
			t.Fatalf("depth %d changed pointer edges: %q %v %+v", depth, text, err, fixture.stackCalls)
		}
	}
	addressWalkTestWords(fixture, map[target.Address]uint64{0x1000: 0x41414141, 0x41414141: 0x41414141})
	walker = addressWalkTestView(t, fixture, display.Renderer{})
	text, err = walker.Value(context.Background(), 0x1000, 4)
	if err != nil || text != "0x0000000000001000 -> 0x0000000041414141 -> [loop detected]" || walker.textCalls != 0 {
		t.Fatalf("text probe replaced a cycle: %q %v", text, err)
	}
}

func TestAddressTextDirectRowsAndShortGuardRetainRawFacts(t *testing.T) {
	walker, fixture := addressTextFixture(t, []byte("SHELL=/bin/bash\x00"))
	text, err := walker.Rows(context.Background(), 0x1000, 1, 4)
	if err != nil || !strings.HasSuffix(text, "0x622f3d4c4c454853 'SHELL=/bin/bash'\n") || strings.Count(text, "\n") != 1 {
		t.Fatalf("direct qword source lost: %q %v", text, err)
	}
	for _, data := range [][]byte{[]byte("hi\x00"), []byte("日\x00"), []byte("A\x00"), []byte("NO!")} {
		walker, fixture = addressTextFixture(t, data)
		text, err := walker.Value(context.Background(), 0x1000, 4)
		want := "0x0000000000001000"
		if data[len(data)-1] == 0 {
			want += " '" + string(data[:len(data)-1]) + "'"
		}
		if err != nil || text != want || len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x1000, len(data)}) || walker.reads != 0 {
			t.Fatalf("short guard synthesized a qword: %q %v %+v", text, err, fixture.stackCalls)
		}
	}
	walker, fixture = addressTextFixture(t, []byte("hi\x00"))
	fixture.mappings = append(fixture.mappings, procMap{Start: 0x1003, End: 0x1010})
	walker = addressWalkTestView(t, fixture, display.Renderer{})
	if text, err = walker.Value(context.Background(), 0x1000, 4); err != nil || text != "0x0000000000001000 'hi'" || len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 3 {
		t.Fatalf("short string crossed unreadable next mapping: %q %v %+v", text, err, fixture.stackCalls)
	}
	walker, fixture = addressTextFixture(t, []byte("hi\x00"))
	text, err = walker.Rows(context.Background(), 0x1000, 1, 4)
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(text, "<partial 3/8: 68 69 00>") || strings.Contains(text, "'hi'") || len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 8 {
		t.Fatalf("required raw qword partial was hidden: %q %v %+v", text, err, fixture.stackCalls)
	}
	fixture.mappings[0].Read = false
	walker = addressWalkTestView(t, fixture, display.Renderer{})
	fixture.stackCalls = nil
	if text, err = walker.Value(context.Background(), 0x1000, 4); err != nil || text != "0x0000000000001000" || len(fixture.stackCalls) != 0 {
		t.Fatalf("unreadable mapping probed: %q %v %+v", text, err, fixture.stackCalls)
	}
}

func TestAddressTextNULAndDisplayLimitsAreIndependent(t *testing.T) {
	for _, length := range []int{62, 63, 255, 256} {
		data := append([]byte(strings.Repeat("A", length)), 0)
		walker, fixture := addressTextFixture(t, data)
		text, err := walker.Value(context.Background(), 0x1000, 4)
		if err != nil || strings.Contains(text, "'") != (length < 256) {
			t.Fatalf("length %d: %q %v", length, text, err)
		}
		for _, call := range fixture.stackCalls {
			if call.address+target.Address(call.size) > 0x1100 {
				t.Fatalf("probe exceeded 256 bytes: %+v", call)
			}
		}
	}
	for _, text := range []string{strings.Repeat("a", 62), strings.Repeat("a", 63), strings.Repeat("日", 32), strings.Repeat("'\\", 32), strings.Repeat("e\u0301", 70)} {
		quoted := addressTextQuote(text)
		if !utf8.ValidString(quoted) || display.VisibleWidth(quoted) > maxAddressTextWidth || !strings.HasPrefix(quoted, "'") {
			t.Fatalf("invalid display limit/encoding: %q", quoted)
		}
		if text != strings.Repeat("a", 62) && !strings.HasSuffix(quoted, "'...") {
			t.Fatalf("truncation was not explicit: %q", quoted)
		}
	}
}

func TestAddressTextCachesOverlappingSuccessfulBytes(t *testing.T) {
	data := append([]byte(strings.Repeat("A", 80)), 0)
	walker, fixture := addressTextFixture(t, data)
	if _, err := walker.Value(context.Background(), 0x1000, 4); err != nil {
		t.Fatal(err)
	}
	calls := len(fixture.stackCalls)
	for _, address := range []target.Address{0x1000, 0x1001, 0x1008, 0x1001} {
		if text, err := walker.Value(context.Background(), uint64(address), 4); err != nil || !strings.Contains(text, "'") || len(fixture.stackCalls) != calls {
			t.Fatalf("overlap reread: address=%#x text=%q error=%v calls=%+v", address, text, err, fixture.stackCalls)
		}
	}
	seen := map[target.Address]bool{}
	for _, call := range fixture.stackCalls {
		for offset := 0; offset < call.size; offset++ {
			address := call.address + target.Address(offset)
			if seen[address] {
				t.Fatalf("successful byte was read twice: %#x %+v", address, fixture.stackCalls)
			}
			seen[address] = true
		}
	}
	if len(seen) != len(data) {
		t.Fatalf("wrong confirmed extent: %d want %d", len(seen), len(data))
	}
}

func TestAddressTextOptionalFailuresOmitButStaleAndCancelDiscard(t *testing.T) {
	for _, failure := range []error{target.ErrPartial, target.ErrUnavailable, target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		walker, fixture := addressTextFixture(t, []byte(strings.Repeat("A", 64)))
		fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
			if address == 0x1000 && len(data) == 8 {
				copy(data, "ABCDEFGH")
				return 8, nil
			}
			copy(data, []byte{'I', 0})
			return 2, failure
		}
		text, err := walker.Value(context.Background(), 0x1000, 4)
		if addressWalkFatal(failure) {
			if !errors.Is(err, failure) || text != "" {
				t.Fatalf("fatal preview retained prefix: %q %v", text, err)
			}
		} else if err != nil || text != "0x0000000000001000 -> 0x4847464544434241" {
			t.Fatalf("optional failure changed raw chain: %q %v", text, err)
		}
		calls := len(fixture.stackCalls)
		walker.Value(context.Background(), 0x1000, 4)
		if len(fixture.stackCalls) != calls {
			t.Fatalf("failed source retried: %+v", fixture.stackCalls)
		}
	}
	walker, fixture := addressTextFixture(t, []byte(strings.Repeat("A", 64)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
		copy(data, "ABCDEFGH")
		if address != 0x1000 {
			cancel()
		}
		return len(data), nil
	}
	if text, err := walker.Value(ctx, 0x1000, 4); text != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("successful read raced cancellation: %q %v", text, err)
	}
}

func TestAddressTextBudgetsDoNotTakeQwordBudget(t *testing.T) {
	data := []byte(strings.Repeat(strings.Repeat("A", 255)+"\x00", 128))
	walker, fixture := addressTextFixture(t, data)
	for index := 0; index < 128; index++ {
		text, err := walker.Value(context.Background(), uint64(0x1000+index*256), 4)
		if err != nil || !strings.HasSuffix(text, "'...") {
			t.Fatalf("default telescope annotation %d omitted: %q %v", index, text, err)
		}
	}
	if walker.reads != 128 || walker.textRead != 128*248 || walker.textCalls != 128*8 {
		t.Fatalf("wrong resource accounting: qword=%d bytes=%d calls=%d", walker.reads, walker.textRead, walker.textCalls)
	}
	for _, call := range fixture.stackCalls {
		if call.size > maxAddressTextChunk || call.token != fixture.snapshot.Memory {
			t.Fatalf("probe size or token changed: %+v", call)
		}
	}
	for _, exhausted := range []string{"bytes", "calls"} {
		walker, fixture = addressTextFixture(t, []byte("SHELL=/bin/bash\x00"))
		if exhausted == "bytes" {
			walker.textRead = maxAddressTextRead
		} else {
			walker.textCalls = maxAddressTextCalls
		}
		text, err := walker.Value(context.Background(), 0x1000, 4)
		if err != nil || strings.Contains(text, "'") || walker.reads != 1 || len(fixture.stackCalls) != 1 {
			t.Fatalf("text budget consumed pointer budget: %q %v %+v", text, err, fixture.stackCalls)
		}
	}
}

func TestAddressTextControllerDiscardKeepsBothFatalCauses(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
		if address == 0x1000 && len(data) == 8 {
			copy(data, "ABCDEFGH")
			return 8, nil
		}
		cancel()
		return 0, target.ErrStale
	}
	if err := controller.showTelescope(ctx, "0x1000 1"); !errors.Is(err, target.ErrStale) || !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("fatal annotation published or lost a cause: %q %v", output.String(), err)
	}
	controller, fixture, output = newAddressWalkTestController()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
		clear(data)
		if address == 0x1000 {
			copy(data, "ABCDEFGH")
		} else {
			fixture.snapshot.Memory.Revision++
		}
		return len(data), nil
	}
	if err := controller.showTelescope(context.Background(), "0x1000 1"); !errors.Is(err, target.ErrStale) || output.Len() != 0 {
		t.Fatalf("post-preview token mismatch published: %q %v", output.String(), err)
	}
}
