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
	"fastdbg2/native"
	"fastdbg2/target"
)

type contextMemoryCall struct {
	token   target.MemoryToken
	address target.Address
	size    int
}

type contextReadFixture struct {
	session
	snapshot        target.Snapshot
	snapshotErr     error
	snapshotReads   int
	registers       []target.Register
	registerErr     error
	location        native.CodeLocation
	locationErr     error
	code            []byte
	codeErr         error
	codeCount       *int
	stack           []byte
	stackErr        error
	stackCount      *int
	registerTokens  []target.ThreadToken
	locationTokens  []target.ThreadToken
	codeCalls       []contextMemoryCall
	stackCalls      []contextMemoryCall
	onReadRegisters func()
}

func (fixture *contextReadFixture) PID() int { return 1234 }

func (fixture *contextReadFixture) Snapshot() (target.Snapshot, error) {
	fixture.snapshotReads++
	return fixture.snapshot, fixture.snapshotErr
}

func (fixture *contextReadFixture) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	fixture.registerTokens = append(fixture.registerTokens, token)
	if fixture.onReadRegisters != nil {
		fixture.onReadRegisters()
	}
	return fixture.registers, fixture.registerErr
}

func (fixture *contextReadFixture) ReadCodeLocation(token target.ThreadToken) (native.CodeLocation, error) {
	fixture.locationTokens = append(fixture.locationTokens, token)
	return fixture.location, fixture.locationErr
}

func (fixture *contextReadFixture) ReadCodeMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	fixture.codeCalls = append(fixture.codeCalls, contextMemoryCall{token, address, len(dst)})
	n := copy(dst, fixture.code)
	if fixture.codeCount != nil {
		n = *fixture.codeCount
	}
	return n, fixture.codeErr
}

func (fixture *contextReadFixture) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	fixture.stackCalls = append(fixture.stackCalls, contextMemoryCall{token, address, len(dst)})
	n := copy(dst, fixture.stack)
	if fixture.stackCount != nil {
		n = *fixture.stackCount
	}
	return n, fixture.stackErr
}

func contextTestRegister(name string, value uint64) target.Register {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, value)
	return target.Register{Name: name, Bits: 64, Data: data, Available: true}
}

func newContextFixture() (*contextReadFixture, target.Snapshot, target.ThreadInfo) {
	ref := target.ThreadRef{Session: 4, ID: 2}
	process := target.ProcessRef{Session: 4, ID: 1}
	pc, breakpoint := target.Address(0x401001), target.Address(0x401000)
	thread := target.ThreadInfo{
		Ref: ref, Process: process, TID: 1234, State: target.StateStopped, Name: "test",
		Token: target.ThreadToken{Thread: ref, Stop: 7, Registers: 9},
		Stop:  target.Stop{Reason: target.StopBreakpoint, RawPC: &pc, Breakpoint: &breakpoint},
	}
	snapshot := target.Snapshot{
		Sequence: 10, State: target.StateStopped, Architecture: target.AMD64, Process: process,
		Threads: []target.ThreadInfo{thread},
		Memory:  target.MemoryToken{Space: target.SpaceRef{Session: 4, ID: 3}, Revision: 12},
	}
	fixture := &contextReadFixture{
		snapshot: snapshot,
		registers: []target.Register{
			contextTestRegister("rax", 0x1234),
			contextTestRegister("rip", uint64(pc)),
			contextTestRegister("rsp", 0x70000000),
		},
		location: native.CodeLocation{RawPC: pc, InstructionPC: breakpoint, Breakpoint: &breakpoint},
		code:     bytes.Repeat([]byte{0x90}, contextCodeBytes),
		stack:    make([]byte, contextStackBytes),
	}
	for i := range fixture.stack {
		fixture.stack[i] = byte(i)
	}
	return fixture, snapshot, thread
}

func contextTestOutput(buffer io.Writer, renderer display.Renderer) contextOutput {
	return contextOutput{
		writef: func(format string, args ...any) error {
			_, err := fmt.Fprintf(buffer, format, args...)
			return err
		},
		renderer: renderer,
	}
}

func contextPlainHeading(name string) string {
	return (display.Renderer{}).Section(name, 100) + "\n"
}

func TestContextCurrentCodeAndRawRegisters(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	var output bytes.Buffer
	if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"Thread #2 (TID 1234) \"test\" — stopped: breakpoint\n",
		contextPlainHeading("registers"),
		"* 2     1234     1",
		"[registers]",
		"$rip   : 0x0000000000401001",
		"*-> 0x0000000000401000  90",
		"[stack]",
		"$rsp>     0x0000000070000000|+0x0000|+000: 0x0706050403020100\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
	if strings.Count(text, " 90 nop\n") != contextInstructionCount || strings.Contains(text, "\x1b") {
		t.Fatalf("unexpected instruction count or color:\n%s", text)
	}
	if len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != thread.Token ||
		len(fixture.locationTokens) != 1 || fixture.locationTokens[0] != thread.Token {
		t.Fatalf("thread token changed: registers=%+v location=%+v", fixture.registerTokens, fixture.locationTokens)
	}
	if len(fixture.codeCalls) != 1 || fixture.codeCalls[0] != (contextMemoryCall{snapshot.Memory, 0x401000, contextCodeBytes}) {
		t.Fatalf("code calls: %+v", fixture.codeCalls)
	}
	if len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{snapshot.Memory, 0x70000000, contextStackBytes}) {
		t.Fatalf("stack calls: %+v", fixture.stackCalls)
	}
	if *thread.Stop.RawPC != 0x401001 || fixture.registers[1].Data[0] != 1 {
		t.Fatal("display mutated raw stop or register values")
	}
}

func TestContextIgnoresHistoricalBreakpointLocation(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	oldPC, oldBreakpoint := target.Address(0xdeadbeef), target.Address(0xdeadbeee)
	thread.Stop.RawPC, thread.Stop.Breakpoint = &oldPC, &oldBreakpoint
	fixture.location = native.CodeLocation{RawPC: 0x401001, InstructionPC: 0x401001}
	var output bytes.Buffer
	if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, "deadbe") || strings.Contains(text, " breakpoint=") ||
		!strings.Contains(text, " -> 0x0000000000401001") {
		t.Fatalf("history was used as current code location:\n%s", text)
	}
	if fixture.codeCalls[0].address != fixture.location.InstructionPC {
		t.Fatalf("code address: %+v", fixture.codeCalls)
	}
}

func TestContextUnavailableCodePreservesRawRegisters(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	fixture.locationErr = target.ErrUnavailable
	var output bytes.Buffer
	if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "$rip   : 0x0000000000401001") ||
		!strings.Contains(text, contextPlainHeading("code")+"  unavailable: unavailable\n") ||
		strings.Contains(text, "instruction-pc=") || len(fixture.codeCalls) != 0 || len(fixture.stackCalls) != 1 {
		t.Fatalf("unavailable code handling:\n%s\ncalls=%+v %+v", text, fixture.codeCalls, fixture.stackCalls)
	}
}

func TestContextStaleTokensAreNotRetried(t *testing.T) {
	for _, failure := range []string{"registers", "location", "code", "pc-mismatch", "breakpoint-mismatch"} {
		t.Run(failure, func(t *testing.T) {
			fixture, snapshot, thread := newContextFixture()
			switch failure {
			case "registers":
				fixture.registerErr = target.ErrStale
			case "location":
				fixture.locationErr = target.ErrStale
			case "code":
				fixture.code, fixture.codeErr = nil, target.ErrStale
			case "pc-mismatch":
				fixture.location.RawPC++
			case "breakpoint-mismatch":
				other := *fixture.location.Breakpoint + 1
				fixture.location.Breakpoint = &other
			}
			var output bytes.Buffer
			if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); !errors.Is(err, target.ErrStale) {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "stale state") ||
				len(fixture.registerTokens) != 1 || len(fixture.locationTokens) > 1 ||
				len(fixture.codeCalls) > 1 || len(fixture.stackCalls) != 0 {
				t.Fatalf("stale read was retried or used:\n%s\nfixture=%+v", output.String(), fixture)
			}
			if failure == "registers" && (len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0) {
				t.Fatalf("read after stale registers: %+v", fixture)
			}
		})
	}
}

func TestContextPartialReadsOnlyDisplayConfirmedBytes(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	fixture.code = []byte{0x90, 0x48, 0x89}
	fixture.codeErr = io.ErrUnexpectedEOF
	fixture.stack = fixture.stack[:10]
	fixture.stackErr = io.ErrUnexpectedEOF
	var output bytes.Buffer
	if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); !errors.Is(err, target.ErrPartial) {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Count(text, " 90 nop\n") != 1 || strings.Contains(text, "0x0000000000401003") ||
		!strings.Contains(text, "3 of 120 confirmed") ||
		!strings.Contains(text, "0x0000000070000008|+0x0008|+001: <partial bytes: 08 09>\n") ||
		strings.Contains(text, "0x0000000070000010") ||
		!strings.Contains(text, "10 of 64 confirmed") {
		t.Fatalf("unconfirmed bytes rendered:\n%s", text)
	}
}

func TestContextInvalidReadCountsFailClosed(t *testing.T) {
	for _, count := range []int{-1, contextCodeBytes + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fixture, snapshot, thread := newContextFixture()
			fixture.codeCount = &count
			var output bytes.Buffer
			if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); !errors.Is(err, target.ErrUnknown) {
				t.Fatal(err)
			}
			text := output.String()
			if strings.Contains(text, "  nop\n") || !strings.Contains(text, "invalid memory read count") {
				t.Fatalf("invalid read count used:\n%s", text)
			}
		})
	}
}

func TestContextStackRequiresExactRegister(t *testing.T) {
	for _, state := range []string{"missing", "unavailable", "wrong-width", "bad-data", "duplicate"} {
		t.Run(state, func(t *testing.T) {
			fixture, snapshot, thread := newContextFixture()
			switch state {
			case "missing":
				fixture.registers = fixture.registers[:2]
			case "unavailable":
				fixture.registers[2].Available = false
			case "wrong-width":
				fixture.registers[2].Bits = 32
				fixture.registers[2].Data = fixture.registers[2].Data[:4]
			case "bad-data":
				fixture.registers[2].Data = nil
			case "duplicate":
				fixture.registers = append(fixture.registers, fixture.registers[2])
			}
			want := target.ErrUnavailable
			if state == "duplicate" {
				want = target.ErrAmbiguous
			}
			var output bytes.Buffer
			if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if len(fixture.stackCalls) != 0 || !strings.Contains(output.String(), contextPlainHeading("stack")+"  unavailable:") {
				t.Fatalf("invalid rsp used:\n%s\ncalls=%+v", output.String(), fixture.stackCalls)
			}
		})
	}
}

func TestContextRegisterValueFormatting(t *testing.T) {
	for _, test := range []struct {
		register target.Register
		want     string
	}{
		{contextTestRegister("rax", math.MaxUint64), "$rax   : 0xffffffffffffffff"},
		{target.Register{Name: "eax", Bits: 32, Available: true, Data: []byte{0x78, 0x56, 0x34, 0x12}}, "$eax   : 0x12345678"},
		{target.Register{Name: "rax"}, "$rax   : <unavailable>"},
		{target.Register{Name: "rax", Bits: 64, Available: true, Data: []byte{1}}, "$rax   : <invalid 64-bit value>"},
		{target.Register{Name: "bad\nname", Bits: 64}, `$bad\nname: <unavailable>`},
	} {
		if got := contextRegisterText(test.register); got != test.want {
			t.Fatalf("register %+v: got %q, want %q", test.register, got, test.want)
		}
	}
}

func TestContextExternalTextCannotControlTheTerminal(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	payload := "unsafe\x1b[31m\x07\u202e\nnext"
	fixture.registers[0].Name = payload
	fixture.locationErr = errors.New(payload)
	thread.Name = payload
	thread.Stop.Signal = target.Signal{Domain: target.SignalDomain(payload), Number: 5}
	var output bytes.Buffer
	if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); !errors.Is(err, fixture.locationErr) {
		t.Fatal(err)
	}
	text := output.String()
	if strings.ContainsAny(text, "\x1b\x07\u202e") || strings.Contains(text, "\nnext") {
		t.Fatalf("external terminal control leaked: %q", text)
	}
	for _, want := range []string{`\x1b[31m`, `\a`, `\u202e`, `\nnext`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing literal escape %q: %q", want, text)
		}
	}
}

func TestContextColorPolicyUsesDisplayRenderer(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := contextTestOutput(&output, renderer).context(context.Background(), fixture, snapshot, thread); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[registers]",
		"\x1b[34m0x0000000000401000\x1b[0m",
		"\x1b[36m0x0000000070000000\x1b[0m",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing display style %q:\n%q", want, output.String())
		}
	}
}

func TestContextCancellationAndOutputFailuresStopReading(t *testing.T) {
	t.Run("cancel-before", func(t *testing.T) {
		fixture, snapshot, thread := newContextFixture()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var output bytes.Buffer
		err := contextTestOutput(&output, display.Renderer{}).context(ctx, fixture, snapshot, thread)
		if !errors.Is(err, context.Canceled) || output.Len() != 0 || len(fixture.registerTokens) != 0 {
			t.Fatalf("canceled context: %v output=%q calls=%+v", err, output.String(), fixture.registerTokens)
		}
	})
	t.Run("cancel-after-registers", func(t *testing.T) {
		fixture, snapshot, thread := newContextFixture()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fixture.onReadRegisters = cancel
		var output bytes.Buffer
		err := contextTestOutput(&output, display.Renderer{}).context(ctx, fixture, snapshot, thread)
		if !errors.Is(err, context.Canceled) || len(fixture.locationTokens) != 0 || len(fixture.stackCalls) != 0 {
			t.Fatalf("read after cancellation: %v %+v", err, fixture)
		}
	})
	t.Run("writer", func(t *testing.T) {
		fixture, snapshot, thread := newContextFixture()
		want := errors.New("writer stopped")
		view := contextOutput{writef: func(string, ...any) error { return want }}
		err := view.context(context.Background(), fixture, snapshot, thread)
		if !errors.Is(err, want) || len(fixture.registerTokens) != 0 || len(fixture.locationTokens) != 0 {
			t.Fatalf("output failure: %v %+v", err, fixture)
		}
	})
}

func TestContextRejectsOtherArchitectures(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	snapshot.Architecture = target.AArch64
	var output bytes.Buffer
	err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread)
	if !errors.Is(err, target.ErrUnsupported) || output.Len() != 0 || len(fixture.registerTokens) != 0 {
		t.Fatalf("unexpected architecture: %v output=%q calls=%+v", err, output.String(), fixture.registerTokens)
	}
}

func TestContextAddressWidthBounds(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	fixture.registers[1] = contextTestRegister("rip", math.MaxUint64)
	fixture.registers[2] = contextTestRegister("rsp", math.MaxUint64)
	fixture.location = native.CodeLocation{RawPC: math.MaxUint64, InstructionPC: math.MaxUint64}
	var output bytes.Buffer
	if err := contextTestOutput(&output, display.Renderer{}).context(context.Background(), fixture, snapshot, thread); err != nil {
		t.Fatal(err)
	}
	if len(fixture.codeCalls) != 1 || fixture.codeCalls[0].size != 1 || len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 1 {
		t.Fatalf("address width overflow: code=%+v stack=%+v", fixture.codeCalls, fixture.stackCalls)
	}
	if !strings.Contains(output.String(), "0xffffffffffffffff|+0x0000|+000: <partial bytes: 00>\n") {
		t.Fatalf("single stack byte not preserved:\n%s", output.String())
	}
}

func TestMemoryArgumentsPreserveExpression(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		count int
	}{
		{"$rsp + 8", "$rsp + 8", 64},
		{" --count 16 $rip + 1 ", "$rip + 1", 16},
		{"--count\t4096\t`symbol with spaces` + 8", "`symbol with spaces` + 8", 4096},
		{"--count 1 0xffffffffffffffff", "0xffffffffffffffff", 1},
	} {
		expression, count, err := memoryArguments(test.input)
		if err != nil || expression != test.want || count != test.count {
			t.Fatalf("%q: expression=%q count=%d err=%v", test.input, expression, count, err)
		}
	}
	for _, input := range []string{"", " ", "--count", "--count 0 $rsp", "--count -1 $rsp", "--count 4097 $rsp", "--count 2", "--count nope $rsp", "--count 4294967296 $rsp"} {
		if _, _, err := memoryArguments(input); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%q: %v", input, err)
		}
	}
}

func TestContextConfirmedMemoryPrefix(t *testing.T) {
	for _, test := range []struct {
		name string
		n    int
		err  error
		size int
		want error
	}{
		{"full", 4, nil, 4, nil},
		{"partial", 2, io.ErrUnexpectedEOF, 2, target.ErrPartial},
		{"silent-short", 2, nil, 2, io.ErrUnexpectedEOF},
		{"empty", 0, nil, 0, io.ErrUnexpectedEOF},
		{"error-after-full", 4, target.ErrStale, 0, target.ErrStale},
		{"stale-partial", 2, target.ErrStale, 0, target.ErrStale},
		{"negative", -1, nil, 0, target.ErrUnknown},
		{"too-long", 5, nil, 0, target.ErrUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix, err := confirmedContextBytes([]byte{1, 2, 3, 4}, test.n, test.err)
			if len(prefix) != test.size || !errors.Is(err, test.want) {
				t.Fatalf("prefix=%v error=%v", prefix, err)
			}
		})
	}
}

func TestMemoryCommandUsesRawBytesAndActualRegisterExpression(t *testing.T) {
	fixture, snapshot, thread := newContextFixture()
	fixture.stack = []byte{0xcc, 0x48, 0x31, 0xc0}
	var output bytes.Buffer
	controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := controller.showMemory(context.Background(), "--count 4 $rip + 8"); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), contextPlainHeading("memory")+"0x0000000000401009  cc 48 31 c0\n"; got != want {
		t.Fatalf("raw memory: got %q, want %q", got, want)
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != thread.Token ||
		len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{snapshot.Memory, 0x401009, 4}) ||
		len(fixture.codeCalls) != 0 || len(fixture.locationTokens) != 0 {
		t.Fatalf("raw memory command used wrong API or token: %+v", fixture)
	}
}

func TestMemoryCommandRangeAndArgumentsFailBeforeMemoryRead(t *testing.T) {
	for _, input := range []string{"--count 0 $rsp", "--count 4097 $rsp", "--count 8 0xffffffffffffffff"} {
		t.Run(input, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			var output bytes.Buffer
			controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
			err := controller.showMemory(context.Background(), input)
			want := target.ErrInvalidArgument
			if strings.HasSuffix(input, "0xffffffffffffffff") {
				want = target.ErrOverflow
			}
			if !errors.Is(err, want) || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("invalid range or count was read: %v output=%q calls=%+v", err, output.String(), fixture.stackCalls)
			}
		})
	}
}

func TestContextCommandsRequireSelectedStoppedThread(t *testing.T) {
	for _, command := range []string{"context", "regs", "memory"} {
		for _, state := range []string{"no-selection", "running", "other-process", "snapshot-error"} {
			t.Run(command+"/"+state, func(t *testing.T) {
				fixture, _, thread := newContextFixture()
				var output bytes.Buffer
				controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
				switch state {
				case "no-selection":
					controller.selected = target.ThreadRef{}
				case "running":
					fixture.snapshot.State = target.StateRunning
				case "other-process":
					fixture.snapshot.Threads[0].Process.ID++
				case "snapshot-error":
					fixture.snapshotErr = target.ErrStale
				}
				args := ""
				if command == "memory" {
					args = "$rsp"
				}
				exit, err := controller.Execute(context.Background(), command, args)
				if exit || err == nil || output.Len() != 0 || len(fixture.registerTokens) != 0 ||
					len(fixture.locationTokens) != 0 || len(fixture.stackCalls) != 0 {
					t.Fatalf("invalid inspection allowed: exit=%t err=%v output=%q fixture=%+v", exit, err, output.String(), fixture)
				}
			})
		}
	}
}

func TestRegistersCommandReadsOnlyActualSelectedRegisters(t *testing.T) {
	fixture, _, thread := newContextFixture()
	var output bytes.Buffer
	controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
	if err := controller.showRegisters(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), contextPlainHeading("registers")) ||
		!strings.Contains(output.String(), "$rip   : 0x0000000000401001") ||
		len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != thread.Token ||
		len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0 || len(fixture.stackCalls) != 0 {
		t.Fatalf("register command performed unexpected inspection:\n%s\n%+v", output.String(), fixture)
	}
}

type contextFailingWriter struct {
	err error
}

func (writer contextFailingWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestContextCommandsPreserveOutputErrors(t *testing.T) {
	for _, command := range []string{"context", "regs", "memory"} {
		t.Run(command, func(t *testing.T) {
			fixture, _, thread := newContextFixture()
			want := errors.New("writer failed")
			controller := &Controller{session: fixture, selected: thread.Ref, out: contextFailingWriter{want}}
			args := ""
			if command == "memory" {
				args = "--count 8 $rsp"
			}
			_, err := controller.Execute(context.Background(), command, args)
			var outputErr *OutputError
			if !errors.Is(err, want) || !errors.As(err, &outputErr) {
				t.Fatalf("output error was hidden: %v", err)
			}
		})
	}
}
