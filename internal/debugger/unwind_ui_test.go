package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

type unwindUISession struct {
	*controllerTestSession
	snapshots int
}

func (session *unwindUISession) Snapshot() (target.Snapshot, error) {
	session.snapshots++
	return session.controllerTestSession.Snapshot()
}

func unwindUIFixture() (*Controller, unwindCommandSeed, inspect.UnwindResult, *unwindUISession) {
	session := &unwindUISession{controllerTestSession: controllerSession(71)}
	thread := session.snapshot.Threads[0]
	thread.Ref.ID, thread.Token.Thread.ID, thread.TID = 7, 7, 1234
	session.snapshot.Threads[0] = thread
	address := target.Address(0x401000)
	seed := unwindCommandSeed{
		snapshot: session.snapshot, thread: thread, profile: inspect.UnwindSysVAMD64, abiExplicit: true,
		location: native.CodeLocation{RawPC: 0x401001, InstructionPC: address, Breakpoint: &address},
	}
	registers := inspect.AMD64UnwindRegisters{Known: 1<<7 | 1<<16}
	registers.Values[7], registers.Values[16], registers.Values[0] = 0x700000, 0x401001, 0xdeadbeef
	frame := inspect.UnwindFrame{
		PC: address, RawPC: 0x401001, LookupPC: address, Registers: registers,
		CFA: 0x700008, CFAKnown: true, CFARegister: 7, CFAOffset: 8,
		Source: "module=\"main\" proof=\"runtime\"\x1b[2J\n", FDE: 0x403040, Start: address, End: 0x401020,
		Saved: []inspect.UnwindSavedRegister{
			{Register: 0, Rule: "unavailable", Provenance: "unavailable", Address: 0xdeadbeef, Value: 0xdeadbeef},
			{Register: 7, Rule: "val_offset", Provenance: "abi:sysv-amd64", Value: 0x700008, Available: true},
			{Register: 16, Rule: "offset", Provenance: "cfi", Offset: -8, Address: 0x700000, AddressKnown: true, Value: 0x402008, Available: true},
		},
	}
	caller := inspect.UnwindFrame{PC: 0x402008, RawPC: 0x402008, LookupPC: 0x402007, ReturnPC: true, Signal: true}
	result := inspect.UnwindResult{Frames: []inspect.UnwindFrame{frame, caller}, Complete: true}
	controller := New(io.Discard, display.Renderer{})
	controller.session, controller.selected = session, thread.Ref
	return controller, seed, result, session
}

func unwindUICacheSymbols(t *testing.T, controller *Controller, seed *unwindCommandSeed, symbols []elf.Symbol) {
	t.Helper()
	path := imageTestELF(t, elf.ET_DYN, symbols)
	index, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x400000}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	seed.symbols, err = index.Symbols("main")
	if err != nil {
		t.Fatal(err)
	}
	seed.symbolKey = newUISymbolCacheKey(seed.snapshot, seed.thread)
}

func TestUnwindUICompactTraceUsesOnlyConfirmedFacts(t *testing.T) {
	controller, seed, result, session := unwindUIFixture()
	before, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := controller.backtraceText(seed, result)
	for _, expected := range []string{
		"[trace]", "Thread 7 (tid 1234) | ABI: sysv-amd64 (explicit)",
		"[*#0] 0x0000000000401000", "[ #1] 0x0000000000402008 [signal]",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{"lookup-pc=", "raw-rip=", "cfi-source=", "module=", "proof=", "Raw RIP:", "End of stack", "0x00000000deadbeef", "\x1b"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("trace leaked machine diagnostics or unconfirmed values %q:\n%s", forbidden, text)
		}
	}
	if display.VisibleWidth(strings.Split(text, "\n")[0]) != display.DefaultWidth {
		t.Fatalf("section width:\n%s", text)
	}
	after, err := json.Marshal(result)
	if err != nil || !bytes.Equal(before, after) || session.snapshots != 0 || len(session.registerReads) != 0 ||
		len(session.memoryReads) != 0 || session.runCalls != 0 || session.stepCalls != 0 {
		t.Fatalf("formatting read or changed target facts: %v", err)
	}
	t.Logf("\n%s", text)
}

func TestUnwindUITraceSummaryDoesNotInventBottom(t *testing.T) {
	controller, seed, result, _ := unwindUIFixture()
	seed.profile, seed.location = inspect.UnwindStrictCFI, native.CodeLocation{}
	for _, test := range []struct {
		complete bool
		limited  bool
		want     string
	}{
		{false, false, "Unwind incomplete: caller information unavailable."},
		{false, true, "Unwind partial: frame limit reached (2)."},
		{true, false, ""},
	} {
		result.Complete, result.Limited = test.complete, test.limited
		text := controller.backtraceText(seed, result)
		if !strings.Contains(text, "ABI: strict-cfi") || (test.want != "" && strings.Count(text, test.want) != 1) || (test.complete && strings.Contains(text, "Unwind")) || strings.Contains(text, "Raw RIP:") ||
			!test.complete && strings.Contains(text, "End of stack") {
			t.Fatalf("summary changed certainty:\n%s", text)
		}
	}
}

func TestUnwindUIStackFrameTablesKeepUnknownsAndProvenance(t *testing.T) {
	controller, seed, result, _ := unwindUIFixture()
	text := controller.stackFrameText(seed, result.Frames[0], 0)
	for _, expected := range []string{
		"[stackframe #0]", "CFA: 0x0000000000700008 ($rsp +8)", "CFI record: 0x403040",
		"[frame registers]", "$rax   <unavailable>", "$rsp   0x0000000000700000", "[caller recovery]",
		"Saved at / source", "Caller value", "Origin", "memory CFA-8", "value CFA+0",
		"0x0000000000700000", "0x0000000000402008", "CFI", "SysV",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "deadbeef") || strings.Contains(text, "proof=") || strings.ContainsRune(text, '\x1b') {
		t.Fatalf("invented or unsafe values:\n%s", text)
	}
	unknown := inspect.UnwindFrame{PC: 0x401000, CFA: 0xdeadbeef, CFARegister: 0, FDE: 0xdeadbeef}
	text = controller.stackFrameText(unwindCommandSeed{}, unknown, 4)
	if !strings.Contains(text, "CFA: <unavailable>") || !strings.Contains(text, "Caller recovery information unavailable.") ||
		!strings.Contains(text, "Thread <unavailable>") || strings.Contains(text, "deadbeef") ||
		strings.Contains(text, "CFI record:") || strings.Contains(text, "$rax +0") || strings.Contains(text, "Thread 0") {
		t.Fatalf("unknown frame invented facts:\n%s", text)
	}
	t.Logf("\n%s", controller.stackFrameText(seed, result.Frames[0], 0))
}

func TestUnwindUICachedSymbolsAreExactSpaceBoundAndReadFree(t *testing.T) {
	controller, seed, result, session := unwindUIFixture()
	unwindUICacheSymbols(t, controller, &seed, []elf.Symbol{{Name: "leaf", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1000, Size: 0x10}})
	result.Frames[0].PC, result.Frames[0].LookupPC = 0x401004, 0x401004
	text := controller.backtraceText(seed, result)
	if !strings.Contains(text, "0x0000000000401004 <leaf+0x4>") || session.snapshots != 0 ||
		len(session.registerReads) != 0 || len(session.memoryReads) != 0 {
		t.Fatalf("cached label or read contract:\n%s", text)
	}
	seed.snapshot.Memory.Space.ID++
	if text := controller.backtraceText(seed, result); strings.Contains(text, "leaf") {
		t.Fatalf("symbol from stale address space:\n%s", text)
	}
	seed.snapshot.Memory.Space.ID--
	result.Frames[0].PC, result.Frames[0].LookupPC = 0x401020, 0x401020
	if text := controller.backtraceText(seed, result); strings.Contains(text, "leaf") {
		t.Fatalf("nearest-symbol inference:\n%s", text)
	}
	unwindUICacheSymbols(t, controller, &seed, []elf.Symbol{
		{Name: "leaf", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1000, Size: 0x10},
		{Name: "alias", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1000, Size: 0x10},
	})
	result.Frames[0].PC, result.Frames[0].LookupPC = 0x401000, 0x401000
	if text := controller.backtraceText(seed, result); !strings.Contains(text, "<leaf>") {
		t.Fatalf("single symbol label missing:\n%s", text)
	}
}

func TestUnwindUIReturnPCAtSymbolBoundaryDoesNotRelabelCaller(t *testing.T) {
	controller, seed, result, _ := unwindUIFixture()
	unwindUICacheSymbols(t, controller, &seed, []elf.Symbol{
		{Name: "caller", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1000, Size: 0x10},
		{Name: "next_function", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1010, Size: 0x10},
	})
	result.Frames = []inspect.UnwindFrame{{PC: 0x401010, LookupPC: 0x40100f, RawPC: 0x401010, ReturnPC: true}}
	text := controller.backtraceText(seed, result)
	if strings.Contains(text, "<next_function") || !strings.Contains(text, "<caller+0x10>") || !strings.Contains(text, "0x0000000000401010") {
		t.Fatalf("misleading return-PC label:\n%s", text)
	}
}

func TestUnwindUISingleSymbolPresentation(t *testing.T) {
	controller, seed, result, _ := unwindUIFixture()
	seed.symbols = []inspect.Symbol{
		{ModuleID: "libc", Name: "__GI___libc_free", Type: elf.STT_FUNC, Section: 1, Address: 0x401000, AddressKnown: true, Size: 32},
		{ModuleID: "libc", Name: "__libc_free", Type: elf.STT_FUNC, Section: 1, Address: 0x401000, AddressKnown: true, Size: 32},
		{ModuleID: "libc", Name: "free", Version: "GLIBC_2.2.5", Type: elf.STT_FUNC, Section: 1, Address: 0x401000, AddressKnown: true, Size: 32},
		{ModuleID: "libc", Name: "cfree", Type: elf.STT_FUNC, Section: 1, Address: 0x401000, AddressKnown: true, Size: 32},
	}
	seed.symbolKey = newUISymbolCacheKey(seed.snapshot, seed.thread)
	view := controller.newUnwindUIView(seed)
	if label := view.symbol(result.Frames[0]); label != "free" {
		t.Fatalf("symbol=%q", label)
	}
	for _, width := range []int{40, 80, 120} {
		view.width = width
		var output strings.Builder
		view.frame(&output, result.Frames[0], 0)
		text := output.String()
		if !strings.Contains(text, "<free>") || strings.Contains(text, "cfree") || strings.Contains(text, "aliases") || strings.Contains(text, " | ") {
			t.Fatalf("width%d: %s", width, text)
		}
	}
}

func TestUnwindUINoSymbolUsesProvenModuleOffset(t *testing.T) {
	controller, seed, result, _ := unwindUIFixture()
	seed.modules = []*runtimeELFModule{{ID: "libc-id", Name: "/usr/lib/libc.so.6", LoadBias: 0x400000, Programs: []elf.ProgHeader{{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: 0, Memsz: 0x4000}}}}
	text := controller.backtraceText(seed, result)
	if !strings.Contains(text, "<module:libc.so.6+0x1000> [libc.so.6]") || !strings.Contains(text, "<module:libc.so.6+0x2008> [signal] [libc.so.6]") {
		t.Fatalf("unknown symbol lost module facts:\n%s", text)
	}
}

func TestUnwindUIColorNoColorAndEscaping(t *testing.T) {
	for _, colored := range []bool{false, true} {
		controller, seed, result, _ := unwindUIFixture()
		noColor := "1"
		if colored {
			noColor = ""
		}
		renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAuto, IsTerminal: true, Term: "xterm", NoColor: noColor})
		if err != nil {
			t.Fatal(err)
		}
		controller.renderer = renderer
		unwindUICacheSymbols(t, controller, &seed, []elf.Symbol{{Name: "bad\x1b[2J\nname", Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1000, Size: 16}})
		text := controller.backtraceText(seed, result)
		if strings.Contains(text, "\x1b[2J") || !strings.Contains(text, "bad\\x1b[2J\\nname") || strings.Contains(text, "\x1b[") != colored {
			t.Fatalf("color/escaping policy:\n%q", text)
		}
		plain := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(text, "")
		if strings.ContainsRune(plain, '\x1b') {
			t.Fatalf("non-SGR control sequence: %q", text)
		}
	}
}

func TestUnwindUIWidthUsesTerminalWithoutChangingFlags(t *testing.T) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "unwind-ui-pty")
	defer master.Close()
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slaveFD, err := unix.Open(fmt.Sprintf("/dev/pts/%d", number), unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(slaveFD), "unwind-ui-output")
	defer slave.Close()
	before, err := unix.FcntlInt(uintptr(slaveFD), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	controller, seed, result, _ := unwindUIFixture()
	controller.out = slave
	unwindUICacheSymbols(t, controller, &seed, []elf.Symbol{{Name: strings.Repeat("長い関数名", 40), Info: byte(elf.STT_FUNC), Section: 1, Value: 0x1000, Size: 16}})
	for _, width := range []uint16{80, 100, 140} {
		if err := unix.IoctlSetWinsize(slaveFD, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: width}); err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{controller.backtraceText(seed, result), controller.stackFrameText(seed, result.Frames[0], 0)} {
			for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
				if display.VisibleWidth(line) > int(width) {
					t.Fatalf("line exceeds %d columns (%d): %q", width, display.VisibleWidth(line), line)
				}
			}
			if display.VisibleWidth(strings.Split(text, "\n")[0]) != int(width) || !strings.Contains(text, "...>") {
				t.Fatalf("terminal width or symbol truncation:\n%s", text)
			}
		}
	}
	after, err := unix.FcntlInt(uintptr(slaveFD), unix.F_GETFL, 0)
	if err != nil || before != after {
		t.Fatalf("caller FD flags changed: %#x -> %#x (%v)", before, after, err)
	}
}

func TestUnwindUIPublisherPreservesErrorsAndCancellation(t *testing.T) {
	controller, seed, result, _ := unwindUIFixture()
	text := controller.backtraceText(seed, result)
	controller.out = controllerTestWriter(func([]byte) (int, error) { return 0, nil })
	err := controller.publishUnwind(context.Background(), text, target.ErrUnavailable)
	var outputErr *OutputError
	if !errors.As(err, &outputErr) || !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("lost output/walk failure: %v", err)
	}
	var output bytes.Buffer
	controller.out = &output
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.publishUnwind(ctx, text, target.ErrPartial); !errors.Is(err, context.Canceled) || !errors.Is(err, target.ErrPartial) || output.Len() != 0 {
		t.Fatalf("cancel publication error=%v bytes=%d", err, output.Len())
	}
}

func unwindUIAllCFAKnown(result inspect.UnwindResult) bool {
	for _, frame := range result.Frames {
		if !frame.CFAKnown {
			return false
		}
	}
	return true
}
