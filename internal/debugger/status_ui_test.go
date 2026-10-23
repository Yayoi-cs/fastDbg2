package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func statusUIFixture(t *testing.T, output io.Writer) (*Controller, *controllerTestSession) {
	t.Helper()
	c, s := runningController(t, output)
	c.contextDisabled = true
	c.breakpoints = []*breakpoint{
		{id: 1, expression: "main", enabled: true, installed: true, attempted: true, address: 0x401000, space: s.snapshot.Memory.Space},
		{id: 2, expression: "0x20", kind: breakpointPIE, enabled: false},
		{id: 3, expression: "$rip + 8", enabled: true, attempted: true, address: 0x401008, space: s.snapshot.Memory.Space, err: target.ErrPartial},
	}
	c.watchpoints = []*watchRecord{
		{thread: c.selected, space: s.snapshot.Memory.Space, request: target.WatchpointRequest{Slot: 0, Address: 0x405000, Size: 4, Access: target.WatchWrite}, ref: target.WatchpointRef{Thread: c.selected, Slot: 0, Generation: 17}, installed: true, attempted: true},
		{thread: c.selected, space: s.snapshot.Memory.Space, request: target.WatchpointRequest{Slot: 1, Address: 0x405008, Size: 8, Access: target.WatchReadWrite}, attempted: true, err: target.ErrPartial},
		{thread: target.ThreadRef{Session: 2, ID: 3}, space: target.SpaceRef{Session: 2, ID: 4}, request: target.WatchpointRequest{Slot: 2, Address: 0x406000, Size: 1, Access: target.WatchReadWrite}, ref: target.WatchpointRef{Thread: target.ThreadRef{Session: 2, ID: 3}, Slot: 2, Generation: 29}, installed: true, attempted: true, expired: true},
	}
	return c, s
}

func TestStatusUIBreakpointTableRetainsCertaintyAndLiteralExpressions(t *testing.T) {
	var output bytes.Buffer
	c, _ := statusUIFixture(t, &output)
	if err := c.listBreakpoints(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"[breakpoints]", "Num", "Type", "Enb", "Address", "State", "What", "0x0000000000401000 installed", "<pending>", `"0x20" (PIE offset)`, "0x0000000000401008 unconfirmed", `"$rip + 8"`, `Error: "partial operation"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %q", expected, text)
		}
	}
	if !c.breakpoints[0].installed || c.breakpoints[1].enabled || !c.breakpoints[2].attempted || !errors.Is(c.breakpoints[2].err, target.ErrPartial) {
		t.Fatal("formatting changed breakpoint state")
	}
}

func TestStatusUIWatchpointTableRetainsHandlesWithoutInventingFreeSlots(t *testing.T) {
	var output bytes.Buffer
	c, _ := statusUIFixture(t, &output)
	if err := c.listWatchpoints(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"[watchpoints: debugger-owned]", "Thread", "Slot", "Access", "Size", "Address", "State", "Generation", "unconfirmed", "unknown", "invalidated", "Handle: session 2, address space 4.", "29"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %q", expected, text)
		}
	}
	if strings.Contains(text, "free") || strings.Contains(text, "idle") || !c.watchpoints[0].installed || !c.watchpoints[1].attempted || c.watchpoints[2].ref.Generation != 29 {
		t.Fatal("formatting changed or invented watchpoint ownership")
	}
	if strings.Contains(text, "Four hardware slots") || strings.Contains(text, "New threads do not inherit") || strings.Contains(text, "Controller-owned settings only") {
		t.Fatalf("watchpoint listing repeated help text: %q", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "#") && len(line) > 90 {
			t.Fatalf("watchpoint row is unnecessarily wide (%d): %q", len(line), line)
		}
	}
}

func TestStatusUISectionsFollowEightyColumnTerminal(t *testing.T) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	c, _ := statusUIFixture(t, slave)
	if err := c.listBreakpoints(); err != nil {
		t.Fatal(err)
	}
	if err := c.listWatchpoints(); err != nil {
		t.Fatal(err)
	}
	c.renderer, err = display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	pc := target.Address(0x401000)
	stop := target.Stop{
		Reason: target.StopWatchpoint, RawPC: &pc, Signal: target.Signal{Domain: target.SignalLinux, Number: 5},
		Watchpoints:         []target.WatchpointHit{{Ref: target.WatchpointRef{Thread: c.selected, Slot: 2, Generation: 23}, Address: 0x407000, Size: 4, Access: target.WatchWrite}},
		HardwareBreakpoints: []target.HardwareBreakpointHit{{Ref: target.HardwareBreakpointRef{Thread: c.selected, Slot: 3, Generation: 24}, Address: 0x408000}},
	}
	if err := c.showStop(context.Background(), stop, c.selected); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var data [4096]byte
	for {
		n, err := unix.Read(fd, data[:])
		if n > 0 {
			output.Write(data[:n])
		}
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil || n == 0 {
			t.Fatalf("PTY read n=%d err=%v", n, err)
		}
	}
	headings := 0
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if display.VisibleWidth(line) > 80 {
			t.Fatalf("status did not wrap to the terminal width: %q", line)
		}
		if strings.Contains(line, "[breakpoints]") || strings.Contains(line, "[watchpoints: debugger-owned]") {
			headings++
			if display.VisibleWidth(line) != 80 {
				t.Fatalf("section ignored terminal width: %q", line)
			}
		}
	}
	if headings != 2 {
		t.Fatalf("missing table headings: %q", output.String())
	}
	for _, token := range []string{"0x0000000000407000", "0x0000000000408000", "\x1b[1m", "\x1b[0m"} {
		if !strings.Contains(output.String(), token) {
			t.Fatalf("wrapped output split address or ANSI token %q: %q", token, output.String())
		}
	}
	t.Logf("STATUS_UI_TTY80_BEGIN\n%sSTATUS_UI_TTY80_END", output.String())
}

func TestStatusUIStopUsesExactBreakpointAndRawPCWithoutArithmetic(t *testing.T) {
	var output bytes.Buffer
	c, _ := statusUIFixture(t, &output)
	pc, bp := target.Address(0x401001), target.Address(0x401000)
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopBreakpoint, RawPC: &pc, Breakpoint: &bp}, c.selected); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Thread #1 (TID 4401) stopped at 0x0000000000401000 (breakpoint).") || !strings.Contains(output.String(), "Raw PC: 0x0000000000401001") || pc != 0x401001 {
		t.Fatalf("output=%q pc=%#x", output.String(), pc)
	}
	output.Reset()
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopStep, RawPC: &pc}, c.selected); err != nil || !strings.Contains(output.String(), "stopped at 0x0000000000401001 (instruction step).") || strings.Contains(output.String(), "step completed") {
		t.Fatalf("instruction PC was inferred or completion invented: err=%v output=%q", err, output.String())
	}
}

func TestStatusUIStopPreservesThreadExitAndProcessExitDistinction(t *testing.T) {
	var output bytes.Buffer
	c, s := statusUIFixture(t, &output)
	code := 7
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopExited, ExitCode: &code}, c.selected); err != nil || !strings.Contains(output.String(), "Thread #1 (TID 4401) exited (code 7); process 4401 remains stopped.") || strings.Contains(output.String(), "Process 4401 exited") {
		t.Fatalf("thread exit ended process in UI: err=%v output=%q", err, output.String())
	}
	output.Reset()
	s.snapshot.State = target.StateExited
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopExited, ExitCode: &code}, c.selected); err != nil || output.String() != "Process 4401 exited (code 7).\n" {
		t.Fatalf("process exit err=%v output=%q", err, output.String())
	}
	output.Reset()
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopSignaled, Signal: target.Signal{Domain: target.SignalLinux, Number: 9}}, c.selected); err != nil || output.String() != "Process 4401 exited (SIGKILL (9)).\n" {
		t.Fatalf("signaled exit err=%v output=%q", err, output.String())
	}
}

func TestStatusUIUnknownFactsAreNotReplacedBySelectedThreadOrZeroPC(t *testing.T) {
	var output bytes.Buffer
	c, s := statusUIFixture(t, &output)
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopInterrupt}, target.ThreadRef{}); err != nil || output.String() != "Process 4401 stopped (interrupt).\n" {
		t.Fatalf("aggregate stop fabricated a thread or address: err=%v output=%q", err, output.String())
	}
	output.Reset()
	s.snapshot.State = target.StateRunning
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopBreakpoint}, c.selected); err != nil || output.String() != "Process 4401 is running; last stop reason: breakpoint.\n" {
		t.Fatalf("running target reported stopped: err=%v output=%q", err, output.String())
	}
}

func TestStatusUISignalAndIndependentHardwareFacts(t *testing.T) {
	var output bytes.Buffer
	c, _ := statusUIFixture(t, &output)
	stop := target.Stop{
		Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 12}, StepCompleted: true,
		Watchpoints:         []target.WatchpointHit{{Ref: target.WatchpointRef{Thread: target.ThreadRef{Session: 7, ID: 8}, Slot: 2, Generation: 9}, Address: 0x407000, Size: 4, Access: target.WatchWrite}},
		HardwareBreakpoints: []target.HardwareBreakpointHit{{Ref: target.HardwareBreakpointRef{Thread: target.ThreadRef{Session: 7, ID: 8}, Slot: 1, Generation: 11}, Address: 0x401020}},
	}
	if err := c.showStop(context.Background(), stop, c.selected); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"stopped by SIGUSR2 (12).", "Instruction step completed.", "Watchpoint: thread #8, slot 2, generation 9; write 4 byte(s) at 0x0000000000407000 (session 7).", "Hardware breakpoint: thread #8, slot 1, generation 11; execution at 0x0000000000401020 (session 7)."} {
		if !strings.Contains(strings.Join(strings.Fields(output.String()), " "), expected) {
			t.Fatalf("missing %q in %q", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "stopped at 0x0000000000407000") {
		t.Fatal("watchpoint data address was represented as a stop PC")
	}
}

func TestStatusUIDebuggerTrapIsNotPresentedAsPendingDelivery(t *testing.T) {
	for _, reason := range []target.StopReason{target.StopBreakpoint, target.StopStep, target.StopInterrupt, target.StopExec, target.StopClone, target.StopFork, target.StopVFork, target.StopAttach, target.StopWatchpoint, target.StopHardwareBreakpoint} {
		t.Run(reason.String(), func(t *testing.T) {
			var output bytes.Buffer
			c, s := statusUIFixture(t, &output)
			stop := target.Stop{Reason: reason, Signal: target.Signal{Domain: target.SignalLinux, Number: 5}}
			s.snapshot.Threads[0].Stop = stop
			if err := c.showStop(context.Background(), stop, c.selected); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output.String(), "Signal:") || strings.Contains(output.String(), "SIGTRAP") || s.snapshot.Threads[0].Stop.Signal != stop.Signal {
				t.Fatalf("debugger trap display changed or misrepresented core signal: %q", output.String())
			}
		})
	}
	for _, test := range []struct {
		reason target.StopReason
		signal uint32
		want   string
	}{
		{target.StopSignal, 5, "stopped by SIGTRAP (5)"},
		{target.StopSignaled, 5, "exited (SIGTRAP (5))"},
		{target.StopGroupStop, 19, "Signal: SIGSTOP (19)"},
		{target.StopUnknown, 5, "Signal: SIGTRAP (5)"},
		{target.StopExec, 12, "Signal: SIGUSR2 (12)"},
	} {
		var output bytes.Buffer
		c, _ := statusUIFixture(t, &output)
		if err := c.showStop(context.Background(), target.Stop{Reason: test.reason, Signal: target.Signal{Domain: target.SignalLinux, Number: test.signal}}, c.selected); err != nil || !strings.Contains(output.String(), test.want) {
			t.Fatalf("real signal reason=%s err=%v output=%q", test.reason, err, output.String())
		}
	}
}

func TestStatusUIEscapesExternalTextAndPreservesColorPolicy(t *testing.T) {
	for _, color := range []bool{false, true} {
		var output bytes.Buffer
		c, _ := statusUIFixture(t, &output)
		options := display.Options{Mode: display.ColorAuto, IsTerminal: true, Term: "xterm"}
		if !color {
			options.NoColor = "1"
		}
		var err error
		c.renderer, err = display.NewRenderer(options)
		if err != nil {
			t.Fatal(err)
		}
		payload := "x\x1b[2J\nforged row"
		c.breakpoints[0].expression = payload
		c.breakpoints[2].err = errors.New(payload)
		c.watchpoints[1].err = errors.New(payload)
		if err := c.listBreakpoints(); err != nil {
			t.Fatal(err)
		}
		if err := c.listWatchpoints(); err != nil {
			t.Fatal(err)
		}
		if err := c.showStop(context.Background(), target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalDomain(payload), Number: 3}}, c.selected); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), payload) || strings.Contains(output.String(), "\x1b[2J") || !color && strings.ContainsRune(output.String(), '\x1b') || color && !strings.ContainsRune(output.String(), '\x1b') {
			t.Fatalf("color=%t output=%q", color, output.String())
		}
	}
}

func TestStatusUIOutputFailureStopsBeforeFurtherRowsOrContext(t *testing.T) {
	for _, command := range []string{"stop", "breakpoints", "watchpoints"} {
		t.Run(command, func(t *testing.T) {
			want := errors.New("output failed")
			writes := 0
			c, s := statusUIFixture(t, controllerTestWriter(func(data []byte) (int, error) {
				writes++
				if writes == 2 {
					return 0, want
				}
				return len(data), nil
			}))
			var err error
			switch command {
			case "stop":
				err = c.showStop(context.Background(), target.Stop{Reason: target.StopStep, StepCompleted: true}, c.selected)
			case "breakpoints":
				err = c.listBreakpoints()
			case "watchpoints":
				err = c.listWatchpoints()
			}
			var outputErr *OutputError
			if !errors.Is(err, want) || !errors.As(err, &outputErr) || writes != 2 || len(s.registerReads) != 0 || c.session != s {
				t.Fatalf("err=%v writes=%d reads=%+v session=%v", err, writes, s.registerReads, c.session)
			}
		})
	}
}

func TestStatusUIExamples(t *testing.T) {
	var output bytes.Buffer
	c, _ := statusUIFixture(t, &output)
	pc, bp := target.Address(0x401001), target.Address(0x401000)
	if err := c.showStop(context.Background(), target.Stop{Reason: target.StopBreakpoint, RawPC: &pc, Breakpoint: &bp}, c.selected); err != nil {
		t.Fatal(err)
	}
	if err := c.listBreakpoints(); err != nil {
		t.Fatal(err)
	}
	if err := c.listWatchpoints(); err != nil {
		t.Fatal(err)
	}
	t.Logf("STATUS_UI_EXAMPLE_BEGIN\n%sSTATUS_UI_EXAMPLE_END", output.String())
}
