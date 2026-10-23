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
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

type screenOutput struct {
	bytes.Buffer
	writes int
	err    error
}

func (w *screenOutput) Write(data []byte) (int, error) {
	w.writes++
	if w.err != nil {
		return 0, w.err
	}
	return w.Buffer.Write(data)
}

func (w *screenOutput) WriteString(text string) (int, error) { return w.Write([]byte(text)) }

func TestContextScreenPublishesStopAndPanesTogether(t *testing.T) {
	fixture, _, thread := newContextFixture()
	output := &screenOutput{}
	c := &Controller{session: fixture, selected: thread.Ref, out: output, contextScreen: true}
	if err := c.showStop(context.Background(), thread.Stop, thread.Ref); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.HasPrefix(text, "\x1b[H\x1b[2JThread #2 (TID 1234) stopped") || strings.Count(text, "\x1b[2J") != 1 || output.writes != 1 {
		t.Fatalf("stop was not published atomically after clear: writes=%d, %q", output.writes, text)
	}
	for _, pane := range []string{"registers", "stack", "code", "threads"} {
		if !strings.Contains(text, "["+pane+"]") {
			t.Fatalf("missing pane %s: %s", pane, text)
		}
	}
	if strings.Index(text, "stopped at") > strings.Index(text, "[registers]") || len(c.registerHistory) == 0 {
		t.Fatalf("stop metadata lost or register observation not recorded: %s", text)
	}
}

func TestContextScreenRejectsStaleOrCanceledFramesBeforeClearing(t *testing.T) {
	for _, stop := range []bool{false, true} {
		for _, fail := range []string{"sequence", "token", "canceled"} {
			t.Run(fmt.Sprintf("stop=%t/%s", stop, fail), func(t *testing.T) {
				fixture, _, thread := newContextFixture()
				output := &screenOutput{}
				c := &Controller{session: fixture, selected: thread.Ref, out: output, contextScreen: true}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fixture.onReadRegisters = func() {
					switch fail {
					case "sequence":
						fixture.snapshot.Sequence++
					case "token":
						fixture.snapshot.Threads[0].Token.Registers++
					case "canceled":
						cancel()
					}
				}
				var err error
				if stop {
					err = c.showStop(ctx, thread.Stop, thread.Ref)
				} else {
					err = c.showContext(ctx)
				}
				if err == nil || output.Len() != 0 || output.writes != 0 || len(c.registerHistory) != 0 {
					t.Fatalf("unvalidated frame altered display: err=%v writes=%d output=%q", err, output.writes, output.String())
				}
			})
		}
	}
}

func TestContextScreenPanedAndHiddenViewsDoNotClear(t *testing.T) {
	fixture, _, thread := newContextFixture()
	output := &screenOutput{}
	c := &Controller{session: fixture, selected: thread.Ref, out: output, contextScreen: true}
	if err := c.showContext(context.Background(), "regs"); err != nil || strings.Contains(output.String(), "\x1b[2J") || !strings.Contains(output.String(), "[registers]") {
		t.Fatalf("named pane clear policy: %v, %q", err, output.String())
	}
	c.contextDisabled = true
	for _, pane := range []string{"", "regs", "threads"} {
		output.Reset()
		reads := fixture.snapshotReads
		if err := c.showContext(context.Background(), pane); err != nil || output.Len() != 0 || fixture.snapshotReads != reads {
			t.Fatalf("hidden context %q still rendered: %v, %q", pane, err, output.String())
		}
	}
	if err := c.showRegisters(context.Background(), "-s rip"); err != nil || !strings.Contains(output.String(), "$rip") {
		t.Fatalf("context off hid standalone registers: %v, %q", err, output.String())
	}
	output.Reset()
	if err := c.showStop(context.Background(), thread.Stop, thread.Ref); err != nil || strings.Contains(output.String(), "\x1b[2J") || !strings.Contains(output.String(), "stopped at") {
		t.Fatalf("hidden automatic context erased its stop status: %v, %q", err, output.String())
	}
}

func TestContextScreenOutputFailureIsTypedAndNotRetried(t *testing.T) {
	fixture, _, thread := newContextFixture()
	failure := errors.New("screen output failed")
	output := &screenOutput{err: failure}
	c := &Controller{session: fixture, selected: thread.Ref, out: output, contextScreen: true}
	var writeErr *OutputError
	if err := c.showStop(context.Background(), thread.Stop, thread.Ref); !errors.As(err, &writeErr) || !errors.Is(err, failure) || output.writes != 1 || len(c.registerHistory) != 0 {
		t.Fatalf("screen output failure: err=%v writes=%d", err, output.writes)
	}
}

func screenPTYOutput(t *testing.T, file *os.File) string {
	t.Helper()
	connection, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var readErr error
	err = connection.Control(func(fd uintptr) {
		var buffer [4096]byte
		for {
			n, err := unix.Read(int(fd), buffer[:])
			if n > 0 {
				output.Write(buffer[:n])
			}
			if errors.Is(err, unix.EAGAIN) {
				return
			}
			if err != nil || n == 0 {
				readErr = errors.Join(err, io.ErrUnexpectedEOF)
				return
			}
		}
	})
	if err != nil || readErr != nil {
		t.Fatalf("read screen PTY: %v, %v", err, readErr)
	}
	return output.String()
}

func TestContextScreenCapabilityKeepsNoColorSeparateFromTTY(t *testing.T) {
	master, slave := pagerTestPTY(t)
	fixture, _, thread := newContextFixture()
	c := &Controller{session: fixture, selected: thread.Ref, out: slave}
	c.EnableContextScreen(true)
	if !c.contextScreen {
		t.Fatal("terminal screen capability was not enabled")
	}
	if err := c.showContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := screenPTYOutput(t, master)
	if !strings.HasPrefix(text, "\x1b[H\x1b[2J") || strings.Contains(text, "\x1b[36m") {
		t.Fatalf("NO_COLOR disabled screen controls or retained color: %q", text)
	}
	var pipe bytes.Buffer
	c.out = &pipe
	c.EnableContextScreen(true)
	if c.contextScreen {
		t.Fatal("nonterminal output obtained screen control")
	}
	if err := c.showContext(context.Background()); err != nil || strings.ContainsRune(pipe.String(), '\x1b') {
		t.Fatalf("redirected context contains screen controls: %v, %q", err, pipe.String())
	}
}

func TestContextCodeColumnUsesConfirmedInstructionLengths(t *testing.T) {
	instructions, err := inspect.Disassemble(target.AMD64, 0x401000, []byte{0x48, 0x89, 0xe5, 0x5d, 0xc3}, 3)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view := contextOutput{
		width: 80,
		writef: func(format string, args ...any) error {
			_, err := io.WriteString(&output, display.Wrap(fmt.Sprintf(format, args...), 80, 4))
			return err
		},
		walker: &addressWalker{symbol: func(address target.Address) string {
			return fmt.Sprintf("ui_libc_checkpoint+0x%x", address-0x401000)
		}},
	}
	if err := view.code(contextCode{location: &native.CodeLocation{InstructionPC: 0x401000}, instructions: instructions}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mov rbp, rsp", "pop rbp"} {
		found := false
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.Contains(line, want) {
				found = strings.Contains(line, "ui_libc_checkpoint+") && strings.Contains(line, "0x0000000000401") && display.VisibleWidth(line) <= 80
			}
		}
		if !found {
			t.Fatalf("instruction operands wrapped despite available width: %q\n%s", want, output.String())
		}
	}
}
