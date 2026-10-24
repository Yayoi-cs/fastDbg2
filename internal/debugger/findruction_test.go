package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func TestFindructionOutputOptions(t *testing.T) {
	for _, option := range []string{"-n", "--no-tui", "--pager"} {
		got, err := parseSearchArguments("findruction", option+` --max-matches 2 "pop rdi; ret" $rip "$rip+16"`)
		if err != nil || got.maxMatches != 2 || got.noTUI != (option != "--pager") || got.pager != (option == "--pager") {
			t.Fatalf("%s: %+v %v", option, got, err)
		}
	}
	for _, args := range []string{`-n --pager nop`, `--no-tui -n nop`, `--pager --pager nop`, `--no-tui`} {
		if _, err := parseSearchArguments("findruction", args); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%s: %v", args, err)
		}
	}
	if _, err := parseSearchArguments("search-string", "--pager nop"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestFindructionPreviewMergesWindowsAndCrossesAdjacentMappings(t *testing.T) {
	spans := []searchSpan{{0x1000, 0x1002}, {0x1002, 0x1010}}
	groups := findructionMemoryGroups([]procMap{{Start: 0x1000, End: 0x1002, Path: "a"}, {Start: 0x1002, End: 0x1010, Path: "b"}}, spans, []target.Address{0x1001, 0x1002, 0x1003})
	calls := 0
	reader := searchTestReader(func(address target.Address, buf []byte) (int, error) {
		calls++
		for i := range buf {
			buf[i] = 0x90
		}
		if address == 0x1001 {
			copy(buf, []byte{0x48, 0x89, 0xc0})
		}
		return len(buf), nil
	})
	if err := findructionPreviews(context.Background(), reader, groups, findructionContextCount); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("windows not merged: %d reads", calls)
	}
	if got := groups[0].matches[0].instructions; len(got) == 0 || got[0].Text != "mov rax, rax" {
		t.Fatalf("instruction across adjacent maps: %+v", got)
	}
	if groups[1].matches[0].instructions[0].Address != 0x1002 || groups[1].matches[1].instructions[0].Address != 0x1003 {
		t.Fatal("parallel decode reordered results")
	}
	groups[1].start = 0x1003
	if err := findructionPreviews(context.Background(), reader, groups[:1], findructionContextCount); err != nil {
		t.Fatal(err)
	}
	if len(groups[0].matches[0].instructions) != 0 {
		t.Fatal("preview crossed end of scope")
	}
}

func TestFindructionPreviewErrorsAndCancellation(t *testing.T) {
	for _, failure := range []error{target.ErrPartial, target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		group := []findructionGroup{{start: 0x1000, end: 0x1010, matches: []findructionMatch{{address: 0x1000, readAddress: 0x1000}}}}
		reader := searchTestReader(func(_ target.Address, buf []byte) (int, error) { buf[0] = 0x90; return 1, failure })
		err := findructionPreviews(context.Background(), reader, group, findructionContextCount)
		if !errors.Is(err, failure) {
			t.Fatalf("%v: %v", failure, err)
		}
		if failure == target.ErrPartial && (len(group[0].matches[0].instructions) != 1 || group[0].matches[0].instructions[0].Text != "nop") {
			t.Fatalf("partial data padded or discarded: %+v", group)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := findructionPreviews(ctx, searchTestReader(func(target.Address, []byte) (int, error) { t.Fatal("read after cancel"); return 0, nil }), []findructionGroup{{start: 1, end: 2, matches: []findructionMatch{{address: 1}}}}, findructionContextCount)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFindructionStaleContextDoesNotPublishMatches(t *testing.T) {
	c, session, output, mapping := searchCommandFixture(t)
	calls := 0
	session.codeReader = func(address target.Address, buf []byte) (int, error) {
		calls++
		if calls == 2 {
			return 0, target.ErrStale
		}
		copy(buf, []byte{0x90, 0xc3})
		return len(buf), nil
	}
	err := c.commandSearch(context.Background(), "findruction", fmt.Sprintf(`nop %#x %#x`, mapping.Start, mapping.Start+2))
	if !errors.Is(err, target.ErrStale) || output.Len() != 0 {
		t.Fatalf("stale context published: %v %q", err, output.String())
	}
}

func findructionUITestData() []findructionGroup {
	return []findructionGroup{
		{label: "/first/library.so", start: 0x1000, end: 0x2000, matches: []findructionMatch{{address: 0x1234, instructions: []inspect.Instruction{{Address: 0x1234, Text: "pop rdi"}, {Address: 0x1235, Text: "ret"}}}}},
		{label: "/second/library.so", start: 0x3000, end: 0x4000, matches: []findructionMatch{{address: 0x3456, instructions: []inspect.Instruction{{Address: 0x3456, Text: "ret"}}}}},
	}
}

func TestFindructionNavigationAndFrames(t *testing.T) {
	ui := findructionUI{groups: findructionUITestData(), pattern: []byte{0xc3}}
	ui.key("j", 24)
	if ui.group != 1 || ui.match != 0 {
		t.Fatal(ui)
	}
	ui.key("\t", 24)
	ui.key("j", 24)
	if ui.focus != 1 || ui.match != 0 {
		t.Fatal(ui)
	}
	ui.key("\t", 24)
	ui.key("G", 24)
	if ui.scroll != 0 {
		t.Fatal("short pane scrolled off screen")
	}
	ui.key("l", 24)
	if ui.horizontal != 8 {
		t.Fatal(ui)
	}
	ui.key("\x1b[Z", 24)
	if ui.focus != 1 || ui.horizontal != 0 {
		t.Fatal(ui)
	}
	for _, size := range [][2]int{{80, 24}, {120, 30}, {50, 6}, {20, 4}, {1, 1}} {
		frame := ui.frame(display.Renderer{}, size[0], size[1])
		if !strings.Contains(frame, "\x1b[1;1H") {
			t.Fatal(frame)
		}
		for _, line := range strings.Split(frame, "\x1b[2K")[1:] {
			text := strings.SplitN(line, "\x1b[", 2)[0]
			if display.VisibleWidth(text) > size[0] {
				t.Fatalf("overflow %v: %q", size, text)
			}
		}
		if strings.Contains(frame, "\x1b[0m") {
			t.Fatal("NO_COLOR emitted SGR")
		}
	}
	for _, key := range []string{"q", "\x1b", "\x03"} {
		if !ui.key(key, 24) {
			t.Fatalf("did not quit: %q", key)
		}
	}
	for _, fragment := range []string{"\x1b", "\x1b[", "\x1b[6"} {
		if _, n := findructionKey([]byte(fragment)); n != 0 {
			t.Fatalf("fragment consumed: %q", fragment)
		}
	}
	key, n := findructionKey([]byte("\x1b[6~q"))
	if key != "\x1b[6~" || n != 4 {
		t.Fatalf("%q %d", key, n)
	}
}

func TestFindructionTUIRestoresTerminal(t *testing.T) {
	for _, action := range []string{"quit", "cancel"} {
		t.Run(action, func(t *testing.T) {
			master, slave := pagerTestPTY(t)
			fd, err := findructionFD(slave)
			if err != nil {
				t.Fatal(err)
			}
			before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			flags := pagerTestFlags(t, slave)
			if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: 80, Row: 24}); err != nil {
				t.Fatal(err)
			}
			c := New(slave, display.Renderer{})
			c.pager = &commandPager{input: slave, output: slave}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- c.findructionTUI(ctx, findructionUITestData(), []byte{0xc3}, false) }()
			var output bytes.Buffer
			mfd, err := findructionFD(master)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(output.String(), "q/Esc/Ctrl-C quit") {
				if time.Now().After(deadline) {
					t.Fatalf("TUI not rendered: %q", output.String())
				}
				var buf [8192]byte
				n, err := unix.Read(mfd, buf[:])
				if n > 0 {
					output.Write(buf[:n])
				}
				if err != nil && err != unix.EAGAIN {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
			}
			if action == "cancel" {
				cancel()
			} else {
				if _, err := io.WriteString(master, "\t\x1b[6~\x1b[Zjq"); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if action == "quit" && err != nil || action == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("TUI did not exit")
			}
			after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			if *before != *after || flags != pagerTestFlags(t, slave) {
				t.Fatal("terminal state or descriptor flags changed")
			}
			var buf [8192]byte
			n, _ := unix.Read(mfd, buf[:])
			if n > 0 {
				output.Write(buf[:n])
			}
			if !strings.Contains(output.String(), "\x1b[?25h\x1b[?1049l") {
				t.Fatal("screen/cursor not restored")
			}
		})
	}
}
