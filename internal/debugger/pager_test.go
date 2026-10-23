package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/internal/shellcmd"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func pagerTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "pager-pty-master")
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
	return master, slave
}

func pagerTestFlags(t *testing.T, file *os.File) [2]int {
	t.Helper()
	connection, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags [2]int
	var failure error
	err = connection.Control(func(fd uintptr) {
		flags[0], failure = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if failure == nil {
			flags[1], failure = unix.FcntlInt(fd, unix.F_GETFD, 0)
		}
	})
	if err != nil || failure != nil {
		t.Fatal(errors.Join(err, failure))
	}
	return flags
}

func TestPagerEnableOnlyActualTerminalFilesPreservesIdentity(t *testing.T) {
	utilityWorkingDirectory(t)
	master, slave := pagerTestPTY(t)
	regular, err := os.Create("regular")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	before := [2][2]int{pagerTestFlags(t, master), pagerTestFlags(t, slave)}
	connection, err := slave.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sizeErr error
	if err := connection.Control(func(fd uintptr) {
		sizeErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 140})
	}); err != nil || sizeErr != nil {
		t.Fatal(errors.Join(err, sizeErr))
	}
	for _, test := range []struct {
		name     string
		input    io.Reader
		output   io.Writer
		terminal string
		want     bool
	}{
		{"tty", slave, slave, "xterm-256color", true},
		{"stdin-not-tty", regular, slave, "xterm", false},
		{"stdout-not-tty", slave, regular, "xterm", false},
		{"reader-wrapper", io.LimitReader(slave, 1), slave, "xterm", false},
		{"writer-wrapper", slave, struct{ io.Writer }{slave}, "xterm", false},
		{"fake-streams", strings.NewReader(""), &bytes.Buffer{}, "xterm", false},
		{"dumb", slave, slave, "dumb", false},
		{"empty-term", slave, slave, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TERM", test.terminal)
			t.Setenv("NO_COLOR", "1")
			controller := &Controller{out: test.output}
			controller.EnablePager(test.input)
			if (controller.pager != nil) != test.want || controller.out != test.output {
				t.Fatalf("pager=%+v output identity preserved=%t", controller.pager, controller.out == test.output)
			}
			if test.output == slave && display.OutputWidth(controller.out) != 140 {
				t.Fatal("pager changed terminal width identity")
			}
			controller.EnablePager(strings.NewReader(""))
			if controller.pager != nil {
				t.Fatal("nonterminal input did not disable pager")
			}
		})
	}
	if after := [2][2]int{pagerTestFlags(t, master), pagerTestFlags(t, slave)}; after != before {
		t.Fatalf("caller descriptor flags changed: before=%v after=%v", before, after)
	}
}

func pagerTestOutput(t *testing.T) (*commandPager, *os.File) {
	t.Helper()
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close() })
	output, err := os.Create("output")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { output.Close() })
	return &commandPager{input: input, output: output}, output
}

func pagerAssertClean(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(pagerCache)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil || len(entries) != 0 {
		t.Fatalf("pager files remain: entries=%v error=%v", entries, err)
	}
}

func TestPagerVerifiedBufferCommandAndEnvironment(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	pager, output := pagerTestOutput(t)
	for _, name := range []string{"LESS", "LESSOPEN", "LESSCLOSE", "LESSSECURE_ALLOW", "LESSKEYIN", "LESSHISTFILE", "LESSANSIENDCHARS", "LESS_TERMCAP_so", "TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, "unsafe inherited configuration")
	}
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm-256color")
	text := "[symbols]\n" + strings.Repeat("exact verified symbol row\n", 40000)
	called := false
	before := [2][2]int{pagerTestFlags(t, pager.input), pagerTestFlags(t, output)}
	err := pager.displayWith(context.Background(), text, func(ctx context.Context, command shellcmd.Command) error {
		called = true
		if ctx == nil || !filepath.IsAbs(command.Path) || filepath.Base(command.Path) != "less" || len(command.Args) != 4 || command.Args[0] != "-SR" || command.Args[1] != pagerPrompt || command.Args[2] != "--" ||
			command.Stdin != pager.input || command.Output != output || !command.Foreground || !command.TerminalOutput || !command.Pager || len(command.ExtraFiles) != 0 {
			t.Fatalf("pager command=%+v", command)
		}
		wantDirectory := filepath.Join(directory, pagerCache)
		if command.Dir != wantDirectory || filepath.Dir(command.Args[3]) != wantDirectory {
			t.Fatalf("pager escaped cache: %+v", command)
		}
		stat, err := os.Stat(command.Args[3])
		if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 {
			t.Fatalf("pager file stat=%v error=%v", stat, err)
		}
		data, err := os.ReadFile(command.Args[3])
		if err != nil || string(data) != text {
			t.Fatalf("pager buffer length=%d want=%d error=%v", len(data), len(text), err)
		}
		seen := make(map[string]string)
		for _, entry := range command.Env {
			name, value, _ := strings.Cut(entry, "=")
			if _, exists := seen[name]; exists {
				t.Fatalf("duplicate environment name %q", name)
			}
			seen[name] = value
			if strings.HasPrefix(name, "LESS") && name != "LESSSECURE" && name != "LESSHISTFILE" {
				t.Fatalf("unsafe pager environment %q", entry)
			}
		}
		for name, want := range map[string]string{"LESSSECURE": "1", "LESSHISTFILE": "-", "NO_COLOR": "1", "TERM": "xterm-256color", "TMPDIR": wantDirectory, "TMP": wantDirectory, "TEMP": wantDirectory} {
			if seen[name] != want {
				t.Fatalf("environment %s=%q want=%q", name, seen[name], want)
			}
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("called=%t error=%v", called, err)
	}
	if after := [2][2]int{pagerTestFlags(t, pager.input), pagerTestFlags(t, output)}; after != before {
		t.Fatalf("pager changed borrowed descriptors: before=%v after=%v", before, after)
	}
	data, err := os.ReadFile("output")
	if err != nil || len(data) != 0 {
		t.Fatalf("pager output was also dumped raw: %q error=%v", data, err)
	}
	pagerAssertClean(t)
}

func TestPagerMissingLessWarnsAndFallsBackWithoutChild(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	pager, _ := pagerTestOutput(t)
	t.Setenv("PATH", directory)
	text := "verified output\n"
	err := pager.displayWith(context.Background(), text, func(context.Context, shellcmd.Command) error {
		t.Fatal("missing pager spawned a child")
		return nil
	})
	data, readErr := os.ReadFile("output")
	if err != nil || readErr != nil || !bytes.HasPrefix(data, []byte("pager unavailable: ")) || !bytes.HasSuffix(data, []byte("displaying output directly\n"+text)) || bytes.Contains(data, []byte{0x1b}) {
		t.Fatalf("error=%v read=%v output=%q", err, readErr, data)
	}
	pagerAssertClean(t)
	if err := pager.output.Close(); err != nil {
		t.Fatal(err)
	}
	err = pager.displayWith(context.Background(), text, func(context.Context, shellcmd.Command) error { return nil })
	var outputErr *OutputError
	if !errors.As(err, &outputErr) {
		t.Fatalf("fallback write failure is untyped: %v", err)
	}
}

func TestPagerErrorsCancelAndEmptyDoNotRedump(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		cancel bool
	}{
		{"exit", &shellcmd.ExitError{Code: 17}, false},
		{"output", &shellcmd.OutputError{Err: io.ErrClosedPipe}, false},
		{"canceled", nil, true},
		{"canceled-once", context.Canceled, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			utilityWorkingDirectory(t)
			pager, _ := pagerTestOutput(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := pager.displayWith(ctx, "verified content\n", func(context.Context, shellcmd.Command) error {
				if test.cancel {
					cancel()
				}
				return test.err
			})
			want := test.err
			if test.cancel {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			if test.cancel && strings.Count(err.Error(), context.Canceled.Error()) != 1 {
				t.Fatalf("pager duplicated cancellation diagnostics: %v", err)
			}
			if test.name == "output" {
				var outputErr *OutputError
				if !errors.As(err, &outputErr) {
					t.Fatalf("pager output failure is untyped: %v", err)
				}
			}
			data, readErr := os.ReadFile("output")
			if readErr != nil || len(data) != 0 {
				t.Fatalf("failed pager redumped content: %q error=%v", data, readErr)
			}
			pagerAssertClean(t)
		})
	}
	utilityWorkingDirectory(t)
	pager, _ := pagerTestOutput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	run := func(context.Context, shellcmd.Command) error { called = true; return nil }
	for _, test := range []struct {
		ctx  context.Context
		text string
		want error
	}{
		{nil, "data", target.ErrInvalidArgument},
		{ctx, "data", context.Canceled},
		{context.Background(), "", nil},
	} {
		if err := pager.displayWith(test.ctx, test.text, run); !errors.Is(err, test.want) || called {
			t.Fatalf("invalid or empty page: called=%t error=%v want=%v", called, err, test.want)
		}
	}
	pagerAssertClean(t)
}

func TestPagerCacheCannotEscapeWorkingDirectory(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	pager, _ := pagerTestOutput(t)
	outside := directory + "-outside"
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)
	if err := os.Symlink(outside, ".cache"); err != nil {
		t.Fatal(err)
	}
	err := pager.displayWith(context.Background(), "verified data\n", func(context.Context, shellcmd.Command) error {
		t.Fatal("pager started after an escaped cache")
		return nil
	})
	if err == nil {
		t.Fatal("pager cache escaped the working directory")
	}
	entries, readErr := os.ReadDir(outside)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: entries=%v error=%v", entries, readErr)
	}
	data, readErr := os.ReadFile("output")
	if readErr != nil || len(data) != 0 {
		t.Fatalf("cache failure was redumped: %q error=%v", data, readErr)
	}
}

func TestPagerRawOutputAndAddressWalkFatality(t *testing.T) {
	var output bytes.Buffer
	controller := &Controller{out: &output}
	controller.EnablePager(strings.NewReader(""))
	if err := controller.publishPaged(context.Background(), "raw data\n"); err != nil || output.String() != "raw data\n" {
		t.Fatalf("raw error=%v output=%q", err, output.String())
	}
	output.Reset()
	controller.pager = &commandPager{}
	for _, failure := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		if err := controller.publishPagedAddressWalk(context.Background(), "telescope", "unconfirmed data", failure); !errors.Is(err, failure) || output.Len() != 0 {
			t.Fatalf("unconfirmed data published: error=%v output=%q", err, output.String())
		}
	}
	controller.pager = nil
	err := controller.publishPagedAddressWalk(context.Background(), "telescope", "confirmed prefix\n", io.ErrUnexpectedEOF)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(output.String(), "confirmed prefix") {
		t.Fatalf("confirmed partial data lost: error=%v output=%q", err, output.String())
	}
	var expected bytes.Buffer
	plain := &Controller{out: &expected}
	plain.publishAddressWalk(context.Background(), "telescope", "confirmed prefix\n", io.ErrUnexpectedEOF)
	if expected.String() != output.String() {
		t.Fatalf("pager raw formatting changed: output=%q want=%q", output.String(), expected.String())
	}
	controller.out = controllerTestWriter(func([]byte) (int, error) { return 0, nil })
	err = controller.publishPaged(context.Background(), "raw")
	var outputErr *OutputError
	if !errors.Is(err, io.ErrShortWrite) || !errors.As(err, &outputErr) {
		t.Fatalf("raw output error=%v", err)
	}
}

func TestPagerTelescopePreservesLogicalRowsAndLegacyDefault(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	fixture.stack = make([]byte, 128*8)
	quit, err := controller.Execute(context.Background(), "tel", "$rsp")
	if err != nil || quit || len(fixture.stackCalls) != 128 || strings.Count(output.String(), "\n") != 129 || !strings.Contains(output.String(), "|+0x03f8|+127:") {
		t.Fatalf("legacy default: quit=%t error=%v reads=%d output=%q", quit, err, len(fixture.stackCalls), output.String())
	}
	for _, call := range fixture.stackCalls {
		if call.size != 8 || call.token != fixture.snapshot.Memory {
			t.Fatalf("default read changed width or token: %+v", call)
		}
	}
	controller, fixture, output = newAddressWalkTestController()
	words := make(map[target.Address]uint64)
	for address := target.Address(0x1000); address < 0x1088; address += 8 {
		words[address] = uint64(address + 8)
	}
	addressWalkTestWords(fixture, words)
	quit, err = controller.Execute(context.Background(), "telescope", "--depth 16 0x1000 1")
	rows := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if err != nil || quit || len(fixture.stackCalls) != 17 || len(rows) != 2 || display.VisibleWidth(rows[1]) <= 120 || strings.Count(rows[1], " -> ") != 17 || !strings.HasSuffix(rows[1], "0x0000000000001088 -> ...") {
		t.Fatalf("logical chain was wrapped or shortened: quit=%t error=%v reads=%d rows=%q", quit, err, len(fixture.stackCalls), rows)
	}
	var ordinary bytes.Buffer
	controller.out = &ordinary
	if err := controller.publishAddressWalk(context.Background(), "stack", rows[1]+"\n", nil); err != nil || strings.Count(ordinary.String(), "\n") <= 2 {
		t.Fatalf("nonpager stack wrapping changed: error=%v text=%q", err, ordinary.String())
	}
}

func TestPagerSymbolRenderingUsesIsolatedBufferAndCancels(t *testing.T) {
	controller, _, original := newInspectionTestController()
	facts := legacyFunctionFacts()
	base := facts[0].symbols[0]
	for index := 0; index < 20000; index++ {
		symbol := base
		symbol.Name = fmt.Sprintf("symbol_%d", index)
		facts[0].symbols = append(facts[0].symbols, symbol)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output strings.Builder
	calls := 0
	err := controller.renderSymbolFactsWith(ctx, facts, "", func(format string, args ...any) error {
		calls++
		if calls == 7 {
			cancel()
		}
		_, err := fmt.Fprintf(&output, format, args...)
		return err
	})
	if !errors.Is(err, context.Canceled) || calls != 7 || original.Len() != 0 || controller.out != original || output.Len() == 0 {
		t.Fatalf("isolated render calls=%d error=%v original=%q buffered=%d", calls, err, original.String(), output.Len())
	}
	output.Reset()
	if err := controller.renderSymbolFactsWith(context.Background(), facts, "", func(format string, args ...any) error {
		_, err := fmt.Fprintf(&output, format, args...)
		return err
	}); err != nil || !strings.Contains(output.String(), "20001 symbol(s)") || original.Len() != 0 {
		t.Fatalf("large symbol buffer error=%v length=%d original=%q", err, output.Len(), original.String())
	}
}
