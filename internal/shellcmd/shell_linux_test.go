package shellcmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if code, handled := Helper(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestHelperProcess(t *testing.T) {
	for index, argument := range os.Args {
		if argument == "--" {
			code, handled := Helper(os.Args[index+1:])
			if !handled {
				os.Exit(126)
			}
			os.Exit(code)
		}
	}
}

func runShellTest(ctx context.Context, command string, input *os.File, output io.Writer) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return run(ctx, command, input, output, executable, []string{"-test.run=^TestHelperProcess$", "--", helperArgument})
}

func shellInput(t *testing.T) *os.File {
	t.Helper()
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close() })
	return input
}

func shellContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestShellQuotingExpansionAndNewlines(t *testing.T) {
	var output bytes.Buffer
	err := runShellTest(shellContext(t), "word='a b'; printf '%s|%s|%s\\n' \"$word\" '\\n' \"$(printf c)\"\nprintf stderr >&2", shellInput(t), &output)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "a b|\\n|c\nstderr"; got != want {
		t.Fatalf("output %q, want %q", got, want)
	}
}

func TestShellReadsStdin(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := io.WriteString(writer, "literal 'quoted' \\ value\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	var output bytes.Buffer
	if err := runShellTest(shellContext(t), "IFS= read -r line; printf '%s\\n' \"$line\"", input, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "literal 'quoted' \\ value\n" {
		t.Fatalf("stdin changed: %q", output.String())
	}
}

func TestShellExitErrors(t *testing.T) {
	for _, test := range []struct {
		command string
		code    int
		signal  int
	}{
		{"exit 19", 19, 0},
		{"kill -TERM $$", 0, int(syscall.SIGTERM)},
		{"kill -PIPE $$", 0, int(syscall.SIGPIPE)},
	} {
		t.Run(test.command, func(t *testing.T) {
			err := runShellTest(shellContext(t), test.command, shellInput(t), io.Discard)
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != test.code || exit.Signal != test.signal {
				t.Fatalf("exit error: %#v, %v", exit, err)
			}
		})
	}
}

func TestShellValidation(t *testing.T) {
	for _, command := range []string{"", " \t\n", "printf a\x00printf b", strings.Repeat("x", commandLimit+1)} {
		if err := runShellTest(shellContext(t), command, shellInput(t), io.Discard); err == nil {
			t.Fatalf("accepted invalid command of length %d", len(command))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runShellTest(ctx, "exit 0", shellInput(t), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled command: %v", err)
	}
	if err := runShellTest(nil, "exit 0", shellInput(t), io.Discard); err == nil {
		t.Fatal("accepted nil context")
	}
}

type observedOutput struct {
	mu     sync.Mutex
	buffer string
	pids   map[int]bool
	ready  chan struct{}
	want   int
	once   sync.Once
}

func (w *observedOutput) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buffer += string(value)
	for {
		line, rest, found := strings.Cut(w.buffer, "\n")
		if !found {
			break
		}
		w.buffer = rest
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "PID" {
			pid, err := strconv.Atoi(fields[1])
			if err == nil && pid > 0 {
				w.pids[pid] = true
			}
		}
	}
	if len(w.pids) >= w.want {
		w.once.Do(func() { close(w.ready) })
	}
	return len(value), nil
}

func (w *observedOutput) assertReaped(t *testing.T) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pids) < w.want {
		t.Fatalf("observed %d PIDs, want %d", len(w.pids), w.want)
	}
	for pid := range w.pids {
		if data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("shell descendant %d was not reaped: %q, %v", pid, data, err)
		}
	}
}

func newObservedOutput(want int) *observedOutput {
	return &observedOutput{pids: make(map[int]bool), ready: make(chan struct{}), want: want}
}

func TestShellCancellationReapsDescendants(t *testing.T) {
	ctx, cancel := context.WithCancel(shellContext(t))
	defer cancel()
	output := newObservedOutput(3)
	done := make(chan error, 1)
	command := "printf 'PID %s\\n' \"$$\"; sh -c 'trap \"\" INT TERM; sleep 3600 & printf \"PID %s\\n\" \"$!\"; wait' & printf 'PID %s\\n' \"$!\"; wait"
	input := shellInput(t)
	go func() { done <- runShellTest(ctx, command, input, output) }()
	select {
	case <-output.ready:
		cancel()
	case err := <-done:
		t.Fatalf("shell exited before descendants were ready: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	output.assertReaped(t)
}

func TestShellNormalExitReapsBackgroundChildren(t *testing.T) {
	output := newObservedOutput(1)
	if err := runShellTest(shellContext(t), "sleep 3600 & printf 'PID %s\\n' \"$!\"", shellInput(t), output); err != nil {
		t.Fatal(err)
	}
	output.assertReaped(t)
}

func TestShellSupervisorSignalsReapChildren(t *testing.T) {
	for _, name := range []string{"INT", "TERM", "PIPE", "HUP"} {
		t.Run(name, func(t *testing.T) {
			output := newObservedOutput(2)
			command := "sleep 3600 & printf 'PID %s\\nPID %s\\n' \"$$\" \"$!\"; kill -" + name + " \"$PPID\"; wait"
			err := runShellTest(shellContext(t), command, shellInput(t), output)
			if err == nil || !strings.Contains(err.Error(), "shell interrupted") {
				t.Fatalf("supervisor signal %s: %v", name, err)
			}
			output.assertReaped(t)
		})
	}
}

func TestShellNormalExitReapsDetachedGrandchildren(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Fatal(err)
	}
	ctx := shellContext(t)
	output := newObservedOutput(2)
	command := "trap 'exit 0' USR1; setsid sh -c 'printf \"PID %s\\n\" \"$$\"; sleep 3600 & printf \"PID %s\\n\" \"$!\"; kill -USR1 \"$1\"; wait' helper \"$$\" & wait"
	if err := runShellTest(ctx, command, shellInput(t), output); err != nil {
		t.Fatal(err)
	}
	output.assertReaped(t)
}

type failingOutput struct {
	observed *observedOutput
	err      error
	short    bool
}

func (w failingOutput) Write(value []byte) (int, error) {
	w.observed.Write(value)
	if w.short {
		return 0, nil
	}
	return 0, w.err
}

func TestShellOutputFailureReapsChildren(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(strconv.FormatBool(short), func(t *testing.T) {
			output := newObservedOutput(1)
			failure := errors.New("writer failed")
			err := runShellTest(shellContext(t), "printf 'PID %s\\n' \"$$\"; exec sleep 3600", shellInput(t), failingOutput{observed: output, err: failure, short: short})
			if short {
				failure = io.ErrShortWrite
			}
			var writeErr *OutputError
			if !errors.As(err, &writeErr) || !errors.Is(err, failure) {
				t.Fatalf("write failure: %v", err)
			}
			output.assertReaped(t)
		})
	}
}

type countingOutput struct {
	total   int
	largest int
}

func (w *countingOutput) Write(value []byte) (int, error) {
	w.total += len(value)
	if len(value) > w.largest {
		w.largest = len(value)
	}
	return len(value), nil
}

func TestShellStreamsOutputInBoundedChunks(t *testing.T) {
	var output countingOutput
	if err := runShellTest(shellContext(t), "head -c 2097152 /dev/zero", shellInput(t), &output); err != nil {
		t.Fatal(err)
	}
	if output.total != 2097152 || output.largest > 32768 {
		t.Fatalf("streamed bytes=%d largest=%d", output.total, output.largest)
	}
}

func TestShellDoesNotInheritSupervisorDescriptors(t *testing.T) {
	var output bytes.Buffer
	if err := runShellTest(shellContext(t), "for fd in /proc/$$/fd/*; do if [ -e \"$fd\" ]; then printf '%s\\n' \"$fd\"; fi; done", shellInput(t), &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(output.String())
	if len(lines) != 3 {
		t.Fatalf("inherited descriptors: %q", output.String())
	}
	for index, line := range lines {
		if !strings.HasSuffix(line, "/"+strconv.Itoa(index)) {
			t.Fatalf("inherited descriptor: %q", line)
		}
	}
}

func TestShellParentSubreaperAndChildrenRemainUntouched(t *testing.T) {
	var before int32
	err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&before)), 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := exec.Command("/bin/sh", "-c", "exit 23")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer unrelated.Wait()
	if err := runShellTest(shellContext(t), "exit 0", shellInput(t), io.Discard); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := unrelated.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("unrelated child status consumed: %v", err)
	}
	var after int32
	err = unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&after)), 0, 0, 0)
	if err != nil || before != after {
		t.Fatalf("parent subreaper changed: %d -> %d (%v)", before, after, err)
	}
}

func TestShellProtocolValidation(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {helperArgument, "extra"}, {"--fastdbg2-shell-helper"}} {
		if code, handled := Helper(args); handled || code != 0 {
			t.Fatalf("claimed ordinary args %q", args)
		}
	}
	for _, input := range [][]byte{
		nil,
		[]byte(strings.Repeat("!", len(protocolMagic)+4)),
		configurationForTest(""),
		configurationForTest("\x00"),
		configurationForTest("{}"),
		configurationForTest(`{"path":"/bin/true","unknown":true}`),
		configurationForTest(`{"path":"/bin/true"} {}`),
		append(configurationForTest("x")[:len(protocolMagic)+4], byte('x'))[:len(protocolMagic)+4],
	} {
		if _, err := readConfiguration(bytes.NewReader(input)); err == nil {
			t.Fatalf("accepted invalid protocol: %q", input)
		}
	}
	value := request{Path: "/bin/sh", Args: []string{"-c", "printf '%s\\n' 'value'"}}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := readConfiguration(bytes.NewReader(configurationForTest(string(encoded)))); err != nil || got.Path != value.Path || len(got.Args) != 2 || got.Args[1] != value.Args[1] {
		t.Fatalf("configuration %#v: %v", got, err)
	}
}

func configurationForTest(command string) []byte {
	value := make([]byte, len(protocolMagic)+4+len(command))
	copy(value, protocolMagic)
	binary.LittleEndian.PutUint32(value[len(protocolMagic):], uint32(len(command)))
	copy(value[len(protocolMagic)+4:], command)
	return value
}

func TestShellChildIdentityRejectsUnownedPID(t *testing.T) {
	fd, err := childHandle(os.Getpid())
	if fd >= 0 {
		unix.Close(fd)
	}
	if err == nil {
		t.Fatal("claimed the test process as its own child")
	}
}

func TestShellDescriptorCountStable(t *testing.T) {
	input := shellInput(t)
	if err := runShellTest(shellContext(t), "exit 0", input, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 8; index++ {
		if err := runShellTest(shellContext(t), "exit 0", input, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal(fmt.Sprintf("descriptor count %d -> %d: %v", len(before), len(after), err))
	}
}

func TestShellHelperRejectsMissingPrivateDescriptors(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(shellContext(t), executable, "-test.run=^TestHelperProcess$", "--", helperArgument)
	command.Stdin = shellInput(t)
	var exit *exec.ExitError
	if err := command.Run(); !errors.As(err, &exit) || exit.ExitCode() != 125 {
		t.Fatalf("helper without protocol: %v", err)
	}
}

func TestRunCommandPreservesLiteralArguments(t *testing.T) {
	var output bytes.Buffer
	values := []string{"$HOME", "$(printf not-expanded)", "a b", "'quoted'", "\\n", ""}
	command := Command{Path: "/usr/bin/printf", Args: append([]string{"<%s>\\n"}, values...), Stdin: shellInput(t), Output: &output}
	if err := RunCommand(shellContext(t), command); err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, value := range values {
		fmt.Fprintf(&want, "<%s>\n", value)
	}
	if output.String() != want.String() {
		t.Fatalf("literal arguments: %q", output.String())
	}
}

func TestRunCommandMapsExtraDescriptorAndEnvironment(t *testing.T) {
	directory := t.TempDir()
	object, err := os.OpenFile(filepath.Join(directory, "object"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	var output bytes.Buffer
	command := Command{
		Path: "/bin/sh", Args: []string{"-c", "printf 'object bytes' >&3; printf '%s\\n' \"$SUPERVISED_VALUE\"; pwd"},
		Dir: directory, Env: []string{"SUPERVISED_VALUE=literal $HOME"}, Stdin: shellInput(t), Output: &output,
		ExtraFiles: []*os.File{object},
	}
	if err := RunCommand(shellContext(t), command); err != nil {
		t.Fatal(err)
	}
	if output.String() != "literal $HOME\n"+directory+"\n" {
		t.Fatalf("environment/directory: %q", output.String())
	}
	if _, err := object.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(object)
	if err != nil || string(data) != "object bytes" {
		t.Fatalf("child fd 3: %q (%v)", data, err)
	}
}

func TestRunCommandExplicitEmptyEnvironment(t *testing.T) {
	var output bytes.Buffer
	if err := RunCommand(shellContext(t), Command{Path: "/usr/bin/env", Env: []string{}, Stdin: shellInput(t), Output: &output}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("empty environment inherited values: %q", output.String())
	}
}

func TestRunCommandCancellationReapsChildren(t *testing.T) {
	ctx, cancel := context.WithCancel(shellContext(t))
	defer cancel()
	output := newObservedOutput(2)
	done := make(chan error, 1)
	command := Command{Path: "/bin/sh", Args: []string{"-c", "sleep 3600 & printf 'PID %s\\nPID %s\\n' \"$$\" \"$!\"; wait"}, Stdin: shellInput(t), Output: output}
	go func() { done <- RunCommand(ctx, command) }()
	select {
	case <-output.ready:
		cancel()
	case err := <-done:
		t.Fatalf("command completed before readiness: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel direct command: %v", err)
	}
	output.assertReaped(t)
}

func TestRunCommandRejectsInvalidRequests(t *testing.T) {
	for _, command := range []Command{
		{Path: "relative"},
		{Path: "/bin/true\x00"},
		{Path: "/bin/true", Args: []string{"\xff"}},
		{Path: "/bin/true", Env: []string{"NAME=\x00"}},
		{Path: "/bin/true", Dir: "\x00"},
		{Path: "/bin/true", ExtraFiles: []*os.File{nil}},
	} {
		command.Stdin, command.Output = shellInput(t), io.Discard
		if err := RunCommand(shellContext(t), command); err == nil {
			t.Fatalf("accepted invalid request %#v", command)
		}
	}
}
