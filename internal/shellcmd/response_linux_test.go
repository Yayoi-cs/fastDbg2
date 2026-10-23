package shellcmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCapacityHelperProcess(t *testing.T) {
	for index, argument := range os.Args {
		if argument != "--" || len(os.Args) != index+3 || os.Args[index+1] != "pipe-capacity" {
			continue
		}
		capacity, err := strconv.Atoi(os.Args[index+2])
		if err != nil {
			os.Exit(124)
		}
		if _, err := unix.FcntlInt(4, unix.F_SETPIPE_SZ, capacity); err != nil {
			os.Exit(123)
		}
		code, handled := Helper([]string{helperArgument})
		if !handled {
			os.Exit(122)
		}
		os.Exit(code)
	}
}

func runCapacityCommand(t *testing.T, ctx context.Context, command Command, capacity int) error {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return runCommand(ctx, command, executable, []string{"-test.run=^TestCapacityHelperProcess$", "--", "pipe-capacity", strconv.Itoa(capacity)})
}

func TestSupervisorResponseDoesNotDependOnPipeCapacity(t *testing.T) {
	for _, capacity := range []int{4096, 65536} {
		for _, value := range []string{"\\", "\"", "界"} {
			t.Run(strconv.Itoa(capacity)+"/"+strconv.Quote(value), func(t *testing.T) {
				command := Command{Path: "/" + strings.Repeat(value, 5000), Stdin: shellInput(t), Output: io.Discard}
				err := runCapacityCommand(t, shellContext(t), command, capacity)
				if err == nil || !strings.Contains(err.Error(), "start ") || !strings.HasSuffix(err.Error(), " ... [truncated]") || strings.Contains(err.Error(), "supervisor response") || errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("large quoted startup error: %v", err)
				}
			})
		}
	}
}

func TestSupervisorSmallPipesHandleLargeRequests(t *testing.T) {
	arguments := []string{"%s"}
	for range 10000 {
		arguments = append(arguments, "literal")
	}
	var output countingOutput
	err := runCapacityCommand(t, shellContext(t), Command{Path: "/usr/bin/printf", Args: arguments, Stdin: shellInput(t), Output: &output}, 4096)
	if err != nil || output.total != 70000 {
		t.Fatalf("large request on a small pipe: output=%d, error=%v", output.total, err)
	}
}

func TestSupervisorSmallPipesJoinCanceledAndFailedCommands(t *testing.T) {
	for _, mode := range []string{"cancel", "output failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(shellContext(t))
			defer cancel()
			output := newObservedOutput(1)
			command := Command{Path: "/bin/sh", Args: []string{"-c", "printf 'PID %s\\n' \"$$\"; exec sleep 3600"}, Stdin: shellInput(t), Output: output}
			failure := errors.New("output failed")
			if mode == "output failure" {
				command.Output = failingOutput{observed: output, err: failure}
			}
			done := make(chan error, 1)
			go func() { done <- runCapacityCommand(t, ctx, command, 4096) }()
			select {
			case <-output.ready:
				if mode == "cancel" {
					cancel()
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if mode == "cancel" {
				failure = context.Canceled
			}
			if err := <-done; !errors.Is(err, failure) {
				t.Fatalf("command termination: %v", err)
			}
			output.assertReaped(t)
		})
	}
}

func exitedSupervisor(t *testing.T) int {
	t.Helper()
	child := exec.Command("/bin/true")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()
	pidfd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(pidfd) })
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	return pidfd
}

func responsePipe(t *testing.T, payload string, open bool) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })
	connection, err := writer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sizeErr error
	if err := connection.Control(func(fd uintptr) { _, sizeErr = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, 65536) }); err != nil || sizeErr != nil {
		t.Fatalf("resize response fixture pipe: %v, %v", err, sizeErr)
	}
	if _, err := io.WriteString(writer, payload); err != nil {
		t.Fatal(err)
	}
	if !open {
		writer.Close()
	}
	return reader
}

func TestSupervisorResponseRequiresRealEOF(t *testing.T) {
	pidfd := exitedSupervisor(t)
	for _, blocking := range []bool{false, true} {
		reader := responsePipe(t, `{"code":0,"signal":0,"canceled":false}`, true)
		if blocking {
			if err := privateBlocking(reader); err != nil {
				t.Fatal(err)
			}
		}
		outcome := readSupervisorResponse(reader, pidfd)
		if outcome.err == nil || !strings.Contains(outcome.err.Error(), "remained open") {
			t.Fatalf("retained writer accepted or not diagnosed: blocking=%t, %+v", blocking, outcome)
		}
	}
}

func TestSupervisorResponseStrictBoundsAndProtocol(t *testing.T) {
	pidfd := exitedSupervisor(t)
	for _, payload := range []string{
		"",
		"null",
		`{"code":256}`,
		`{"signal":65}`,
		`{"code":1,"signal":9}`,
		`{"unknown":true}`,
		`{"code":0} {}`,
		`{"code":0} trailing`,
		`{"error":"` + strings.Repeat("x", 4097) + `"}`,
		strings.Repeat(" ", responseLimit+1),
	} {
		outcome := readSupervisorResponse(responsePipe(t, payload, false), pidfd)
		if outcome.err == nil {
			t.Fatalf("accepted invalid response of %d bytes", len(payload))
		}
	}
	maximum := result{Error: strings.Repeat("\x01", 4096)}
	encoded, err := json.Marshal(maximum)
	if err != nil {
		t.Fatal(err)
	}
	outcome := readSupervisorResponse(responsePipe(t, string(encoded), false), pidfd)
	if outcome.err != nil || outcome.value.Error != maximum.Error {
		t.Fatalf("maximum escaped response: length=%d, %v", len(encoded), outcome.err)
	}
}
