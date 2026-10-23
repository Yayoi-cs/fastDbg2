package shellcmd

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

type descriptorFlags struct {
	status     int
	descriptor int
}

func readDescriptorFlags(file *os.File) (descriptorFlags, error) {
	connection, err := file.SyscallConn()
	if err != nil {
		return descriptorFlags{}, err
	}
	var flags descriptorFlags
	var flagErr error
	err = connection.Control(func(fd uintptr) {
		flags.status, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if flagErr == nil {
			flags.descriptor, flagErr = unix.FcntlInt(fd, unix.F_GETFD, 0)
		}
	})
	return flags, errors.Join(err, flagErr)
}

func TestRunCommandPreservesCallerDescriptorFlags(t *testing.T) {
	for _, mode := range []string{"normal", "cancel", "output-error", "exec-error"} {
		t.Run(mode, func(t *testing.T) {
			input, inputWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer inputWriter.Close()
			extra, extraWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer extra.Close()
			defer extraWriter.Close()
			var before []descriptorFlags
			for _, file := range []*os.File{input, extra} {
				flags, err := readDescriptorFlags(file)
				if err != nil || flags.status&unix.O_NONBLOCK == 0 || flags.descriptor&unix.FD_CLOEXEC == 0 {
					t.Fatalf("nonblocking caller descriptor: %+v, %v", flags, err)
				}
				before = append(before, flags)
			}
			ctx, cancel := context.WithCancel(shellContext(t))
			defer cancel()
			command := Command{Path: "/bin/true", Stdin: input, Output: io.Discard, ExtraFiles: []*os.File{extra}}
			switch mode {
			case "cancel":
				output := newObservedOutput(2)
				command.Path, command.Args, command.Output = "/bin/sh", []string{"-c", "sleep 3600 & printf 'PID %s\\nPID %s\\n' \"$$\" \"$!\"; wait"}, output
				done := make(chan error, 1)
				go func() { done <- RunCommand(ctx, command) }()
				select {
				case <-output.ready:
					cancel()
				case err := <-done:
					t.Fatalf("early command completion: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel: %v", err)
				}
				output.assertReaped(t)
			case "output-error":
				output := newObservedOutput(1)
				failure := errors.New("output failed")
				command.Path, command.Args = "/bin/sh", []string{"-c", "printf 'PID %s\\n' \"$$\"; exec sleep 3600"}
				command.Output = failingOutput{observed: output, err: failure}
				if err := RunCommand(ctx, command); !errors.Is(err, failure) {
					t.Fatalf("output failure: %v", err)
				}
				output.assertReaped(t)
			case "exec-error":
				command.Path = "/proc/self/fastdbg2-no-such-program"
				if err := RunCommand(ctx, command); err == nil {
					t.Fatal("missing executable succeeded")
				}
			default:
				if err := RunCommand(ctx, command); err != nil {
					t.Fatal(err)
				}
			}
			for index, file := range []*os.File{input, extra} {
				after, err := readDescriptorFlags(file)
				if err != nil || after != before[index] {
					t.Fatalf("caller descriptor %d changed: %+v -> %+v (%v)", index, before[index], after, err)
				}
			}
		})
	}
}

func TestRunCommandRejectsNonterminalDirectOutput(t *testing.T) {
	for _, foreground := range []bool{false, true} {
		if err := RunCommand(shellContext(t), Command{Path: "/bin/true", Stdin: shellInput(t), Output: io.Discard, Foreground: foreground, TerminalOutput: true}); err == nil {
			t.Fatalf("accepted direct output without controlling terminal, foreground=%t", foreground)
		}
	}
}
