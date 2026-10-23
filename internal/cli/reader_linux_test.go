package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStreamPipeCloseCancelsReadAndPreservesCallerDescriptors(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	testStreamFileClose(t, input, writer)
}

func TestStreamSocketCloseCancelsReadAndPreservesCallerDescriptors(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fds[0]), "input socket")
	writer := os.NewFile(uintptr(fds[1]), "peer socket")
	defer input.Close()
	defer writer.Close()
	testStreamFileClose(t, input, writer)
}

func TestStreamDumbTerminalCloseCancelsReadWithoutChangingTermios(t *testing.T) {
	master, slave := openTestPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	testStreamFileClose(t, slave, master)
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if *before != *after {
		t.Fatalf("stream terminal changed termios: before=%+v after=%+v", before, after)
	}
}

func testStreamFileClose(t *testing.T, input, writer *os.File) {
	t.Helper()
	var baseline int
	for iteration := range 6 {
		reader, err := NewReader(Config{Input: input, Output: io.Discard, Term: "dumb"})
		if err != nil {
			t.Fatal(err)
		}
		if reader.Interactive() || reader.cancel == nil {
			reader.Close()
			t.Fatal("pollable file did not select cancellable stream mode")
		}
		started := make(chan struct{})
		source := reader.cancel
		reader.stream = bufio.NewReader(readerFunc(func(p []byte) (int, error) {
			close(started)
			return source.Read(p)
		}))
		done := make(chan error, 1)
		go func() {
			_, err := reader.ReadLine()
			done <- err
		}()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("stream read did not start")
		}
		closed := make(chan error, 1)
		go func() { closed <- reader.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("stream close did not cancel pending read")
		}
		select {
		case err := <-done:
			if err != io.EOF {
				t.Fatalf("read returned %v, want EOF", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("stream read survived close")
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("caller probe\n")); err != nil {
			t.Fatal(err)
		}
		probe := make(chan readEvent, 1)
		go func() {
			data := make([]byte, len("caller probe\n"))
			_, err := io.ReadFull(input, data)
			probe <- readEvent{data: data, err: err}
		}()
		select {
		case result := <-probe:
			if result.err != nil || string(result.data) != "caller probe\n" {
				t.Fatalf("caller input unavailable: %q, %v", result.data, result.err)
			}
		case <-time.After(3 * time.Second):
			input.Close()
			t.Fatal("closed stream reader stole caller input")
		}
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			baseline = len(fds)
		} else if len(fds) != baseline {
			t.Fatalf("stream descriptor leak: got %d, want %d", len(fds), baseline)
		}
	}
}

func TestStreamRegularFileDoesNotUsePollCancellation(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "input"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := NewReader(Config{Input: file, Output: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if reader.cancel != nil {
		reader.Close()
		t.Fatal("regular file used unsupported epoll cancellation")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatalf("caller file closed: %v", err)
	}
}

func TestStreamClosedFileReturnsInitializationError(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "input"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if reader, err := NewReader(Config{Input: file, Output: io.Discard}); err == nil || reader != nil {
		t.Fatalf("got reader=%v, error=%v for closed input", reader, err)
	}
}

func TestStreamReaderPreservesCallerFileFlags(t *testing.T) {
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer inputWriter.Close()
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputReader.Close()
	defer output.Close()
	flags := func(file *os.File) int {
		fd, err := fileDescriptor(file)
		if err != nil {
			t.Fatal(err)
		}
		value, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	inputBefore, outputBefore := flags(input), flags(output)
	reader, err := NewReader(Config{Input: input, Output: output, Term: "xterm"})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := inputWriter.Write([]byte("command\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadLine(); err != nil || line != "command" {
		t.Fatalf("got %q, %v", line, err)
	}
	if flags(input) != inputBefore || flags(output) != outputBefore {
		t.Fatal("reader changed caller descriptor flags during a read")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if flags(input) != inputBefore || flags(output) != outputBefore {
		t.Fatal("reader changed caller descriptor flags after close")
	}
}

func TestTerminalReaderPreservesCallerFileFlags(t *testing.T) {
	master, slave := openTestPTY(t)
	fd, err := fileDescriptor(slave)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := flags | unix.O_NONBLOCK
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, before); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReader(Config{Input: slave, Output: slave, Prompt: "> ", Term: "xterm"})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	done := make(chan readEvent, 1)
	go func() {
		line, err := reader.ReadLine()
		done <- readEvent{data: []byte(line), err: err}
	}()
	if err := master.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var output []byte
	for !bytes.Contains(output, []byte("\x1b[6n")) {
		var buffer [512]byte
		n, err := master.Read(buffer[:])
		if err != nil {
			t.Fatalf("waiting for terminal query: %v", err)
		}
		output = append(output, buffer[:n]...)
	}
	if _, err := master.Write([]byte("\x1b[1;1R日本語 🌐\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || string(result.data) != "日本語 🌐" {
			t.Fatalf("terminal read: %q, %v", result.data, result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("terminal read did not finish")
	}
	after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || after != before {
		t.Fatalf("terminal read changed caller flags: before=%#x after=%#x error=%v", before, after, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	after, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || after != before {
		t.Fatalf("terminal close changed caller flags: before=%#x after=%#x error=%v", before, after, err)
	}
}

func TestTerminalReaderRepeatedClosePreservesDescriptors(t *testing.T) {
	master, slave := openTestPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	var baseline int
	for iteration := range 6 {
		reader, err := NewReader(Config{
			Input:    slave,
			Output:   slave,
			Prompt:   "> ",
			Commands: []string{"help", "exit", "quit"},
			Term:     "xterm",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !reader.Interactive() {
			t.Fatal("PTY did not select terminal editor")
		}
		done := make(chan error, 1)
		go func() {
			_, err := reader.ReadLine()
			done <- err
		}()
		if err := master.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var output []byte
		for !bytes.Contains(output, []byte("\x1b[6n")) {
			var buffer [512]byte
			n, err := master.Read(buffer[:])
			if err != nil {
				reader.Close()
				t.Fatalf("waiting for terminal query: %v", err)
			}
			output = append(output, buffer[:n]...)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != io.EOF {
				t.Fatalf("read returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("read remained active after close")
		}
		after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if *before != *after {
			t.Fatalf("terminal state changed after close: before=%+v after=%+v", before, after)
		}
		if _, err := master.Write([]byte("caller probe\n")); err != nil {
			t.Fatal(err)
		}
		if err := slave.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len("caller probe\n"))
		if _, err := io.ReadFull(slave, got); err != nil {
			t.Fatalf("caller input unavailable after close: %v", err)
		}
		if string(got) != "caller probe\n" {
			t.Fatalf("caller input consumed by closed editor: %q", got)
		}
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			baseline = len(fds)
		} else if len(fds) != baseline {
			t.Fatalf("descriptor leak at iteration %d: got %d, want %d", iteration, len(fds), baseline)
		}
	}
}

func openTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
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
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	return master, slave
}
