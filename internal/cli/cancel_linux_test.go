package cli

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/muesli/cancelreader"
	"golang.org/x/sys/unix"
)

func testFileCancelIO() fileCancelIO {
	return fileCancelIO{
		eventfd: func(uint, int) (int, error) { return 12345, nil },
		poll:    func([]unix.PollFd, int) (int, error) { return 0, errors.New("unexpected poll") },
		write:   func(_ int, data []byte) (int, error) { return len(data), nil },
		close:   func(int) error { return nil },
	}
}

func testFileCancelSource(t *testing.T, calls fileCancelIO) (*fileCancelReader, *os.File) {
	t.Helper()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); writer.Close() })
	source, err := newFileCancelReaderIO(input, calls)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	return source, writer
}

func TestFileCancelReaderConstructor(t *testing.T) {
	calls := testFileCancelIO()
	calls.eventfd = func(value uint, flags int) (int, error) {
		if value != 0 || flags != unix.EFD_CLOEXEC|unix.EFD_NONBLOCK {
			t.Fatalf("eventfd arguments: value=%d flags=%#x", value, flags)
		}
		return 12345, nil
	}
	source, _ := testFileCancelSource(t, calls)
	if source.wake != 12345 || source.fd < 0 {
		t.Fatalf("invalid descriptor ownership: input=%d wake=%d", source.fd, source.wake)
	}
}

func TestFileCancelReaderConstructorFailure(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	want := errors.New("eventfd failed")
	calls := testFileCancelIO()
	calls.eventfd = func(uint, int) (int, error) { return -1, want }
	calls.close = func(int) error { t.Fatal("closing a descriptor that was never acquired"); return nil }
	source, err := newFileCancelReaderIO(input, calls)
	if source != nil || !errors.Is(err, want) {
		t.Fatalf("got %v, %v; want constructor failure", source, err)
	}
	if _, err := input.Stat(); err != nil {
		t.Fatalf("constructor failure closed caller input: %v", err)
	}
	if source, err := newFileCancelReader(nil); source != nil || !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil file: got %v, %v", source, err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if source, err := newFileCancelReader(input); source != nil || err == nil {
		t.Fatalf("closed file: got %v, %v", source, err)
	}
}

func TestFileCancelReaderPollRetryAndInput(t *testing.T) {
	calls := testFileCancelIO()
	var polls int
	calls.poll = func(events []unix.PollFd, timeout int) (int, error) {
		polls++
		if timeout != -1 || len(events) != 2 || events[0].Events != unix.POLLIN || events[1].Events != unix.POLLIN {
			t.Fatalf("unexpected poll arguments: %+v, %d", events, timeout)
		}
		if polls == 1 {
			return -1, unix.EINTR
		}
		if polls == 2 {
			return 0, nil
		}
		events[0].Revents = unix.POLLIN
		return 1, nil
	}
	source, writer := testFileCancelSource(t, calls)
	if _, err := writer.Write([]byte("input")); err != nil {
		t.Fatal(err)
	}
	var data [5]byte
	n, err := source.Read(data[:])
	if err != nil || n != len(data) || string(data[:]) != "input" || polls != 3 {
		t.Fatalf("got %q, %d, %v, polls=%d", data, n, err, polls)
	}
}

func TestFileCancelReaderReadFailures(t *testing.T) {
	failure := errors.New("poll failed")
	for _, test := range []struct {
		name  string
		input int16
		wake  int16
		err   error
		want  error
	}{
		{"poll", 0, 0, failure, failure},
		{"input invalid", unix.POLLNVAL, 0, nil, unix.EBADF},
		{"wake invalid", 0, unix.POLLNVAL, nil, nil},
		{"wake error", 0, unix.POLLERR, nil, nil},
		{"wake hangup", 0, unix.POLLHUP, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := testFileCancelIO()
			calls.poll = func(events []unix.PollFd, _ int) (int, error) {
				events[0].Revents, events[1].Revents = test.input, test.wake
				return 1, test.err
			}
			source, _ := testFileCancelSource(t, calls)
			n, err := source.Read(make([]byte, 1))
			if n != 0 || err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("got %d, %v; want error %v", n, err, test.want)
			}
		})
	}
}

func TestFileCancelReaderReadEOFAndClosedInput(t *testing.T) {
	for _, closed := range []bool{false, true} {
		calls := testFileCancelIO()
		calls.poll = func(events []unix.PollFd, _ int) (int, error) {
			events[0].Revents = unix.POLLHUP | unix.POLLERR
			return 1, nil
		}
		source, writer := testFileCancelSource(t, calls)
		writer.Close()
		want := io.EOF
		if closed {
			source.input.Close()
			want = os.ErrClosed
		}
		n, err := source.Read(make([]byte, 1))
		if n != 0 || !errors.Is(err, want) {
			t.Fatalf("closed=%t: got %d, %v; want %v", closed, n, err, want)
		}
	}
}

func TestFileCancelReaderCancellationPriority(t *testing.T) {
	for _, mode := range []string{"both ready", "canceled input", "interrupted poll"} {
		t.Run(mode, func(t *testing.T) {
			calls := testFileCancelIO()
			var source *fileCancelReader
			calls.poll = func(events []unix.PollFd, _ int) (int, error) {
				events[0].Revents = unix.POLLIN
				if mode == "both ready" {
					events[1].Revents = unix.POLLIN
				} else {
					source.Cancel()
				}
				if mode == "interrupted poll" {
					return -1, unix.EINTR
				}
				return 2, nil
			}
			var writer *os.File
			source, writer = testFileCancelSource(t, calls)
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 1)
			if n, err := source.Read(data); n != 0 || err != cancelreader.ErrCanceled {
				t.Fatalf("got %d, %v; want cancellation", n, err)
			}
			if n, err := source.input.Read(data); n != 1 || err != nil || data[0] != 'x' {
				t.Fatalf("canceled read consumed caller input: %q, %d, %v", data, n, err)
			}
		})
	}
}

func TestFileCancelReaderCancelRetryAndIdempotence(t *testing.T) {
	calls := testFileCancelIO()
	var writes, closes int
	calls.write = func(fd int, data []byte) (int, error) {
		writes++
		if fd != 12345 || len(data) != 8 || binary.NativeEndian.Uint64(data) != 1 {
			t.Fatalf("invalid native-endian event write: fd=%d data=%x", fd, data)
		}
		if writes == 1 {
			return -1, unix.EINTR
		}
		return len(data), nil
	}
	calls.close = func(int) error { closes++; return nil }
	source, _ := testFileCancelSource(t, calls)
	if n, err := source.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d, %v", n, err)
	}
	for range 2 {
		if !source.Cancel() {
			t.Fatal("cancel failed")
		}
		if n, err := source.Read(make([]byte, 1)); n != 0 || err != cancelreader.ErrCanceled {
			t.Fatalf("read after cancellation: %d, %v", n, err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 2 || closes != 1 {
		t.Fatalf("non-idempotent cleanup: writes=%d closes=%d", writes, closes)
	}
}

func TestFileCancelReaderCancelAndCloseFailures(t *testing.T) {
	writeFailure := errors.New("eventfd write failed")
	closeFailure := errors.New("eventfd close failed")
	for _, test := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{"write error", 0, writeFailure, writeFailure},
		{"short write", 7, nil, io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := testFileCancelIO()
			var writes, closes int
			calls.write = func(int, []byte) (int, error) { writes++; return test.n, test.err }
			calls.close = func(int) error { closes++; return closeFailure }
			source, _ := testFileCancelSource(t, calls)
			if source.Cancel() {
				t.Fatal("failed cancellation reported success")
			}
			for range 2 {
				err := source.Close()
				if !errors.Is(err, test.want) || !errors.Is(err, closeFailure) {
					t.Fatalf("cleanup lost independent errors: %v", err)
				}
			}
			if writes != 1 || closes != 1 {
				t.Fatalf("cleanup repeated failed syscalls: writes=%d closes=%d", writes, closes)
			}
		})
	}
}

func TestFileCancelReaderCloseJoinsRead(t *testing.T) {
	calls := testFileCancelIO()
	started, wake, leftPoll := make(chan struct{}), make(chan struct{}), make(chan struct{})
	calls.poll = func(events []unix.PollFd, _ int) (int, error) {
		close(started)
		<-wake
		events[1].Revents = unix.POLLIN
		close(leftPoll)
		return 1, nil
	}
	calls.write = func(_ int, data []byte) (int, error) { close(wake); return len(data), nil }
	calls.close = func(int) error {
		select {
		case <-leftPoll:
		default:
			t.Error("private descriptor closed before read left poll")
		}
		return nil
	}
	source, _ := testFileCancelSource(t, calls)
	done := make(chan error, 1)
	go func() {
		_, err := source.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not start")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := source.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	select {
	case err := <-done:
		if err != cancelreader.ErrCanceled {
			t.Fatalf("read returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read remained active after close")
	}
}

func TestFileCancelReaderDescriptorFlags(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	fd, err := fileDescriptor(input)
	if err != nil {
		t.Fatal(err)
	}
	before, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	source, err := newFileCancelReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	flags, err := unix.FcntlInt(uintptr(source.wake), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("private event descriptor lacks CLOEXEC: %#x, %v", flags, err)
	}
	flags, err = unix.FcntlInt(uintptr(source.wake), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("private event descriptor is blocking: %#x, %v", flags, err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || before != after {
		t.Fatalf("caller input flags changed: before=%#x after=%#x error=%v", before, after, err)
	}
	if _, err := unix.FcntlInt(uintptr(source.wake), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("private descriptor survived close: %v", err)
	}
}
