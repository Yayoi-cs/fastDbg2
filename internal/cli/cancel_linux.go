package cli

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/muesli/cancelreader"
	"golang.org/x/sys/unix"
)

type fileCancelIO struct {
	eventfd func(uint, int) (int, error)
	poll    func([]unix.PollFd, int) (int, error)
	write   func(int, []byte) (int, error)
	close   func(int) error
}

type fileCancelReader struct {
	input      *os.File
	fd         int
	wake       int
	calls      fileCancelIO
	canceled   atomic.Bool
	readMu     sync.Mutex
	cancelOnce sync.Once
	closeOnce  sync.Once
	cancelErr  error
	closeErr   error
}

func fileDescriptor(file *os.File) (int, error) {
	if file == nil {
		return -1, os.ErrInvalid
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	if err := raw.Control(func(value uintptr) { fd = int(value) }); err != nil {
		return -1, err
	}
	return fd, nil
}

func newFileCancelReader(input *os.File) (*fileCancelReader, error) {
	return newFileCancelReaderIO(input, fileCancelIO{
		eventfd: unix.Eventfd,
		poll:    unix.Poll,
		write:   unix.Write,
		close:   unix.Close,
	})
}

func newFileCancelReaderIO(input *os.File, calls fileCancelIO) (*fileCancelReader, error) {
	fd, err := fileDescriptor(input)
	if err != nil {
		return nil, err
	}
	wake, err := calls.eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("create input cancellation event: %w", err)
	}
	return &fileCancelReader{input: input, fd: fd, wake: wake, calls: calls}, nil
}

func (r *fileCancelReader) Read(p []byte) (int, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if r.canceled.Load() {
		return 0, cancelreader.ErrCanceled
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		events := []unix.PollFd{
			{Fd: int32(r.fd), Events: unix.POLLIN},
			{Fd: int32(r.wake), Events: unix.POLLIN},
		}
		_, err := r.calls.poll(events, -1)
		if errors.Is(err, unix.EINTR) {
			if r.canceled.Load() {
				return 0, cancelreader.ErrCanceled
			}
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("wait for input: %w", err)
		}
		if r.canceled.Load() || events[1].Revents&unix.POLLIN != 0 {
			return 0, cancelreader.ErrCanceled
		}
		if events[1].Revents != 0 {
			return 0, fmt.Errorf("input cancellation event failed: %#x", events[1].Revents)
		}
		if events[0].Revents&unix.POLLNVAL != 0 {
			return 0, unix.EBADF
		}
		if events[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			return r.input.Read(p)
		}
	}
}

func (r *fileCancelReader) Cancel() bool {
	r.cancelOnce.Do(func() {
		r.canceled.Store(true)
		var value [8]byte
		binary.NativeEndian.PutUint64(value[:], 1)
		for {
			n, err := r.calls.write(r.wake, value[:])
			if errors.Is(err, unix.EINTR) && n <= 0 {
				continue
			}
			if err == nil && n != len(value) {
				err = io.ErrShortWrite
			}
			r.cancelErr = err
			return
		}
	})
	return r.cancelErr == nil
}

func (r *fileCancelReader) Close() error {
	r.closeOnce.Do(func() {
		r.Cancel()
		r.readMu.Lock()
		defer r.readMu.Unlock()
		r.closeErr = errors.Join(r.cancelErr, r.calls.close(r.wake))
	})
	return r.closeErr
}
