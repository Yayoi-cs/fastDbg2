package native

import (
	"errors"
	"io"
	"math"
	"testing"

	"fastdbg2/native/amd64"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func TestNativeMemoryRange(t *testing.T) {
	profile := amd64.Descriptor()
	cases := []struct {
		address target.Address
		size    int
		want    error
	}{
		{0, 0, nil},
		{0, 1, nil},
		{target.Address(math.MaxUint64), 0, nil},
		{target.Address(math.MaxUint64), 1, nil},
		{target.Address(math.MaxUint64 - 1), 2, nil},
		{target.Address(math.MaxUint64), 2, target.ErrOverflow},
		{target.Address(math.MaxUint64 - 1), 3, target.ErrOverflow},
		{0, -1, target.ErrInvalidArgument},
	}
	for _, test := range cases {
		if err := validateMemoryRange(&profile, test.address, test.size); !errors.Is(err, test.want) {
			t.Fatalf("address=%#x size=%d err=%v want=%v", test.address, test.size, err, test.want)
		}
	}
}

func TestNativeMemoryX86Range(t *testing.T) {
	profile := x86.Descriptor()
	for _, test := range []struct {
		address target.Address
		size    int
		want    error
	}{
		{0xf0000000, 16, nil},
		{0xffffffff, 0, nil},
		{0xffffffff, 1, nil},
		{0xfffffffe, 2, nil},
		{0xfffffffe, 3, target.ErrOverflow},
		{1 << 32, 0, target.ErrOverflow},
		{1 << 32, 1, target.ErrOverflow},
		{target.Address(math.MaxUint64), 0, target.ErrOverflow},
	} {
		if err := validateMemoryRange(&profile, test.address, test.size); !errors.Is(err, test.want) {
			t.Fatalf("case=%+v err=%v", test, err)
		}
	}
	e := &engine{profile: &profile}
	if _, err := e.readByte(-1, 1<<32); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("wide byte read must not reach ptrace: %v", err)
	}
	if err := e.writeByte(-1, 1<<32, 0); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("wide byte write must not reach ptrace: %v", err)
	}
	if err := validateMemoryRange(nil, 0, 0); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("unknown memory profile: %v", err)
	}
}

func TestNativeMemoryRejectsAnyArmedBreakpointOverlap(t *testing.T) {
	profile := amd64.Descriptor()
	e := &engine{profile: &profile, breakpoints: map[target.Address]*breakpoint{
		0x1001:                         {addr: 0x1001, original: 0x90, armed: true},
		0x1002:                         {addr: 0x1002, original: 0x90, armed: true},
		0x1004:                         {addr: 0x1004, original: 0x90},
		target.Address(math.MaxUint64): {addr: target.Address(math.MaxUint64), original: 0x90, armed: true},
	}}
	cases := []struct {
		address target.Address
		size    int
		want    error
	}{
		{0x1000, 1, nil},
		{0x1001, 0, nil},
		{0x1000, 2, target.ErrInvalidState},
		{0x1000, 3, target.ErrInvalidState},
		{0x1001, 1, target.ErrInvalidState},
		{0x1002, 1, target.ErrInvalidState},
		{0x1003, 1, nil},
		{0x1004, 1, nil},
		{target.Address(math.MaxUint64), 0, nil},
		{target.Address(math.MaxUint64), 1, target.ErrInvalidState},
		{target.Address(math.MaxUint64), 2, target.ErrOverflow},
	}
	for _, test := range cases {
		if err := e.checkMemoryWrite(test.address, test.size); !errors.Is(err, test.want) {
			t.Fatalf("address=%#x size=%d err=%v want=%v", test.address, test.size, err, test.want)
		}
	}
	for _, bp := range e.breakpoints {
		if bp.original != 0x90 {
			t.Fatal("validation changed breakpoint data")
		}
	}
	e.suspended = e.breakpoints[0x1004]
	if err := e.checkMemoryWrite(0x1003, 2); !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("suspended breakpoint must retain its original byte: %v", err)
	}
}

func TestNativeMemoryTransferErrors(t *testing.T) {
	cases := []struct {
		completed int
		total     int
		err       error
		short     error
		want      error
		partial   bool
	}{
		{8, 8, nil, io.ErrUnexpectedEOF, nil, false},
		{0, 0, nil, io.ErrUnexpectedEOF, nil, false},
		{0, 8, unix.EIO, io.ErrUnexpectedEOF, unix.EIO, false},
		{3, 8, unix.EIO, io.ErrUnexpectedEOF, unix.EIO, true},
		{3, 8, nil, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, true},
		{0, 8, nil, io.ErrShortWrite, io.ErrShortWrite, false},
		{3, 8, nil, io.ErrShortWrite, io.ErrShortWrite, true},
		{8, 8, unix.EIO, io.ErrShortWrite, unix.EIO, false},
		{-1, 8, nil, io.ErrShortWrite, target.ErrUnknown, false},
		{9, 8, nil, io.ErrShortWrite, target.ErrUnknown, false},
	}
	for _, test := range cases {
		err := memoryTransferError("test transfer", 0x1000, test.completed, test.total, test.err, test.short)
		if !errors.Is(err, test.want) || errors.Is(err, target.ErrPartial) != test.partial {
			t.Fatalf("case=%+v err=%v", test, err)
		}
		if test.partial {
			var partial *target.PartialError
			if !errors.As(err, &partial) || partial.Completed != test.completed || partial.Total != test.total {
				t.Fatalf("partial count lost: %v", err)
			}
		}
	}
}

func TestNativeMemoryRequiresStoppedEvenForEmptyTransfers(t *testing.T) {
	for _, test := range []struct {
		state target.State
		want  error
	}{
		{target.StateRunning, target.ErrRunning},
		{target.StateExited, target.ErrExited},
		{target.StateDetached, target.ErrDetached},
		{target.StateUnknown, target.ErrInvalidState},
	} {
		session := memoryTestSession(t, test.state)
		for _, data := range [][]byte{nil, {1}} {
			if n, err := session.ReadMemory(0x1000, data); n != 0 || !errors.Is(err, test.want) {
				t.Fatalf("read state=%v n=%d err=%v", test.state, n, err)
			}
			if n, err := session.WriteMemory(0x1000, data); n != 0 || !errors.Is(err, test.want) {
				t.Fatalf("write state=%v n=%d err=%v", test.state, n, err)
			}
		}
	}
}

func memoryTestSession(t *testing.T, state target.State) *Session {
	t.Helper()
	session := &Session{requests: make(chan func(*engine)), done: make(chan struct{})}
	session.state.Store(uint32(state))
	e := &engine{s: session}
	quit := make(chan struct{})
	go func() {
		defer close(session.done)
		for {
			select {
			case request := <-session.requests:
				request(e)
			case <-quit:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(quit)
		<-session.done
	})
	return session
}
