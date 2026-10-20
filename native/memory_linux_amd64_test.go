package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
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
	e, _, _ := nativeDataTestEngine(profile)
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

func TestNativeMemoryRejectsAnyRegisteredBreakpointOverlap(t *testing.T) {
	profile := amd64.Descriptor()
	e, th, space := nativeDataTestEngine(profile)
	space.breakpoints = map[target.Address]*breakpoint{
		0x1001:                         {addr: 0x1001, original: 0x90, armed: true},
		0x1002:                         {addr: 0x1002, original: 0x90, armed: true},
		0x1004:                         {addr: 0x1004, original: 0x90},
		target.Address(math.MaxUint64): {addr: target.Address(math.MaxUint64), original: 0x90, armed: true},
	}
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
		{0x1004, 1, target.ErrInvalidState},
		{target.Address(math.MaxUint64), 0, nil},
		{target.Address(math.MaxUint64), 1, target.ErrInvalidState},
		{target.Address(math.MaxUint64), 2, target.ErrOverflow},
	}
	for _, test := range cases {
		if err := e.checkMemoryWrite(space, &profile, test.address, test.size); !errors.Is(err, test.want) {
			t.Fatalf("address=%#x size=%d err=%v want=%v", test.address, test.size, err, test.want)
		}
	}
	for _, bp := range space.breakpoints {
		if bp.original != 0x90 {
			t.Fatal("validation changed breakpoint data")
		}
	}
	th.suspended = space.breakpoints[0x1004]
	if err := e.checkMemoryWrite(space, &profile, 0x1003, 2); !errors.Is(err, target.ErrInvalidState) {
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
		{target.StateUnknown, target.ErrBusy},
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
	e := &engine{s: session, threads: map[int]*thread{1: {tid: 1, state: state, process: &process{}}}}
	if state == target.StateExited || state == target.StateDetached || state == target.StateClosed {
		e.life.terminal = state
	}
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

func nativeDataTestEngine(profile arch.Descriptor) (*engine, *thread, *addressSpace) {
	space := &addressSpace{breakpoints: make(map[target.Address]*breakpoint)}
	p := &process{profile: &profile, space: space}
	th := &thread{tid: -1, state: target.StateStopped, process: p}
	e := &engine{threads: map[int]*thread{th.tid: th}}
	return e, th, space
}

func TestNativeMemoryBreakpointValidationUsesSelectedSpace(t *testing.T) {
	profile := amd64.Descriptor()
	e, _, first := nativeDataTestEngine(profile)
	second := &addressSpace{breakpoints: map[target.Address]*breakpoint{0x1000: {addr: 0x1000, armed: true}}}
	if err := e.checkMemoryWrite(first, &profile, 0x1000, 1); err != nil {
		t.Fatalf("unrelated address-space breakpoint affected write: %v", err)
	}
	if err := e.checkMemoryWrite(second, &profile, 0x1000, 1); !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("selected address-space breakpoint ignored: %v", err)
	}
	if err := e.checkMemoryWrite(nil, &profile, 0x1000, 1); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("missing address space accepted: %v", err)
	}
}

func TestNativeMemoryByteWriteFailureInvalidatesSelectedSpace(t *testing.T) {
	profile := amd64.Descriptor()
	e, th, space := nativeDataTestEngine(profile)
	otherSpace := &addressSpace{revision: 7}
	other := &thread{tid: -2, state: target.StateStopped, process: &process{profile: &profile, space: otherSpace}}
	e.threads[other.tid] = other
	if err := e.writeByte(th.tid, 0x1000, 0x90); err == nil {
		t.Fatal("invalid ptrace TID was accepted")
	}
	if space.revision != 1 || otherSpace.revision != 7 {
		t.Fatalf("memory revisions selected=%d other=%d", space.revision, otherSpace.revision)
	}
}

func TestNativeSpaceMemoryTokens(t *testing.T) {
	s := nativeDataSession(t)
	snapshot := nativeDataSnapshot(t, s)
	registers, err := s.ReadThreadRegisters(snapshot.Threads[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	var address target.Address
	for _, register := range registers {
		if register.Name == "rip" {
			address = target.Address(binary.LittleEndian.Uint64(register.Data))
		}
	}
	if address == 0 {
		t.Fatal("raw PC is missing")
	}
	data := make([]byte, 1)
	if n, err := s.ReadSpaceMemory(snapshot.Memory, address, data); n != 1 || err != nil {
		t.Fatalf("selected-space read n=%d err=%v", n, err)
	}
	foreign := snapshot.Memory
	foreign.Space.Session ^= uint64(1) << 63
	if n, err := s.ReadSpaceMemory(foreign, address, nil); n != 0 || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign empty memory read n=%d err=%v", n, err)
	}
	if n, err := s.WriteSpaceMemory(foreign, address, nil); n != 0 || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign empty memory write n=%d err=%v", n, err)
	}
	if n, err := s.WriteSpaceMemory(snapshot.Memory, address, data); n != 1 || err != nil {
		t.Fatalf("selected-space write n=%d err=%v", n, err)
	}
	if n, err := s.ReadSpaceMemory(snapshot.Memory, address, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale empty memory read n=%d err=%v", n, err)
	}
	if n, err := s.WriteSpaceMemory(snapshot.Memory, address, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale empty memory write n=%d err=%v", n, err)
	}
	after := nativeDataSnapshot(t, s)
	if after.Memory.Space != snapshot.Memory.Space || after.Memory.Revision == snapshot.Memory.Revision {
		t.Fatalf("memory write token transition old=%+v new=%+v", snapshot.Memory, after.Memory)
	}
	if after.Threads[0].Token != snapshot.Threads[0].Token {
		t.Fatal("memory-only write changed the register token")
	}
	if n, err := s.WriteSpaceMemory(after.Memory, address, nil); n != 0 || err != nil {
		t.Fatalf("empty memory write n=%d err=%v", n, err)
	}
	if current := nativeDataSnapshot(t, s); current.Memory != after.Memory {
		t.Fatal("empty memory write changed the token")
	}
}

func TestNativeMemoryUsesSurvivingStoppedThread(t *testing.T) {
	e, leader := nativeDataTokenEngine()
	peer := e.newThread(leader.process, 102, true)
	peer.state, peer.stopEpoch = target.StateStopped, 1
	space := leader.process.space
	leader.state = target.StateExited
	token := target.MemoryToken{Space: space.ref, Revision: space.revision}
	selected, window, err := e.requireMemory(token)
	if err != nil || selected != space || window != peer {
		t.Fatalf("exited leader selected as memory window space=%p thread=%p err=%v", selected, window, err)
	}
	if n, err := e.readSpaceMemory(token, 0, nil); n != 0 || err != nil {
		t.Fatalf("empty read through surviving thread n=%d err=%v", n, err)
	}
	if n, err := e.writeSpaceMemory(token, 0, nil); n != 0 || err != nil {
		t.Fatalf("empty write through surviving thread n=%d err=%v", n, err)
	}
	if got, err := e.primaryMemory(); err != nil || got != token {
		t.Fatalf("legacy memory rejected an unambiguous surviving space: %v", err)
	}
	peer.state = target.StateRunning
	if _, _, err := e.requireMemory(token); !errors.Is(err, target.ErrRunning) {
		t.Fatalf("running memory window accepted: %v", err)
	}
}

func TestNativeMemoryRejectsStaleRevisionAndImage(t *testing.T) {
	e, th := nativeDataTokenEngine()
	space := th.process.space
	token := target.MemoryToken{Space: space.ref, Revision: space.revision}
	e.memoryChanged(space)
	if n, err := e.readSpaceMemory(token, 0, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale empty read n=%d err=%v", n, err)
	}
	if n, err := e.writeSpaceMemory(token, 0, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale empty write n=%d err=%v", n, err)
	}
	token.Revision = space.revision
	th.process.space = e.newSpace()
	if n, err := e.readSpaceMemory(token, 0, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("old image memory token n=%d err=%v", n, err)
	}
}

func TestNativeMemoryLegacyRejectsMultipleSpacesOnly(t *testing.T) {
	e, th := nativeDataTokenEngine()
	peer := e.newThread(th.process, 102, true)
	peer.state, peer.stopEpoch = target.StateStopped, 1
	if _, err := e.singleStoppedThread(); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("legacy registers guessed one of two threads: %v", err)
	}
	if _, err := e.primaryMemory(); err != nil {
		t.Fatalf("one shared space is not ambiguous: %v", err)
	}
	other := e.newProcess(103, -1, false)
	other.profile = th.process.profile
	peer.process = other
	if _, err := e.primaryMemory(); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("legacy memory guessed one of two spaces: %v", err)
	}
	first := target.MemoryToken{Space: th.process.space.ref, Revision: th.process.space.revision}
	if _, selected, err := e.requireMemory(first); err != nil || selected != th {
		t.Fatalf("explicit space selection failed: %v", err)
	}
}

func TestNativeMemoryPartialWriteInvalidatesWithoutPoisoning(t *testing.T) {
	s := nativeDataSession(t)
	snapshot := nativeDataSnapshot(t, s)
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", snapshot.Threads[0].TID))
	if err != nil {
		t.Fatal(err)
	}
	type interval struct{ start, end uint64 }
	var ranges []interval
	var stackEnd uint64
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		first, last, found := strings.Cut(fields[0], "-")
		if !found {
			t.Fatalf("invalid maps range %q", fields[0])
		}
		start, err := strconv.ParseUint(first, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		end, err := strconv.ParseUint(last, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		ranges = append(ranges, interval{start, end})
		if fields[len(fields)-1] == "[stack]" {
			stackEnd = end
		}
	}
	if stackEnd < 8 || stackEnd > math.MaxUint64-8 {
		t.Fatalf("invalid stack end %#x", stackEnd)
	}
	for _, region := range ranges {
		if region.start < stackEnd+8 && region.end > stackEnd {
			t.Fatalf("fixture stack end has no unmapped boundary: %#x", stackEnd)
		}
	}
	address := target.Address(stackEnd - 8)
	data := make([]byte, 16)
	if n, err := s.ReadSpaceMemory(snapshot.Memory, address, data); n != 8 || !errors.Is(err, target.ErrPartial) {
		t.Fatalf("partial read n=%d err=%v", n, err)
	}
	n, err := s.WriteSpaceMemory(snapshot.Memory, address, data)
	var partial *target.PartialError
	if n != 8 || !errors.As(err, &partial) || partial.Completed != 8 || partial.Total != 16 {
		t.Fatalf("partial write n=%d err=%v", n, err)
	}
	if _, err := s.ReadSpaceMemory(snapshot.Memory, address, nil); !errors.Is(err, target.ErrStale) {
		t.Fatalf("partial write retained old memory token: %v", err)
	}
	after := nativeDataSnapshot(t, s)
	if _, err := s.ReadThreadRegisters(after.Threads[0].Token); err != nil {
		t.Fatalf("ordinary partial memory write poisoned registers: %v", err)
	}
	if n, err := s.ReadSpaceMemory(after.Memory, address, data[:8]); n != 8 || err != nil {
		t.Fatalf("ordinary partial memory write poisoned memory n=%d err=%v", n, err)
	}
}

func TestNativeMemoryRunningSnapshotCannotBecomeValid(t *testing.T) {
	e, th := nativeDataTokenEngine()
	space := th.process.space
	stopped := e.snapshot()
	if stopped.Memory.Space != space.ref || stopped.Memory.Revision != space.revision {
		t.Fatalf("stopped memory token=%+v", stopped.Memory)
	}
	th.state = target.StateRunning
	e.memoryChanged(space)
	running := e.snapshot()
	if running.Memory.Space != space.ref || running.Memory.Revision != 0 {
		t.Fatalf("running snapshot issued a valid memory token: %+v", running.Memory)
	}
	th.state = target.StateStopped
	if _, _, err := e.requireMemory(running.Memory); !errors.Is(err, target.ErrStale) {
		t.Fatalf("running snapshot token became valid after stop: %v", err)
	}
	e.barrier = &stopBarrier{}
	settling := e.snapshot()
	if settling.Memory.Space != space.ref || settling.Memory.Revision != 0 {
		t.Fatalf("unsettled barrier issued a valid memory token: %+v", settling.Memory)
	}
	e.barrier = nil
	if _, _, err := e.requireMemory(settling.Memory); !errors.Is(err, target.ErrStale) {
		t.Fatalf("barrier snapshot token became valid after settle: %v", err)
	}
}
