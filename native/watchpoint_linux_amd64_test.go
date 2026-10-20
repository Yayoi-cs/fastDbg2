package native

import (
	"errors"
	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/arch"
	"fastdbg2/native/x86"
	"fastdbg2/target"
	"fmt"
	"testing"
)

type debugTestWrite struct {
	register int
	value    uint64
}

type debugTestBank struct {
	image       debugImage
	writes      []debugTestWrite
	fail        map[int]bool
	applyFailed bool
	readFail    map[int]bool
	reads       int
}

func (bank *debugTestBank) access() debugAccess {
	return debugAccess{
		read: func() (debugImage, error) {
			bank.reads++
			if bank.readFail[bank.reads] {
				return debugImage{}, target.ErrUnavailable
			}
			return bank.image, nil
		},
		write: func(register int, value uint64) error {
			bank.writes = append(bank.writes, debugTestWrite{register, value})
			failed := bank.fail[len(bank.writes)]
			if !failed || bank.applyFailed {
				switch register {
				case 0, 1, 2, 3:
					bank.image.address[register] = value
				case 6:
					bank.image.status = value
				case 7:
					bank.image.control = value
				default:
					return target.ErrInvalidArgument
				}
			}
			if failed {
				return target.ErrUnavailable
			}
			return nil
		},
	}
}

func TestWatchpointHostDebugOffsets(t *testing.T) {
	for register, want := range map[int]uintptr{0: 848, 1: 856, 2: 864, 3: 872, 6: 896, 7: 904} {
		got, err := debugOffset(register)
		if err != nil || got != want {
			t.Fatalf("DR%d offset=%d error=%v", register, got, err)
		}
	}
	for _, register := range []int{-1, 4, 5, 8} {
		if _, err := debugOffset(register); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("DR%d accepted: %v", register, err)
		}
	}
}

func TestWatchpointExactEncoding(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		for size, length := range map[int]uint64{1: 0, 2: 4, 4: 12, 8: 8} {
			for access, rw := range map[target.WatchAccess]uint64{target.WatchWrite: 1, target.WatchReadWrite: 3} {
				for slot := 0; slot < 4; slot++ {
					request := target.WatchpointRequest{Slot: slot, Address: 0x1000, Size: size, Access: access}
					encoding, err := watchpointEncoding(&profile, request)
					if err != nil || encoding != length|rw {
						t.Fatalf("%s request=%+v encoding=%x error=%v", profile.Architecture, request, encoding, err)
					}
				}
			}
		}
	}
	profile := x86.Descriptor()
	for _, test := range []struct {
		request target.WatchpointRequest
		want    error
	}{
		{target.WatchpointRequest{Slot: -1, Size: 1, Access: target.WatchWrite}, target.ErrInvalidArgument},
		{target.WatchpointRequest{Slot: 4, Size: 1, Access: target.WatchWrite}, target.ErrInvalidArgument},
		{target.WatchpointRequest{Size: 3, Access: target.WatchWrite}, target.ErrUnsupported},
		{target.WatchpointRequest{Size: 0, Access: target.WatchWrite}, target.ErrUnsupported},
		{target.WatchpointRequest{Size: 1, Access: target.WatchAccess(3)}, target.ErrUnsupported},
		{target.WatchpointRequest{Address: 0x1001, Size: 2, Access: target.WatchWrite}, target.ErrInvalidArgument},
		{target.WatchpointRequest{Address: 0xffffffff, Size: 8, Access: target.WatchWrite}, target.ErrOverflow},
		{target.WatchpointRequest{Address: 1 << 32, Size: 1, Access: target.WatchWrite}, target.ErrOverflow},
	} {
		if _, err := watchpointEncoding(&profile, test.request); !errors.Is(err, test.want) {
			t.Fatalf("request=%+v error=%v want=%v", test.request, err, test.want)
		}
	}
}

func TestWatchpointForeignBankIsReadOnly(t *testing.T) {
	for foreign := 0; foreign < 4; foreign++ {
		for requested := 0; requested < 4; requested++ {
			before := debugImage{status: debugStatusReserved, control: uint64(1) << (2 * foreign)}
			state := &watchpointState{baseline: before, current: before}
			bank := &debugTestBank{image: before}
			request := target.WatchpointRequest{Slot: requested, Address: 0x1000, Size: 1, Access: target.WatchWrite}
			if _, err := watchpointImage(state, before, request, 1); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("foreign=%d requested=%d error=%v", foreign, requested, err)
			}
			if bank.image != before || len(bank.writes) != 0 || state.current != before || state.pending != nil {
				t.Fatal("foreign bank was changed")
			}
		}
	}
}

func TestWatchpointImagePreservesUnrelatedBits(t *testing.T) {
	before := debugImage{address: [4]uint64{7, 8, 9, 10}, status: debugStatusReserved | debugStep | 15, control: 0x700}
	state := &watchpointState{baseline: before, current: before}
	request := target.WatchpointRequest{Slot: 2, Address: 0x1000, Size: 8, Access: target.WatchReadWrite}
	after, err := watchpointImage(state, before, request, 11)
	if err != nil {
		t.Fatal(err)
	}
	if after.address != [4]uint64{7, 8, 0x1000, 10} || after.status != before.status&^4 || after.control != before.control|(11<<24)|(1<<4) {
		t.Fatalf("planned image=%+v", after)
	}
	if state.current != before || state.baseline != before {
		t.Fatal("planning mutated committed state")
	}
}

func TestWatchpointTransactionRollbackEveryWrite(t *testing.T) {
	before := debugImage{address: [4]uint64{0x2000, 0, 0, 0}, status: debugStatusReserved}
	after := before
	after.address[0], after.control = 0x1000, 1|(1<<16)
	for phase := 1; phase <= 4; phase++ {
		for _, applied := range []bool{false, true} {
			t.Run(fmt.Sprintf("phase_%d_applied_%t", phase, applied), func(t *testing.T) {
				bank := &debugTestBank{image: before, fail: map[int]bool{phase: true}, applyFailed: applied}
				state := &watchpointState{baseline: before, current: before}
				if err := changeDebugImage(state, bank.access(), before, after, 1); !errors.Is(err, target.ErrUnavailable) {
					t.Fatalf("failure not reported: %v", err)
				}
				if bank.image != before || state.current != before || state.pending != nil || state.fault != nil {
					t.Fatalf("rollback image=%+v state=%+v", bank.image, state)
				}
				if bank.writes[len(bank.writes)-1] != (debugTestWrite{7, before.control}) {
					t.Fatal("rollback did not enable control last")
				}
			})
		}
	}
}

func TestWatchpointTransactionReadbackFailureRollsBack(t *testing.T) {
	before := debugImage{status: debugStatusReserved}
	after := before
	after.address[0], after.control = 0x1000, 1|(1<<16)
	bank := &debugTestBank{image: before, readFail: map[int]bool{1: true}}
	state := &watchpointState{baseline: before, current: before}
	if err := changeDebugImage(state, bank.access(), before, after, 1); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("readback failure=%v", err)
	}
	if bank.image != before || state.current != before || state.pending != nil || state.fault != nil {
		t.Fatal("readback failure did not restore the original image")
	}
}

func TestWatchpointFailedRollbackRetainsCleanupJournal(t *testing.T) {
	before := debugImage{address: [4]uint64{0x2000}, status: debugStatusReserved}
	after := before
	after.address[0], after.control = 0x1000, 1|(1<<16)
	bank := &debugTestBank{image: before, fail: map[int]bool{3: true, 4: true}}
	state := &watchpointState{baseline: before, current: before, nextGeneration: 9}
	if err := changeDebugImage(state, bank.access(), before, after, 1); !errors.Is(err, target.ErrPartial) {
		t.Fatalf("uncertain rollback=%v", err)
	}
	if state.pending == nil || state.fault == nil || state.pending.dirty != 1 || state.nextGeneration != 9 {
		t.Fatal("uncertain rollback lost its cleanup journal")
	}
	bank.fail = nil
	if err := restoreWatchpointState(state, bank.access()); err != nil {
		t.Fatal(err)
	}
	if bank.image != before || state.pending != nil || state.fault != nil || state.nextGeneration != 9 {
		t.Fatal("cleanup retry did not restore the baseline")
	}
}

func TestWatchpointUnknownPartialStateIsNotOverwritten(t *testing.T) {
	before := debugImage{status: debugStatusReserved}
	after := before
	after.address[0], after.control = 0x1000, 1|(1<<16)
	bank := &debugTestBank{image: before}
	state := &watchpointState{baseline: before, current: before,
		pending: &debugTransaction{before: before, after: after, dirty: 1}, fault: target.ErrPartial}
	bank.image.address[0] = 0xdead
	if err := restoreWatchpointState(state, bank.access()); !errors.Is(err, target.ErrStale) {
		t.Fatalf("unknown partial state=%v", err)
	}
	if len(bank.writes) != 0 || state.pending == nil || state.fault == nil {
		t.Fatal("unknown image was overwritten or its journal discarded")
	}
}

func TestWatchpointMixedStepAndMultipleHits(t *testing.T) {
	state := &watchpointState{}
	for _, slot := range []int{0, 2} {
		request := target.WatchpointRequest{Slot: slot, Address: 0x1000, Size: 1, Access: target.WatchWrite}
		ref := target.WatchpointRef{Thread: target.ThreadRef{Session: 1, ID: 1}, Slot: slot, Generation: uint64(slot + 1)}
		state.slots[slot] = &physicalWatchpoint{ref: ref, request: request}
		state.current.address[slot] = uint64(request.Address)
		state.current.control |= 1<<(2*slot) | 1<<(16+4*slot)
	}
	image := state.current
	image.status = debugStatusReserved | debugStep | 5
	hits, step, raw, err := decodeWatchpointStop(state, image)
	if err != nil || !step || raw != image.status || len(hits) != 2 || hits[0].Ref.Slot != 0 || hits[1].Ref.Slot != 2 {
		t.Fatalf("hits=%+v step=%t dr6=%x error=%v", hits, step, raw, err)
	}
	image.status |= 2
	if _, _, _, err := decodeWatchpointStop(state, image); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("unowned hardware cause consumed: %v", err)
	}
	image = state.current
	image.control ^= 1 << 16
	if _, _, _, err := decodeWatchpointStop(state, image); !errors.Is(err, target.ErrStale) {
		t.Fatalf("changed installed configuration accepted: %v", err)
	}
}

func TestWatchpointExecReadFailureCannotRestoreOldImage(t *testing.T) {
	old := &watchpointState{space: target.SpaceRef{Session: 1, ID: 1}, nextGeneration: 42,
		baseline: debugImage{address: [4]uint64{0x1234}, control: 1 | 1<<16}}
	current := &thread{tid: -1, state: target.StateStopped, watchpoints: old,
		process: &process{space: &addressSpace{ref: target.SpaceRef{Session: 1, ID: 2}}}}
	e := &engine{}
	if err := e.resetExecWatchpoints(current); err == nil {
		t.Fatal("invalid TID read succeeded")
	}
	if current.watchpoints == old || current.watchpoints.nextGeneration != 42 || current.watchpoints.baseline != (debugImage{status: debugStatusReserved}) || current.watchpoints.space != current.process.space.ref || current.watchpoints.fault == nil {
		t.Fatalf("old image or generation survived reset incorrectly: %+v", current.watchpoints)
	}
}

func TestWatchpointRollbackFailureAtEveryPhase(t *testing.T) {
	for phase := 1; phase <= 5; phase++ {
		t.Run(fmt.Sprintf("rollback_%d", phase), func(t *testing.T) {
			before := debugImage{address: [4]uint64{0x2000}, status: debugStatusReserved}
			after := before
			after.address[0], after.control = 0x1000, 1|(1<<16)
			bank := &debugTestBank{image: before, fail: map[int]bool{3: true}}
			if phase <= 4 {
				bank.fail[3+phase] = true
			} else {
				bank.readFail = map[int]bool{2: true}
			}
			state := &watchpointState{baseline: before, current: before, nextGeneration: 5}
			if err := changeDebugImage(state, bank.access(), before, after, 1); !errors.Is(err, target.ErrPartial) {
				t.Fatalf("rollback failure=%v", err)
			}
			if state.pending == nil || state.fault == nil {
				t.Fatal("failed rollback was reported as known")
			}
			bank.fail, bank.readFail = nil, nil
			bank.fail = map[int]bool{len(bank.writes) + 3: true}
			if err := restoreWatchpointState(state, bank.access()); !errors.Is(err, target.ErrPartial) {
				t.Fatalf("cleanup restore failure=%v", err)
			}
			if state.pending == nil || state.fault == nil || state.pending.dirty != 1 {
				t.Fatal("failed cleanup lost retry progress")
			}
			bank.fail = nil
			if err := restoreWatchpointState(state, bank.access()); err != nil {
				t.Fatalf("second cleanup=%v", err)
			}
			if bank.image != before || state.current != before || state.pending != nil || state.fault != nil || state.nextGeneration != 5 {
				t.Fatal("cleanup retry did not restore the exact baseline")
			}
		})
	}
}

func TestWatchpointUnexpectedReadbackDoesNotForceRollback(t *testing.T) {
	before := debugImage{status: debugStatusReserved}
	after := before
	after.address[0], after.control = 0x1000, 1|(1<<16)
	bank := &debugTestBank{image: before}
	access := bank.access()
	access.read = func() (debugImage, error) {
		bank.image.address[0] = 0xdead
		return bank.image, nil
	}
	state := &watchpointState{baseline: before, current: before}
	if err := changeDebugImage(state, access, before, after, 1); !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrStale) {
		t.Fatalf("unexpected readback=%v", err)
	}
	if len(bank.writes) != 4 || bank.image.address[0] != 0xdead || state.pending == nil || state.fault == nil {
		t.Fatal("an unrecognized hardware state was overwritten by rollback")
	}
}

func TestWatchpointForeignBankPublicSetDoesNotWrite(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	var token target.ThreadToken
	var foreign debugImage
	err = command(s, func(e *engine) error {
		current := e.threads[s.pid]
		access := e.debugAccess(current)
		if err := access.write(3, uint64(entry)); err != nil {
			return err
		}
		if err := access.write(7, 1<<6|1<<28); err != nil {
			return err
		}
		current.watchpoints = nil
		if err := e.initializeWatchpoints(current); err != nil {
			return err
		}
		foreign = current.watchpoints.current
		token = current.token()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SetWatchpoint(token, target.WatchpointRequest{Slot: 0, Address: entry, Size: 1, Access: target.WatchWrite})
	if !errors.Is(err, target.ErrBusy) {
		t.Fatalf("foreign-bank Set=%v", err)
	}
	err = command(s, func(e *engine) error {
		current := e.threads[s.pid]
		actual, err := readDebugImage(current)
		if err != nil {
			return err
		}
		if actual != foreign || current.token() != token || current.watchpoints.ownedSlots() != 0 {
			return errors.New("foreign bank rejection mutated registers, token, or ownership")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWatchpointFailedInstallInvalidatesToken(t *testing.T) {
	path, _ := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	var token target.ThreadToken
	var before debugImage
	err = command(s, func(e *engine) error {
		current := e.threads[s.pid]
		token = current.token()
		var err error
		before, err = readDebugImage(current)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SetWatchpoint(token, target.WatchpointRequest{Slot: 0, Address: target.Address(^uint64(0)), Size: 1, Access: target.WatchWrite})
	if err == nil {
		t.Fatal("kernel-space hardware watchpoint was installed")
	}
	err = command(s, func(e *engine) error {
		current := e.threads[s.pid]
		actual, err := readDebugImage(current)
		if err != nil {
			return err
		}
		if actual != before || current.token() == token || current.watchpoints.pending != nil || current.watchpoints.fault != nil || current.watchpoints.ownedSlots() != 0 {
			return errors.New("failed install did not confirm rollback and invalidate the token")
		}
		if _, err := e.requireThread(token); !errors.Is(err, target.ErrStale) {
			return errors.New("pre-write token remained valid after a failed install")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWatchpointRestoredStatusIsNotANewStepHit(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := s.AddBreakpoint(entry); err != nil {
		t.Fatal(err)
	}
	if stop, err := s.Continue(target.Signal{}); err != nil || stop.Reason != target.StopBreakpoint {
		t.Fatalf("initial breakpoint=%+v error=%v", stop, err)
	}
	var token target.ThreadToken
	err = command(s, func(e *engine) error {
		current := e.threads[s.pid]
		if err := e.debugAccess(current).write(6, debugStatusReserved|debugStep|1); err != nil {
			return err
		}
		token = current.token()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	watch, err := s.SetWatchpoint(token, target.WatchpointRequest{Slot: 0, Address: entry, Size: 1, Access: target.WatchWrite})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClearWatchpoint(watch.Token, watch.Ref); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveBreakpoint(entry); err != nil {
		t.Fatal(err)
	}
	stop, err := s.Step(target.Signal{})
	if err != nil || stop.Reason != target.StopStep || !stop.StepCompleted || len(stop.Watchpoints) != 0 || stop.RawDR6 == nil || *stop.RawDR6&15 != 0 {
		t.Fatalf("restored old status became a fresh hit: stop=%+v error=%v", stop, err)
	}
}

func TestWatchpointAttachReadFailureRetainsUncapturedState(t *testing.T) {
	current := &thread{tid: -1, state: target.StateStopped,
		process: &process{space: &addressSpace{ref: target.SpaceRef{Session: 1, ID: 1}}}}
	e := &engine{}
	if err := e.initializeWatchpoints(current); err == nil {
		t.Fatal("invalid TID read succeeded")
	}
	state := current.watchpoints
	if state == nil || !state.uncaptured || state.fault == nil || state.ownedSlots() != 0 {
		t.Fatal("missing original image was treated as restored")
	}
	original := debugImage{address: [4]uint64{0x1000}, status: debugStatusReserved | 1, control: 1 | 1<<16}
	bank := &debugTestBank{image: original, readFail: map[int]bool{1: true}}
	if err := restoreWatchpointState(state, bank.access()); err == nil || !state.uncaptured {
		t.Fatal("failed baseline capture was discarded")
	}
	bank.readFail = nil
	if err := restoreWatchpointState(state, bank.access()); err != nil {
		t.Fatal(err)
	}
	if state.uncaptured || state.fault != nil || state.baseline != original || state.current != original || len(bank.writes) != 0 {
		t.Fatal("baseline capture cleanup changed the original hardware state")
	}
}

func TestWatchpointRejectsInconsistentKernelCause(t *testing.T) {
	for _, test := range []struct {
		code   int32
		status uint64
	}{
		{2, debugStatusReserved | 1},
		{4, debugStatusReserved | debugStep | 1},
	} {
		if err := validateWatchpointCause(test.code, test.status); !errors.Is(err, target.ErrUnknown) {
			t.Fatalf("code=%d dr6=%x error=%v", test.code, test.status, err)
		}
	}
}
