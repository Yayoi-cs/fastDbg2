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

func TestHardwareBreakpointEncoding(t *testing.T) {
	for _, profile := range []arch.Descriptor{amd64.Descriptor(), x86.Descriptor()} {
		for slot := 0; slot < 4; slot++ {
			for _, address := range []target.Address{0, 0x1001, 0xffffffff} {
				request := target.HardwareBreakpointRequest{Slot: slot, Address: address}
				encoding, err := hardwareBreakpointEncoding(&profile, request)
				if err != nil || encoding != 0 {
					t.Fatalf("%s request=%+v encoding=%x error=%v", profile.Architecture, request, encoding, err)
				}
			}
		}
	}
	profile := x86.Descriptor()
	for _, slot := range []int{-1, 4} {
		if _, err := hardwareBreakpointEncoding(&profile, target.HardwareBreakpointRequest{Slot: slot}); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("slot=%d error=%v", slot, err)
		}
	}
	if _, err := hardwareBreakpointEncoding(&profile, target.HardwareBreakpointRequest{Address: 1 << 32}); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("out-of-range execute address=%v", err)
	}
	if _, err := hardwareBreakpointEncoding(nil, target.HardwareBreakpointRequest{}); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("missing profile=%v", err)
	}
}

func TestHardwareBreakpointSharesPhysicalBank(t *testing.T) {
	state := &watchpointState{baseline: debugImage{status: debugStatusReserved}, current: debugImage{status: debugStatusReserved}}
	for slot := 0; slot < 4; slot++ {
		request := target.WatchpointRequest{Slot: slot, Address: 0x1001, Size: 1, Access: target.WatchWrite}
		execute := slot%2 == 0
		encoding := uint64(1)
		if execute {
			request.Access, encoding = target.WatchUnknown, 0
		}
		after, err := watchpointImage(state, state.current, request, encoding)
		if err != nil {
			t.Fatal(err)
		}
		ref := target.WatchpointRef{Thread: target.ThreadRef{Session: 1, ID: 2}, Slot: slot, Generation: uint64(slot + 1)}
		state.slots[slot] = &physicalWatchpoint{ref: ref, request: request, execute: execute}
		state.current = after
	}
	if state.ownedSlots() != 15 || state.current.control != 0x10100055 {
		t.Fatalf("owned=%x DR7=%x", state.ownedSlots(), state.current.control)
	}
	image := state.current
	image.status |= 15
	watches, execution, step, raw, err := decodeWatchpointStop(state, image)
	if err != nil || step || raw != image.status || len(watches) != 2 || len(execution) != 2 {
		t.Fatalf("watches=%+v execution=%+v step=%t raw=%x error=%v", watches, execution, step, raw, err)
	}
	if execution[0].Ref.Slot != 0 || execution[1].Ref.Slot != 2 || watches[0].Ref.Slot != 1 || watches[1].Ref.Slot != 3 {
		t.Fatal("physical slot kinds were conflated")
	}
	image.status = debugStatusReserved | debugStep | 10
	watches, execution, step, _, err = decodeWatchpointStop(state, image)
	if err != nil || !step || len(watches) != 2 || len(execution) != 0 {
		t.Fatalf("data+BS with configured execution slots: watches=%+v execution=%+v step=%t error=%v", watches, execution, step, err)
	}
	before := state.current
	image.status |= 1
	if _, _, _, _, err := decodeWatchpointStop(state, image); !errors.Is(err, target.ErrUnknown) {
		t.Fatalf("execution+BS accepted: %v", err)
	}
	if state.current != before {
		t.Fatal("contradictory execution cause consumed the status")
	}
}

func TestHardwareBreakpointCrossKindDoesNotAccessRegisters(t *testing.T) {
	for _, execute := range []bool{false, true} {
		e, tasks := controlModel(1)
		task := tasks[0]
		token := task.token()
		ref := target.WatchpointRef{Thread: task.ref, Slot: 1, Generation: 9}
		point := &physicalWatchpoint{ref: ref, request: target.WatchpointRequest{Slot: 1, Address: 0x1001, Size: 1, Access: target.WatchWrite}, execute: execute}
		state := &watchpointState{space: task.process.space.ref, nextGeneration: 9}
		state.slots[1] = point
		task.watchpoints = state
		if execute {
			if _, err := e.setWatchpoint(token, point.request); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("data over execute: %v", err)
			}
			if _, err := e.clearWatchpoint(token, ref); !errors.Is(err, target.ErrStale) {
				t.Fatalf("data clear over execute: %v", err)
			}
		} else {
			if _, err := e.setHardwareBreakpoint(token, target.HardwareBreakpointRequest{Slot: 1, Address: 0x1001}); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("execute over data: %v", err)
			}
			if _, err := e.clearHardwareBreakpoint(token, target.HardwareBreakpointRef(ref)); !errors.Is(err, target.ErrStale) {
				t.Fatalf("execute clear over data: %v", err)
			}
		}
		if task.token() != token || task.watchpoints != state || state.slots[1] != point || state.nextGeneration != 9 || state.pending != nil || state.fault != nil {
			t.Fatal("cross-kind rejection mutated hardware state")
		}
	}
}

func TestHardwareBreakpointForeignCauseIsNotOwned(t *testing.T) {
	image := debugImage{address: [4]uint64{0x1001}, status: debugStatusReserved | 1, control: 1}
	watches, execution, step, raw, err := decodeWatchpointStop(&watchpointState{}, image)
	if err != nil || len(watches) != 0 || len(execution) != 0 || step || raw != image.status {
		t.Fatalf("foreign execution cause changed: watch=%+v execute=%+v step=%t raw=%x error=%v", watches, execution, step, raw, err)
	}
	stop, signal := applyWatchpointStop(target.Stop{}, 4, watches, step, raw, false)
	if stop.Reason != target.StopSignal || signal != 5 || stop.StepCompleted {
		t.Fatalf("foreign execution cause consumed: stop=%+v pending=%d", stop, signal)
	}
}

func TestHardwareBreakpointTransactionFailurePreservesBank(t *testing.T) {
	before := debugImage{address: [4]uint64{0x2000, 0x3000}, status: debugStatusReserved | debugStep | 2, control: 4 | 1<<20}
	after := before
	after.address[0], after.control = 0x1001, before.control|1
	for phase := 1; phase <= 4; phase++ {
		for _, applied := range []bool{false, true} {
			t.Run(fmt.Sprintf("phase_%d_applied_%t", phase, applied), func(t *testing.T) {
				bank := &debugTestBank{image: before, fail: map[int]bool{phase: true}, applyFailed: applied}
				state := &watchpointState{baseline: before, current: before, nextGeneration: 7}
				if err := changeDebugImage(state, bank.access(), before, after, 1); !errors.Is(err, target.ErrUnavailable) {
					t.Fatalf("failure=%v", err)
				}
				if bank.image != before || state.current != before || state.pending != nil || state.fault != nil || state.nextGeneration != 7 {
					t.Fatalf("failed execution install corrupted shared bank: bank=%+v state=%+v", bank.image, state)
				}
			})
		}
	}
	bank := &debugTestBank{image: before, fail: map[int]bool{3: true, 4: true}}
	state := &watchpointState{baseline: before, current: before, nextGeneration: 7}
	if err := changeDebugImage(state, bank.access(), before, after, 1); !errors.Is(err, target.ErrPartial) {
		t.Fatalf("rollback failure=%v", err)
	}
	if state.pending == nil || state.pending.dirty != 1 || state.fault == nil {
		t.Fatal("execution rollback lost ownership")
	}
	bank.fail = nil
	if err := restoreWatchpointState(state, bank.access()); err != nil {
		t.Fatal(err)
	}
	if bank.image != before || state.pending != nil || state.fault != nil || state.nextGeneration != 7 {
		t.Fatal("execution cleanup did not restore the bank")
	}
}

func TestHardwareBreakpointFaultFacts(t *testing.T) {
	pc := target.Address(0x1001)
	ref := target.HardwareBreakpointRef{Thread: target.ThreadRef{Session: 1, ID: 2}, Slot: 0, Generation: 3}
	hits := []target.HardwareBreakpointHit{{Ref: ref, Address: pc}}
	data := []target.WatchpointHit{{Ref: target.WatchpointRef{Thread: ref.Thread, Slot: 1, Generation: 4}, Address: 0x2000, Size: 1, Access: target.WatchWrite}}
	for _, stepping := range []bool{false, true} {
		stop, signal := applyWatchpointStop(target.Stop{RawPC: &pc, HardwareBreakpoints: hits}, 4, data, false, 3, stepping)
		if stop.Reason != target.StopHardwareBreakpoint || stop.StepCompleted || signal != 0 || len(stop.Watchpoints) != 1 || len(stop.HardwareBreakpoints) != 1 || *stop.RawPC != pc {
			t.Fatalf("stepping=%t stop=%+v pending=%d", stepping, stop, signal)
		}
		if err := validateHardwareBreakpointPC(stop); err != nil {
			t.Fatal(err)
		}
	}
	for _, stop := range []target.Stop{
		{HardwareBreakpoints: hits},
		{RawPC: &pc, HardwareBreakpoints: []target.HardwareBreakpointHit{{Ref: ref, Address: pc + 1}}},
		{RawPC: &pc, HardwareBreakpoints: append(append([]target.HardwareBreakpointHit{}, hits...), target.HardwareBreakpointHit{Ref: ref, Address: pc + 1})},
	} {
		if err := validateHardwareBreakpointPC(stop); !errors.Is(err, target.ErrUnknown) {
			t.Fatalf("unmatched execution fault accepted: %+v error=%v", stop, err)
		}
	}
}
