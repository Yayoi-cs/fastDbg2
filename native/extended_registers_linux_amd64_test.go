package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"fastdbg2/native/amd64"
	"fastdbg2/native/internal/xstate"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func extendedTestState(t *testing.T) (xstate.CPU, target.ExtendedRegisterState) {
	t.Helper()
	cpu := xstate.CPU{
		XSave: true, Size: 2696, Supported: 0x2e7, Enabled: 0x2e7, MXCSRMask: 0xffff,
		Components: []xstate.Component{
			{ID: 2, Offset: 576, Size: 256},
			{ID: 5, Offset: 1088, Size: 64},
			{ID: 6, Offset: 1152, Size: 512},
			{ID: 7, Offset: 1664, Size: 1024},
			{ID: 9, Offset: 2688, Size: 8},
		},
	}
	state := target.ExtendedRegisterState{
		Token:        target.ThreadToken{Thread: target.ThreadRef{Session: 1, ID: 1}, Stop: 1, Registers: 1},
		Architecture: target.AMD64, Format: target.ExtendedFormatXSave, Data: make([]byte, cpu.Size),
	}
	binary.LittleEndian.PutUint16(state.Data[:2], 0x37f)
	binary.LittleEndian.PutUint32(state.Data[24:28], 0x1f80)
	binary.LittleEndian.PutUint32(state.Data[28:32], cpu.MXCSRMask)
	binary.LittleEndian.PutUint64(state.Data[464:472], cpu.Enabled)
	binary.LittleEndian.PutUint64(state.Data[512:520], cpu.Enabled)
	var err error
	state.XState, err = inspectExtendedState(cpu, state.Format, state.Data)
	if err != nil {
		t.Fatal(err)
	}
	return cpu, state
}

func TestNativeExtendedStateLayout(t *testing.T) {
	cpu, state := extendedTestState(t)
	if state.XState.KernelFeatures != 0x2e7 || state.XState.Present != 0x2e7 || len(state.XState.ExtendedComponents) != 5 {
		t.Fatalf("metadata=%+v", state.XState)
	}
	binary.LittleEndian.PutUint64(state.Data[512:520], 0)
	initial, err := inspectExtendedState(cpu, state.Format, state.Data)
	if err != nil || initial.Present != 0 || initial.KernelFeatures != 0x2e7 {
		t.Fatalf("initial state mistaken for unavailable: %+v %v", initial, err)
	}
	if value, err := inspectExtendedState(cpu, target.ExtendedFormatFXSave, state.Data[:512]); err != nil || value != nil {
		t.Fatalf("FXSAVE metadata=%+v err=%v", value, err)
	}
}

func TestNativeExtendedStateRejectsInvalidShapes(t *testing.T) {
	cpu, state := extendedTestState(t)
	for _, size := range []int{0, 512, 575, 577, 2695, 2704} {
		if _, err := inspectExtendedState(cpu, state.Format, make([]byte, size)); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("size=%d err=%v", size, err)
		}
	}
	for _, modify := range []func(*xstate.CPU, []byte){
		func(_ *xstate.CPU, b []byte) { binary.LittleEndian.PutUint64(b[520:528], 1<<63) },
		func(_ *xstate.CPU, b []byte) { b[528] = 1 },
		func(_ *xstate.CPU, b []byte) { b[464] = 0 },
		func(_ *xstate.CPU, b []byte) { b[471] = 0x80 },
		func(_ *xstate.CPU, b []byte) { b[519] = 0x80 },
		func(c *xstate.CPU, _ []byte) { c.Components = c.Components[:4] },
		func(c *xstate.CPU, _ []byte) { c.Components[0].Offset = 512 },
		func(c *xstate.CPU, _ []byte) { c.Components[0].Size = 0 },
		func(c *xstate.CPU, _ []byte) { c.Components[1].Offset = 600 },
		func(c *xstate.CPU, _ []byte) { c.Components[1].ID = 2 },
		func(c *xstate.CPU, _ []byte) { c.Components[4].Size = 16 },
	} {
		cpu, state := extendedTestState(t)
		modify(&cpu, state.Data)
		if _, err := inspectExtendedState(cpu, state.Format, state.Data); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("invalid state accepted: %v", err)
		}
	}
}

func TestNativeExtendedWriteValidatesRawNotCallerMetadata(t *testing.T) {
	cpu, current := extendedTestState(t)
	for _, offset := range []int{0, 32, 160, 576, 1088, 1152, 1664, 2688} {
		requested := copyExtendedRegisterState(current)
		requested.Data[offset] ^= 1
		requested.XState = &target.XStateInfo{KernelFeatures: ^uint64(0), Present: 0}
		if err := validateExtendedWrite(cpu, current, requested); err != nil {
			t.Fatalf("valid raw component write offset=%d: %v", offset, err)
		}
	}
	requested := copyExtendedRegisterState(current)
	binary.LittleEndian.PutUint64(requested.Data[512:520], 0)
	if err := validateExtendedWrite(cpu, current, requested); err != nil {
		t.Fatalf("explicit initial-state request rejected: %v", err)
	}
}

func TestNativeExtendedWritePrevalidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		want   error
		modify func(*target.ExtendedRegisterState)
	}{
		{"token", target.ErrStale, func(s *target.ExtendedRegisterState) { s.Token.Registers++ }},
		{"architecture", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Architecture = target.X86 }},
		{"format", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Format = target.ExtendedFormatFXSave }},
		{"length", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data = s.Data[:len(s.Data)-8] }},
		{"mask", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[28] ^= 1 }},
		{"mxcsr", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[27] = 0x80 }},
		{"fpu-reserved", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[5] = 1 }},
		{"opcode-reserved", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[7] |= 0x80 }},
		{"st-padding", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[42] = 1 }},
		{"legacy-padding", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[416] = 1 }},
		{"software-mask", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[464] ^= 1 }},
		{"software-reserved", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[480] = 1 }},
		{"present", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[519] = 0x80 }},
		{"compacted", target.ErrUnsupported, func(s *target.ExtendedRegisterState) { s.Data[527] = 0x80 }},
		{"header-reserved", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[528] = 1 }},
		{"component-gap", target.ErrInvalidArgument, func(s *target.ExtendedRegisterState) { s.Data[832] = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cpu, current := extendedTestState(t)
			before := bytes.Clone(current.Data)
			requested := copyExtendedRegisterState(current)
			test.modify(&requested)
			if err := validateExtendedWrite(cpu, current, requested); !errors.Is(err, test.want) {
				t.Fatalf("err=%v want=%v", err, test.want)
			}
			if !bytes.Equal(before, current.Data) {
				t.Fatal("validation mutated current state")
			}
		})
	}
}

func TestNativeExtendedCommitFaultAndRecovery(t *testing.T) {
	for _, kind := range []string{"set", "short", "readback", "layout"} {
		t.Run(kind, func(t *testing.T) {
			_, requested := extendedTestState(t)
			e, th, space := nativeDataTestEngine(amd64.Descriptor())
			hit := &breakpointHit{}
			th.hit = hit
			e.life.syscallSteps = map[*thread]syscallStep{th: {pc: 0x1002}}
			setCalls, getCalls := 0, 0
			_, err := e.commitExtendedRegisters(th, requested, func(data []byte) (int, error) {
				setCalls++
				if kind == "set" {
					return 0, unix.EIO
				}
				if kind == "short" {
					return len(data) - 8, nil
				}
				return len(data), nil
			}, func() (target.ExtendedRegisterState, error) {
				getCalls++
				if kind == "readback" {
					return target.ExtendedRegisterState{}, unix.EIO
				}
				result := copyExtendedRegisterState(requested)
				result.Format = target.ExtendedFormatFXSave
				return result, nil
			})
			var partial *target.PartialError
			if !errors.As(err, &partial) || partial.Completed != 0 || partial.Total != len(requested.Data) || th.extendedFault != err {
				t.Fatalf("fault=%v partial=%+v", err, partial)
			}
			if setCalls != 1 || (kind == "set" || kind == "short") && getCalls != 0 || th.registerRevision != 1 || space.revision != 0 || th.hit != hit || e.unsupported != nil {
				t.Fatal("invalid partial-write owner state")
			}
			if proof, exists := e.life.syscallSteps[th]; !exists || proof.pc != 0x1002 {
				t.Fatal("extended write discarded syscall provenance")
			}
			actual := copyExtendedRegisterState(requested)
			actual.Data[32] = 0xaa
			post, err := e.commitExtendedRegisters(th, requested, func(data []byte) (int, error) { return len(data), nil }, func() (target.ExtendedRegisterState, error) { return actual, nil })
			if err != nil || post.Data[32] != 0xaa || th.extendedFault != nil || post.Token != th.token() || th.registerRevision != 2 || th.hit != hit || space.revision != 0 {
				t.Fatalf("authoritative recovery result=%+v err=%v", post, err)
			}
		})
	}
}

func TestNativeExtendedReadAndFullRewriteRecovery(t *testing.T) {
	s := nativeDataSession(t)
	snapshot := nativeDataSnapshot(t, s)
	state, err := s.ReadExtendedRegisters(snapshot.Threads[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	err = command(s, func(e *engine) error {
		th, err := e.requireThread(state.Token)
		if err != nil {
			return err
		}
		_, _, note, err := e.loadExtendedRegisters(th)
		if err != nil {
			return err
		}
		_, err = e.commitExtendedRegisters(th, state, func(data []byte) (int, error) {
			return ptraceRegisterSetNote(unix.PTRACE_SETREGSET, th.tid, note, data)
		}, func() (target.ExtendedRegisterState, error) { return target.ExtendedRegisterState{}, unix.EIO })
		return err
	})
	if !errors.Is(err, target.ErrPartial) {
		t.Fatalf("injected confirmation failure: %v", err)
	}
	snapshot = nativeDataSnapshot(t, s)
	observed, err := s.ReadExtendedRegisters(snapshot.Threads[0].Token)
	if err != nil {
		t.Fatalf("recovery read: %v", err)
	}
	faulted, err := call(s, func(e *engine) (bool, error) {
		th, err := e.requireThread(observed.Token)
		if err != nil {
			return false, err
		}
		return th.extendedFault != nil, nil
	})
	if err != nil || !faulted {
		t.Fatalf("read alone cleared fault: %v %v", faulted, err)
	}
	confirmed, err := s.WriteExtendedRegisters(observed.Token, observed)
	if err != nil {
		t.Fatalf("fullstate recovery: %v", err)
	}
	faulted, err = call(s, func(e *engine) (bool, error) {
		th, err := e.requireThread(confirmed.Token)
		if err != nil {
			return false, err
		}
		return th.extendedFault != nil, nil
	})
	if err != nil || faulted {
		t.Fatalf("fullstate recovery retained fault: %v %v", faulted, err)
	}
}
