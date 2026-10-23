package native

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"fastdbg2/native/internal/xstate"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const (
	x86XStateNote  = 0x202
	x86FXStateNote = 0x46e62b7f
)

func (e *engine) readExtendedRegisters(token target.ThreadToken) (target.ExtendedRegisterState, error) {
	t, err := e.requireThread(token)
	if err != nil {
		return target.ExtendedRegisterState{}, err
	}
	state, _, _, err := e.loadExtendedRegisters(t)
	return state, err
}

func (e *engine) writeExtendedRegisters(token target.ThreadToken, state target.ExtendedRegisterState) (target.ExtendedRegisterState, error) {
	t, err := e.requireThread(token)
	if err != nil {
		return target.ExtendedRegisterState{}, err
	}
	if state.Token != token {
		return target.ExtendedRegisterState{}, target.ErrStale
	}
	if state.Architecture != t.process.profile.Architecture || state.Format != target.ExtendedFormatXSave && state.Format != target.ExtendedFormatFXSave {
		return target.ExtendedRegisterState{}, target.ErrInvalidArgument
	}
	current, cpu, note, err := e.loadExtendedRegisters(t)
	if err != nil {
		return target.ExtendedRegisterState{}, err
	}
	if err := validateExtendedWrite(cpu, current, state); err != nil {
		return target.ExtendedRegisterState{}, err
	}
	return e.commitExtendedRegisters(t, state, func(data []byte) (int, error) {
		return ptraceRegisterSetNote(unix.PTRACE_SETREGSET, t.tid, note, data)
	}, func() (target.ExtendedRegisterState, error) {
		result, _, _, err := e.loadExtendedRegisters(t)
		return result, err
	})
}

func (e *engine) loadExtendedRegisters(t *thread) (target.ExtendedRegisterState, xstate.CPU, uintptr, error) {
	var empty target.ExtendedRegisterState
	if _, err := e.readRegisterSet(t.tid); err != nil {
		return empty, xstate.CPU{}, 0, err
	}
	cpu, err := xstate.Host()
	if err != nil {
		return empty, cpu, 0, err
	}
	format, note := target.ExtendedFormatXSave, uintptr(x86XStateNote)
	if !cpu.XSave {
		format, note = target.ExtendedFormatFXSave, 2
		if t.process.profile.Architecture == target.X86 {
			note = x86FXStateNote
		}
	}
	data := make([]byte, int(cpu.Size)+8)
	n, err := ptraceRegisterSetNote(unix.PTRACE_GETREGSET, t.tid, note, data)
	if err != nil {
		return empty, cpu, note, fmt.Errorf("read thread %d extended registers: %w", t.tid, err)
	}
	if n > int(cpu.Size) {
		return empty, cpu, note, fmt.Errorf("extended register set exceeds CPU layout: %w", target.ErrUnsupported)
	}
	state := target.ExtendedRegisterState{
		Token: t.token(), Architecture: t.process.profile.Architecture,
		Format: format, Data: data[:n:n],
	}
	state.XState, err = inspectExtendedState(cpu, format, state.Data)
	if err != nil {
		return empty, cpu, note, err
	}
	return state, cpu, note, nil
}

func inspectExtendedState(cpu xstate.CPU, format target.ExtendedRegisterFormat, data []byte) (*target.XStateInfo, error) {
	if format == target.ExtendedFormatFXSave {
		if len(data) != 512 {
			return nil, fmt.Errorf("FXSAVE register set size %d: %w", len(data), target.ErrUnsupported)
		}
		return nil, nil
	}
	if format != target.ExtendedFormatXSave || !cpu.XSave || len(data) < 576 || len(data)%8 != 0 || uint64(len(data)) > uint64(cpu.Size) {
		return nil, fmt.Errorf("invalid XSAVE register set shape: %w", target.ErrUnsupported)
	}
	if binary.LittleEndian.Uint64(data[520:528]) != 0 {
		return nil, fmt.Errorf("compacted XSAVE is not a Linux regset format: %w", target.ErrUnsupported)
	}
	if !zeroBytes(data[528:576]) {
		return nil, fmt.Errorf("unknown XSAVE header fields: %w", target.ErrUnsupported)
	}
	info := &target.XStateInfo{
		KernelFeatures: binary.LittleEndian.Uint64(data[464:472]),
		Present:        binary.LittleEndian.Uint64(data[512:520]),
	}
	if info.KernelFeatures&1 == 0 || info.KernelFeatures&^cpu.Enabled != 0 || info.KernelFeatures&^cpu.Supported != 0 || info.Present&^info.KernelFeatures != 0 {
		return nil, fmt.Errorf("inconsistent XSAVE feature masks: %w", target.ErrUnsupported)
	}
	covered := uint64(3)
	ordered := append([]xstate.Component(nil), cpu.Components...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	end := uint64(576)
	seen := uint64(0)
	for _, component := range ordered {
		if component.ID < 2 || component.ID >= 63 || component.Size == 0 || uint64(component.Offset) < end || uint64(component.Offset)+uint64(component.Size) > uint64(cpu.Size) || seen&(uint64(1)<<component.ID) != 0 {
			return nil, fmt.Errorf("invalid XSAVE component layout: %w", target.ErrUnsupported)
		}
		seen |= uint64(1) << component.ID
		end = uint64(component.Offset) + uint64(component.Size)
	}
	for _, component := range cpu.Components {
		bit := uint64(1) << component.ID
		if info.KernelFeatures&bit == 0 {
			continue
		}
		if uint64(component.Offset)+uint64(component.Size) > uint64(len(data)) {
			return nil, fmt.Errorf("truncated XSAVE component %d: %w", component.ID, target.ErrUnsupported)
		}
		info.ExtendedComponents = append(info.ExtendedComponents, target.XStateComponent{
			ID: component.ID, Offset: component.Offset, Size: component.Size,
		})
		covered |= bit
	}
	if info.KernelFeatures&^covered != 0 {
		return nil, fmt.Errorf("XSAVE component metadata is missing: %w", target.ErrUnsupported)
	}
	return info, nil
}

func validateExtendedWrite(cpu xstate.CPU, current, requested target.ExtendedRegisterState) error {
	if requested.Token != current.Token {
		return target.ErrStale
	}
	if requested.Architecture != current.Architecture || requested.Format != current.Format || len(requested.Data) != len(current.Data) {
		return target.ErrInvalidArgument
	}
	data, old := requested.Data, current.Data
	if len(data) < 512 {
		return target.ErrInvalidArgument
	}
	if !bytes.Equal(data[28:32], old[28:32]) || data[5] != old[5] || !bytes.Equal(data[416:464], old[416:464]) {
		return fmt.Errorf("readonly FXSAVE fields changed: %w", target.ErrInvalidArgument)
	}
	if binary.LittleEndian.Uint16(data[6:8])&0xf800 != binary.LittleEndian.Uint16(old[6:8])&0xf800 {
		return fmt.Errorf("reserved FPU opcode bits changed: %w", target.ErrInvalidArgument)
	}
	for offset := 42; offset < 160; offset += 16 {
		if !bytes.Equal(data[offset:offset+6], old[offset:offset+6]) {
			return fmt.Errorf("reserved x87 register bytes changed: %w", target.ErrInvalidArgument)
		}
	}
	checkMXCSR := requested.Format == target.ExtendedFormatFXSave
	if requested.Format == target.ExtendedFormatXSave {
		if len(data) < 576 || current.XState == nil {
			return target.ErrInvalidArgument
		}
		if binary.LittleEndian.Uint64(data[520:528]) != 0 {
			return target.ErrUnsupported
		}
		if !zeroBytes(data[528:576]) || !bytes.Equal(data[464:512], old[464:512]) {
			return fmt.Errorf("readonly XSAVE fields changed: %w", target.ErrInvalidArgument)
		}
		present := binary.LittleEndian.Uint64(data[512:520])
		if present&^current.XState.KernelFeatures != 0 {
			return fmt.Errorf("unsupported XSAVE feature requested: %w", target.ErrInvalidArgument)
		}
		checkMXCSR = present&7 != 0
		components := append([]target.XStateComponent(nil), current.XState.ExtendedComponents...)
		sort.Slice(components, func(i, j int) bool { return components[i].Offset < components[j].Offset })
		end := uint32(576)
		for _, component := range components {
			if !bytes.Equal(data[end:component.Offset], old[end:component.Offset]) {
				return fmt.Errorf("XSAVE layout padding changed: %w", target.ErrInvalidArgument)
			}
			end = component.Offset + component.Size
		}
		if !bytes.Equal(data[end:], old[end:]) {
			return fmt.Errorf("XSAVE trailing padding changed: %w", target.ErrInvalidArgument)
		}
	}
	if checkMXCSR && binary.LittleEndian.Uint32(data[24:28])&^cpu.MXCSRMask != 0 {
		return fmt.Errorf("reserved MXCSR bits requested: %w", target.ErrInvalidArgument)
	}
	return nil
}

func zeroBytes(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func (e *engine) commitExtendedRegisters(t *thread, requested target.ExtendedRegisterState, set func([]byte) (int, error), get func() (target.ExtendedRegisterState, error)) (target.ExtendedRegisterState, error) {
	e.registersChanged(t)
	n, err := set(requested.Data)
	if err == nil && n != len(requested.Data) {
		err = fmt.Errorf("written extended register set size %d, expected %d: %w", n, len(requested.Data), target.ErrUnknown)
	}
	var actual target.ExtendedRegisterState
	if err == nil {
		actual, err = get()
		if err == nil && (actual.Architecture != requested.Architecture || actual.Format != requested.Format || len(actual.Data) != len(requested.Data)) {
			err = fmt.Errorf("extended register layout changed after write: %w", target.ErrUnsupported)
		}
	}
	if err != nil {
		partial := &target.PartialError{
			Op: "write extended registers", Completed: 0, Total: len(requested.Data),
			Err: fmt.Errorf("thread %d extended register state could not be confirmed: %w", t.tid, err),
		}
		t.extendedFault = partial
		return target.ExtendedRegisterState{}, partial
	}
	t.extendedFault = nil
	actual.Token = t.token()
	return actual, nil
}
