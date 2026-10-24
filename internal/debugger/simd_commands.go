package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/target"
)

type extendedRegisterReader interface {
	ReadExtendedRegisters(target.ThreadToken) (target.ExtendedRegisterState, error)
}

type simdState struct {
	arch         target.Architecture
	fcs, fds     uint16
	format       target.ExtendedRegisterFormat
	features     uint64
	present      uint64
	mxcsr        uint32
	mxcsrMask    uint32
	xmmAvailable bool
	ymmAvailable bool
	xmm          [16][16]byte
	ymmHigh      [16][16]byte
	fcw          uint16
	fsw          uint16
	ftw          uint8
	fop          uint16
	fip          uint64
	fdp          uint64
	x87          [8][10]byte
}

func simdArguments(name, rawArgs string) (int, error) {
	if name != "simd" && name != "xmm" && name != "ymm" {
		return 0, fmt.Errorf("unknown SIMD command %q: %w", name, target.ErrInvalidArgument)
	}
	argument := strings.TrimSpace(rawArgs)
	if argument == "" {
		return -1, nil
	}
	if name == "simd" {
		return 0, fmt.Errorf("simd takes no arguments: %w", target.ErrInvalidArgument)
	}
	if strings.IndexFunc(argument, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("usage: %s [INDEX 0..15]: %w", name, target.ErrInvalidArgument)
	}
	index, err := strconv.ParseUint(argument, 10, 4)
	if err != nil {
		return 0, fmt.Errorf("%s index must be between 0 and 15: %w", name, target.ErrInvalidArgument)
	}
	return int(index), nil
}

func decodeSIMDState(state target.ExtendedRegisterState) (simdState, error) {
	var result simdState
	result.arch = state.Architecture
	if state.Architecture != target.AMD64 && state.Architecture != target.X86 {
		return result, fmt.Errorf("SIMD display requires x86 or amd64, got %q: %w", state.Architecture, target.ErrUnsupported)
	}
	data := state.Data
	result.format = state.Format
	var ymmOffset uint32
	switch state.Format {
	case target.ExtendedFormatFXSave:
		if len(data) != 512 || state.XState != nil {
			return result, fmt.Errorf("invalid FXSAVE register state: %w", target.ErrUnsupported)
		}
		result.features, result.present = 3, 3
	case target.ExtendedFormatXSave:
		if len(data) < 576 || len(data)%8 != 0 || state.XState == nil {
			return result, fmt.Errorf("invalid XSAVE register state: %w", target.ErrUnsupported)
		}
		if binary.LittleEndian.Uint64(data[520:528]) != 0 {
			return result, fmt.Errorf("compacted XSAVE register state: %w", target.ErrUnsupported)
		}
		for _, value := range data[528:576] {
			if value != 0 {
				return result, fmt.Errorf("unknown XSAVE header fields: %w", target.ErrUnsupported)
			}
		}
		result.features, result.present = state.XState.KernelFeatures, state.XState.Present
		if result.features != binary.LittleEndian.Uint64(data[464:472]) || result.present != binary.LittleEndian.Uint64(data[512:520]) ||
			result.features&1 == 0 || result.present&^result.features != 0 || result.features&4 != 0 && result.features&2 == 0 {
			return result, fmt.Errorf("inconsistent XSAVE feature metadata: %w", target.ErrUnsupported)
		}
		covered := uint64(3)
		for index, component := range state.XState.ExtendedComponents {
			if component.ID < 2 || component.ID >= 63 || component.Size == 0 || component.Offset < 576 ||
				uint64(component.Offset)+uint64(component.Size) > uint64(len(data)) {
				return result, fmt.Errorf("invalid XSAVE component %d layout: %w", component.ID, target.ErrUnsupported)
			}
			bit := uint64(1) << component.ID
			if covered&bit != 0 || result.features&bit == 0 {
				return result, fmt.Errorf("inconsistent XSAVE component %d metadata: %w", component.ID, target.ErrUnsupported)
			}
			for _, previous := range state.XState.ExtendedComponents[:index] {
				if uint64(component.Offset) < uint64(previous.Offset)+uint64(previous.Size) &&
					uint64(previous.Offset) < uint64(component.Offset)+uint64(component.Size) {
					return result, fmt.Errorf("overlapping XSAVE components %d and %d: %w", component.ID, previous.ID, target.ErrUnsupported)
				}
			}
			covered |= bit
			if component.ID == 2 {
				if component.Size != 256 {
					return result, fmt.Errorf("YMM high register component has size %d, expected 256: %w", component.Size, target.ErrUnsupported)
				}
				ymmOffset = component.Offset
			}
		}
		if result.features&^covered != 0 {
			return result, fmt.Errorf("missing XSAVE component metadata: %w", target.ErrUnsupported)
		}
	default:
		return result, fmt.Errorf("extended register format %d: %w", state.Format, target.ErrUnsupported)
	}
	result.xmmAvailable = result.features&2 != 0
	result.ymmAvailable = result.features&4 != 0
	result.mxcsr = binary.LittleEndian.Uint32(data[24:28])
	result.mxcsrMask = binary.LittleEndian.Uint32(data[28:32])
	if result.present&1 == 0 {
		result.fcw = 0x37f
	} else {
		result.fcw = binary.LittleEndian.Uint16(data[0:2])
		result.fsw = binary.LittleEndian.Uint16(data[2:4])
		result.ftw = data[4]
		result.fop = binary.LittleEndian.Uint16(data[6:8]) & 0x7ff
		result.fip = binary.LittleEndian.Uint64(data[8:16])
		result.fdp = binary.LittleEndian.Uint64(data[16:24])
		if state.Architecture == target.X86 {
			result.fip = uint64(binary.LittleEndian.Uint32(data[8:12]))
			result.fdp = uint64(binary.LittleEndian.Uint32(data[16:20]))
			result.fcs = binary.LittleEndian.Uint16(data[12:14])
			result.fds = binary.LittleEndian.Uint16(data[20:22])
		}
		for index := range result.x87 {
			copy(result.x87[index][:], data[32+16*index:42+16*index])
		}
	}
	if result.present&2 != 0 {
		for index := range result.xmm[:result.vectorCount()] {
			copy(result.xmm[index][:], data[160+16*index:176+16*index])
		}
	}
	if result.present&4 != 0 {
		for index := range result.ymmHigh[:result.vectorCount()] {
			offset := uint64(ymmOffset) + uint64(index)*16
			copy(result.ymmHigh[index][:], data[offset:offset+16])
		}
	}
	return result, nil
}

func (c *Controller) showSIMD(ctx context.Context, name, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	index, err := simdArguments(name, rawArgs)
	if err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if _, ok := c.session.(*qemuSession); ok {
		return c.showQemuSIMD(ctx, name, index, thread)
	}
	reader, ok := c.session.(extendedRegisterReader)
	if !ok {
		return fmt.Errorf("extended register access: %w", target.ErrUnsupported)
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	state, err := reader.ReadExtendedRegisters(thread.Token)
	if canceled := contextReady(ctx); canceled != nil {
		return errors.Join(err, canceled)
	}
	if err != nil {
		return err
	}
	if state.Architecture != target.AMD64 && state.Architecture != target.X86 {
		return target.ErrUnsupported
	}
	if state.Token != thread.Token || state.Architecture != snapshot.Architecture {
		return fmt.Errorf("extended register token differs from selected thread: %w", target.ErrStale)
	}
	registers, err := decodeSIMDState(state)
	if err != nil {
		return err
	}
	if index >= registers.vectorCount() {
		return fmt.Errorf("%s index must be below %d for %s: %w", name, registers.vectorCount(), state.Architecture, target.ErrInvalidArgument)
	}
	if index >= 0 {
		if name == "xmm" {
			if !registers.xmmAvailable {
				return fmt.Errorf("XMM registers are not supported by this register state: %w", target.ErrUnsupported)
			}
			return c.writeXMM(ctx, index, registers.xmm[index][:])
		}
		if !registers.ymmAvailable {
			return fmt.Errorf("YMM registers are not supported by this register state: %w", target.ErrUnsupported)
		}
		return c.writeYMM(ctx, index, registers.xmm[index][:], registers.ymmHigh[index][:])
	}
	return c.writeSIMD(ctx, registers)
}

func simdHex(data []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(data)*2)
	for index, value := range data {
		position := (len(data) - index - 1) * 2
		encoded[position], encoded[position+1] = digits[value>>4], digits[value&15]
	}
	return string(encoded)
}

func (c *Controller) writeXMM(ctx context.Context, index int, data []byte) error {
	return c.writeXMMWidth(ctx, index, data, display.OutputWidth(c.out))
}

func (c *Controller) writeXMMWidth(ctx context.Context, index int, data []byte, width int) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	low := math.Float64frombits(binary.LittleEndian.Uint64(data[:8]))
	high := math.Float64frombits(binary.LittleEndian.Uint64(data[8:]))
	label := fmt.Sprintf("%-6s: ", fmt.Sprintf("XMM%d", index))
	raw := simdHex(data[8:]) + " " + simdHex(data[:8])
	lanes := "f64-le:[" + strconv.FormatFloat(low, 'g', -1, 64) + " " + strconv.FormatFloat(high, 'g', -1, 64) + "]"
	text := c.renderer.Text(display.StyleRegister, label) + raw
	if display.VisibleWidth(label+raw+" | "+lanes) <= width {
		return c.writef("%s | %s\n", text, lanes)
	}
	continuation := strings.Repeat(" ", len(label)) + lanes
	return c.writef("%s\n%s\n", text, display.Wrap(continuation, width, len(label)))
}

func (c *Controller) writeYMM(ctx context.Context, index int, low, high []byte) error {
	return c.writeYMMWidth(ctx, index, low, high, display.OutputWidth(c.out))
}

func (c *Controller) writeYMMWidth(ctx context.Context, index int, low, high []byte, width int) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	label := c.renderer.Text(display.StyleRegister, fmt.Sprintf("%-6s: ", fmt.Sprintf("YMM%d", index)))
	return c.writef("%s\n", display.Wrap(label+simdHex(high)+" "+simdHex(low), width, 8))
}

func simdFeatureNames(mask uint64) string {
	known := [...]string{"x87", "SSE", "AVX", "BNDREGS", "BNDCSR", "AVX512_OPMASK", "AVX512_ZMM_Hi256", "AVX512_Hi16_ZMM"}
	var names []string
	for index := uint(0); index < 64; index++ {
		if mask&(uint64(1)<<index) == 0 {
			continue
		}
		if int(index) < len(known) {
			names = append(names, known[index])
		} else {
			names = append(names, fmt.Sprintf("component%d", index))
		}
	}
	return strings.Join(names, " ")
}

func (c *Controller) writeSIMD(ctx context.Context, state simdState) error {
	width := display.OutputWidth(c.out)
	writef := func(format string, args ...any) error {
		if err := contextReady(ctx); err != nil {
			return err
		}
		text := strings.TrimSuffix(fmt.Sprintf(format, args...), "\n")
		return c.writef("%s\n", strings.Join(metadataLines(text, width, 4), "\n"))
	}
	view := contextOutput{writef: writef, renderer: c.renderer, width: width}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if err := view.heading("SIMD"); err != nil {
		return err
	}
	if state.xmmAvailable {
		var flags []string
		for index, flag := range [...]string{"IE", "DE", "ZE", "OE", "UE", "PE"} {
			if state.mxcsr&(uint32(1)<<index) != 0 {
				flags = append(flags, flag)
			}
		}
		value := c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%08x", state.mxcsr))
		if err := writef("MXCSR: %s [%s] RC:%d FTZ:%d DAZ:%d\nMXCSR_MASK: 0x%08x\n", value, strings.Join(flags, " "),
			(state.mxcsr>>13)&3, (state.mxcsr>>15)&1, (state.mxcsr>>6)&1, state.mxcsrMask); err != nil {
			return err
		}
	} else if err := writef("MXCSR: unsupported\n"); err != nil {
		return err
	}
	if state.format == target.ExtendedFormatXSave {
		if err := writef("XSTATE_BV: 0x%016x [%s]\nKernel features: 0x%016x [%s]\n", state.present, simdFeatureNames(state.present), state.features, simdFeatureNames(state.features)); err != nil {
			return err
		}
	} else if err := writef("XSTATE_BV: unavailable (FXSAVE has no component bitmap)\n"); err != nil {
		return err
	}
	if err := view.heading("XMM Registers (SSE - 128 bit)"); err != nil {
		return err
	}
	if state.xmmAvailable {
		if state.present&2 == 0 {
			if err := writef("SSE state: initial\n"); err != nil {
				return err
			}
		}
		for index := range state.xmm[:state.vectorCount()] {
			if err := c.writeXMMWidth(ctx, index, state.xmm[index][:], width); err != nil {
				return err
			}
		}
	} else if err := writef("unsupported\n"); err != nil {
		return err
	}
	if err := view.heading("YMM Registers (AVX - 256 bit)"); err != nil {
		return err
	}
	if state.ymmAvailable {
		if state.present&4 == 0 {
			if err := writef("AVX upper state: initial\n"); err != nil {
				return err
			}
		}
		for index := range state.ymmHigh[:state.vectorCount()] {
			if err := c.writeYMMWidth(ctx, index, state.xmm[index][:], state.ymmHigh[index][:], width); err != nil {
				return err
			}
		}
	} else if err := writef("unsupported by this register state\n"); err != nil {
		return err
	}
	if err := view.heading("x87 FPU Registers"); err != nil {
		return err
	}
	if state.present&1 == 0 {
		if err := writef("x87 state: initial\n"); err != nil {
			return err
		}
	}
	if err := writef("FCW: 0x%04x  FSW: 0x%04x  FTW (abridged): 0x%02x  FOP: 0x%04x\nFIP: 0x%0*x  FDP: 0x%0*x\n",
		state.fcw, state.fsw, state.ftw, state.fop, abiFor(state.arch).word*2, state.fip, abiFor(state.arch).word*2, state.fdp); err != nil {
		return err
	}
	if state.arch == target.X86 {
		if err := writef("FCS: 0x%04x  FDS: 0x%04x\n", state.fcs, state.fds); err != nil {
			return err
		}
	}
	for index, data := range state.x87 {
		if err := contextReady(ctx); err != nil {
			return err
		}
		if err := writef("%s: %s\n", c.renderer.Text(display.StyleRegister, fmt.Sprintf("ST(%d) ", index)), simdHex(data[:])); err != nil {
			return err
		}
	}
	return nil
}

func (state simdState) vectorCount() int {
	if state.arch == target.X86 {
		return 8
	}
	return 16
}
