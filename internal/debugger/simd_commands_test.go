package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

type simdReadFixture struct {
	*contextReadFixture
	state  target.ExtendedRegisterState
	err    error
	tokens []target.ThreadToken
	onRead func()
}

func (fixture *simdReadFixture) ReadExtendedRegisters(token target.ThreadToken) (target.ExtendedRegisterState, error) {
	fixture.tokens = append(fixture.tokens, token)
	if fixture.onRead != nil {
		fixture.onRead()
	}
	return fixture.state, fixture.err
}

func simdTestState(format target.ExtendedRegisterFormat) target.ExtendedRegisterState {
	size := 512
	if format == target.ExtendedFormatXSave {
		size = 1024
	}
	state := target.ExtendedRegisterState{Architecture: target.AMD64, Format: format, Data: make([]byte, size)}
	binary.LittleEndian.PutUint16(state.Data[:2], 0x27f)
	binary.LittleEndian.PutUint16(state.Data[2:4], 0x5a34)
	state.Data[4], state.Data[5] = 0xa5, 0xcc
	binary.LittleEndian.PutUint16(state.Data[6:8], 0xfbff)
	binary.LittleEndian.PutUint64(state.Data[8:16], 0x1020304050607080)
	binary.LittleEndian.PutUint64(state.Data[16:24], 0x8070605040302010)
	binary.LittleEndian.PutUint32(state.Data[24:28], 0xdfc3)
	binary.LittleEndian.PutUint32(state.Data[28:32], 0xffff)
	for index := range 8 {
		for offset := range 10 {
			state.Data[32+16*index+offset] = byte(index*10 + offset)
		}
		for offset := 10; offset < 16; offset++ {
			state.Data[32+16*index+offset] = 0xee
		}
	}
	for index := range 16 {
		for offset := range 16 {
			state.Data[160+16*index+offset] = byte(index*16 + offset)
		}
	}
	binary.LittleEndian.PutUint64(state.Data[160:168], math.Float64bits(1.5))
	binary.LittleEndian.PutUint64(state.Data[168:176], math.Float64bits(-2.25))
	if format == target.ExtendedFormatXSave {
		state.XState = &target.XStateInfo{KernelFeatures: 7, Present: 7, ExtendedComponents: []target.XStateComponent{{ID: 2, Offset: 768, Size: 256}}}
		binary.LittleEndian.PutUint64(state.Data[464:472], state.XState.KernelFeatures)
		binary.LittleEndian.PutUint64(state.Data[512:520], state.XState.Present)
		for index := range 256 {
			state.Data[768+index] = byte(0x80 + index)
		}
		for index := 576; index < 768; index++ {
			state.Data[index] = 0xcc
		}
	}
	return state
}

func newSIMDTestController(format target.ExtendedRegisterFormat) (*Controller, *simdReadFixture, *bytes.Buffer) {
	base, _, thread := newContextFixture()
	fixture := &simdReadFixture{contextReadFixture: base, state: simdTestState(format)}
	fixture.state.Token = thread.Token
	var output bytes.Buffer
	controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
	return controller, fixture, &output
}

func TestSIMDDecodesMetadataOffsetsAndLegacyPayloads(t *testing.T) {
	state := simdTestState(target.ExtendedFormatXSave)
	before := bytes.Clone(state.Data)
	result, err := decodeSIMDState(state)
	if err != nil {
		t.Fatal(err)
	}
	if result.format != target.ExtendedFormatXSave || result.features != 7 || result.present != 7 || !result.xmmAvailable || !result.ymmAvailable ||
		result.fcw != 0x27f || result.fsw != 0x5a34 || result.ftw != 0xa5 || result.fop != 0x3ff ||
		result.fip != 0x1020304050607080 || result.fdp != 0x8070605040302010 || result.mxcsr != 0xdfc3 || result.mxcsrMask != 0xffff {
		t.Fatalf("decoded state=%+v", result)
	}
	for index := range 16 {
		if !bytes.Equal(result.xmm[index][:], state.Data[160+16*index:176+16*index]) ||
			!bytes.Equal(result.ymmHigh[index][:], state.Data[768+16*index:784+16*index]) {
			t.Fatalf("register %d did not follow component descriptor", index)
		}
	}
	for index := range 8 {
		if !bytes.Equal(result.x87[index][:], state.Data[32+16*index:42+16*index]) {
			t.Fatalf("x87 register %d includes padding or wrong payload", index)
		}
	}
	if !bytes.Equal(state.Data, before) {
		t.Fatal("decode mutated source")
	}
	state.Data[160] ^= 1
	state.Data[768] ^= 1
	if result.xmm[0][0] != before[160] || result.ymmHigh[0][0] != before[768] {
		t.Fatal("decoded state aliases input data")
	}
}

func TestSIMDInitialComponentsIgnoreStalePayloadButPreserveMXCSR(t *testing.T) {
	for _, present := range []uint64{0, 1, 2, 3, 4, 5, 6, 7} {
		t.Run(simdFeatureNames(present), func(t *testing.T) {
			state := simdTestState(target.ExtendedFormatXSave)
			state.XState.Present = present
			binary.LittleEndian.PutUint64(state.Data[512:520], present)
			result, err := decodeSIMDState(state)
			if err != nil {
				t.Fatal(err)
			}
			if !result.xmmAvailable || !result.ymmAvailable || result.mxcsr != 0xdfc3 || result.mxcsrMask != 0xffff {
				t.Fatalf("initial interpreted as unavailable or MXCSR reset: %+v", result)
			}
			if present&1 == 0 && (result.fcw != 0x37f || result.fsw != 0 || result.ftw != 0 || result.fop != 0 || result.fip != 0 || result.fdp != 0 || result.x87 != ([8][10]byte{})) {
				t.Fatalf("x87 initial state=%+v", result)
			}
			if present&2 == 0 && result.xmm != ([16][16]byte{}) {
				t.Fatal("initial XMM used stale payload")
			}
			if present&4 == 0 && result.ymmHigh != ([16][16]byte{}) {
				t.Fatal("initial YMM high used stale payload")
			}
		})
	}
}

func TestSIMDFXSaveDoesNotInventBitmapOrAVX(t *testing.T) {
	controller, fixture, output := newSIMDTestController(target.ExtendedFormatFXSave)
	binary.LittleEndian.PutUint32(fixture.state.Data[28:32], 0)
	if err := controller.showSIMD(context.Background(), "simd", ""); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MXCSR_MASK: 0x00000000", "XSTATE_BV: unavailable (FXSAVE has no component bitmap)", "unsupported by this register state", "XMM15 ", "ST(7)"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %q", want, output.String())
		}
	}
	if strings.Contains(output.String(), "YMM0") || strings.Contains(output.String(), "Kernel features") || strings.Contains(output.String(), "XSTATE_BV: 0x") {
		t.Fatalf("invented XSAVE state: %q", output.String())
	}
	output.Reset()
	err := controller.showSIMD(context.Background(), "ymm", "0")
	if !errors.Is(err, target.ErrUnsupported) || output.Len() != 0 {
		t.Fatalf("unsupported YMM error=%v output=%q", err, output.String())
	}
}

func TestSIMDRejectsMalformedStateBeforeOutput(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*target.ExtendedRegisterState)
	}{
		{"architecture", func(state *target.ExtendedRegisterState) { state.Architecture = target.AArch64 }},
		{"unknown-format", func(state *target.ExtendedRegisterState) { state.Format = target.ExtendedFormatUnknown }},
		{"nil-data", func(state *target.ExtendedRegisterState) { state.Data = nil }},
		{"truncated-header", func(state *target.ExtendedRegisterState) { state.Data = state.Data[:575] }},
		{"misaligned-length", func(state *target.ExtendedRegisterState) { state.Data = state.Data[:1023] }},
		{"missing-info", func(state *target.ExtendedRegisterState) { state.XState = nil }},
		{"compacted", func(state *target.ExtendedRegisterState) { binary.LittleEndian.PutUint64(state.Data[520:528], 1<<63|7) }},
		{"nonzero-xcomp", func(state *target.ExtendedRegisterState) { state.Data[520] = 1 }},
		{"unknown-header", func(state *target.ExtendedRegisterState) { state.Data[575] = 1 }},
		{"metadata-features", func(state *target.ExtendedRegisterState) { state.XState.KernelFeatures = 3 }},
		{"metadata-present", func(state *target.ExtendedRegisterState) { state.XState.Present = 3 }},
		{"missing-x87", func(state *target.ExtendedRegisterState) {
			state.XState.KernelFeatures = 6
			binary.LittleEndian.PutUint64(state.Data[464:472], 6)
		}},
		{"unsupported-present", func(state *target.ExtendedRegisterState) {
			state.XState.Present = 15
			binary.LittleEndian.PutUint64(state.Data[512:520], 15)
		}},
		{"avx-without-sse", func(state *target.ExtendedRegisterState) {
			state.XState.KernelFeatures, state.XState.Present = 5, 5
			binary.LittleEndian.PutUint64(state.Data[464:472], 5)
			binary.LittleEndian.PutUint64(state.Data[512:520], 5)
		}},
		{"missing-component", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents = nil }},
		{"legacy-component", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].ID = 1 }},
		{"invalid-component-id", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].ID = 63 }},
		{"overflow-component-id", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].ID = 255 }},
		{"empty-component", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].Size = 0 }},
		{"short-ymm-component", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].Size = 248 }},
		{"long-ymm-component", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].Size = 264 }},
		{"legacy-offset", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].Offset = 512 }},
		{"out-of-bounds", func(state *target.ExtendedRegisterState) { state.XState.ExtendedComponents[0].Offset = 1024 }},
		{"range-overflow", func(state *target.ExtendedRegisterState) {
			state.XState.ExtendedComponents[0].Offset = math.MaxUint32 - 127
		}},
		{"duplicate", func(state *target.ExtendedRegisterState) {
			state.XState.ExtendedComponents = append(state.XState.ExtendedComponents, state.XState.ExtendedComponents[0])
		}},
		{"unadvertised-component", func(state *target.ExtendedRegisterState) {
			state.XState.ExtendedComponents = append(state.XState.ExtendedComponents, target.XStateComponent{ID: 9, Offset: 576, Size: 8})
		}},
		{"overlap", func(state *target.ExtendedRegisterState) {
			state.XState.KernelFeatures |= 1 << 9
			binary.LittleEndian.PutUint64(state.Data[464:472], state.XState.KernelFeatures)
			state.XState.ExtendedComponents = append(state.XState.ExtendedComponents, target.XStateComponent{ID: 9, Offset: 768, Size: 8})
		}},
		{"unknown-bit-without-descriptor", func(state *target.ExtendedRegisterState) {
			state.XState.KernelFeatures |= 1 << 20
			binary.LittleEndian.PutUint64(state.Data[464:472], state.XState.KernelFeatures)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
			test.modify(&fixture.state)
			err := controller.showSIMD(context.Background(), "simd", "")
			if !errors.Is(err, target.ErrUnsupported) || output.Len() != 0 || len(fixture.tokens) != 1 {
				t.Fatalf("error=%v output=%q reads=%d", err, output.String(), len(fixture.tokens))
			}
		})
	}
	for _, modify := range []func(*target.ExtendedRegisterState){
		func(state *target.ExtendedRegisterState) { state.Data = state.Data[:511] },
		func(state *target.ExtendedRegisterState) { state.Data = append(state.Data, make([]byte, 8)...) },
		func(state *target.ExtendedRegisterState) { state.XState = &target.XStateInfo{} },
	} {
		state := simdTestState(target.ExtendedFormatFXSave)
		modify(&state)
		if _, err := decodeSIMDState(state); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("malformed FXSAVE error=%v", err)
		}
	}
}

func TestSIMDUnrelatedOpaqueComponentUsesValidatedMetadata(t *testing.T) {
	state := simdTestState(target.ExtendedFormatXSave)
	state.XState.KernelFeatures |= 1 << 20
	state.XState.Present |= 1 << 20
	binary.LittleEndian.PutUint64(state.Data[464:472], state.XState.KernelFeatures)
	binary.LittleEndian.PutUint64(state.Data[512:520], state.XState.Present)
	state.XState.ExtendedComponents = append(state.XState.ExtendedComponents, target.XStateComponent{ID: 20, Offset: 576, Size: 8})
	result, err := decodeSIMDState(state)
	if err != nil || result.ymmHigh[0][0] != 0x80 || simdFeatureNames(result.present) != "x87 SSE AVX component20" {
		t.Fatalf("unrelated component result=%+v error=%v", result, err)
	}
}

func TestSIMDNoArgumentAliasesPreserveFullDisplay(t *testing.T) {
	var previous string
	for _, name := range []string{"simd", "xmm", "ymm"} {
		controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
		if err := controller.showSIMD(context.Background(), name, ""); err != nil {
			t.Fatal(err)
		}
		if previous != "" && previous != output.String() {
			t.Fatalf("alias %q changed full display", name)
		}
		previous = output.String()
		for _, want := range []string{"[SIMD]", "MXCSR: 0x0000dfc3 [IE DE] RC:2 FTZ:1 DAZ:1", "XSTATE_BV: 0x0000000000000007 [x87 SSE AVX]", "Kernel features: 0x0000000000000007", "XMM0  : c002000000000000 3ff8000000000000 | f64-le:[1.5 -2.25]", "XMM15 ", "YMM0  : 8f8e8d8c8b8a89888786858483828180 c0020000000000003ff8000000000000", "YMM15 ", "FTW (abridged): 0xa5", "ST(0) : 09080706050403020100"} {
			if !strings.Contains(previous, want) {
				t.Fatalf("missing %q in %q", want, previous)
			}
		}
		if strings.Contains(previous, "eeeeeeee") || strings.Contains(previous, "\x1b") || fixture.snapshotReads != 1 || len(fixture.tokens) != 1 || fixture.tokens[0] != fixture.state.Token || len(fixture.registerTokens) != 0 || len(fixture.stackCalls) != 0 || len(fixture.locationTokens) != 0 || len(fixture.codeCalls) != 0 {
			t.Fatalf("unexpected state/display: %q fixture=%+v", previous, fixture)
		}
	}
}

func TestSIMDFocusedRegisterIndexAndInitialYMM(t *testing.T) {
	for _, test := range []struct{ name, index, want string }{
		{"xmm", "0", "XMM0  : c002000000000000 3ff8000000000000 | f64-le:[1.5 -2.25]\n"},
		{"xmm", "15", "XMM15 : fffefdfcfbfaf9f8 f7f6f5f4f3f2f1f0"},
		{"ymm", "0", "YMM0  : 8f8e8d8c8b8a89888786858483828180 c0020000000000003ff8000000000000\n"},
		{"ymm", "15", "YMM15 : 7f7e7d7c7b7a79787776757473727170 fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\n"},
	} {
		controller, _, output := newSIMDTestController(target.ExtendedFormatXSave)
		if err := controller.showSIMD(context.Background(), test.name, test.index); err != nil || !strings.HasPrefix(output.String(), test.want) || strings.Count(output.String(), "\n") != 1 {
			t.Fatalf("%s %s error=%v output=%q", test.name, test.index, err, output.String())
		}
	}
	controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
	fixture.state.XState.Present = 0
	binary.LittleEndian.PutUint64(fixture.state.Data[512:520], 0)
	if err := controller.showSIMD(context.Background(), "ymm", "0"); err != nil || output.String() != "YMM0  : 00000000000000000000000000000000 00000000000000000000000000000000\n" {
		t.Fatalf("initial YMM error=%v output=%q", err, output.String())
	}
}

func TestSIMDUnavailableSSEAndAVXAreNotInitialState(t *testing.T) {
	controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
	fixture.state.XState = &target.XStateInfo{KernelFeatures: 1, Present: 1}
	binary.LittleEndian.PutUint64(fixture.state.Data[464:472], 1)
	binary.LittleEndian.PutUint64(fixture.state.Data[512:520], 1)
	if err := controller.showSIMD(context.Background(), "simd", ""); err != nil || strings.Contains(output.String(), "XMM0") || strings.Contains(output.String(), "YMM0") || !strings.Contains(output.String(), "MXCSR: unsupported") {
		t.Fatalf("unsupported state error=%v output=%q", err, output.String())
	}
	for _, name := range []string{"xmm", "ymm"} {
		output.Reset()
		if err := controller.showSIMD(context.Background(), name, "0"); !errors.Is(err, target.ErrUnsupported) || output.Len() != 0 {
			t.Fatalf("focused unsupported %s error=%v output=%q", name, err, output.String())
		}
	}
}

func TestSIMDArgumentsPrevalidateWithoutTargetAccess(t *testing.T) {
	for _, test := range []struct{ name, args string }{
		{"unknown", ""}, {"simd", "0"}, {"simd", "xmm"}, {"xmm", "-1"}, {"xmm", "+1"}, {"xmm", "16"},
		{"xmm", "1 2"}, {"xmm", "0x1"}, {"xmm", "$rax"}, {"xmm", "\"1\""}, {"ymm", "18446744073709551616"},
	} {
		controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
		err := controller.showSIMD(context.Background(), test.name, test.args)
		if !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || len(fixture.tokens) != 0 || output.Len() != 0 {
			t.Fatalf("%q %q error=%v output=%q reads=%d", test.name, test.args, err, output.String(), fixture.snapshotReads)
		}
	}
	for _, test := range []struct {
		name, args string
		want       int
	}{
		{"simd", " \t ", -1}, {"xmm", "", -1}, {"ymm", "", -1}, {"xmm", " 0 ", 0}, {"ymm", "15", 15}, {"ymm", "01", 1},
	} {
		if index, err := simdArguments(test.name, test.args); err != nil || index != test.want {
			t.Fatalf("%q %q index=%d error=%v", test.name, test.args, index, err)
		}
	}
}

func TestSIMDReadErrorsAndStaleTokensAreNotRetried(t *testing.T) {
	for _, want := range []error{target.ErrStale, target.ErrUnavailable, target.ErrUnsupported, target.ErrBusy} {
		controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
		fixture.err = want
		if err := controller.showSIMD(context.Background(), "simd", ""); !errors.Is(err, want) || len(fixture.tokens) != 1 || fixture.snapshotReads != 1 || output.Len() != 0 {
			t.Fatalf("read error=%v want=%v output=%q", err, want, output.String())
		}
	}
	for _, change := range []func(*target.ThreadToken){
		func(token *target.ThreadToken) { token.Thread.ID++ },
		func(token *target.ThreadToken) { token.Thread.Session++ },
		func(token *target.ThreadToken) { token.Stop++ },
		func(token *target.ThreadToken) { token.Registers++ },
	} {
		controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
		change(&fixture.state.Token)
		if err := controller.showSIMD(context.Background(), "simd", ""); !errors.Is(err, target.ErrStale) || len(fixture.tokens) != 1 || fixture.snapshotReads != 1 || output.Len() != 0 {
			t.Fatalf("token mismatch error=%v output=%q", err, output.String())
		}
	}
}

func TestSIMDRequiresOptionalCapabilityAndInspectableThread(t *testing.T) {
	controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
	controller.session = fixture.contextReadFixture
	if err := controller.showSIMD(context.Background(), "simd", ""); !errors.Is(err, target.ErrUnsupported) || output.Len() != 0 {
		t.Fatalf("optional capability error=%v output=%q", err, output.String())
	}
	for _, alter := range []func(*Controller, *simdReadFixture){
		func(controller *Controller, _ *simdReadFixture) { controller.session = nil },
		func(_ *Controller, fixture *simdReadFixture) { fixture.snapshot.State = target.StateRunning },
		func(_ *Controller, fixture *simdReadFixture) { fixture.snapshot.Threads[0].Exiting = true },
		func(_ *Controller, fixture *simdReadFixture) { fixture.snapshot.Threads[0].Listening = true },
		func(controller *Controller, _ *simdReadFixture) { controller.selected.ID++ },
		func(_ *Controller, fixture *simdReadFixture) { fixture.snapshot.Architecture = target.AArch64 },
	} {
		controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
		alter(controller, fixture)
		if err := controller.showSIMD(context.Background(), "simd", ""); err == nil || len(fixture.tokens) != 0 || output.Len() != 0 {
			t.Fatalf("invalid state error=%v reads=%d output=%q", err, len(fixture.tokens), output.String())
		}
	}
}

type simdOutputWriter struct {
	writes int
	cancel context.CancelFunc
	err    error
}

func (writer *simdOutputWriter) Write(data []byte) (int, error) {
	writer.writes++
	if writer.cancel != nil {
		writer.cancel()
	}
	if writer.err != nil {
		return 0, writer.err
	}
	return len(data), nil
}

func TestSIMDCancellationBeforeReadAndDuringRead(t *testing.T) {
	controller, fixture, output := newSIMDTestController(target.ExtendedFormatXSave)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.showSIMD(ctx, "simd", ""); !errors.Is(err, context.Canceled) || fixture.snapshotReads != 0 || len(fixture.tokens) != 0 || output.Len() != 0 {
		t.Fatalf("pre-cancel error=%v output=%q", err, output.String())
	}
	if err := controller.showSIMD(nil, "simd", ""); !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	fixture.onRead, fixture.err = cancel, target.ErrStale
	err := controller.showSIMD(ctx, "simd", "")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, target.ErrStale) || fixture.snapshotReads != 1 || len(fixture.tokens) != 1 || output.Len() != 0 {
		t.Fatalf("during-read cancel error=%v output=%q", err, output.String())
	}
}

func TestSIMDOutputErrorAndCancellationStopFurtherRows(t *testing.T) {
	for _, name := range []string{"simd", "xmm", "ymm"} {
		controller, _, _ := newSIMDTestController(target.ExtendedFormatXSave)
		writer := &simdOutputWriter{err: io.ErrClosedPipe}
		controller.out = writer
		args := ""
		if name != "simd" {
			args = "0"
		}
		err := controller.showSIMD(context.Background(), name, args)
		var outputErr *OutputError
		if !errors.As(err, &outputErr) || !errors.Is(err, io.ErrClosedPipe) || writer.writes != 1 {
			t.Fatalf("%s output error=%v writes=%d", name, err, writer.writes)
		}
	}
	controller, _, _ := newSIMDTestController(target.ExtendedFormatXSave)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &simdOutputWriter{cancel: cancel}
	controller.out = writer
	if err := controller.showSIMD(ctx, "simd", ""); !errors.Is(err, context.Canceled) || writer.writes != 1 {
		t.Fatalf("output cancel error=%v writes=%d", err, writer.writes)
	}
}

func TestSIMDRenderingDoesNotMutateExtendedState(t *testing.T) {
	controller, fixture, _ := newSIMDTestController(target.ExtendedFormatXSave)
	before := fixture.state
	before.Data = bytes.Clone(before.Data)
	metadata := *before.XState
	metadata.ExtendedComponents = append([]target.XStateComponent(nil), metadata.ExtendedComponents...)
	before.XState = &metadata
	if err := controller.showSIMD(context.Background(), "simd", ""); err != nil || !reflect.DeepEqual(fixture.state, before) {
		t.Fatalf("state mutation error=%v", err)
	}
}

func TestSIMDHeadingColorsHonorRendererPolicy(t *testing.T) {
	for _, mode := range []display.ColorMode{display.ColorNever, display.ColorAlways} {
		controller, _, output := newSIMDTestController(target.ExtendedFormatXSave)
		renderer, err := display.NewRenderer(display.Options{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		controller.renderer = renderer
		if err := controller.showSIMD(context.Background(), "simd", ""); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "\x1b[") != (mode == display.ColorAlways) {
			t.Fatalf("mode=%v output=%q", mode, output.String())
		}
	}
}
