package native

import (
	"testing"

	"fastdbg2/target"
)

func extendedCopyTestState() target.ExtendedRegisterState {
	data := make([]byte, 2696)
	data[100] = 17
	return target.ExtendedRegisterState{
		Token:        target.ThreadToken{Thread: target.ThreadRef{Session: 4, ID: 5}, Stop: 6, Registers: 7},
		Architecture: target.AMD64, Format: target.ExtendedFormatXSave, Data: data,
		XState: &target.XStateInfo{
			KernelFeatures: 0x207, Present: 7,
			ExtendedComponents: []target.XStateComponent{{ID: 2, Offset: 576, Size: 256}, {ID: 9, Offset: 2688, Size: 8}},
		},
	}
}

func TestCopyExtendedRegisterStatePreservesIndependentBytesAndMetadata(t *testing.T) {
	input := extendedCopyTestState()
	first, second := copyExtendedRegisterState(input), copyExtendedRegisterState(input)
	input.Data[100] = 0
	input.XState.KernelFeatures = 0
	input.XState.ExtendedComponents[0].Size = 0
	for _, value := range []target.ExtendedRegisterState{first, second} {
		if value.Data[100] != 17 || value.XState.KernelFeatures != 0x207 || value.XState.ExtendedComponents[0].Size != 256 {
			t.Fatalf("copy retained input state: %+v", value.XState)
		}
	}
	first.Data[100] = 3
	first.XState.Present = 0
	first.XState.ExtendedComponents[1].Offset = 0
	if second.Data[100] != 17 || second.XState.Present != 7 || second.XState.ExtendedComponents[1].Offset != 2688 {
		t.Fatal("one consumer changed another consumer's extended register state")
	}
	zero := copyExtendedRegisterState(target.ExtendedRegisterState{})
	if zero.Data != nil || zero.XState != nil {
		t.Fatal("copy invented unavailable bytes or metadata")
	}
	fxsave := copyExtendedRegisterState(target.ExtendedRegisterState{Format: target.ExtendedFormatFXSave, Data: make([]byte, 512)})
	if fxsave.XState != nil || len(fxsave.Data) != 512 {
		t.Fatal("FXSAVE copy invented XSAVE metadata")
	}
}

func TestCopyExtendedRegisterStateAllowsIndependentConcurrentConsumers(t *testing.T) {
	input := extendedCopyTestState()
	const count = 16
	results := make(chan bool, count)
	for range count {
		go func() {
			value := copyExtendedRegisterState(input)
			valid := value.Data[100] == 17 && value.XState.KernelFeatures == 0x207 && value.XState.ExtendedComponents[0].Offset == 576
			value.Data[100] = 0
			value.XState.KernelFeatures = 0
			value.XState.ExtendedComponents[0].Offset = 0
			results <- valid
		}()
	}
	for range count {
		if !<-results {
			t.Fatal("concurrent consumers shared extended register buffers")
		}
	}
	if input.Data[100] != 17 || input.XState.KernelFeatures != 0x207 || input.XState.ExtendedComponents[0].Offset != 576 {
		t.Fatal("a consumer changed the source extended register state")
	}
}
