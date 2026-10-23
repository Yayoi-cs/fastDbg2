package target_test

import (
	"testing"

	"fastdbg2/target"
)

func TestExtendedRegisterFormatNames(t *testing.T) {
	for _, test := range []struct {
		format target.ExtendedRegisterFormat
		want   string
	}{
		{target.ExtendedFormatUnknown, "unknown"},
		{target.ExtendedFormatXSave, "linux-x86-xsave-standard"},
		{target.ExtendedFormatFXSave, "linux-x86-fxsave"},
		{target.ExtendedRegisterFormat(255), "unknown"},
	} {
		if got := test.format.String(); got != test.want {
			t.Fatalf("format %d: got %q, want %q", test.format, got, test.want)
		}
	}
}

func TestExtendedRegisterZeroStateDoesNotInventAvailability(t *testing.T) {
	var state target.ExtendedRegisterState
	if state.Format != target.ExtendedFormatUnknown || state.Data != nil || state.XState != nil || state.Token != (target.ThreadToken{}) {
		t.Fatal("zero state must not invent a format, register bytes, or xstate observations")
	}
	info := target.XStateInfo{KernelFeatures: 0x207, Present: 7}
	if info.KernelFeatures == info.Present {
		t.Fatal("kernel feature mask and present state must remain independently represented")
	}
}
