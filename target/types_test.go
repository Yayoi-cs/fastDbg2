package target_test

import (
	"testing"

	"fastdbg2/target"
)

func TestUnknownValues(t *testing.T) {
	var state target.State
	var byteOrder target.ByteOrder
	var stop target.Stop
	var register target.Register
	if state != target.StateUnknown || stop.Reason != target.StopUnknown {
		t.Fatal("zero values must not imply an observed state or stop reason")
	}
	if stop.ThreadID != nil || stop.RawPC != nil || stop.ExitCode != nil || stop.Breakpoint != nil {
		t.Fatal("zero stop must not invent observed values")
	}
	if register.Available || register.Data != nil {
		t.Fatal("zero register must not imply available data")
	}
	if byteOrder != target.ByteOrderUnknown {
		t.Fatal("zero byte order must not imply a byte encoding")
	}
}

func TestArchitectureIdentifiers(t *testing.T) {
	if target.X86 != "x86" || target.AMD64 != "amd64" || target.AArch64 != "aarch64" {
		t.Fatal("architecture identifiers changed")
	}
	if target.X86 == target.AMD64 || target.X86 == target.Architecture("i386") || target.X86 == target.Architecture("x32") {
		t.Fatal("32-bit x86 must remain distinct from AMD64, x32, and alternate names")
	}
	if target.AArch64 == target.Architecture("arm") || target.AArch64 == target.Architecture("arm64") {
		t.Fatal("different architecture names must not become implicit aliases")
	}
}

func TestByteOrderString(t *testing.T) {
	for _, test := range []struct {
		order target.ByteOrder
		want  string
	}{
		{target.ByteOrderUnknown, "unknown"},
		{target.LittleEndian, "little-endian"},
		{target.BigEndian, "big-endian"},
		{target.ByteOrder(255), "unknown"},
	} {
		t.Run(test.want, func(t *testing.T) {
			if got := test.order.String(); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestStateString(t *testing.T) {
	for _, test := range []struct {
		state target.State
		want  string
	}{
		{target.StateUnknown, "unknown"},
		{target.StateStopped, "stopped"},
		{target.StateRunning, "running"},
		{target.StateExited, "exited"},
		{target.StateDetached, "detached"},
		{target.StateClosed, "closed"},
		{target.State(255), "unknown"},
	} {
		t.Run(test.want, func(t *testing.T) {
			if got := test.state.String(); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestStopReasonString(t *testing.T) {
	for _, test := range []struct {
		reason target.StopReason
		want   string
	}{
		{target.StopUnknown, "unknown"},
		{target.StopSignal, "signal"},
		{target.StopBreakpoint, "breakpoint"},
		{target.StopStep, "step"},
		{target.StopInterrupt, "interrupt"},
		{target.StopExited, "exited"},
		{target.StopSignaled, "signaled"},
		{target.StopExec, "exec"},
		{target.StopClone, "clone"},
		{target.StopFork, "fork"},
		{target.StopVFork, "vfork"},
		{target.StopAttach, "attach"},
		{target.StopReason(255), "unknown"},
	} {
		t.Run(test.want, func(t *testing.T) {
			if got := test.reason.String(); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestSignalDomainsRemainDistinct(t *testing.T) {
	linux := target.Signal{Domain: target.SignalLinux, Number: 7}
	gdb := target.Signal{Domain: target.SignalGDB, Number: 7}
	if linux == gdb {
		t.Fatal("equal numbers in different signal domains must remain distinct")
	}
	if (target.Signal{}) != (target.Signal{Domain: target.SignalNone}) {
		t.Fatal("zero signal must represent an explicit no-signal request")
	}
}
