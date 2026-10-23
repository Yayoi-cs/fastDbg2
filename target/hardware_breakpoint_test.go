package target_test

import (
	"reflect"
	"testing"

	"fastdbg2/target"
)

func TestHardwareBreakpointReferencesPreserveKindAndLifetime(t *testing.T) {
	if reflect.TypeOf(target.HardwareBreakpointRef{}) == reflect.TypeOf(target.WatchpointRef{}) {
		t.Fatal("execution and data breakpoint references must remain distinct")
	}
	ref := target.HardwareBreakpointRef{Thread: target.ThreadRef{Session: 4, ID: 5}, Slot: 2, Generation: 8}
	others := []target.HardwareBreakpointRef{ref, ref, ref, ref}
	others[0].Thread.Session++
	others[1].Thread.ID++
	others[2].Slot++
	others[3].Generation++
	for _, other := range others {
		if ref == other {
			t.Fatalf("hardware breakpoint identity collided: %+v", other)
		}
	}
}

func TestHardwareBreakpointStopIsDistinct(t *testing.T) {
	if target.StopHardwareBreakpoint.String() != "hardware-breakpoint" || target.StopBreakpoint.String() != "breakpoint" || target.StopWatchpoint.String() != "watchpoint" {
		t.Fatal("hardware execution, software, and data breakpoints must remain distinct")
	}
	var stop target.Stop
	if stop.HardwareBreakpoints != nil {
		t.Fatal("zero stop must not invent a hardware breakpoint hit")
	}
}
