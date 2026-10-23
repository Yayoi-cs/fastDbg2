package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func legacyBreakpointImage(t *testing.T, c *Controller, s *controllerTestSession, kind elf.Type, entry, actual uint64) uint64 {
	t.Helper()
	bias, err := imageLoadBias(kind, entry, imageTestAuxv(9, actual, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	c.image = imageState{space: s.snapshot.Memory.Space, image: &loadedImage{loadBias: bias}}
	return bias
}

func TestLegacyBreakpointPIEUsesExactLoadBias(t *testing.T) {
	for _, test := range []struct {
		name   string
		kind   elf.Type
		entry  uint64
		actual uint64
		offset string
		want   target.Address
	}{
		{"PIE", elf.ET_DYN, 0x1234, 0x701234, "0x1000 + 0x27", 0x701027},
		{"ET_EXEC", elf.ET_EXEC, 0x401234, 0x401234, "0x401000 + 0x27", 0x401027},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			c, s := runningController(t, &output)
			legacyBreakpointImage(t, c, s, test.kind, test.entry, test.actual)
			executeController(t, c, "break", "pie "+test.offset)
			bp := c.breakpoints[0]
			if bp.kind != breakpointPIE || bp.expression != test.offset || bp.address != test.want || !bp.installed || !reflect.DeepEqual(s.added, []target.Address{test.want}) {
				t.Fatalf("bp=%+v added=%v want=%#x", bp, s.added, test.want)
			}
			if !strings.Contains(output.String(), fmt.Sprintf("address=%#x expression=%q kind=pie", test.want, test.offset)) {
				t.Fatalf("relative kind missing from install output: %q", output.String())
			}
			output.Reset()
			executeController(t, c, "break", "l")
			if !uiBreakpointRowMatches(output.String(), bp.id, true, fmt.Sprintf("0x%016x", test.want), "installed", test.offset, true) {
				t.Fatalf("relative kind missing from list: %q", output.String())
			}
		})
	}
}

func TestLegacyBreakpointPIEReadsLiveMainImage(t *testing.T) {
	c, s := runningController(t, io.Discard)
	s.snapshot.Threads[0].TID = os.Getpid()
	file, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		t.Fatal(err)
	}
	bias, err := imageLoadBias(file.Type, file.Entry, auxv)
	if err != nil {
		t.Fatal(err)
	}
	executeController(t, c, "break", "pie 0x20")
	if !reflect.DeepEqual(s.added, []target.Address{target.Address(bias + 0x20)}) || c.image.space != s.snapshot.Memory.Space || c.image.image == nil || c.image.image.loadBias != bias {
		t.Fatalf("added=%v image=%+v bias=%#x", s.added, c.image, bias)
	}
}

func TestLegacyBreakpointPIEPendingDisabledAndRestart(t *testing.T) {
	var output bytes.Buffer
	c := configuredController(t, &output)
	var sessions []*controllerTestSession
	var biases []uint64
	c.launch = func(string, []string) (session, error) {
		s := controllerSession(uint64(len(sessions) + 1))
		sessions = append(sessions, s)
		bias := legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, uint64(len(sessions))*0x100000+0x1000)
		biases = append(biases, bias)
		return s, nil
	}
	expression := "$rip - 0x400000"
	executeController(t, c, "break", "pie "+expression)
	executeController(t, c, "break", "pie 1 +")
	executeController(t, c, "disable", "2")
	if !strings.Contains(output.String(), fmt.Sprintf("pending expression=%q kind=pie", expression)) {
		t.Fatalf("pending relative kind absent: %q", output.String())
	}
	executeController(t, c, "start", "")
	first := c.breakpoints[0].address
	if first != target.Address(biases[0]+sessions[0].pc-0x400000) || len(sessions[0].added) != 1 || c.breakpoints[1].err != nil {
		t.Fatalf("first=%#x added=%v disabled=%+v", first, sessions[0].added, c.breakpoints[1])
	}
	executeController(t, c, "disable", "1")
	executeController(t, c, "run", "")
	if len(sessions[1].added) != 0 || sessions[1].runCalls != 1 {
		t.Fatalf("disabled relative breakpoint blocked run: %+v", sessions[1])
	}
	for _, bp := range c.breakpoints {
		if bp.kind != breakpointPIE || bp.enabled || bp.attempted || bp.installed || bp.address != 0 {
			t.Fatalf("disabled relative state changed after restart: %+v", bp)
		}
	}
	executeController(t, c, "enable", "1")
	executeController(t, c, "start", "")
	want := target.Address(biases[2] + sessions[2].pc - 0x400000)
	bp := c.breakpoints[0]
	if bp.kind != breakpointPIE || bp.expression != expression || bp.address != want || bp.address == first || !reflect.DeepEqual(sessions[2].added, []target.Address{want}) {
		t.Fatalf("restarted bp=%+v added=%v want=%#x first=%#x", bp, sessions[2].added, want, first)
	}
}

func TestLegacyBreakpointPIEEnableReevaluatesOffset(t *testing.T) {
	c, s := runningController(t, io.Discard)
	bias := legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x501000)
	executeController(t, c, "break", "pie $rip - 0x400000")
	first := c.breakpoints[0].address
	executeController(t, c, "disable", "1")
	s.pc += 0x100
	executeController(t, c, "enable", "1")
	want := target.Address(bias + s.pc - 0x400000)
	if c.breakpoints[0].address != want || first == want || !reflect.DeepEqual(s.removed, []target.Address{first}) || !reflect.DeepEqual(s.added, []target.Address{first, want}) {
		t.Fatalf("bp=%+v added=%v removed=%v", c.breakpoints[0], s.added, s.removed)
	}
}

func TestLegacyBreakpointPIEAndAbsoluteDuplicateAddress(t *testing.T) {
	for _, relativeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(relativeFirst), func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x501000)
			first, second := "0x501020", "pie 0x1020"
			if relativeFirst {
				first, second = second, first
			}
			executeController(t, c, "break", first)
			_, err := c.Execute(context.Background(), "break", second)
			if !errors.Is(err, target.ErrInvalidArgument) || len(s.added) != 1 || len(c.breakpoints) != 2 || !c.breakpoints[0].installed || c.breakpoints[1].attempted || c.breakpoints[1].installed {
				t.Fatalf("err=%v added=%v breakpoints=%v", err, s.added, c.breakpoints)
			}
			executeController(t, c, "disable", "1")
			executeController(t, c, "enable", "2")
			if !c.breakpoints[1].installed || c.breakpoints[1].address != 0x501020 || len(s.added) != 2 || len(s.removed) != 1 {
				t.Fatalf("retry bp=%+v added=%v removed=%v", c.breakpoints[1], s.added, s.removed)
			}
		})
	}
}

func TestLegacyBreakpointPIECheckedAdditionAndExpressionErrors(t *testing.T) {
	for _, test := range []struct {
		bias uint64
		expr string
		want target.Address
		err  error
	}{
		{0, "0xffffffffffffffff", math.MaxUint64, nil},
		{math.MaxUint64, "0", math.MaxUint64, nil},
		{math.MaxUint64 - 1, "1", math.MaxUint64, nil},
		{1, "0xffffffffffffffff", 0, target.ErrOverflow},
		{math.MaxUint64, "1", 0, target.ErrOverflow},
		{0x500000, "0xffffffffffffffff + 1", 0, target.ErrOverflow},
		{0x500000, "1 - 2", 0, target.ErrOverflow},
		{0x500000, "-1", 0, target.ErrInvalidArgument},
		{0x500000, "1 +", 0, target.ErrInvalidArgument},
	} {
		t.Run(fmt.Sprintf("%x/%s", test.bias, test.expr), func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			legacyBreakpointImage(t, c, s, elf.ET_DYN, 0, test.bias)
			bp := &breakpoint{expression: test.expr, kind: breakpointPIE, enabled: true}
			got, err := c.breakpointAddress(context.Background(), bp, s.snapshot, s.snapshot.Threads[0])
			if got != test.want || !errors.Is(err, test.err) || len(s.added) != 0 {
				t.Fatalf("got=%#x err=%v want=%#x %v added=%v", got, err, test.want, test.err, s.added)
			}
			if test.err != nil {
				_, err = c.Execute(context.Background(), "break", "pie "+test.expr)
				if !errors.Is(err, test.err) || len(s.added) != 0 || c.breakpoints[0].attempted || c.breakpoints[0].installed || c.breakpoints[0].address != 0 {
					t.Fatalf("invalid offset mutated target: err=%v added=%v bp=%+v", err, s.added, c.breakpoints[0])
				}
			}
		})
	}
}

func TestLegacyBreakpointPIERequiresCurrentValidImage(t *testing.T) {
	for _, staleCache := range []bool{false, true} {
		t.Run(fmt.Sprint(staleCache), func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			s.snapshot.Threads[0].TID = math.MaxInt
			if staleCache {
				legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x501000)
				c.image.space.ID++
			}
			_, err := c.Execute(context.Background(), "break", "pie 0x1020")
			if !errors.Is(err, os.ErrNotExist) || len(s.added) != 0 || c.breakpoints[0].attempted || c.breakpoints[0].address != 0 || c.image.image != nil || c.image.space != (target.SpaceRef{}) {
				t.Fatalf("missing main image used cached bias: err=%v added=%v bp=%+v image=%+v", err, s.added, c.breakpoints[0], c.image)
			}
		})
	}
	c, s := runningController(t, io.Discard)
	legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x501000)
	s.snapshot.Memory.Revision = 0
	_, err := c.Execute(context.Background(), "break", "pie 0x1020")
	if !errors.Is(err, target.ErrUnavailable) || len(s.added) != 0 || c.breakpoints[0].attempted {
		t.Fatalf("invalid image snapshot accepted: err=%v added=%v bp=%+v", err, s.added, c.breakpoints[0])
	}
}

func TestLegacyBreakpointPIEImageChangeDoesNotReuseOldAddress(t *testing.T) {
	c, s := runningController(t, io.Discard)
	legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x501000)
	executeController(t, c, "break", "pie 0x1020")
	first := c.breakpoints[0].address
	s.snapshot.Memory.Space.ID++
	s.snapshot.Threads[0].TID = math.MaxInt
	_, err := c.Execute(context.Background(), "enable", "1")
	bp := c.breakpoints[0]
	if !errors.Is(err, os.ErrNotExist) || bp.kind != breakpointPIE || bp.expression != "0x1020" || !bp.enabled || bp.attempted || bp.address != 0 || len(s.removed) != 0 || len(s.added) != 1 {
		t.Fatalf("changed image reused old address: err=%v bp=%+v added=%v removed=%v", err, bp, s.added, s.removed)
	}
	legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x901000)
	executeController(t, c, "enable", "1")
	if bp.address != 0x901020 || bp.address == first || !bp.installed || !reflect.DeepEqual(s.added, []target.Address{first, 0x901020}) || len(s.removed) != 0 {
		t.Fatalf("new image installation=%+v added=%v removed=%v", bp, s.added, s.removed)
	}
}

func TestLegacyBreakpointPIEPartialCleanupRetainsOriginalRuntimeAddress(t *testing.T) {
	c, s := runningController(t, io.Discard)
	bias := legacyBreakpointImage(t, c, s, elf.ET_DYN, 0x1000, 0x501000)
	s.addError = target.ErrPartial
	_, err := c.Execute(context.Background(), "break", "pie $rip - 0x400000")
	bp := c.breakpoints[0]
	first := bp.address
	if !errors.Is(err, target.ErrPartial) || !bp.attempted || bp.installed || bp.kind != breakpointPIE {
		t.Fatalf("partial add err=%v bp=%+v", err, bp)
	}
	s.pc += 0x1000
	s.addError, s.removeError = nil, target.ErrPartial
	_, err = c.Execute(context.Background(), "enable", "1")
	if !errors.Is(err, target.ErrPartial) || bp.address != first || !bp.attempted || len(s.added) != 1 || !reflect.DeepEqual(s.removed, []target.Address{first}) {
		t.Fatalf("cleanup failed at wrong address: err=%v bp=%+v added=%v removed=%v", err, bp, s.added, s.removed)
	}
	s.removeError = nil
	executeController(t, c, "enable", "1")
	want := target.Address(bias + s.pc - 0x400000)
	if bp.address != want || bp.address == first || !bp.installed || bp.kind != breakpointPIE || !reflect.DeepEqual(s.added, []target.Address{first, want}) || !reflect.DeepEqual(s.removed, []target.Address{first, first}) {
		t.Fatalf("retry did not preserve relative spec: bp=%+v added=%v removed=%v", bp, s.added, s.removed)
	}
}

func TestLegacyBreakpointPIEArgumentAndIDContracts(t *testing.T) {
	c := New(io.Discard, display.Renderer{})
	for _, arguments := range []string{"pie", "pie   "} {
		if _, err := c.Execute(context.Background(), "break", arguments); !errors.Is(err, target.ErrInvalidArgument) || len(c.breakpoints) != 0 {
			t.Fatalf("missing offset: err=%v breakpoints=%v", err, c.breakpoints)
		}
	}
	executeController(t, c, "break", "pie 0x1020")
	if _, err := c.Execute(context.Background(), "disable", "0x1020"); !errors.Is(err, target.ErrInvalidArgument) || !c.breakpoints[0].enabled {
		t.Fatalf("address fallback changed relative breakpoint: err=%v bp=%+v", err, c.breakpoints[0])
	}
	executeController(t, c, "disable", "1")
	if c.breakpoints[0].enabled || c.breakpoints[0].kind != breakpointPIE {
		t.Fatalf("ID disable changed relative kind: %+v", c.breakpoints[0])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.addPIEBreakpoint(ctx, "0x1020"); !errors.Is(err, context.Canceled) || len(c.breakpoints) != 1 {
		t.Fatalf("canceled add created breakpoint: err=%v breakpoints=%v", err, c.breakpoints)
	}
}
