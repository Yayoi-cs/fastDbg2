package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/native"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

type independentLoaderSession struct {
	*controllerTestSession
	locations   map[target.ThreadRef]native.CodeLocation
	locationErr error
}

func (s *independentLoaderSession) ReadCodeLocation(token target.ThreadToken) (native.CodeLocation, error) {
	return s.locations[token.Thread], s.locationErr
}

func independentLoaderController() (*Controller, *independentLoaderSession, *bytes.Buffer) {
	s := &independentLoaderSession{controllerTestSession: controllerSession(70), locations: make(map[target.ThreadRef]native.CodeLocation)}
	var out bytes.Buffer
	c := &Controller{session: s, selected: s.snapshot.Threads[0].Ref, out: &out, contextDisabled: true}
	return c, s, &out
}

func independentLoaderPending() *breakpoint {
	return &breakpoint{id: 999, expression: "malloc", enabled: true, err: &symbolPendingError{Name: "malloc", Err: &runtimeLoaderPendingError{}}}
}

func TestIndependentLoaderSharedPhysicalOwnership(t *testing.T) {
	for _, first := range []string{"loader", "user"} {
		for _, release := range []string{"loader", "user"} {
			t.Run(first+"/"+release, func(t *testing.T) {
				c, s, _ := independentLoaderController()
				info := loaderRendezvousInfo{Space: s.snapshot.Memory.Space, Hook: 0x5000}
				ctx := context.Background()
				if first == "loader" {
					if err := c.armLoaderBreakpoint(info); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.addBreakpoint(ctx, "0x5000"); err != nil {
					t.Fatal(err)
				}
				bp := c.breakpoints[0]
				if first == "user" {
					if err := c.armLoaderBreakpoint(info); err != nil {
						t.Fatal(err)
					}
				}
				if len(s.added) != 1 || !bp.installed || c.loaderBreakpoint == nil {
					t.Fatalf("duplicate installation: adds=%v bp=%+v internal=%+v", s.added, bp, c.loaderBreakpoint)
				}
				if release == "loader" {
					if err := c.removeLoaderBreakpoint(); err != nil {
						t.Fatal(err)
					}
					if len(s.removed) != 0 || !bp.installed || c.loaderBreakpoint != nil {
						t.Fatal("physical removal while user owns")
					}
					if done, err := c.uninstallBreakpoint(bp); !done || err != nil {
						t.Fatalf("done=%t err=%v", done, err)
					}
				} else {
					if done, err := c.uninstallBreakpoint(bp); !done || err != nil {
						t.Fatalf("done=%t err=%v", done, err)
					}
					if len(s.removed) != 0 || bp.attempted || c.loaderBreakpoint == nil {
						t.Fatal("physical removal while internal owns")
					}
					if err := c.removeLoaderBreakpoint(); err != nil {
						t.Fatal(err)
					}
				}
				if len(s.removed) != 1 || s.removed[0] != 0x5000 || c.loaderBreakpoint != nil {
					t.Fatalf("removes=%v internal=%+v", s.removed, c.loaderBreakpoint)
				}
			})
		}
	}
}

func TestIndependentLoaderPartialInstallRetainedAndNotShared(t *testing.T) {
	c, s, _ := independentLoaderController()
	s.addError = &target.PartialError{Op: "add", Completed: 1, Total: 2, Err: io.ErrUnexpectedEOF}
	info := loaderRendezvousInfo{Space: s.snapshot.Memory.Space, Hook: 0x5000}
	if err := c.armLoaderBreakpoint(info); !errors.Is(err, target.ErrPartial) {
		t.Fatal(err)
	}
	state := c.loaderBreakpoint
	if state == nil || !state.attempted || state.installed || state.err == nil {
		t.Fatalf("lost partial install %+v", state)
	}
	if err := c.addBreakpoint(context.Background(), "0x5000"); !errors.Is(err, target.ErrBusy) || c.breakpoints[0].attempted || len(s.added) != 1 {
		t.Fatalf("shared unconfirmed installation err=%v bp=%+v adds=%v", err, c.breakpoints[0], s.added)
	}
	s.removeError = target.ErrNotFound
	if err := c.removeLoaderBreakpoint(); err != nil || c.loaderBreakpoint != nil || len(s.removed) != 1 {
		t.Fatalf("unconfirmed absent cleanup err=%v internal=%+v removed=%v", err, c.loaderBreakpoint, s.removed)
	}
}

func TestIndependentLoaderPartialRemoveRetainsExactOwnerForRetry(t *testing.T) {
	c, s, _ := independentLoaderController()
	info := loaderRendezvousInfo{Space: s.snapshot.Memory.Space, Hook: 0x5000}
	if err := c.armLoaderBreakpoint(info); err != nil {
		t.Fatal(err)
	}
	state := c.loaderBreakpoint
	s.removeError = &target.PartialError{Op: "remove", Completed: 1, Total: 2, Err: io.ErrUnexpectedEOF}
	if err := c.removeLoaderBreakpoint(); !errors.Is(err, target.ErrPartial) || c.loaderBreakpoint != state || state.err == nil {
		t.Fatalf("error=%v internal=%+v", err, c.loaderBreakpoint)
	}
	if err := c.addBreakpoint(context.Background(), "0x5000"); !errors.Is(err, target.ErrBusy) || len(s.added) != 1 {
		t.Fatalf("unconfirmed owner replaced err=%v adds=%v", err, s.added)
	}
	s.removeError = nil
	if err := c.removeLoaderBreakpoint(); err != nil || c.loaderBreakpoint != nil || len(s.removed) != 2 {
		t.Fatalf("retry failed err=%v removes=%v", err, s.removed)
	}
}

func TestIndependentLoaderLastPendingDeleteDisableRetriesCleanup(t *testing.T) {
	for _, action := range []string{"delete", "disable"} {
		t.Run(action, func(t *testing.T) {
			c, s, _ := independentLoaderController()
			info := loaderRendezvousInfo{Space: s.snapshot.Memory.Space, Hook: 0x5000}
			if err := c.armLoaderBreakpoint(info); err != nil {
				t.Fatal(err)
			}
			c.breakpoints = []*breakpoint{independentLoaderPending()}
			s.removeError = io.ErrUnexpectedEOF
			var err error
			if action == "delete" {
				err = c.deleteBreakpoints(context.Background(), "all")
			} else {
				err = c.setBreakpointsEnabled(context.Background(), "999", false)
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) || c.hasPendingBreakpoints() || c.loaderBreakpoint == nil {
				t.Fatalf("state lost err=%v internal=%+v", err, c.loaderBreakpoint)
			}
			s.removeError = nil
			if action == "delete" {
				err = c.deleteBreakpoints(context.Background(), "all")
			} else {
				err = c.setBreakpointsEnabled(context.Background(), "999", false)
			}
			if err != nil || c.loaderBreakpoint != nil || len(s.removed) != 2 {
				t.Fatalf("cleanup retry err=%v removed=%v internal=%+v", err, s.removed, c.loaderBreakpoint)
			}
		})
	}
}

func TestIndependentLoaderExecCloseAndDetachedOwnership(t *testing.T) {
	for _, action := range []string{"exec", "exit", "close-failure", "detach"} {
		t.Run(action, func(t *testing.T) {
			c, s, _ := independentLoaderController()
			if err := c.armLoaderBreakpoint(loaderRendezvousInfo{Space: s.snapshot.Memory.Space, Hook: 0x5000}); err != nil {
				t.Fatal(err)
			}
			if err := c.addBreakpoint(context.Background(), "0x5000"); err != nil {
				t.Fatal(err)
			}
			bp, state := c.breakpoints[0], c.loaderBreakpoint
			switch action {
			case "exec":
				s.snapshot.Memory.Space.ID++
				_, _ = c.refresh()
			case "exit":
				s.snapshot.State = target.StateExited
				_, _ = c.refresh()
			case "detach":
				if err := c.releaseTarget(false); err != nil {
					t.Fatal(err)
				}
			case "close-failure":
				s.closeError = io.ErrUnexpectedEOF
				if err := c.Close(); !errors.Is(err, io.ErrUnexpectedEOF) || c.loaderBreakpoint != state || !bp.installed || c.session == nil {
					t.Fatalf("failed Close lost ownership: %v", err)
				}
				s.closeError = nil
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if c.loaderBreakpoint != nil || bp.attempted || bp.installed || len(s.removed) != 0 {
				t.Fatalf("stale physical cleanup or retained old ownership: %+v %+v removes=%v", c.loaderBreakpoint, bp, s.removed)
			}
		})
	}
}

func independentLoaderStopFixture() (*Controller, *independentLoaderSession, target.Snapshot, target.RunResult) {
	c, s, _ := independentLoaderController()
	peer := s.snapshot.Threads[0]
	peer.Ref.ID = 2
	peer.Token.Thread = peer.Ref
	peer.TID++
	s.snapshot.Threads = append(s.snapshot.Threads, peer)
	before := s.snapshot
	before.Threads = slices.Clone(before.Threads)
	address, raw := target.Address(0x5000), target.Address(0x5001)
	primary := &s.snapshot.Threads[0]
	primary.Token.Stop++
	primary.Token.Registers++
	primary.Stop = target.Stop{Reason: target.StopBreakpoint, Breakpoint: &address, RawPC: &raw, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGTRAP)}}
	peerp := &s.snapshot.Threads[1]
	peerp.Token.Stop++
	peerp.Token.Registers++
	peerp.Stop = target.Stop{Reason: target.StopInterrupt}
	s.locations[primary.Ref] = native.CodeLocation{RawPC: raw, InstructionPC: address, Breakpoint: &address}
	s.locations[peerp.Ref] = native.CodeLocation{RawPC: raw, InstructionPC: address, Breakpoint: &address}
	c.loaderBreakpoint = &loaderBreakpointState{space: s.snapshot.Memory.Space, address: address, installed: true, attempted: true}
	result := target.RunResult{Thread: primary.Ref, Token: primary.Token, Stop: primary.Stop, Sequence: s.snapshot.Sequence}
	return c, s, before, result
}

func TestIndependentLoaderOnlyInternalStopsEligible(t *testing.T) {
	for _, mode := range []string{"internal", "second-internal", "unchanged-peer", "step-result", "watch-result", "hardware-result", "signal-result", "stale-token", "raw-mismatch", "location-mismatch", "snapshot-step", "peer-signal", "peer-step", "peer-watch", "peer-hardware", "peer-clone", "peer-exiting", "peer-listening", "peer-groupstop", "added-thread", "removed-thread", "space-change", "result-signal-contradiction", "interrupt-signal-contradiction"} {
		t.Run(mode, func(t *testing.T) {
			c, s, before, result := independentLoaderStopFixture()
			want := mode == "internal" || mode == "second-internal" || mode == "unchanged-peer"
			switch mode {
			case "second-internal":
				s.snapshot.Threads[1].Stop = s.snapshot.Threads[0].Stop
			case "unchanged-peer":
				s.snapshot.Threads[1] = before.Threads[1]
			case "step-result":
				result.Stop.StepCompleted = true
			case "watch-result":
				result.Stop.Watchpoints = []target.WatchpointHit{{}}
			case "hardware-result":
				result.Stop.HardwareBreakpoints = []target.HardwareBreakpointHit{{}}
			case "signal-result":
				result.Stop.Reason = target.StopSignal
			case "stale-token":
				result.Token.Registers++
			case "raw-mismatch":
				p := target.Address(0x5002)
				result.Stop.RawPC = &p
			case "location-mismatch":
				s.locations[result.Thread] = native.CodeLocation{RawPC: 0x5001, InstructionPC: 0x5001}
			case "snapshot-step":
				s.snapshot.Threads[0].Stop.StepCompleted = true
			case "peer-signal":
				s.snapshot.Threads[1].Stop.Reason = target.StopSignal
			case "peer-step":
				s.snapshot.Threads[1].Stop.StepCompleted = true
			case "peer-watch":
				s.snapshot.Threads[1].Stop.Watchpoints = []target.WatchpointHit{{}}
			case "peer-hardware":
				s.snapshot.Threads[1].Stop.HardwareBreakpoints = []target.HardwareBreakpointHit{{}}
			case "peer-clone":
				s.snapshot.Threads[1].Stop.Reason = target.StopClone
			case "peer-exiting":
				s.snapshot.Threads[1].Exiting = true
			case "peer-listening":
				s.snapshot.Threads[1].Listening = true
			case "peer-groupstop":
				s.snapshot.Threads[1].GroupStopped = true
			case "added-thread":
				newThread := s.snapshot.Threads[1]
				newThread.Ref.ID = 3
				s.snapshot.Threads = append(s.snapshot.Threads, newThread)
			case "removed-thread":
				s.snapshot.Threads = s.snapshot.Threads[:1]
			case "space-change":
				s.snapshot.Memory.Space.ID++
			case "result-signal-contradiction":
				result.Stop.Signal.Number = uint32(unix.SIGUSR1)
			case "interrupt-signal-contradiction":
				s.snapshot.Threads[1].Stop.Signal = target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}
			}
			matched, err := c.loaderStopMatches(before, result)
			if err != nil || matched != want {
				t.Fatalf("matched=%t want=%t err=%v", matched, want, err)
			}
		})
	}
}

func TestIndependentLoaderLocationStaleIsNotConsumed(t *testing.T) {
	c, s, before, result := independentLoaderStopFixture()
	s.locationErr = target.ErrStale
	if matched, err := c.loaderStopMatches(before, result); matched || !errors.Is(err, target.ErrStale) {
		t.Fatalf("matched=%t err=%v", matched, err)
	}
}

func TestIndependentLoaderNativeSharedHookThenPendingMallocFree(t *testing.T) {
	for _, pie := range []bool{false, true} {
		for _, action := range []string{"disable", "delete"} {
			t.Run(fmt.Sprintf("pie_%t/%s", pie, action), func(t *testing.T) {
				dir := loaderBreakpointReviewDirectory(t)
				source, path := filepath.Join(dir, "probe.c"), filepath.Join(dir, "probe")
				if err := os.WriteFile(source, []byte(loaderRendezvousConstructorSource), 0600); err != nil {
					t.Fatal(err)
				}
				flags := []string{"-O0", "-g", "-fno-builtin", "-fcf-protection=none", "-fno-pie", "-no-pie"}
				if pie {
					flags[len(flags)-2], flags[len(flags)-1] = "-fPIE", "-pie"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, "cc", append(flags, "-o", path, source)...)
				command.Env = append(os.Environ(), "TMPDIR="+dir)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("compile %v %s", err, output)
				}
				var output bytes.Buffer
				c := New(&output, display.Renderer{})
				c.contextDisabled = true
				t.Cleanup(func() {
					if err := c.Close(); err != nil {
						t.Error(err)
					}
				})
				if err := c.Configure(path, nil); err != nil {
					t.Fatal(err)
				}
				if err := c.start(ctx, "", false); err != nil {
					t.Fatal(err)
				}
				snapshot, thread, err := c.stopped()
				if err != nil {
					t.Fatal(err)
				}
				info, err := c.loaderRendezvous(ctx, snapshot, thread)
				if err != nil {
					t.Fatal(err)
				}
				if err := c.addBreakpoint(ctx, fmt.Sprintf("%#x", info.Hook)); err != nil {
					t.Fatal(err)
				}
				userID := c.breakpoints[0].id
				for _, name := range []string{"malloc", "free"} {
					if err := c.addBreakpoint(ctx, name); err != nil {
						t.Fatal(err)
					}
				}
				if !c.hasPendingBreakpoints() {
					t.Fatalf("initial symbols not pending: %s", output.String())
				}
				if err := c.resume(ctx, "", false); err != nil {
					t.Fatalf("first hook stop %v %s", err, output.String())
				}
				if c.session.LastStop().Breakpoint == nil || *c.session.LastStop().Breakpoint != info.Hook || c.loaderBreakpoint == nil || !c.hasPendingBreakpoints() {
					t.Fatalf("shared hook was swallowed %s", output.String())
				}
				if action == "disable" {
					err = c.setBreakpointsEnabled(ctx, fmt.Sprint(userID), false)
				} else {
					err = c.deleteBreakpoints(ctx, fmt.Sprint(userID))
				}
				if err != nil || c.loaderBreakpoint == nil {
					t.Fatalf("release user %v internal=%+v", err, c.loaderBreakpoint)
				}
				for _, name := range []string{"malloc", "free"} {
					if err := c.resume(ctx, "", false); err != nil {
						t.Fatalf("await %s: %v %s", name, err, output.String())
					}
					var bp *breakpoint
					for _, candidate := range c.breakpoints {
						if candidate.expression == name {
							bp = candidate
						}
					}
					stop := c.session.LastStop()
					if bp == nil || !bp.installed || stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != bp.address || c.loaderBreakpoint != nil {
						t.Fatalf("expected %s hit stop=%+v bp=%+v loader=%+v out=%s", name, stop, bp, c.loaderBreakpoint, output.String())
					}
				}
				if err := c.deleteBreakpoints(ctx, "all"); err != nil {
					t.Fatal(err)
				}
				if err := c.resume(ctx, "", false); err != nil || c.session.State() != target.StateExited {
					t.Fatalf("completion err=%v state=%s out=%s", err, c.session.State(), output.String())
				}
				if code := c.session.LastStop().ExitCode; code == nil || *code != 11 {
					t.Fatalf("unexpected completion %s", output.String())
				}
				if strings.Contains(output.String(), "SIGSEGV") {
					t.Fatalf("bad rearm %s", output.String())
				}
			})
		}
	}
}

func TestIndependentLoaderPendingClassificationRejectsOtherErrors(t *testing.T) {
	pending := &symbolPendingError{Name: "malloc", Err: &runtimeLoaderPendingError{}}
	if !isPendingBreakpointError(pending) || !isPendingBreakpointError(fmt.Errorf("wrapped: %w", pending)) {
		t.Fatal("exact pending not recognized")
	}
	for _, extra := range []error{io.ErrUnexpectedEOF, io.EOF, target.ErrClosed, target.ErrStale, target.ErrAmbiguous, target.ErrNotFound, target.ErrUnsupported, target.ErrOverflow, context.Canceled} {
		if isPendingBreakpointError(errors.Join(pending, extra)) {
			t.Fatalf("hard error downgraded to pending: %v", extra)
		}
	}
	if isPendingBreakpointError(&symbolPendingError{Name: "malloc", Err: target.ErrUnavailable}) {
		t.Fatal("generic unavailable treated as loader proof")
	}
}

func TestIndependentLoaderPendingRejectsRegisterDependentAndMalformedExpressions(t *testing.T) {
	for _, expression := range []string{"malloc+$rax", "$rax+malloc", "malloc + $", "malloc + )", "`malloc` + $rax", "malloc + (1/0)", "(malloc)"} {
		t.Run(expression, func(t *testing.T) {
			fixture := newLoaderBreakpointNativeFixture(t, false)
			c := fixture.controller
			err := c.addBreakpoint(fixture.ctx, expression)
			if err == nil || isPendingBreakpointError(err) || c.hasPendingBreakpoints() {
				t.Fatalf("unsafe deferred expression accepted: error=%v output=%s", err, fixture.output.String())
			}
			for _, bp := range c.breakpoints {
				if bp.attempted || bp.installed {
					t.Fatalf("unsafe expression mutated breakpoint state: %+v", bp)
				}
			}
		})
	}
}

func TestIndependentLoaderDTDebugPublicationWatchpointKeepsPending(t *testing.T) {
	fixture := newLoaderBreakpointNativeFixture(t, true)
	c := fixture.controller
	snapshot, thread, err := c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	image, err := readLiveImage(fixture.ctx, thread.TID)
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.Open(c.path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var slot target.Address
	for _, program := range file.Progs {
		if program.Type != elf.PT_DYNAMIC {
			continue
		}
		data, err := io.ReadAll(program.Open())
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off+16 <= len(data); off += 16 {
			tag := elf.DynTag(binary.LittleEndian.Uint64(data[off:]))
			if tag == elf.DT_NULL {
				break
			}
			if tag == elf.DT_DEBUG {
				if slot != 0 {
					t.Fatal("fixture has duplicate DT_DEBUG")
				}
				slot = target.Address(image.loadBias + program.Vaddr + uint64(off) + 8)
			}
		}
	}
	if slot == 0 {
		t.Fatal("fixture has no DT_DEBUG")
	}
	fixture.command(t, "break", "malloc")
	fixture.command(t, "wp", fmt.Sprintf("%#x --size 8 --access write", slot))
	fixture.command(t, "continue", "")
	if c.session.LastStop().Reason != target.StopWatchpoint {
		t.Fatalf("publication watchpoint swallowed: %+v", c.session.LastStop())
	}
	snapshot, thread, err = c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.loaderRendezvous(fixture.ctx, snapshot, thread)
	if err != nil || !info.Published || !info.Consistent {
		t.Fatalf("publication boundary info=%+v err=%v", info, err)
	}
	if !c.hasPendingBreakpoints() {
		t.Fatal("watchpoint unexpectedly resolved unbound symbol")
	}
	fixture.command(t, "wp", "d 0")
	if err := c.resume(fixture.ctx, "", false); err != nil {
		t.Fatalf("pending was lost before first loader RT_ADD notification: %v output=%s", err, fixture.output.String())
	}
	bp := c.breakpoints[0]
	stop := c.session.LastStop()
	if !bp.installed || stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != bp.address {
		t.Fatalf("did not reach malloc: %+v %+v", bp, stop)
	}
}

type independentLoaderStepSession struct {
	*independentLoaderSession
	raw     byte
	logical byte
	rawErr  error
	codeErr error
}

func (s *independentLoaderStepSession) ReadSpaceMemory(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
	for i := range dst {
		dst[i] = s.raw
	}
	return len(dst), s.rawErr
}
func (s *independentLoaderStepSession) ReadCodeMemory(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
	for i := range dst {
		dst[i] = s.logical
	}
	return len(dst), s.codeErr
}

func TestIndependentLoaderStepEntryProcessesButNeverConsumes(t *testing.T) {
	for _, mode := range []string{"entry", "not-completed", "stale-token", "outside-entry", "raw-disagrees", "historical-bp", "raw-not-patched", "logical-int3", "stale-memory", "watch-event", "hardware-event", "snapshot-not-step", "snapshot-signal-contradiction"} {
		t.Run(mode, func(t *testing.T) {
			c, base, before, result := independentLoaderStopFixture()
			address := target.Address(0x5000)
			stop := target.Stop{Reason: target.StopStep, StepCompleted: true, RawPC: &address, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGTRAP)}}
			result.Stop = stop
			base.snapshot.Threads[0].Stop = stop
			base.locations[result.Thread] = native.CodeLocation{RawPC: address, InstructionPC: address}
			s := &independentLoaderStepSession{independentLoaderSession: base, raw: 0xcc, logical: 0x90}
			c.session = s
			switch mode {
			case "not-completed":
				result.Stop.StepCompleted = false
			case "stale-token":
				result.Token.Registers++
			case "outside-entry":
				base.locations[result.Thread] = native.CodeLocation{RawPC: address + 1, InstructionPC: address + 1}
			case "raw-disagrees":
				base.locations[result.Thread] = native.CodeLocation{RawPC: address + 1, InstructionPC: address}
			case "historical-bp":
				base.locations[result.Thread] = native.CodeLocation{RawPC: address, InstructionPC: address, Breakpoint: &address}
			case "raw-not-patched":
				s.raw = 0x90
			case "logical-int3":
				s.logical = 0xcc
			case "stale-memory":
				s.rawErr = target.ErrStale
			case "watch-event":
				result.Stop.Watchpoints = []target.WatchpointHit{{}}
			case "hardware-event":
				result.Stop.HardwareBreakpoints = []target.HardwareBreakpointHit{{}}
			case "snapshot-not-step":
				base.snapshot.Threads[0].Stop.Reason = target.StopSignal
			case "snapshot-signal-contradiction":
				base.snapshot.Threads[0].Stop.Signal.Number = uint32(unix.SIGUSR1)
			}
			owned, err := c.ownsLoaderStop(result)
			if mode == "entry" {
				if !owned || err != nil {
					t.Fatalf("valid formal step entry rejected: %t %v", owned, err)
				}
			} else if owned {
				t.Fatalf("unproven step entry processed: %t %v", owned, err)
			}
			if consumed, err := c.loaderStopMatches(before, result); consumed {
				t.Fatalf("visible step consumed: %v", err)
			}
		})
	}
}

const independentLoaderThunkSource = `#include <link.h>
#include <stdlib.h>
void *volatile allocated;
__attribute__((naked,noinline)) void independent_loader_thunk(void (*entry)(void)) {
    __asm__ volatile("call *%rdi\n\tret");
}
static unsigned long formal_hook(void) {
    for (ElfW(Dyn) *entry = _DYNAMIC; entry->d_tag != DT_NULL; ++entry)
        if (entry->d_tag == DT_DEBUG)
            return ((struct r_debug *)entry->d_un.d_ptr)->r_brk;
    return 0;
}
int main(void) {
    unsigned long hook = formal_hook();
    if (!hook) return 90;
    independent_loader_thunk((void (*)(void))hook);
    allocated = malloc(96);
    free((void *)allocated);
    return 17;
}
`

func TestIndependentLoaderNativeSingleStepFormalHookEntry(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			dir := loaderBreakpointReviewDirectory(t)
			source, path := filepath.Join(dir, "thunk.c"), filepath.Join(dir, "thunk")
			if err := os.WriteFile(source, []byte(independentLoaderThunkSource), 0600); err != nil {
				t.Fatal(err)
			}
			flags := []string{"-O0", "-g", "-fno-builtin", "-fcf-protection=none", "-fno-pie", "-no-pie"}
			if pie {
				flags[len(flags)-2], flags[len(flags)-1] = "-fPIE", "-pie"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "cc", append(flags, "-o", path, source)...)
			command.Env = append(os.Environ(), "TMPDIR="+dir)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile %v %s", err, output)
			}
			var out bytes.Buffer
			c := New(&out, display.Renderer{})
			c.contextDisabled = true
			t.Cleanup(func() {
				if err := c.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := c.Configure(path, nil); err != nil {
				t.Fatal(err)
			}
			if err := c.start(ctx, "", false); err != nil {
				t.Fatal(err)
			}
			if err := c.addBreakpoint(ctx, "malloc"); err != nil {
				t.Fatal(err)
			}
			if !c.hasPendingBreakpoints() {
				t.Fatal("malloc was not genuinely pending before loader publication")
			}
			if err := c.addBreakpoint(ctx, "main"); err != nil {
				t.Fatal(err)
			}
			mainBP := c.breakpoints[1]
			snapshot, _, err := c.stopped()
			if err != nil {
				t.Fatal(err)
			}
			op, err := c.session.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := op.Wait(ctx)
			if err != nil || result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != mainBP.address {
				t.Fatalf("direct test setup run: %+v %v", result, err)
			}
			if err := c.deleteBreakpoints(ctx, fmt.Sprint(mainBP.id)); err != nil {
				t.Fatal(err)
			}
			if err := c.addBreakpoint(ctx, "independent_loader_thunk"); err != nil {
				t.Fatal(err)
			}
			if err := c.resume(ctx, "", false); err != nil {
				t.Fatalf("thunk arrival: %v %s", err, out.String())
			}
			snapshot, thread, err := c.stopped()
			if err != nil {
				t.Fatal(err)
			}
			info, err := c.loaderRendezvous(ctx, snapshot, thread)
			if err != nil || !info.Published || !info.Consistent || !c.hasPendingBreakpoints() || c.loaderBreakpoint == nil {
				t.Fatalf("before-step info=%+v err=%v pending=%t internal=%+v", info, err, c.hasPendingBreakpoints(), c.loaderBreakpoint)
			}
			thunk := c.breakpoints[1]
			if stop := c.session.LastStop(); stop.Breakpoint == nil || *stop.Breakpoint != thunk.address {
				t.Fatalf("not stopped at exact thunk: %+v", stop)
			}
			if err := c.resume(ctx, "", true); err != nil {
				t.Fatalf("formal step: %v %s", err, out.String())
			}
			stop := c.session.LastStop()
			mallocBP := c.breakpoints[0]
			if stop.Reason != target.StopStep || !stop.StepCompleted || stop.RawPC == nil || *stop.RawPC != info.Hook || !mallocBP.installed || c.hasPendingBreakpoints() || c.loaderBreakpoint != nil {
				t.Fatalf("formal step was consumed or pending missed: stop=%+v malloc=%+v internal=%+v output=%s", stop, mallocBP, c.loaderBreakpoint, out.String())
			}
			if err := c.resume(ctx, "", false); err != nil {
				t.Fatalf("resume after step: %v %s", err, out.String())
			}
			if stop := c.session.LastStop(); stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != mallocBP.address {
				t.Fatalf("malloc missed after visible formal step: %+v", stop)
			}
		})
	}
}

func TestIndependentLoaderPeerArrivalSurvivesVisibleSignalAndCancellation(t *testing.T) {
	c, s, before, result := independentLoaderStopFixture()
	hookStop := s.snapshot.Threads[0].Stop
	primary := &s.snapshot.Threads[0]
	primary.Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(unix.SIGUSR1)}}
	peer := &s.snapshot.Threads[1]
	peer.Stop = hookStop
	result.Stop = primary.Stop
	c.beginLoaderOperation(before)
	if err := c.captureLoaderArrivals(); err != nil {
		t.Fatal(err)
	}
	state := c.loaderBreakpoint
	if state.before != nil || len(state.arrivals) != 1 || state.arrivals[peer.Ref] != peer.Token {
		t.Fatalf("fresh peer arrival was missed: %+v", state)
	}
	if consumed, err := c.loaderStopMatches(before, result); consumed || err != nil {
		t.Fatalf("visible primary signal was consumed: %t %v", consumed, err)
	}
	peerResult := target.RunResult{Thread: peer.Ref, Token: peer.Token, Stop: peer.Stop}
	if owned, err := c.ownsLoaderStop(peerResult); !owned || err != nil {
		t.Fatalf("fresh peer hook was not proven: %t %v", owned, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.processLoaderArrivals(ctx); !errors.Is(err, context.Canceled) || len(state.arrivals) != 1 {
		t.Fatalf("cancel lost captured arrival: %v %+v", err, state)
	}
	if err := c.captureLoaderArrivals(); err != nil || len(state.arrivals) != 1 {
		t.Fatalf("idle recapture changed witness: %v %+v", err, state)
	}
}

func TestIndependentLoaderArrivalInvalidationIsFailClosed(t *testing.T) {
	for _, mode := range []string{"register-write", "stale-location", "thread-gone", "exec"} {
		t.Run(mode, func(t *testing.T) {
			c, s, before, _ := independentLoaderStopFixture()
			c.breakpoints = []*breakpoint{independentLoaderPending()}
			c.beginLoaderOperation(before)
			if err := c.captureLoaderArrivals(); err != nil {
				t.Fatal(err)
			}
			state := c.loaderBreakpoint
			if len(state.arrivals) != 1 {
				t.Fatalf("missing original arrival: %+v", state)
			}
			switch mode {
			case "register-write":
				s.snapshot.Threads[0].Token.Registers++
			case "stale-location":
				s.locationErr = target.ErrStale
			case "thread-gone":
				s.snapshot.Threads = s.snapshot.Threads[1:]
			case "exec":
				s.snapshot.Memory.Space.ID++
			}
			if _, err := c.processLoaderArrivals(context.Background()); !errors.Is(err, target.ErrStale) {
				t.Fatalf("invalid witness allowed: %v", err)
			}
			if len(s.added) != 0 || s.runCalls != 0 {
				t.Fatal("invalid witness mutated or resumed target")
			}
			if mode == "exec" {
				if c.loaderBreakpoint != nil {
					t.Fatal("old-space arrival retained")
				}
			} else if c.loaderBreakpoint != state || len(state.arrivals) != 1 {
				t.Fatal("uncertain same-space evidence silently discarded")
			}
		})
	}
}

func TestIndependentLoaderOldStopsCannotCreateArrival(t *testing.T) {
	c, s, before, _ := independentLoaderStopFixture()
	for i := range s.snapshot.Threads {
		s.snapshot.Threads[i].Token.Stop = before.Threads[i].Token.Stop
	}
	c.beginLoaderOperation(before)
	if err := c.captureLoaderArrivals(); err != nil || len(c.loaderBreakpoint.arrivals) != 0 {
		t.Fatalf("historical stop captured: %v %+v", err, c.loaderBreakpoint)
	}
}

func TestIndependentLoaderInvalidResumeArgumentsCannotInstallBreakpoints(t *testing.T) {
	for _, step := range []bool{false, true} {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			c, s, _ := independentLoaderController()
			c.breakpoints = []*breakpoint{{id: 1, expression: "0x5000", enabled: true}}
			err := c.resume(context.Background(), "--typo", step)
			if !errors.Is(err, target.ErrInvalidArgument) || len(s.added) != 0 || s.runCalls != 0 || s.stepCalls != 0 {
				t.Fatalf("invalid command changed target: error=%v adds=%v run=%d step=%d", err, s.added, s.runCalls, s.stepCalls)
			}
		})
	}
}

func TestLoaderBreakpointAlreadyEnabledPendingWaitsForRendezvous(t *testing.T) {
	c, s, _ := independentLoaderController()
	bp := independentLoaderPending()
	c.breakpoints = []*breakpoint{bp}
	witness := bp.err
	if err := c.setBreakpointsEnabled(context.Background(), "999", true); err != nil || bp.err != witness || !bp.enabled || bp.attempted || bp.installed || len(s.added) != 0 {
		t.Fatalf("enable polled an already-pending symbol without a rendezvous: error=%v breakpoint=%+v adds=%v", err, bp, s.added)
	}
}

func loaderBreakpointReviewDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "loader-breakpoint-tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "independent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
