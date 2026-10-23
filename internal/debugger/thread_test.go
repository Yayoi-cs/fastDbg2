package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"fastdbg2/target"
)

func controllerPeer(s *controllerTestSession, id uint64) target.ThreadInfo {
	thread := s.snapshot.Threads[0]
	thread.Ref.ID = id
	thread.Token = target.ThreadToken{Thread: thread.Ref, Stop: id + 20, Registers: id + 40}
	thread.TID = s.pid + len(s.snapshot.Threads)
	thread.Name = fmt.Sprintf("worker-%d", id)
	s.snapshot.Threads = append(s.snapshot.Threads, thread)
	return thread
}

func TestThreadCommandIDsAndTIDsAreDistinct(t *testing.T) {
	var output bytes.Buffer
	c, s := runningController(t, &output)
	original := c.selected
	peer := controllerPeer(s, 2)
	if _, err := c.Execute(context.Background(), "thread", fmtInt(peer.TID)); !errors.Is(err, target.ErrNotFound) || c.selected != original {
		t.Fatalf("implicit TID lookup err=%v selected=%+v", err, c.selected)
	}
	executeController(t, c, "thread", "2")
	if c.selected != peer.Ref {
		t.Fatalf("logical ID selected=%+v want=%+v", c.selected, peer.Ref)
	}
	executeController(t, c, "thread", "")
	if !strings.Contains(output.String(), fmt.Sprintf("Current thread tid=%d thread=2 state=stopped", peer.TID)) {
		t.Fatalf("current thread output=%q", output.String())
	}
	executeController(t, c, "thread", "1")
	executeController(t, c, "thread", "tid "+fmtInt(peer.TID))
	if c.selected != peer.Ref {
		t.Fatalf("explicit TID selected=%+v", c.selected)
	}
	large := controllerPeer(s, math.MaxUint64)
	executeController(t, c, "thread", "18446744073709551615")
	if c.selected != large.Ref {
		t.Fatalf("uint64 ID selected=%+v want=%+v", c.selected, large.Ref)
	}
}

func TestThreadSelectionDoesNotReuseTIDOrSession(t *testing.T) {
	c, s := runningController(t, io.Discard)
	peer := controllerPeer(s, 2)
	executeController(t, c, "thread", "2")
	s.snapshot.Threads[1].Ref.ID = 3
	s.snapshot.Threads[1].Token.Thread.ID = 3
	if _, _, err := c.stopped(); !errors.Is(err, target.ErrNotFound) || c.selected != peer.Ref {
		t.Fatalf("TID reused selected=%+v err=%v", c.selected, err)
	}
	if _, err := c.Execute(context.Background(), "thread", "2"); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("removed logical ID err=%v", err)
	}
	executeController(t, c, "thread", "3")
	c.selected.Session++
	if _, _, err := c.stopped(); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("old-session selection accepted: %v", err)
	}
}

func TestThreadSelectionRejectsUninspectableSubjects(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*target.ThreadInfo)
		want error
	}{
		{"running", func(thread *target.ThreadInfo) { thread.State = target.StateRunning }, target.ErrInvalidState},
		{"unknown", func(thread *target.ThreadInfo) { thread.State = target.StateUnknown }, target.ErrInvalidState},
		{"exited", func(thread *target.ThreadInfo) { thread.State = target.StateExited }, target.ErrInvalidState},
		{"exiting", func(thread *target.ThreadInfo) { thread.Exiting = true }, target.ErrInvalidState},
		{"listening", func(thread *target.ThreadInfo) { thread.Listening = true }, target.ErrInvalidState},
		{"other-process", func(thread *target.ThreadInfo) { thread.Process.ID++ }, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			original := c.selected
			controllerPeer(s, 2)
			test.edit(&s.snapshot.Threads[1])
			if _, err := c.Execute(context.Background(), "thread", "2"); !errors.Is(err, test.want) || c.selected != original {
				t.Fatalf("selection=%+v err=%v", c.selected, err)
			}
		})
	}
}

func TestThreadIDParserRejectsNonDecimalAndOverflow(t *testing.T) {
	for _, input := range []string{"", "0", "-1", "+1", "0x1", "1 2", "1\x00", "１", "18446744073709551616"} {
		if _, err := positiveThreadID(input); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("input=%q err=%v", input, err)
		}
	}
}

func TestThreadSnapshotShowsIndividualStopReasonsAndEscapesNames(t *testing.T) {
	var output bytes.Buffer
	c, s := runningController(t, &output)
	peer := controllerPeer(s, 2)
	s.snapshot.Threads[0].Stop.Reason = target.StopBreakpoint
	s.snapshot.Threads[1].Stop.Reason = target.StopSignal
	s.snapshot.Threads[1].Name = "worker\x1b[31m\n"
	s.snapshot.Threads[1].Exiting = true
	s.snapshot.Threads[1].Listening = true
	if err := c.showThreads(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if s.snapshot.Threads[1].Ref != peer.Ref || s.snapshot.Threads[1].TID != peer.TID || !uiThreadRowMatches(text, true, s.snapshot.Threads[0]) || !uiThreadRowMatches(text, false, s.snapshot.Threads[1]) ||
		!strings.Contains(text, "stopped/exiting/listening") || strings.ContainsRune(text, '\x1b') {
		t.Fatalf("thread output=%q", text)
	}
	output.Reset()
	c.selected.Session++
	if err := c.showThreads(); err != nil || uiThreadRowMatches(output.String(), true, s.snapshot.Threads[0]) || !uiThreadRowMatches(output.String(), false, s.snapshot.Threads[0]) {
		t.Fatalf("old-session marker output=%q err=%v", output.String(), err)
	}
}

func TestSchedulerModesUseExactResumeScopesAndStopTokens(t *testing.T) {
	for _, mode := range []string{"", "off", "on", "step", "replay"} {
		for _, step := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/step=%t", mode, step), func(t *testing.T) {
				c, s := runningController(t, io.Discard)
				c.schedulerLocking = mode
				controllerPeer(s, 2)
				controllerPeer(s, 3)
				s.snapshot.Threads[2].Process.ID++
				controllerPeer(s, 4)
				s.snapshot.Threads[3].State = target.StateExited
				for i := range s.snapshot.Threads {
					s.snapshot.Threads[i].Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: uint32(10 + i)}, Generation: 999}
				}
				before := slices.Clone(s.snapshot.Threads)
				if err := c.resume(context.Background(), "--deliver", step); err != nil {
					t.Fatal(err)
				}
				peers := mode == "" || mode == "off" || mode == "replay" || mode == "step" && !step
				set, signals := s.runRequest.Threads, s.runRequest.Signals
				if step {
					set, signals = s.stepRequest.Continue, s.stepRequest.Signals
					if s.stepRequest.Thread != before[0].Ref {
						t.Fatalf("step selected=%+v", s.stepRequest.Thread)
					}
				}
				wantCount := 1
				if peers {
					wantCount = 2
					if set.Scope != target.ProcessThreads || set.Process != s.snapshot.Process || len(set.Threads) != 0 {
						t.Fatalf("process scope was narrowed: %+v", set)
					}
				} else if set.Scope != target.ExactThreads || set.Process != (target.ProcessRef{}) || step && len(set.Threads) != 0 || !step && !reflect.DeepEqual(set.Threads, []target.ThreadRef{before[0].Ref}) {
					t.Fatalf("locked scope=%+v", set)
				}
				if len(signals) != wantCount {
					t.Fatalf("signal scope=%+v want=%d", signals, wantCount)
				}
				for i, decision := range signals {
					if decision.Thread != before[i].Ref || decision.Stop != before[i].Token.Stop || decision.Signal != before[i].Stop.Signal {
						t.Fatalf("decision=%+v thread=%+v", decision, before[i])
					}
				}
			})
		}
	}
}

func TestUnlockedStepRequiresPeerSignalDecision(t *testing.T) {
	for _, mode := range []string{"", "off", "replay"} {
		c, s := runningController(t, io.Discard)
		c.schedulerLocking = mode
		controllerPeer(s, 2)
		s.snapshot.Threads[1].Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 12}}
		if err := c.resume(context.Background(), "", true); !errors.Is(err, target.ErrInvalidArgument) || s.stepCalls != 0 {
			t.Fatalf("mode=%q err=%v step calls=%d", mode, err, s.stepCalls)
		}
		if s.snapshot.Threads[1].Stop.Signal.Number != 12 {
			t.Fatal("pending peer signal changed without an explicit decision")
		}
	}
}

func TestSchedulerRejectsUninspectableProcessPeer(t *testing.T) {
	c, s := runningController(t, io.Discard)
	controllerPeer(s, 2)
	s.snapshot.Threads[1].Listening = true
	if err := c.resume(context.Background(), "", true); !errors.Is(err, target.ErrInvalidState) || s.stepCalls != 0 {
		t.Fatalf("unlocked step omitted listening peer: %v", err)
	}
	c.schedulerLocking = "on"
	if err := c.resume(context.Background(), "", true); err != nil || s.stepCalls != 1 {
		t.Fatalf("locked step consulted unrelated peer: %v", err)
	}
}

func TestSchedulerSettingIsExplicitPersistentAndValidated(t *testing.T) {
	var output bytes.Buffer
	c, _ := runningController(t, &output)
	c.schedulerLocking = ""
	if err := c.showSchedulerLocking(); err != nil || !strings.Contains(output.String(), `execution is "replay".`) {
		t.Fatalf("default=%q err=%v", output.String(), err)
	}
	for _, mode := range []string{"off", "on", "step", "replay"} {
		if err := c.setSchedulerLocking(mode); err != nil || c.schedulerMode() != mode {
			t.Fatalf("mode=%q err=%v", mode, err)
		}
	}
	for _, mode := range []string{"", "ON", "on off", "off extra", "heuristic", "replay\x00"} {
		if err := c.setSchedulerLocking(mode); !errors.Is(err, target.ErrInvalidArgument) || c.schedulerMode() != "replay" {
			t.Fatalf("mode=%q stored=%q err=%v", mode, c.schedulerMode(), err)
		}
	}
	if err := c.setSchedulerLocking("on"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil || c.schedulerMode() != "on" {
		t.Fatalf("close changed mode=%q err=%v", c.schedulerMode(), err)
	}
}

func TestThreadApplyCommandAllowlist(t *testing.T) {
	for _, test := range []struct{ name, args string }{
		{"regs", "rip rsp"}, {"registers", "rip"}, {"memory", "--count 8 $rsp"},
		{"p/x", "$rip"}, {"print/u", "1"}, {"x/2gx", "$rsp"}, {"disass", "$rip"},
		{"stack", "8"}, {"hd", "byte $rsp"}, {"db", "$rsp"}, {"dw", "$rsp"}, {"dd", "$rsp"}, {"dq", "$rsp"},
		{"context", ""}, {"context", "regs code stack threads"}, {"thread", ""}, {"t", ""}, {"threads", ""},
		{"info", "registers rip"}, {"info", "threads"}, {"info", "breakpoints"},
	} {
		if err := threadApplyReadOnly(test.name, test.args); err != nil {
			t.Fatalf("read-only %s %s: %v", test.name, test.args, err)
		}
	}
	for _, test := range []struct{ name, args string }{
		{"context", "off"}, {"context", "on"}, {"context", "regs off"},
		{"thread", "1"}, {"thread", "tid 1"}, {"thread", "apply all regs"},
		{"set", "scheduler-locking off"}, {"continue", ""}, {"run", ""}, {"stepi", ""},
		{"break", "1"}, {"delete", "1"}, {"quit", ""}, {"kill", ""}, {"detach", ""},
		{"interrupt", ""}, {"info", "unknown"}, {"info", "threads; continue"}, {"unknown", ""},
	} {
		if err := threadApplyReadOnly(test.name, test.args); err == nil {
			t.Fatalf("unsafe command allowed: %s %s", test.name, test.args)
		}
	}
}

func TestThreadApplyParserRejectsUnsupportedSelectorsAndOptions(t *testing.T) {
	for _, args := range []string{"", "regs", "0 regs", "-1 regs", "1-3 regs", "1 01 regs", "18446744073709551616 regs", "all", "1", "all -q regs", "all -s regs", "all -- regs", "1 -ascending regs", "all -ascending -ascending regs", "all -c -c regs"} {
		if _, err := parseThreadApply(args); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("args=%q err=%v", args, err)
		}
	}
}

func TestThreadApplyOrderingAndSelectionRestoration(t *testing.T) {
	for _, test := range []struct {
		args  string
		order []uint64
	}{
		{"all regs", []uint64{3, 2, 1}},
		{"all -ascending regs", []uint64{1, 2, 3}},
		{"2 1 3 regs", []uint64{2, 1, 3}},
	} {
		t.Run(test.args, func(t *testing.T) {
			var output bytes.Buffer
			c, s := runningController(t, &output)
			peer := controllerPeer(s, 2)
			controllerPeer(s, 3)
			c.selected = peer.Ref
			if err := c.applyThreads(context.Background(), test.args); err != nil {
				t.Fatal(err)
			}
			if c.selected != peer.Ref || len(s.registerReads) != len(test.order) {
				t.Fatalf("selected=%+v reads=%+v", c.selected, s.registerReads)
			}
			previous := -1
			for i, id := range test.order {
				position := strings.Index(output.String(), fmt.Sprintf("\nThread %d (tid=", id))
				if position <= previous || s.registerReads[i].Thread.ID != id {
					t.Fatalf("order=%v reads=%+v output=%q", test.order, s.registerReads, output.String())
				}
				previous = position
			}
		})
	}
}

func TestThreadApplyPrevalidatesEveryRequestedThread(t *testing.T) {
	for _, test := range []struct {
		name string
		args string
		edit func(*controllerTestSession)
		want error
	}{
		{"missing", "1 99 regs", func(*controllerTestSession) {}, target.ErrNotFound},
		{"other-process", "1 2 regs", func(s *controllerTestSession) { s.snapshot.Threads[1].Process.ID++ }, target.ErrUnsupported},
		{"exiting", "1 2 regs", func(s *controllerTestSession) { s.snapshot.Threads[1].Exiting = true }, target.ErrInvalidState},
		{"all-listening", "all regs", func(s *controllerTestSession) { s.snapshot.Threads[1].Listening = true }, target.ErrInvalidState},
		{"all-newborn", "all regs", func(s *controllerTestSession) { s.snapshot.Threads[1].State = target.StateUnknown }, target.ErrInvalidState},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			c, s := runningController(t, &output)
			original := c.selected
			controllerPeer(s, 2)
			test.edit(s)
			if err := c.applyThreads(context.Background(), test.args); !errors.Is(err, test.want) || c.selected != original || len(s.registerReads) != 0 || output.Len() != 0 {
				t.Fatalf("err=%v selected=%+v reads=%+v output=%q", err, c.selected, s.registerReads, output.String())
			}
		})
	}
}

func TestThreadApplyAllDoesNotInspectExitedOrForeignThreads(t *testing.T) {
	c, s := runningController(t, io.Discard)
	controllerPeer(s, 2)
	s.snapshot.Threads[1].State = target.StateExited
	controllerPeer(s, 3)
	s.snapshot.Threads[2].Process.ID++
	if err := c.applyThreads(context.Background(), "all regs"); err != nil || len(s.registerReads) != 1 || s.registerReads[0].Thread != c.selected {
		t.Fatalf("err=%v reads=%+v", err, s.registerReads)
	}
}

func TestThreadApplyAbortAndContinueErrorsRestoreSelection(t *testing.T) {
	for _, keepGoing := range []bool{false, true} {
		var output bytes.Buffer
		c, s := runningController(t, &output)
		peer := controllerPeer(s, 2)
		c.selected = peer.Ref
		args, want := "1 2 memory --count 0 $rsp", 1
		if keepGoing {
			args, want = "1 2 -c memory --count 0 $rsp", 2
		}
		err := c.applyThreads(context.Background(), args)
		if !errors.Is(err, target.ErrInvalidArgument) || c.selected != peer.Ref || uiApplyHeaderCount(output.String()) != want || len(s.registerReads) != 0 {
			t.Fatalf("keepGoing=%t err=%v selected=%+v output=%q", keepGoing, err, c.selected, output.String())
		}
	}
}

type threadSnapshotFixture struct {
	*controllerTestSession
	snapshotCalls int
	onSnapshot    func(int)
	onRead        func(target.ThreadToken) error
	memoryError   error
}

func (s *threadSnapshotFixture) Snapshot() (target.Snapshot, error) {
	s.snapshotCalls++
	if s.onSnapshot != nil {
		s.onSnapshot(s.snapshotCalls)
	}
	return s.controllerTestSession.Snapshot()
}

func (s *threadSnapshotFixture) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	registers, err := s.controllerTestSession.ReadThreadRegisters(token)
	if s.onRead != nil {
		return registers, s.onRead(token)
	}
	return registers, err
}

func (s *threadSnapshotFixture) ReadSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	n, err := s.controllerTestSession.ReadSpaceMemory(token, address, data)
	return n, errors.Join(err, s.memoryError)
}

func TestThreadApplyInspectionErrorsAbortOrContinueWithoutDiscardingFailure(t *testing.T) {
	for _, command := range []string{"regs", "context regs", "memory --count 1 0x800000"} {
		for _, keepGoing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/continue=%t", command, keepGoing), func(t *testing.T) {
				var output bytes.Buffer
				c, s := runningController(t, &output)
				peer := controllerPeer(s, 2)
				fixture := &threadSnapshotFixture{controllerTestSession: s}
				if strings.HasPrefix(command, "memory") {
					fixture.memoryError = target.ErrUnavailable
				} else {
					fixture.onRead = func(target.ThreadToken) error { return target.ErrUnavailable }
				}
				c.session, c.selected = fixture, peer.Ref
				args, want := "1 2 "+command, 1
				if keepGoing {
					args, want = "1 2 -c "+command, 2
				}
				err := c.applyThreads(context.Background(), args)
				reads := len(s.registerReads)
				if strings.HasPrefix(command, "memory") {
					reads = len(s.memoryReads)
				}
				if !errors.Is(err, target.ErrUnavailable) || c.selected != peer.Ref || reads != want || uiApplyHeaderCount(output.String()) != want {
					t.Fatalf("err=%v selected=%+v reads=%d want=%d output=%q", err, c.selected, reads, want, output.String())
				}
			})
		}
	}
}

func TestThreadApplyUsesFreshPerThreadSnapshots(t *testing.T) {
	c, s := runningController(t, io.Discard)
	controllerPeer(s, 2)
	fixture := &threadSnapshotFixture{controllerTestSession: s}
	fixture.onSnapshot = func(call int) {
		for i := range s.snapshot.Threads {
			s.snapshot.Threads[i].Token.Stop = uint64(call*10 + i)
			s.snapshot.Threads[i].Token.Registers = uint64(call*100 + i)
		}
	}
	c.session = fixture
	if err := c.applyThreads(context.Background(), "1 2 regs"); err != nil {
		t.Fatal(err)
	}
	if fixture.snapshotCalls != 3 || len(s.registerReads) != 2 || s.registerReads[0].Stop != 20 || s.registerReads[0].Registers != 200 || s.registerReads[1].Stop != 31 || s.registerReads[1].Registers != 301 {
		t.Fatalf("snapshots=%d reads=%+v", fixture.snapshotCalls, s.registerReads)
	}
}

func TestThreadApplyStaleRegisterTokenIsNotRetried(t *testing.T) {
	c, s := runningController(t, io.Discard)
	peer := controllerPeer(s, 2)
	fixture := &threadSnapshotFixture{controllerTestSession: s, onRead: func(target.ThreadToken) error { return target.ErrStale }}
	c.session, c.selected = fixture, peer.Ref
	err := c.applyThreads(context.Background(), "1 2 memory --count 1 $rip")
	if !errors.Is(err, target.ErrStale) || fixture.snapshotCalls != 2 || len(s.registerReads) != 1 || c.selected != peer.Ref {
		t.Fatalf("err=%v snapshots=%d reads=%+v selected=%+v", err, fixture.snapshotCalls, s.registerReads, c.selected)
	}
}

func TestThreadApplyNeverSubstitutesAReusedTID(t *testing.T) {
	c, s := runningController(t, io.Discard)
	controllerPeer(s, 2)
	original := c.selected
	fixture := &threadSnapshotFixture{controllerTestSession: s}
	fixture.onSnapshot = func(call int) {
		if call == 3 {
			s.snapshot.Threads[1].Ref.ID = 22
			s.snapshot.Threads[1].Token.Thread.ID = 22
		}
	}
	c.session = fixture
	err := c.applyThreads(context.Background(), "1 2 regs")
	if !errors.Is(err, target.ErrNotFound) || len(s.registerReads) != 1 || c.selected != original {
		t.Fatalf("err=%v reads=%+v selected=%+v", err, s.registerReads, c.selected)
	}
}

func TestThreadApplyOutputAndCancellationStopIteration(t *testing.T) {
	t.Run("output", func(t *testing.T) {
		want := errors.New("output failed")
		writes := 0
		writer := controllerTestWriter(func(data []byte) (int, error) {
			writes++
			if writes == 2 {
				return 0, want
			}
			return len(data), nil
		})
		c, s := runningController(t, writer)
		peer := controllerPeer(s, 2)
		c.selected = peer.Ref
		err := c.applyThreads(context.Background(), "1 2 -c regs")
		var outputErr *OutputError
		if !errors.Is(err, want) || !errors.As(err, &outputErr) || writes != 2 || len(s.registerReads) != 1 || c.selected != peer.Ref {
			t.Fatalf("err=%v writes=%d reads=%+v selected=%+v", err, writes, s.registerReads, c.selected)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		c, s := runningController(t, io.Discard)
		peer := controllerPeer(s, 2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fixture := &threadSnapshotFixture{controllerTestSession: s, onRead: func(target.ThreadToken) error { cancel(); return nil }}
		c.session, c.selected = fixture, peer.Ref
		err := c.applyThreads(ctx, "1 2 -c regs")
		if !errors.Is(err, context.Canceled) || len(s.registerReads) != 1 || c.selected != peer.Ref {
			t.Fatalf("err=%v reads=%+v selected=%+v", err, s.registerReads, c.selected)
		}
	})
}

func TestStopSelectionUsesOnlyInspectablePrimaryEventIdentity(t *testing.T) {
	for _, kind := range []string{"valid", "exited", "exiting", "listening", "newborn", "other-process", "other-session", "zero"} {
		t.Run(kind, func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			original := c.selected
			peer := controllerPeer(s, 2)
			ref := peer.Ref
			c.contextDisabled = true
			switch kind {
			case "exited":
				s.snapshot.Threads[1].State = target.StateExited
			case "exiting":
				s.snapshot.Threads[1].Exiting = true
			case "listening":
				s.snapshot.Threads[1].Listening = true
			case "newborn":
				s.snapshot.Threads[1].State = target.StateUnknown
			case "other-process":
				s.snapshot.Threads[1].Process.ID++
			case "other-session":
				ref.Session++
			case "zero":
				ref = target.ThreadRef{}
			}
			if err := c.showStop(context.Background(), target.Stop{Reason: target.StopBreakpoint}, ref); err != nil {
				t.Fatal(err)
			}
			want := original
			if kind == "valid" {
				want = peer.Ref
			}
			if c.selected != want {
				t.Fatalf("selected=%+v want=%+v", c.selected, want)
			}
		})
	}
}

func TestUnlockedStepReportsPeerStopInsteadOfSelectedCompletion(t *testing.T) {
	var output bytes.Buffer
	c, s := runningController(t, &output)
	peer := controllerPeer(s, 2)
	s.operation = controllerTestOperation(func(context.Context) (target.RunResult, error) {
		s.snapshot.State = target.StateStopped
		s.snapshot.Threads[1].Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 12}}
		return target.RunResult{Thread: peer.Ref, Stop: s.snapshot.Threads[1].Stop}, nil
	})
	if err := c.resume(context.Background(), "", true); err != nil || c.selected != peer.Ref || s.snapshot.State != target.StateStopped || !uiOutputHasLine(output.String(), fmt.Sprintf("Thread #2 (TID %d) stopped by SIGUSR2 (12).", peer.TID)) || strings.Contains(output.String(), "Instruction step completed.") || strings.Contains(output.String(), "(instruction step)") {
		t.Fatalf("err=%v selected=%+v output=%q", err, c.selected, output.String())
	}
}

func TestInterruptRequiresRetainedOperation(t *testing.T) {
	c, s := runningController(t, io.Discard)
	if err := c.interruptActive(context.Background()); !errors.Is(err, target.ErrInvalidState) || s.interrupts != 0 {
		t.Fatalf("stopped interrupt err=%v calls=%d", err, s.interrupts)
	}
}

func TestInterruptConfirmsTheSameRetainedOperation(t *testing.T) {
	for _, state := range []target.State{target.StateRunning, target.StateStopped} {
		t.Run(state.String(), func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			s.snapshot.State = state
			waits := 0
			c.active = controllerTestOperation(func(context.Context) (target.RunResult, error) {
				waits++
				s.snapshot.State = target.StateStopped
				s.snapshot.Threads[0].Token.Stop++
				s.snapshot.Threads[0].Stop = target.Stop{Reason: target.StopInterrupt}
				return target.RunResult{Stop: s.snapshot.Threads[0].Stop, Thread: s.snapshot.Threads[0].Ref}, nil
			})
			s.interrupt = func(request target.InterruptRequest) error {
				if request.Threads.Scope != target.ProcessThreads || request.Threads.Process != s.snapshot.Process {
					t.Fatalf("interrupt scope=%+v", request)
				}
				return nil
			}
			if err := c.interruptActive(context.Background()); err != nil || waits != 1 || c.active != nil || c.session != s || s.interrupts != 1 || s.runCalls+s.stepCalls != 0 {
				t.Fatalf("err=%v waits=%d active=%v interrupts=%d", err, waits, c.active, s.interrupts)
			}
			for _, token := range s.registerReads {
				if token != s.snapshot.Threads[0].Token {
					t.Fatalf("stale post-interrupt token=%+v", token)
				}
			}
		})
	}
}

func TestInterruptFailureAndCancellationKeepUnconfirmedOperation(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprintf("interrupt-failure=%t", failure), func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			s.snapshot.State = target.StateRunning
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := errors.New("interrupt failed")
			s.interrupt = func(target.InterruptRequest) error {
				if failure {
					return want
				}
				cancel()
				return nil
			}
			waits := 0
			c.active = controllerTestOperation(func(waitCtx context.Context) (target.RunResult, error) {
				waits++
				if waitCtx.Err() == nil {
					t.Fatal("unbounded wait after failed interrupt")
				}
				return target.RunResult{}, waitCtx.Err()
			})
			err := c.interruptActive(ctx)
			if !errors.Is(err, context.Canceled) || failure && !errors.Is(err, want) || waits != 1 || c.active == nil || c.session != s || len(s.registerReads) != 0 {
				t.Fatalf("err=%v waits=%d active=%v", err, waits, c.active)
			}
			if err := c.setSchedulerLocking("on"); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("setting allowed unconfirmed operation: %v", err)
			}
			if err := c.applyThreads(context.Background(), "all regs"); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("apply allowed unconfirmed operation: %v", err)
			}
		})
	}
}

func TestInterruptFailureCanRecoverAlreadyConfirmedCompletion(t *testing.T) {
	c, s := runningController(t, io.Discard)
	interruptErr := errors.New("interrupt failed")
	waitErr := errors.New("resume failed")
	s.interrupt = func(target.InterruptRequest) error { return interruptErr }
	waits := 0
	c.active = controllerTestOperation(func(ctx context.Context) (target.RunResult, error) {
		waits++
		if ctx.Err() == nil {
			t.Fatal("completion probe was not bounded")
		}
		return target.RunResult{Stop: target.Stop{Reason: target.StopInterrupt}}, waitErr
	})
	err := c.interruptActive(context.Background())
	if !errors.Is(err, interruptErr) || !errors.Is(err, waitErr) || waits != 1 || c.active != nil || c.session != s {
		t.Fatalf("err=%v waits=%d active=%v session=%v", err, waits, c.active, c.session)
	}
}
