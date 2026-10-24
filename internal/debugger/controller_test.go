package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/native"
	"fastdbg2/target"
)

type controllerTestOperation func(context.Context) (target.RunResult, error)

func (f controllerTestOperation) Wait(ctx context.Context) (target.RunResult, error) {
	return f(ctx)
}

type controllerTestSession struct {
	snapshot      target.Snapshot
	pid           int
	pc            uint64
	runCalls      int
	stepCalls     int
	closeCalls    int
	killCalls     int
	detachCalls   int
	interrupts    int
	registerReads []target.ThreadToken
	memoryReads   []target.MemoryToken
	added         []target.Address
	removed       []target.Address
	runRequest    target.RunRequest
	stepRequest   target.StepRequest
	closeError    error
	addError      error
	removeError   error
	snapshotError error
	interrupt     func(target.InterruptRequest) error
	operation     operation
}

func controllerSession(id uint64) *controllerTestSession {
	process := target.ProcessRef{Session: id, ID: 1}
	thread := target.ThreadRef{Session: id, ID: 1}
	token := target.ThreadToken{Thread: thread, Stop: 7, Registers: 11}
	return &controllerTestSession{
		pid: 4400 + int(id), pc: 0x400000 + id*0x1000,
		snapshot: target.Snapshot{
			State: target.StateStopped, Architecture: target.AMD64, Process: process,
			Memory: target.MemoryToken{Space: target.SpaceRef{Session: id, ID: 1}, Revision: 1},
			Threads: []target.ThreadInfo{{
				Ref: thread, Process: process, TID: 4400 + int(id), State: target.StateStopped,
				Token: token, Stop: target.Stop{Reason: target.StopExec, Generation: 1234},
			}},
		},
	}
}

func (s *controllerTestSession) PID() int { return s.pid }

func (s *controllerTestSession) State() target.State { return s.snapshot.State }

func (s *controllerTestSession) Snapshot() (target.Snapshot, error) {
	result := s.snapshot
	result.Threads = slices.Clone(result.Threads)
	return result, s.snapshotError
}

func (s *controllerTestSession) LastStop() target.Stop { return s.snapshot.Threads[0].Stop }

func (s *controllerTestSession) Run(request target.RunRequest) (operation, error) {
	s.runCalls++
	s.runRequest = request
	s.snapshot.State = target.StateRunning
	if s.operation != nil {
		return s.operation, nil
	}
	return controllerTestOperation(func(context.Context) (target.RunResult, error) {
		s.snapshot.State = target.StateExited
		s.snapshot.Threads[0].State = target.StateExited
		code := 0
		stop := target.Stop{Reason: target.StopExited, ExitCode: &code}
		s.snapshot.Threads[0].Stop = stop
		return target.RunResult{Stop: stop, Thread: s.snapshot.Threads[0].Ref}, nil
	}), nil
}

func (s *controllerTestSession) StepInstruction(request target.StepRequest) (operation, error) {
	s.stepCalls++
	s.stepRequest = request
	s.snapshot.State = target.StateRunning
	if s.operation != nil {
		return s.operation, nil
	}
	return controllerTestOperation(func(context.Context) (target.RunResult, error) {
		s.snapshot.State = target.StateStopped
		s.snapshot.Threads[0].Token.Stop++
		s.snapshot.Threads[0].Token.Registers++
		stop := target.Stop{Reason: target.StopStep, StepCompleted: true}
		s.snapshot.Threads[0].Stop = stop
		return target.RunResult{Stop: stop, Thread: s.snapshot.Threads[0].Ref}, nil
	}), nil
}

func (s *controllerTestSession) Interrupt(request target.InterruptRequest) error {
	s.interrupts++
	if s.interrupt != nil {
		return s.interrupt(request)
	}
	return nil
}

func (s *controllerTestSession) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	s.registerReads = append(s.registerReads, token)
	var pc, sp [8]byte
	binary.LittleEndian.PutUint64(pc[:], s.pc)
	binary.LittleEndian.PutUint64(sp[:], 0x800000)
	return []target.Register{
		{Name: "rip", Bits: 64, Available: true, Data: pc[:]},
		{Name: "rsp", Bits: 64, Available: true, Data: sp[:]},
	}, nil
}

func (s *controllerTestSession) ReadSpaceMemory(token target.MemoryToken, _ target.Address, dst []byte) (int, error) {
	s.memoryReads = append(s.memoryReads, token)
	clear(dst)
	return len(dst), nil
}

func (s *controllerTestSession) ReadCodeLocation(target.ThreadToken) (native.CodeLocation, error) {
	return native.CodeLocation{RawPC: target.Address(s.pc), InstructionPC: target.Address(s.pc)}, nil
}

func (s *controllerTestSession) ReadCodeMemory(token target.MemoryToken, _ target.Address, dst []byte) (int, error) {
	s.memoryReads = append(s.memoryReads, token)
	for i := range dst {
		dst[i] = 0x90
	}
	return len(dst), nil
}

func (s *controllerTestSession) AddBreakpoint(address target.Address) error {
	s.added = append(s.added, address)
	s.snapshot.Memory.Revision++
	return s.addError
}

func (s *controllerTestSession) RemoveBreakpoint(address target.Address) error {
	s.removed = append(s.removed, address)
	s.snapshot.Memory.Revision++
	s.snapshot.Threads[0].Token.Registers++
	return s.removeError
}

func (s *controllerTestSession) Kill() error {
	s.killCalls++
	s.snapshot.State = target.StateExited
	return nil
}

func (s *controllerTestSession) Detach() error {
	s.detachCalls++
	s.snapshot.State = target.StateDetached
	return nil
}

func (s *controllerTestSession) Close() error {
	s.closeCalls++
	if s.closeError == nil {
		s.snapshot.State = target.StateClosed
	}
	return s.closeError
}

func configuredController(t *testing.T, output io.Writer) *Controller {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := New(output, display.Renderer{})
	if err := c.Configure(path, []string{"saved"}); err != nil {
		t.Fatal(err)
	}
	return c
}

func runningController(t *testing.T, output io.Writer) (*Controller, *controllerTestSession) {
	t.Helper()
	c := configuredController(t, output)
	s := controllerSession(1)
	c.session, c.owned = s, true
	if err := c.initializeSelection(); err != nil {
		t.Fatal(err)
	}
	return c, s
}

func executeController(t *testing.T, c *Controller, name, arguments string) {
	t.Helper()
	quit, err := c.Execute(context.Background(), name, arguments)
	if err != nil || quit {
		t.Fatalf("%s %s: quit=%t err=%v", name, arguments, quit, err)
	}
}

func TestControllerStartRunRestartAndLiteralArguments(t *testing.T) {
	var output bytes.Buffer
	c := configuredController(t, &output)
	var sessions []*controllerTestSession
	var launches [][]string
	c.launch = func(_ string, args []string) (session, error) {
		launches = append(launches, slices.Clone(args))
		s := controllerSession(uint64(len(launches)))
		sessions = append(sessions, s)
		return s, nil
	}
	executeController(t, c, "break", "$rip + 2")
	executeController(t, c, "start", "'two words' '' '$literal' `literal`")
	wantArgs := []string{"two words", "", "$literal", "`literal`"}
	if !reflect.DeepEqual(launches[0], wantArgs) || sessions[0].runCalls != 0 {
		t.Fatalf("start args=%q run calls=%d", launches[0], sessions[0].runCalls)
	}
	if !reflect.DeepEqual(sessions[0].added, []target.Address{target.Address(sessions[0].pc + 2)}) {
		t.Fatalf("initial breakpoint=%v", sessions[0].added)
	}
	executeController(t, c, "run", "")
	if sessions[0].closeCalls != 1 || sessions[1].runCalls != 1 || !reflect.DeepEqual(launches[1], wantArgs) {
		t.Fatalf("restart old close=%d new runs=%d args=%q", sessions[0].closeCalls, sessions[1].runCalls, launches[1])
	}
	if !reflect.DeepEqual(sessions[1].added, []target.Address{target.Address(sessions[1].pc + 2)}) {
		t.Fatalf("breakpoint was not re-evaluated: %v", sessions[1].added)
	}
	if c.breakpoints[0].id != 1 || c.breakpoints[0].expression != "$rip + 2" || c.breakpoints[0].installed {
		t.Fatalf("logical breakpoint after exit=%+v", c.breakpoints[0])
	}
	if strings.Count(output.String(), "Started native amd64") != 2 || !uiOutputHasLine(output.String(), fmt.Sprintf("Process %d exited (code 0).", sessions[1].pid)) || sessions[1].State() != target.StateExited || sessions[1].LastStop().Reason != target.StopExited {
		t.Fatalf("output=%s", output.String())
	}
}

func TestControllerRestartCloseFailureRetainsSession(t *testing.T) {
	c, s := runningController(t, io.Discard)
	want := errors.New("close failed")
	s.closeError = want
	c.launch = func(string, []string) (session, error) {
		t.Fatal("launch after failed close")
		return nil, nil
	}
	_, err := c.Execute(context.Background(), "start", "")
	if !errors.Is(err, want) || c.session != s || !c.owned || s.closeCalls != 1 {
		t.Fatalf("err=%v session=%v close=%d", err, c.session, s.closeCalls)
	}
}

func TestControllerAttachedCannotRestart(t *testing.T) {
	for _, command := range []string{"start", "run"} {
		t.Run(command, func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			c.owned = false
			_, err := c.Execute(context.Background(), command, "")
			if !errors.Is(err, target.ErrInvalidState) || s.closeCalls != 0 || c.session != s {
				t.Fatalf("err=%v close=%d session=%v", err, s.closeCalls, c.session)
			}
		})
	}
}

func TestControllerPartialInitializationAndQuitFailure(t *testing.T) {
	c := configuredController(t, io.Discard)
	s := controllerSession(2)
	initializeErr := errors.New("initialization cleanup incomplete")
	s.closeError = errors.New("close still incomplete")
	c.launch = func(string, []string) (session, error) { return s, initializeErr }
	if _, err := c.Execute(context.Background(), "start", ""); !errors.Is(err, initializeErr) || c.session != s {
		t.Fatalf("initialization err=%v session=%v", err, c.session)
	}
	if quit, err := c.Execute(context.Background(), "quit", ""); quit || !errors.Is(err, s.closeError) || c.session != s {
		t.Fatalf("failed quit=%t err=%v session=%v", quit, err, c.session)
	}
	s.closeError = nil
	if quit, err := c.Execute(context.Background(), "exit", ""); !quit || err != nil || c.session != nil {
		t.Fatalf("successful quit=%t err=%v session=%v", quit, err, c.session)
	}
}

func TestControllerPartialAttachRetainsUnownedSession(t *testing.T) {
	c := New(io.Discard, display.Renderer{})
	s := controllerSession(3)
	want := errors.New("partial attach")
	c.attach = func(int) (session, error) { return s, want }
	_, err := c.Execute(context.Background(), "attach", fmtInt(os.Getpid()))
	if !errors.Is(err, want) || c.session != s || c.owned {
		t.Fatalf("err=%v session=%v owned=%t", err, c.session, c.owned)
	}
	if err := c.Close(); err != nil || s.closeCalls != 1 {
		t.Fatalf("close err=%v calls=%d", err, s.closeCalls)
	}
}

func fmtInt(value int) string {
	return strconv.Itoa(value)
}

func TestControllerBreakpointErrorsPreventAutomaticRun(t *testing.T) {
	tests := []struct {
		name        string
		expressions []string
		addError    error
		want        error
		addCalls    int
	}{
		{"duplicate", []string{"0x400000", "0x400000"}, nil, target.ErrInvalidArgument, 1},
		{"invalid", []string{"1 +"}, nil, target.ErrInvalidArgument, 0},
		{"backend", []string{"0x400000"}, target.ErrPartial, target.ErrPartial, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := configuredController(t, io.Discard)
			s := controllerSession(1)
			s.addError = test.addError
			c.launch = func(string, []string) (session, error) { return s, nil }
			for _, expression := range test.expressions {
				executeController(t, c, "break", expression)
			}
			_, err := c.Execute(context.Background(), "run", "")
			if !errors.Is(err, test.want) || s.runCalls != 0 || c.session != s || len(s.added) != test.addCalls {
				t.Fatalf("err=%v runs=%d session=%v added=%v", err, s.runCalls, c.session, s.added)
			}
		})
	}
}

func TestControllerBreakpointDeletePreservesFailedNativeOwnership(t *testing.T) {
	c, s := runningController(t, io.Discard)
	executeController(t, c, "b", "0x400000")
	s.removeError = target.ErrPartial
	if _, err := c.Execute(context.Background(), "delete", "1"); !errors.Is(err, target.ErrPartial) || len(c.breakpoints) != 1 {
		t.Fatalf("err=%v breakpoints=%v", err, c.breakpoints)
	}
	s.removeError = nil
	executeController(t, c, "delete", "1")
	if len(c.breakpoints) != 0 || len(s.removed) != 2 {
		t.Fatalf("breakpoints=%v removed=%v", c.breakpoints, s.removed)
	}
	if c.snapshot.Memory.Revision != s.snapshot.Memory.Revision || c.snapshot.Threads[0].Token != s.snapshot.Threads[0].Token {
		t.Fatal("mutation did not refresh memory and register tokens")
	}
}

func TestControllerSignalDecisionsAreExplicitPerStopToken(t *testing.T) {
	for _, test := range []struct {
		option string
		number uint32
		err    bool
	}{
		{"", 0, true}, {"--deliver", 10, false}, {"--suppress", 0, false}, {"--signal 10", 0, true},
	} {
		t.Run(test.option, func(t *testing.T) {
			s := controllerSession(1)
			thread := s.snapshot.Threads[0]
			thread.Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 10}, Generation: 9999}
			second := thread
			second.Ref.ID, second.TID, second.Token.Thread.ID, second.Token.Stop = 2, thread.TID+1, 2, 19
			decisions, err := signalDecisions(test.option, []target.ThreadInfo{thread, second})
			if (err != nil) != test.err {
				t.Fatalf("decisions=%v err=%v", decisions, err)
			}
			if test.err {
				return
			}
			if len(decisions) != 2 || decisions[0].Stop != thread.Token.Stop || decisions[1].Stop != second.Token.Stop ||
				decisions[0].Signal.Number != test.number || decisions[1].Signal.Number != test.number {
				t.Fatalf("decisions=%v", decisions)
			}
		})
	}
}

func TestControllerStepDoesNotDecideOtherThreadsSignals(t *testing.T) {
	c, s := runningController(t, io.Discard)
	c.schedulerLocking = "step"
	second := s.snapshot.Threads[0]
	second.Ref.ID, second.Token.Thread.ID, second.TID = 2, 2, second.TID+1
	second.Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 10}}
	s.snapshot.Threads = append(s.snapshot.Threads, second)
	executeController(t, c, "si", "")
	if s.stepCalls != 1 || len(s.stepRequest.Signals) != 0 || s.stepRequest.Thread != c.selected ||
		len(s.stepRequest.Continue.Threads) != 0 || s.stepRequest.Continue.Scope != target.ExactThreads {
		t.Fatalf("step request=%+v", s.stepRequest)
	}
}

func TestControllerCancelInterruptsAndWaitsForConfirmedStop(t *testing.T) {
	c, s := runningController(t, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waited int
	s.operation = controllerTestOperation(func(waitCtx context.Context) (target.RunResult, error) {
		waited++
		if waited == 1 {
			cancel()
			return target.RunResult{}, waitCtx.Err()
		}
		if waitCtx.Err() != nil || s.interrupts != 1 {
			t.Fatalf("completion wait ctx=%v interrupts=%d", waitCtx.Err(), s.interrupts)
		}
		s.snapshot.State = target.StateStopped
		s.snapshot.Threads[0].Token.Stop++
		s.snapshot.Threads[0].Token.Registers++
		s.snapshot.Threads[0].Stop = target.Stop{Reason: target.StopInterrupt}
		return target.RunResult{Stop: s.snapshot.Threads[0].Stop, Thread: s.snapshot.Threads[0].Ref}, nil
	})
	s.interrupt = func(request target.InterruptRequest) error {
		if request.Threads.Scope != target.ProcessThreads || request.Threads.Process != s.snapshot.Process {
			t.Fatalf("interrupt request=%+v", request)
		}
		return nil
	}
	quit, err := c.Execute(ctx, "continue", "")
	if err != nil || quit || waited != 2 || c.active != nil || c.snapshot.State != target.StateStopped {
		t.Fatalf("quit=%t err=%v waits=%d active=%v state=%v", quit, err, waited, c.active, c.snapshot.State)
	}
	for _, token := range s.registerReads {
		if token != s.snapshot.Threads[0].Token {
			t.Fatalf("stale token read=%+v latest=%+v", token, s.snapshot.Threads[0].Token)
		}
	}
}

func TestControllerInterruptFailureKeepsCleanupOnlyOperation(t *testing.T) {
	c, s := runningController(t, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.operation = controllerTestOperation(func(waitCtx context.Context) (target.RunResult, error) {
		cancel()
		return target.RunResult{}, waitCtx.Err()
	})
	want := errors.New("interrupt unavailable")
	s.interrupt = func(target.InterruptRequest) error { return want }
	_, err := c.Execute(ctx, "continue", "")
	if !errors.Is(err, want) || c.active == nil || c.session != s || c.snapshot.State != target.StateRunning {
		t.Fatalf("err=%v active=%v session=%v state=%v", err, c.active, c.session, c.snapshot.State)
	}
	for _, command := range []struct{ name, args string }{
		{"continue", ""}, {"step", ""}, {"context", ""}, {"regs", ""}, {"memory", "0x400000"},
		{"break", "0x400000"}, {"break", "list"}, {"delete", "1"}, {"thread", fmtInt(s.pid)},
	} {
		if _, err := c.Execute(context.Background(), command.name, command.args); !errors.Is(err, target.ErrBusy) {
			t.Fatalf("%s allowed cleanup-only state: %v", command.name, err)
		}
	}
	s.closeError = target.ErrPartial
	if err := c.Close(); !errors.Is(err, target.ErrPartial) || c.session != s || c.active == nil {
		t.Fatalf("failed close err=%v session=%v active=%v", err, c.session, c.active)
	}
	s.closeError = nil
	if err := c.Close(); err != nil || c.session != nil || c.active != nil {
		t.Fatalf("close err=%v session=%v active=%v", err, c.session, c.active)
	}
}

func TestControllerSelectionNeverFallsBackOrCrossesProcess(t *testing.T) {
	c, s := runningController(t, io.Discard)
	c.selected.ID = 999
	if _, _, err := c.stopped(); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("missing selection err=%v", err)
	}
	child := s.snapshot.Threads[0]
	child.TID++
	child.Ref.ID, child.Token.Thread.ID, child.Process.ID = 2, 2, 2
	s.snapshot.Threads = append(s.snapshot.Threads, child)
	if err := c.selectThread(child.TID); !errors.Is(err, target.ErrUnsupported) || c.selected.ID != 999 {
		t.Fatalf("cross-process selection err=%v selected=%v", err, c.selected)
	}
}

func TestControllerRejectsArchitectureChangeAndRetainsFailedCleanup(t *testing.T) {
	c := configuredController(t, io.Discard)
	s := controllerSession(1)
	s.snapshot.Architecture = target.AArch64
	s.closeError = target.ErrPartial
	c.launch = func(string, []string) (session, error) { return s, nil }
	_, err := c.Execute(context.Background(), "start", "")
	if !errors.Is(err, target.ErrUnsupported) || !errors.Is(err, target.ErrPartial) || c.session != s || s.closeCalls != 1 {
		t.Fatalf("err=%v session=%v closes=%d", err, c.session, s.closeCalls)
	}
}

func TestControllerReleaseAndCommandValidation(t *testing.T) {
	for _, command := range []string{"kill", "detach"} {
		t.Run(command, func(t *testing.T) {
			c, s := runningController(t, io.Discard)
			executeController(t, c, command, "")
			if c.session != nil || s.closeCalls != 1 || s.killCalls+s.detachCalls != 1 {
				t.Fatalf("session=%v closes=%d kill=%d detach=%d", c.session, s.closeCalls, s.killCalls, s.detachCalls)
			}
		})
	}
	c := New(io.Discard, display.Renderer{})
	for _, command := range []struct{ name, args string }{
		{"quit", "now"}, {"help", "extra"}, {"attach", "-1"}, {"attach", "1 2"}, {"thread", "0"}, {"delete", "0x1"},
	} {
		if quit, err := c.Execute(context.Background(), command.name, command.args); quit || !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%s %s quit=%t err=%v", command.name, command.args, quit, err)
		}
	}
	if _, err := c.Execute(context.Background(), "unknown\x1b[31m", ""); err == nil || strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("unescaped unknown command error=%v", err)
	}
}

type controllerTestWriter func([]byte) (int, error)

func (f controllerTestWriter) Write(data []byte) (int, error) { return f(data) }

func TestControllerOutputFailuresAreTypedAndShortWritesDetected(t *testing.T) {
	want := errors.New("output unavailable")
	for _, writer := range []io.Writer{
		controllerTestWriter(func([]byte) (int, error) { return 0, want }),
		controllerTestWriter(func([]byte) (int, error) { return 0, nil }),
	} {
		c := New(writer, display.Renderer{})
		_, err := c.Execute(context.Background(), "help", "")
		var outputError *OutputError
		if !errors.As(err, &outputError) || !(errors.Is(err, want) || errors.Is(err, io.ErrShortWrite)) {
			t.Fatalf("output err=%v", err)
		}
	}
}
