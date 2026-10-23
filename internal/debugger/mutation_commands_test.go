package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"fastdbg2/target"
)

type mutationMemoryWrite struct {
	token   target.MemoryToken
	address target.Address
	data    []byte
}

type mutationRegisterWrite struct {
	token     target.ThreadToken
	registers []target.Register
}

type mutationTestSession struct {
	*controllerTestSession
	snapshots        int
	registerErr      error
	registerWriteErr error
	memoryWriteErr   error
	memoryCount      *int
	readCount        *int
	readErr          error
	readData         []byte
	afterWrite       func()
	afterRead        func()
	registerWrites   []mutationRegisterWrite
	memoryWrites     []mutationMemoryWrite
	watchRequests    []target.WatchpointRequest
	watchTokens      []target.ThreadToken
	watchClears      []target.WatchpointRef
	clearTokens      []target.ThreadToken
	watchErr         error
	clearErr         error
	generation       uint64
	editWatchResult  func(*target.WatchpointResult)
}

func mutationController(t *testing.T, output io.Writer) (*Controller, *mutationTestSession) {
	t.Helper()
	c, base := runningController(t, output)
	s := &mutationTestSession{controllerTestSession: base, readData: make([]byte, 8)}
	binary.LittleEndian.PutUint64(s.readData, 0x1122334455667788)
	c.session = s
	return c, s
}

func (s *mutationTestSession) Snapshot() (target.Snapshot, error) {
	s.snapshots++
	return s.controllerTestSession.Snapshot()
}

func (s *mutationTestSession) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	registers, err := s.controllerTestSession.ReadThreadRegisters(token)
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], 0x1000)
	registers = append(registers, target.Register{Name: "rax", Bits: 64, Available: true, Data: data[:]})
	var flags [8]byte
	binary.LittleEndian.PutUint64(flags[:], 0x202)
	registers = append(registers, target.Register{Name: "eflags", Bits: 64, Available: true, Data: flags[:]})
	return registers, errors.Join(err, s.registerErr)
}

func (s *mutationTestSession) ReadSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	n, err := s.controllerTestSession.ReadSpaceMemory(token, address, data)
	copy(data, s.readData)
	if s.readCount != nil {
		n = *s.readCount
	}
	if s.afterRead != nil {
		s.afterRead()
	}
	return n, errors.Join(err, s.readErr)
}

func (s *mutationTestSession) advanceRegisterToken(ref target.ThreadRef) target.ThreadToken {
	for i := range s.snapshot.Threads {
		if s.snapshot.Threads[i].Ref == ref {
			s.snapshot.Threads[i].Token.Registers++
			return s.snapshot.Threads[i].Token
		}
	}
	return target.ThreadToken{}
}

func (s *mutationTestSession) WriteThreadRegisters(token target.ThreadToken, registers []target.Register) error {
	registers = slices.Clone(registers)
	for i := range registers {
		registers[i].Data = slices.Clone(registers[i].Data)
	}
	s.registerWrites = append(s.registerWrites, mutationRegisterWrite{token, registers})
	s.advanceRegisterToken(token.Thread)
	if s.afterWrite != nil {
		s.afterWrite()
	}
	return s.registerWriteErr
}

func (s *mutationTestSession) WriteSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	s.memoryWrites = append(s.memoryWrites, mutationMemoryWrite{token, address, slices.Clone(data)})
	s.snapshot.Memory.Revision++
	if s.afterWrite != nil {
		s.afterWrite()
	}
	n := len(data)
	if s.memoryCount != nil {
		n = *s.memoryCount
	}
	return n, s.memoryWriteErr
}

func TestMutationSetRegisterNeverFallsThroughToMemory(t *testing.T) {
	for _, destination := range []string{"rax", "$rax", "RAX", "$RAX"} {
		t.Run(destination, func(t *testing.T) {
			var output bytes.Buffer
			c, s := mutationController(t, &output)
			before := s.snapshot.Threads[0].Token
			s.snapshot.Threads[0].Stop = target.Stop{Reason: target.StopSignal, Signal: target.Signal{Domain: target.SignalLinux, Number: 10}}
			if err := c.commandSet(context.Background(), destination+` "$rax + 3"`, 64); err != nil {
				t.Fatal(err)
			}
			if s.snapshots != 2 || len(s.registerWrites) != 1 || len(s.memoryWrites) != 0 || len(s.registerReads) != 1 || s.registerReads[0] != before {
				t.Fatalf("snapshots=%d registers=%+v memory=%+v reads=%+v", s.snapshots, s.registerWrites, s.memoryWrites, s.registerReads)
			}
			write := s.registerWrites[0]
			if write.token != before || len(write.registers) != 1 || write.registers[0].Name != "rax" || write.registers[0].Bits != 64 || !write.registers[0].Available || binary.LittleEndian.Uint64(write.registers[0].Data) != 0x1003 {
				t.Fatalf("write=%+v", write)
			}
			if c.snapshot.Threads[0].Token == before || s.snapshot.Threads[0].Stop.Signal.Number != 10 || s.runCalls+s.stepCalls != 0 || !strings.Contains(output.String(), "$rax requested=0x1003") {
				t.Fatalf("snapshot=%+v output=%q", c.snapshot, output.String())
			}
		})
	}
}

func TestMutationSetMemoryUsesExactWidthsAndOneSnapshot(t *testing.T) {
	for _, bits := range []int{8, 16, 32, 64} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			c, s := mutationController(t, io.Discard)
			before := s.snapshot.Memory
			if err := c.commandSet(context.Background(), `"$rsp + 16" = 0xab`, bits); err != nil {
				t.Fatal(err)
			}
			if len(s.memoryWrites) != 1 || len(s.registerWrites) != 0 || s.snapshots != 2 || len(s.registerReads) != 1 {
				t.Fatalf("writes=%+v registers=%+v snapshots=%d", s.memoryWrites, s.registerWrites, s.snapshots)
			}
			write := s.memoryWrites[0]
			if write.token != before || write.address != 0x800010 || len(write.data) != bits/8 || write.data[0] != 0xab || c.snapshot.Memory.Revision != before.Revision+1 {
				t.Fatalf("write=%+v snapshot=%+v", write, c.snapshot.Memory)
			}
			for _, b := range write.data[1:] {
				if b != 0 {
					t.Fatalf("not little-endian: %x", write.data)
				}
			}
		})
	}
	c, s := mutationController(t, io.Discard)
	if err := c.commandSet(context.Background(), "$rax 1", 8); err != nil || s.memoryWrites[0].address != 0x1000 || len(s.registerWrites) != 0 {
		t.Fatalf("narrow set unexpectedly wrote a register: err=%v writes=%+v", err, s.memoryWrites)
	}
}

func TestMutationInvalidInputHasNoWriteSideEffects(t *testing.T) {
	for _, test := range []struct {
		args string
		bits int
	}{
		{"", 64}, {"rax", 64}, {"rax 1 2", 64}, {"rax = 1 + 2", 64}, {"\"rax 1", 64},
		{"$unknown 1", 64}, {"rax -1", 64}, {"0x1000 256", 8}, {"0x1000 65536", 16},
		{"0x1000 0x100000000", 32}, {"0xffffffffffffffff 1", 64}, {"0x1000 1", 24},
	} {
		c, s := mutationController(t, io.Discard)
		if err := c.commandSet(context.Background(), test.args, test.bits); err == nil || len(s.registerWrites)+len(s.memoryWrites) != 0 {
			t.Fatalf("args=%q bits=%d err=%v", test.args, test.bits, err)
		}
	}
}

func TestMutationWriteErrorsRefreshAndRetainSession(t *testing.T) {
	for _, registers := range []bool{false, true} {
		var output bytes.Buffer
		c, s := mutationController(t, &output)
		want := &target.PartialError{Op: "fixture write", Total: 1, Err: target.ErrUnavailable}
		args := "0x1000 1"
		if registers {
			args, s.registerWriteErr = "rax 1", want
		} else {
			s.memoryWriteErr = want
		}
		err := c.commandSet(context.Background(), args, 64)
		if !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrUnavailable) || s.snapshots != 2 || c.session != s || output.Len() != 0 || len(s.registerWrites)+len(s.memoryWrites) != 1 {
			t.Fatalf("registers=%t err=%v snapshots=%d session=%v output=%q", registers, err, s.snapshots, c.session, output.String())
		}
	}
}

func TestMutationMemoryCountFailuresNeverReportSuccessOrRetry(t *testing.T) {
	for _, test := range []struct {
		n    int
		err  error
		want error
	}{
		{0, nil, io.ErrShortWrite}, {3, nil, target.ErrPartial}, {8, target.ErrUnavailable, target.ErrUnavailable},
		{-1, nil, target.ErrUnknown}, {9, nil, target.ErrUnknown},
	} {
		var output bytes.Buffer
		c, s := mutationController(t, &output)
		s.memoryCount, s.memoryWriteErr = &test.n, test.err
		err := c.commandSet(context.Background(), "0x1000 1", 64)
		if !errors.Is(err, test.want) || s.snapshots != 2 || len(s.memoryWrites) != 1 || output.Len() != 0 {
			t.Fatalf("n=%d err=%v writes=%+v snapshots=%d output=%q", test.n, err, s.memoryWrites, s.snapshots, output.String())
		}
		if test.n >= 0 && test.n <= 8 && !strings.Contains(err.Error(), fmt.Sprintf("%d/8 bytes confirmed", test.n)) {
			t.Fatalf("confirmed count missing: %v", err)
		}
	}
}

func TestMutationPreservesWriteAndRefreshErrors(t *testing.T) {
	c, s := mutationController(t, io.Discard)
	writeErr, snapshotErr := errors.New("write failed"), errors.New("snapshot failed")
	s.memoryWriteErr = writeErr
	s.afterWrite = func() { s.snapshotError = snapshotErr }
	err := c.commandSet(context.Background(), "0x1000 1", 64)
	if !errors.Is(err, writeErr) || !errors.Is(err, snapshotErr) || len(s.memoryWrites) != 1 || c.session != s {
		t.Fatalf("err=%v writes=%+v session=%v", err, s.memoryWrites, c.session)
	}
}

func TestMutationChangedImageAfterWriteIsNotSuccess(t *testing.T) {
	var output bytes.Buffer
	c, s := mutationController(t, &output)
	s.afterWrite = func() { s.snapshot.Memory.Space.ID++ }
	if err := c.commandSet(context.Background(), "rax 1", 64); !errors.Is(err, target.ErrStale) || len(s.registerWrites) != 1 || output.Len() != 0 {
		t.Fatalf("err=%v writes=%+v output=%q", err, s.registerWrites, output.String())
	}
}

func TestMutationXorReadsAndWritesExactlyEightBytesWithSameToken(t *testing.T) {
	var output bytes.Buffer
	c, s := mutationController(t, &output)
	before := s.snapshot.Memory
	if err := c.commandXor(context.Background(), `"$rax + 8" 0xff`); err != nil {
		t.Fatal(err)
	}
	if len(s.memoryReads) != 1 || s.memoryReads[0] != before || len(s.memoryWrites) != 1 || s.memoryWrites[0].token != before || s.memoryWrites[0].address != 0x1008 || binary.LittleEndian.Uint64(s.memoryWrites[0].data) != 0x1122334455667777 || s.snapshots != 2 {
		t.Fatalf("reads=%+v writes=%+v snapshots=%d", s.memoryReads, s.memoryWrites, s.snapshots)
	}
	if !strings.Contains(output.String(), "bytes=8: 0x1122334455667788 ^ 0xff = 0x1122334455667777") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestMutationXorNeverWritesAfterIncompleteOrFailedRead(t *testing.T) {
	for _, test := range []struct {
		n   int
		err error
	}{{0, nil}, {4, nil}, {-1, nil}, {9, nil}, {8, target.ErrStale}, {8, target.ErrUnavailable}} {
		c, s := mutationController(t, io.Discard)
		s.readCount, s.readErr = &test.n, test.err
		if err := c.commandXor(context.Background(), "0x1000 1"); err == nil || len(s.memoryWrites) != 0 || s.snapshots != 1 {
			t.Fatalf("n=%d err=%v writes=%+v snapshots=%d", test.n, err, s.memoryWrites, s.snapshots)
		}
	}
}

func TestMutationCancellationAfterReadPreventsWrite(t *testing.T) {
	c, s := mutationController(t, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.afterRead = cancel
	if err := c.commandXor(ctx, "0x1000 1"); !errors.Is(err, context.Canceled) || len(s.memoryWrites) != 0 {
		t.Fatalf("err=%v writes=%+v", err, s.memoryWrites)
	}
}

func TestMutationOutputFailureDoesNotRepeatConfirmedWrite(t *testing.T) {
	want := errors.New("output failed")
	c, s := mutationController(t, controllerTestWriter(func([]byte) (int, error) { return 0, want }))
	err := c.commandSet(context.Background(), "rax 1", 64)
	var outputErr *OutputError
	if !errors.Is(err, want) || !errors.As(err, &outputErr) || len(s.registerWrites) != 1 || c.session != s || s.snapshots != 2 {
		t.Fatalf("err=%v writes=%+v snapshots=%d", err, s.registerWrites, s.snapshots)
	}
}

func TestMutationOptionalCapabilitiesAndActiveState(t *testing.T) {
	c, _ := runningController(t, io.Discard)
	if err := c.commandSet(context.Background(), "rip 1", 64); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("missing register capability: %v", err)
	}
	if err := c.commandSet(context.Background(), "0x1000 1", 8); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("missing memory capability: %v", err)
	}
	c, s := mutationController(t, io.Discard)
	c.active = controllerTestOperation(func(context.Context) (target.RunResult, error) { return target.RunResult{}, nil })
	for _, command := range []func() error{
		func() error { return c.commandSet(context.Background(), "rax 1", 64) },
		func() error { return c.commandXor(context.Background(), "0x1000 1") },
		func() error { return c.commandWatch(context.Background(), "0x1000") },
	} {
		if err := command(); !errors.Is(err, target.ErrBusy) {
			t.Fatalf("unconfirmed operation was bypassed: %v", err)
		}
	}
	if len(s.memoryWrites)+len(s.registerWrites)+len(s.watchRequests) != 0 {
		t.Fatal("active-operation mutation reached backend")
	}
}

func TestMutationRegisterSelectionRejectsDuplicateOrUnavailableSchema(t *testing.T) {
	register := target.Register{Name: "rax", Bits: 64, Available: true, Data: make([]byte, 8)}
	if _, err := mutationRegister("rax", []target.Register{register, register}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("duplicate register err=%v", err)
	}
	register.Available = false
	if _, err := mutationRegister("rax", []target.Register{register}); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("unavailable register err=%v", err)
	}
	if data, err := mutationBytes(0x12345678, 32); err != nil || !reflect.DeepEqual(data, []byte{0x78, 0x56, 0x34, 0x12}) {
		t.Fatalf("bytes=%x err=%v", data, err)
	}
}

func TestMutationRegisterWriteReportsRequestWithoutInventingNormalizedValue(t *testing.T) {
	var output bytes.Buffer
	c, s := mutationController(t, &output)
	if err := c.commandSet(context.Background(), "eflags 0", 64); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "$eflags requested=0x0") || strings.Contains(output.String(), "$eflags = 0x0") || strings.Contains(output.String(), "actual=") {
		t.Fatalf("request was represented as an actual register value: %q", output.String())
	}
	registers, err := s.ReadThreadRegisters(c.snapshot.Threads[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := (expressionResolver{registers: registers}).ResolveRegister("eflags")
	if err != nil || actual != 0x202 {
		t.Fatalf("normalized fixture value=%#x err=%v", actual, err)
	}
}
