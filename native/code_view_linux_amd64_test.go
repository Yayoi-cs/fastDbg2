package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/native/x86"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func codeViewSession(t *testing.T, path string) *Session {
	t.Helper()
	s, err := Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	coreOwnSession(t, s)
	return s
}

func codeViewHit(t *testing.T, s *Session, address target.Address) target.Snapshot {
	t.Helper()
	if err := s.AddBreakpoint(address); err != nil {
		t.Fatal(err)
	}
	stop, err := coreContinue(t, s)
	if err != nil || stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != address {
		t.Fatalf("breakpoint stop=%+v error=%v", stop, err)
	}
	return nativeDataSnapshot(t, s)
}

func codeViewLocation(t *testing.T, s *Session, snapshot target.Snapshot, raw, instruction target.Address, breakpoint bool) CodeLocation {
	t.Helper()
	location, err := s.ReadCodeLocation(snapshot.Threads[0].Token)
	if err != nil || location.RawPC != raw || location.InstructionPC != instruction || (location.Breakpoint != nil) != breakpoint {
		t.Fatalf("location=%+v error=%v, want raw=%#x instruction=%#x breakpoint=%v", location, err, raw, instruction, breakpoint)
	}
	if breakpoint && *location.Breakpoint != instruction {
		t.Fatalf("breakpoint=%#x instruction=%#x", *location.Breakpoint, instruction)
	}
	return location
}

func TestNativeCodeViewReadOnlyBreakpointOverlay(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n mov $0x12345678, %eax\n nop\n jmp _start\n")
	s := codeViewSession(t, path)
	initial := nativeDataSnapshot(t, s)
	codeViewLocation(t, s, initial, entry, entry, false)
	original := make([]byte, 8)
	if n, err := s.ReadSpaceMemory(initial.Memory, entry, original); n != len(original) || err != nil {
		t.Fatalf("initial raw n=%d error=%v", n, err)
	}
	if err := s.AddBreakpoint(entry); err != nil {
		t.Fatal(err)
	}
	armed := nativeDataSnapshot(t, s)
	codeViewLocation(t, s, armed, entry, entry, false)
	if n, err := s.ReadCodeMemory(initial.Memory, entry, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("old memory token n=%d error=%v", n, err)
	}
	stop, err := coreContinue(t, s)
	if err != nil || stop.Reason != target.StopBreakpoint {
		t.Fatalf("stop=%+v error=%v", stop, err)
	}
	before := nativeDataSnapshot(t, s)
	location := codeViewLocation(t, s, before, entry+1, entry, true)
	*location.Breakpoint = entry + 100
	codeViewLocation(t, s, before, entry+1, entry, true)
	for iteration := 0; iteration < 2; iteration++ {
		raw, code := make([]byte, len(original)), make([]byte, len(original))
		if n, err := s.ReadSpaceMemory(before.Memory, entry, raw); n != len(raw) || err != nil {
			t.Fatalf("raw n=%d error=%v", n, err)
		}
		if raw[0] != 0xcc || !bytes.Equal(raw[1:], original[1:]) {
			t.Fatalf("raw bytes=%x original=%x", raw, original)
		}
		if n, err := s.ReadCodeMemory(before.Memory, entry, code); n != len(code) || err != nil || !bytes.Equal(code, original) {
			t.Fatalf("code=%x n=%d error=%v original=%x", code, n, err, original)
		}
		code[0] ^= 0xff
	}
	registers, err := s.ReadThreadRegisters(before.Threads[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	foundPC := false
	for _, register := range registers {
		if register.Name == "rip" {
			foundPC = true
			if target.Address(binary.LittleEndian.Uint64(register.Data)) != entry+1 {
				t.Fatalf("raw rip changed: %x", register.Data)
			}
		}
	}
	if !foundPC {
		t.Fatal("raw rip is missing")
	}
	if after := nativeDataSnapshot(t, s); !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only view changed snapshot before=%+v after=%+v", before, after)
	}
}

func TestNativeCodeViewBreakpointLifecycle(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n mov $0x12345678, %eax\n nop\n jmp _start\n")
	for _, mode := range []string{"remove", "step", "write-pc", "write-general", "suspended", "rewound"} {
		t.Run(mode, func(t *testing.T) {
			s := codeViewSession(t, path)
			before := codeViewHit(t, s, entry)
			wantPC, wantBreakpoint := entry, false
			switch mode {
			case "remove":
				if err := s.RemoveBreakpoint(entry); err != nil {
					t.Fatal(err)
				}
			case "step":
				run, err := s.StepInstruction(target.StepRequest{Thread: before.Threads[0].Ref})
				if err != nil {
					t.Fatal(err)
				}
				result, err := coreWait(t, run)
				if err != nil || result.Stop.Reason != target.StopStep {
					t.Fatalf("step result=%+v error=%v", result, err)
				}
				wantPC = entry + 5
			case "write-pc", "write-general":
				register := target.Register{Name: "rip", Bits: 64, Data: make([]byte, 8), Available: true}
				binary.LittleEndian.PutUint64(register.Data, uint64(entry+5))
				wantPC = entry + 5
				if mode == "write-general" {
					register.Name = "rbx"
					wantPC, wantBreakpoint = entry+1, true
				}
				if err := s.WriteThreadRegisters(before.Threads[0].Token, []target.Register{register}); err != nil {
					t.Fatal(err)
				}
			case "suspended", "rewound":
				if err := command(s, func(e *engine) error {
					th, err := e.requireThread(before.Threads[0].Token)
					if err != nil {
						return err
					}
					if mode == "rewound" {
						return e.rewindBreakpointHit(th)
					}
					_, err = e.prepareBreakpointStep(th)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				wantBreakpoint = mode == "rewound"
			}
			if _, err := s.ReadCodeLocation(before.Threads[0].Token); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old thread token error=%v", err)
			}
			after := nativeDataSnapshot(t, s)
			instruction := wantPC
			if wantBreakpoint {
				instruction = entry
			}
			codeViewLocation(t, s, after, wantPC, instruction, wantBreakpoint)
			code := make([]byte, 5)
			if n, err := s.ReadCodeMemory(after.Memory, entry, code); n != len(code) || err != nil || !bytes.Equal(code, []byte{0xb8, 0x78, 0x56, 0x34, 0x12}) {
				t.Fatalf("code=%x n=%d error=%v", code, n, err)
			}
			if current := nativeDataSnapshot(t, s); !reflect.DeepEqual(after, current) {
				t.Fatal("code inspection changed lifecycle state")
			}
			if mode != "step" && (after.Threads[0].Stop.Breakpoint == nil || *after.Threads[0].Stop.Breakpoint != entry) {
				t.Fatal("fixture did not retain its historical breakpoint stop")
			}
		})
	}
}

func TestNativeCodeViewUnknownINT3IsNotAdjusted(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n int3\n nop\n jmp _start\n")
	s := codeViewSession(t, path)
	initial := nativeDataSnapshot(t, s)
	data := make([]byte, 2)
	if n, err := s.ReadCodeMemory(initial.Memory, entry, data); n != 2 || err != nil || !bytes.Equal(data, []byte{0xcc, 0x90}) {
		t.Fatalf("unknown INT3=%x n=%d error=%v", data, n, err)
	}
	stop, err := coreContinue(t, s)
	if err != nil || stop.Reason != target.StopSignal || stop.Signal.Number != uint32(unix.SIGTRAP) {
		t.Fatalf("unknown INT3 stop=%+v error=%v", stop, err)
	}
	after := nativeDataSnapshot(t, s)
	codeViewLocation(t, s, after, entry+1, entry+1, false)
}

func TestNativeCodeViewPartialReadKeepsConfirmedPrefix(t *testing.T) {
	path, _ := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	s := codeViewSession(t, path)
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", s.PID()))
	if err != nil {
		t.Fatal(err)
	}
	type interval struct{ start, end uint64 }
	var ranges []interval
	var stackEnd uint64
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		first, last, found := strings.Cut(fields[0], "-")
		if !found {
			t.Fatalf("invalid map range %q", fields[0])
		}
		start, err := strconv.ParseUint(first, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		end, err := strconv.ParseUint(last, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		ranges = append(ranges, interval{start, end})
		if fields[len(fields)-1] == "[stack]" {
			stackEnd = end
		}
	}
	if stackEnd < 8 || stackEnd > math.MaxUint64-8 {
		t.Fatalf("invalid stack mapping end %#x", stackEnd)
	}
	for _, region := range ranges {
		if region.start < stackEnd+8 && region.end > stackEnd {
			t.Fatalf("stack mapping has no unmapped boundary: %#x", stackEnd)
		}
	}
	address := target.Address(stackEnd - 8)
	initial := nativeDataSnapshot(t, s)
	original := bytes.Repeat([]byte{0x90}, 8)
	if n, err := s.WriteSpaceMemory(initial.Memory, address, original); n != len(original) || err != nil {
		t.Fatalf("prepare bytes=%x n=%d error=%v", original, n, err)
	}
	for _, at := range []target.Address{address, address + 7} {
		if err := s.AddBreakpoint(at); err != nil {
			t.Fatal(err)
		}
	}
	before := nativeDataSnapshot(t, s)
	code := bytes.Repeat([]byte{0x55}, 16)
	n, err := s.ReadCodeMemory(before.Memory, address, code)
	var partial *target.PartialError
	if n != 8 || !errors.As(err, &partial) || partial.Completed != 8 || partial.Total != 16 {
		t.Fatalf("partial code n=%d error=%v", n, err)
	}
	if !bytes.Equal(code[:8], original) || !bytes.Equal(code[8:], bytes.Repeat([]byte{0x55}, 8)) {
		t.Fatalf("partial code bytes=%x", code)
	}
	raw := make([]byte, 8)
	if n, err := s.ReadSpaceMemory(before.Memory, address, raw); n != 8 || err != nil || raw[0] != 0xcc || raw[7] != 0xcc {
		t.Fatalf("partial read modified raw=%x n=%d error=%v", raw, n, err)
	}
	if after := nativeDataSnapshot(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("partial read changed state")
	}
	unreadable := bytes.Repeat([]byte{0x55}, 8)
	if n, err := s.ReadCodeMemory(before.Memory, address+8, unreadable); n != 0 || err == nil || !bytes.Equal(unreadable, bytes.Repeat([]byte{0x55}, 8)) {
		t.Fatalf("unreadable code=%x n=%d error=%v", unreadable, n, err)
	}
}

func TestNativeCodeViewRejectsUnconfirmedBreakpointState(t *testing.T) {
	path, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n mov $0x12345678, %eax\n jmp _start\n")
	s := codeViewSession(t, path)
	snapshot := codeViewHit(t, s, entry)
	for _, mode := range []string{"pending", "rewinding", "hit-generation", "hit-pc", "actual-pc", "space-ref", "zero-generation", "original-int3", "unregistered", "physical-byte", "disarmed-byte"} {
		t.Run(mode, func(t *testing.T) {
			if err := command(s, func(e *engine) error {
				th, err := e.requireThread(snapshot.Threads[0].Token)
				if err != nil {
					return err
				}
				space, bp, hit := th.process.space, th.hit.bp, th.hit
				savedBP, savedHit := *bp, *hit
				defer func() {
					*bp, *hit = savedBP, savedHit
					space.breakpoints[entry] = bp
				}()
				memoryFails := true
				switch mode {
				case "pending":
					bp.pending = &breakpointWrite{before: bp.original, after: 0xcc}
				case "rewinding":
					hit.rewinding, memoryFails = true, false
				case "hit-generation":
					hit.generation++
					memoryFails = false
				case "hit-pc":
					hit.rawPC++
					memoryFails = false
				case "actual-pc":
					data, err := e.readRegisterSet(th.tid)
					if err != nil {
						return err
					}
					original := append([]byte(nil), data...)
					field, ok := th.process.profile.Register("rip")
					if !ok {
						return errors.New("fixture has no raw rip")
					}
					binary.LittleEndian.PutUint64(data[field.Offset:field.Offset+8], uint64(entry+5))
					if n, err := ptraceRegisterSet(unix.PTRACE_SETREGSET, th.tid, data); n != len(data) || err != nil {
						return fmt.Errorf("inject changed PC n=%d: %w", n, err)
					}
					defer func() {
						if n, err := ptraceRegisterSet(unix.PTRACE_SETREGSET, th.tid, original); n != len(original) || err != nil {
							t.Errorf("restore changed PC n=%d error=%v", n, err)
						}
					}()
					memoryFails = false
				case "space-ref":
					bp.spaceRef.ID++
				case "zero-generation":
					bp.generation, hit.generation = 0, 0
				case "original-int3":
					bp.original = 0xcc
				case "unregistered":
					space.breakpoints[entry] = nil
				case "disarmed-byte":
					bp.armed = false
				case "physical-byte":
					if n, err := unix.PtracePokeData(th.tid, uintptr(entry), []byte{0x91}); n != 1 || err != nil {
						return fmt.Errorf("inject changed byte n=%d: %w", n, err)
					}
					defer func() {
						if n, err := unix.PtracePokeData(th.tid, uintptr(entry), []byte{0xcc}); n != 1 || err != nil {
							t.Errorf("restore changed byte n=%d error=%v", n, err)
						}
					}()
				}
				expectedBP, expectedHit, before := *bp, *hit, e.snapshot()
				if location, err := e.readCodeLocation(th.token()); !errors.Is(err, target.ErrStale) || !reflect.DeepEqual(location, CodeLocation{}) {
					return fmt.Errorf("location=%+v error=%v", location, err)
				}
				if memoryFails {
					dst := bytes.Repeat([]byte{0x55}, 5)
					n, err := e.readCodeMemory(snapshot.Memory, entry, dst)
					if n != 0 || !errors.Is(err, target.ErrStale) || !bytes.Equal(dst, bytes.Repeat([]byte{0x55}, 5)) {
						return fmt.Errorf("failed validation changed output=%x n=%d error=%v", dst, n, err)
					}
				}
				if !reflect.DeepEqual(before, e.snapshot()) || !reflect.DeepEqual(expectedBP, *bp) || !reflect.DeepEqual(expectedHit, *hit) {
					return errors.New("rejected code view changed debugger state")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	codeViewLocation(t, s, snapshot, entry+1, entry, true)
}

func TestNativeCodeViewStateValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*engine, *thread)
		want   error
	}{
		{"running", func(e *engine, th *thread) { th.state = target.StateRunning }, target.ErrRunning},
		{"listening", func(e *engine, th *thread) { th.listening = true }, target.ErrRunning},
		{"initializing", func(e *engine, th *thread) { e.life.initializing = true }, target.ErrBusy},
		{"unknown-space", func(e *engine, th *thread) { th.process.space.unknown = true }, target.ErrUnknown},
		{"space-fault", func(e *engine, th *thread) { th.process.space.fault = target.ErrUnavailable }, target.ErrUnavailable},
		{"unsupported", func(e *engine, th *thread) { e.unsupported = target.ErrUnsupported }, target.ErrUnsupported},
		{"barrier", func(e *engine, th *thread) { e.barrier = &stopBarrier{} }, target.ErrBusy},
		{"missing-owner", func(e *engine, th *thread) { e.life.missing = map[int]*thread{th.tid: th} }, target.ErrBusy},
		{"lost-owner", func(e *engine, th *thread) { e.life.lost = map[int]error{th.tid: target.ErrUnavailable} }, target.ErrUnavailable},
		{"exited", func(e *engine, th *thread) { e.life.terminal = target.StateExited }, target.ErrExited},
		{"detached", func(e *engine, th *thread) { e.life.terminal = target.StateDetached }, target.ErrDetached},
		{"closed", func(e *engine, th *thread) { e.life.terminal = target.StateClosed }, target.ErrClosed},
		{"unsupported architecture", func(e *engine, th *thread) {
			profile := x86.Descriptor()
			profile.Architecture = target.AArch64
			th.process.profile = &profile
		}, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, th := nativeDataTokenEngine()
			threadToken, memoryToken := th.token(), e.snapshot().Memory
			test.mutate(e, th)
			before := e.snapshot()
			if location, err := e.readCodeLocation(threadToken); !errors.Is(err, test.want) || !reflect.DeepEqual(location, CodeLocation{}) {
				t.Fatalf("location=%+v error=%v want=%v", location, err, test.want)
			}
			dst := []byte{0x55}
			if n, err := e.readCodeMemory(memoryToken, 0, dst); n != 0 || !errors.Is(err, test.want) || dst[0] != 0x55 {
				t.Fatalf("memory=%x n=%d error=%v want=%v", dst, n, err, test.want)
			}
			if !reflect.DeepEqual(before, e.snapshot()) {
				t.Fatal("rejected view changed snapshot")
			}
		})
	}
}

func TestNativeCodeViewTokenAndRangeValidation(t *testing.T) {
	e, th := nativeDataTokenEngine()
	currentThread, currentMemory := th.token(), e.snapshot().Memory
	for _, token := range []target.ThreadToken{
		{Thread: currentThread.Thread},
		{Thread: currentThread.Thread, Stop: currentThread.Stop + 1, Registers: currentThread.Registers},
		{Thread: currentThread.Thread, Stop: currentThread.Stop, Registers: currentThread.Registers + 1},
	} {
		if _, err := e.readCodeLocation(token); !errors.Is(err, target.ErrStale) {
			t.Fatalf("stale thread token accepted: %v", err)
		}
	}
	foreignThread := currentThread
	foreignThread.Thread.Session++
	if _, err := e.readCodeLocation(foreignThread); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign thread token accepted: %v", err)
	}
	for _, revision := range []uint64{0, currentMemory.Revision + 1} {
		stale := currentMemory
		stale.Revision = revision
		if n, err := e.readCodeMemory(stale, 0, nil); n != 0 || !errors.Is(err, target.ErrStale) {
			t.Fatalf("stale empty memory n=%d error=%v", n, err)
		}
	}
	foreignMemory := currentMemory
	foreignMemory.Space.Session++
	if n, err := e.readCodeMemory(foreignMemory, 0, nil); n != 0 || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("foreign empty memory n=%d error=%v", n, err)
	}
	if n, err := e.readCodeMemory(currentMemory, 0, nil); n != 0 || err != nil {
		t.Fatalf("valid empty memory n=%d error=%v", n, err)
	}
	dst := []byte{0x55, 0x55}
	if n, err := e.readCodeMemory(currentMemory, math.MaxUint64, dst); n != 0 || !errors.Is(err, target.ErrOverflow) || !bytes.Equal(dst, []byte{0x55, 0x55}) {
		t.Fatalf("overflow memory=%x n=%d error=%v", dst, n, err)
	}
	th.process.space = e.newSpace()
	if n, err := e.readCodeMemory(currentMemory, 0, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("old image memory n=%d error=%v", n, err)
	}
}

func TestNativeCodeViewExecInvalidatesOldImage(t *testing.T) {
	destination, entry := coreAssembly(t, 64, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	code := ".text\n.global _start\n_start:\n mov $59, %eax\n lea destination(%rip), %rdi\n xor %esi, %esi\n xor %edx, %edx\n syscall\n ud2\n"
	code += fmt.Sprintf(".section .rodata\ndestination: .asciz %q\n", destination)
	path, start := coreAssembly(t, 64, code)
	s := codeViewSession(t, path)
	before := codeViewHit(t, s, start)
	stop, err := coreContinue(t, s)
	if err != nil || stop.Reason != target.StopExec {
		t.Fatalf("exec stop=%+v error=%v", stop, err)
	}
	after := nativeDataSnapshot(t, s)
	if after.Memory.Space == before.Memory.Space {
		t.Fatal("exec retained address-space identity")
	}
	if _, err := s.ReadCodeLocation(before.Threads[0].Token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old image thread error=%v", err)
	}
	if n, err := s.ReadCodeMemory(before.Memory, start, nil); n != 0 || !errors.Is(err, target.ErrStale) {
		t.Fatalf("old image code n=%d error=%v", n, err)
	}
	codeViewLocation(t, s, after, entry, entry, false)
	data := make([]byte, 1)
	if n, err := s.ReadCodeMemory(after.Memory, entry, data); n != 1 || err != nil || data[0] != 0x90 {
		t.Fatalf("new image code=%x n=%d error=%v", data, n, err)
	}
}

func TestNativeCodeViewX86AndClosedSession(t *testing.T) {
	path, entry := coreAssembly(t, 32, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
	s := codeViewSession(t, path)
	snapshot := nativeDataSnapshot(t, s)
	if location, err := s.ReadCodeLocation(snapshot.Threads[0].Token); err != nil || location.InstructionPC != entry {
		t.Fatalf("x86 location error=%v", err)
	}
	dst := []byte{0x55}
	if n, err := s.ReadCodeMemory(snapshot.Memory, entry, dst); n != 1 || err != nil || dst[0] != 0x90 {
		t.Fatalf("x86 code=%x n=%d error=%v", dst, n, err)
	}
	if err := coreClose(t, s); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadCodeLocation(snapshot.Threads[0].Token); !errors.Is(err, target.ErrClosed) {
		t.Fatalf("closed location error=%v", err)
	}
	if n, err := s.ReadCodeMemory(snapshot.Memory, entry, dst); n != 0 || !errors.Is(err, target.ErrClosed) || dst[0] != 0x90 {
		t.Fatalf("closed code=%x n=%d error=%v", dst, n, err)
	}
}
