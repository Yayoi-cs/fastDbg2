package native_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"runtime"
	"testing"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func hardwareSet(t *testing.T, s *native.Session, token target.ThreadToken, request target.HardwareBreakpointRequest) target.HardwareBreakpointResult {
	t.Helper()
	before := threadSnapshot(t, s)
	result, err := threadCall(t, func() (target.HardwareBreakpointResult, error) { return s.SetHardwareBreakpoint(token, request) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Ref.Thread != token.Thread || result.Ref.Slot != request.Slot || result.Ref.Generation == 0 || result.Token.Thread != token.Thread || result.Token.Stop != token.Stop || result.Token.Registers <= token.Registers {
		t.Fatalf("invalid hardware breakpoint identity/token: before=%+v result=%+v", token, result)
	}
	if after := threadSnapshot(t, s); after.Memory != before.Memory {
		t.Fatalf("hardware breakpoint write changed memory token: before=%+v after=%+v", before.Memory, after.Memory)
	}
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(token) }); !errors.Is(err, target.ErrStale) {
		t.Fatalf("hardware breakpoint write retained old register token: %v", err)
	}
	if _, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(result.Token) }); err != nil {
		t.Fatalf("new hardware breakpoint token is unusable: %v", err)
	}
	return result
}

func hardwareClear(t *testing.T, s *native.Session, token target.ThreadToken, ref target.HardwareBreakpointRef) target.ThreadToken {
	t.Helper()
	before := threadSnapshot(t, s)
	updated, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearHardwareBreakpoint(token, ref) })
	if err != nil {
		t.Fatal(err)
	}
	if updated.Thread != token.Thread || updated.Stop != token.Stop || updated.Registers <= token.Registers {
		t.Fatalf("clear did not invalidate hardware breakpoint token: old=%+v new=%+v", token, updated)
	}
	if after := threadSnapshot(t, s); after.Memory != before.Memory {
		t.Fatalf("clear changed memory token: before=%+v after=%+v", before.Memory, after.Memory)
	}
	return updated
}

func hardwareRegister(t *testing.T, s *native.Session, token target.ThreadToken, name string) uint64 {
	t.Helper()
	registers, err := threadCall(t, func() ([]target.Register, error) { return s.ReadThreadRegisters(token) })
	if err != nil {
		t.Fatal(err)
	}
	for _, register := range registers {
		if register.Name != name {
			continue
		}
		if register.Available && register.Bits == 32 && len(register.Data) == 4 {
			return uint64(binary.LittleEndian.Uint32(register.Data))
		}
		if register.Available && register.Bits == 64 && len(register.Data) == 8 {
			return binary.LittleEndian.Uint64(register.Data)
		}
		t.Fatalf("invalid %s register: %+v", name, register)
	}
	t.Fatalf("register %s missing", name)
	return 0
}

func hardwareByte(t *testing.T, s *native.Session, address target.Address) byte {
	t.Helper()
	snapshot := threadSnapshot(t, s)
	var data [1]byte
	if n, err := threadCall(t, func() (int, error) { return s.ReadSpaceMemory(snapshot.Memory, address, data[:]) }); err != nil || n != 1 {
		t.Fatalf("read byte at %#x: %d, %v", address, n, err)
	}
	return data[0]
}

func hardwareStop(t *testing.T, s *native.Session, result target.RunResult, pc target.Address, hits ...target.HardwareBreakpointHit) {
	t.Helper()
	stop := result.Stop
	if stop.Reason != target.StopHardwareBreakpoint || stop.RawPC == nil || *stop.RawPC != pc || stop.StepCompleted || len(stop.HardwareBreakpoints) != len(hits) || len(stop.Watchpoints) != 0 || stop.Breakpoint != nil || stop.RawDR6 == nil {
		t.Fatalf("hardware execution fault: wantPC=%#x hits=%+v result=%+v", pc, hits, result)
	}
	mask := uint64(0)
	for _, want := range hits {
		found := 0
		for _, got := range stop.HardwareBreakpoints {
			if got == want {
				found++
			}
		}
		if found != 1 || want.Ref.Thread != result.Thread {
			t.Fatalf("hardware execution hit identity: got=%+v want=%+v thread=%+v", stop.HardwareBreakpoints, want, result.Thread)
		}
		mask |= uint64(1) << want.Ref.Slot
	}
	if *stop.RawDR6&15 != mask || *stop.RawDR6&(1<<14) != 0 {
		t.Fatalf("execution fault DR6: got=%#x slots=%#x", *stop.RawDR6, mask)
	}
	pcName := "rip"
	if s.Architecture() == target.X86 {
		pcName = "eip"
	}
	if value := hardwareRegister(t, s, result.Token, pcName); target.Address(value) != pc {
		t.Fatalf("hardware fault changed PC: got=%#x want=%#x", value, pc)
	}
	if flags := hardwareRegister(t, s, result.Token, "eflags"); flags&(1<<16) == 0 {
		t.Fatalf("hardware fault lost kernel RF: %#x", flags)
	}
}

func hardwareStep(t *testing.T, s *native.Session, ref target.ThreadRef) target.RunResult {
	t.Helper()
	run, err := threadCall(t, func() (*native.Run, error) { return s.StepInstruction(target.StepRequest{Thread: ref}) })
	if err != nil {
		t.Fatal(err)
	}
	return threadWait(t, run)
}

func hardwareStepped(t *testing.T, s *native.Session, result target.RunResult, pc target.Address) {
	t.Helper()
	stop := result.Stop
	if stop.Reason != target.StopStep || !stop.StepCompleted || stop.RawPC == nil || *stop.RawPC != pc || len(stop.HardwareBreakpoints) != 0 || len(stop.Watchpoints) != 0 || stop.RawDR6 == nil || *stop.RawDR6&15 != 0 || *stop.RawDR6&(1<<14) == 0 {
		t.Fatalf("hardware breakpoint instruction did not complete once: wantPC=%#x result=%+v", pc, result)
	}
	if flags := hardwareRegister(t, s, result.Token, "eflags"); flags&(1<<16) != 0 {
		t.Fatalf("completed instruction retained RF: %#x", flags)
	}
}

func TestNativeHardwareBreakpointFaultAndResume(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(fmt.Sprintf("bits%d", bits), func(t *testing.T) {
			body := fmt.Sprintf("nop\nmov $3, %%ecx\n.global execute_site\nexecute_site:\nincb %s\n.global execute_after\nexecute_after:\nloop execute_site\ncmpb $3, %s\nje verified\nud2\nverified:\n", watchOperand(bits, 0), watchOperand(bits, 0))
			path, symbols := watchAssembly(t, bits, body, false)
			s := watchLaunch(t, path)
			token := watchThread(t, s).Token
			var hits []target.HardwareBreakpointHit
			for _, slot := range []int{0, 2} {
				configured := hardwareSet(t, s, token, target.HardwareBreakpointRequest{Slot: slot, Address: symbols["execute_site"]})
				token = configured.Token
				hits = append(hits, target.HardwareBreakpointHit{Ref: configured.Ref, Address: symbols["execute_site"]})
			}
			original := hardwareByte(t, s, symbols["execute_site"])
			for count := byte(0); count < 3; count++ {
				result := threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
				hardwareStop(t, s, result, symbols["execute_site"], hits...)
				if value := hardwareByte(t, s, symbols["watched"]); value != count {
					t.Fatalf("execution fault ran or repeated instruction: got=%d want=%d", value, count)
				}
				if value := hardwareByte(t, s, symbols["execute_site"]); value != original {
					t.Fatalf("hardware breakpoint patched code: got=%#x want=%#x", value, original)
				}
				if count == 0 {
					hardwareStepped(t, s, hardwareStep(t, s, result.Thread), symbols["execute_after"])
					if value := hardwareByte(t, s, symbols["watched"]); value != 1 {
						t.Fatalf("step from hardware fault wrote %d times", value)
					}
				}
			}
			token = watchThread(t, s).Token
			for _, hit := range hits {
				token = hardwareClear(t, s, token, hit.Ref)
			}
			threadExit(t, s, 0)
		})
	}
}

func TestNativeHardwareBreakpointEntry(t *testing.T) {
	for _, bits := range []int{64, 32} {
		for _, step := range []bool{false, true} {
			t.Run(fmt.Sprintf("bits%d_step%t", bits, step), func(t *testing.T) {
				body := fmt.Sprintf("incb %s\n.global execute_after\nexecute_after:\nnop\ncmpb $1, %s\nje verified\nud2\nverified:\n", watchOperand(bits, 0), watchOperand(bits, 0))
				path, symbols := watchAssembly(t, bits, body, false)
				s := watchLaunch(t, path)
				configured := hardwareSet(t, s, watchThread(t, s).Token, target.HardwareBreakpointRequest{Slot: 1, Address: symbols["_start"]})
				original := hardwareByte(t, s, symbols["_start"])
				var result target.RunResult
				if step {
					result = hardwareStep(t, s, configured.Ref.Thread)
				} else {
					result = threadRun(t, s, threadProcessSet(threadSnapshot(t, s)))
				}
				hardwareStop(t, s, result, symbols["_start"], target.HardwareBreakpointHit{Ref: configured.Ref, Address: symbols["_start"]})
				if code, value := hardwareByte(t, s, symbols["_start"]), hardwareByte(t, s, symbols["watched"]); code != original || value != 0 {
					t.Fatalf("entry fault retained temporary patch or executed instruction: code=%#x want=%#x value=%d", code, original, value)
				}
				hardwareStepped(t, s, hardwareStep(t, s, result.Thread), symbols["execute_after"])
				if value := hardwareByte(t, s, symbols["watched"]); value != 1 {
					t.Fatalf("entry resume instruction count: %d", value)
				}
				hardwareClear(t, s, watchThread(t, s).Token, configured.Ref)
				threadExit(t, s, 0)
			})
		}
	}
}

func TestNativeHardwareBreakpointSharedSlots(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(fmt.Sprintf("bits%d", bits), func(t *testing.T) {
			body := fmt.Sprintf("nop\n.global execute_first\nexecute_first:\nincb %s\n.global after_first\nafter_first:\nnop\n.global execute_second\nexecute_second:\nincb %s\n.global after_second\nafter_second:\nnop\n", watchOperand(bits, 0), watchOperand(bits, 8))
			path, symbols := watchAssembly(t, bits, body, bits == 32)
			s := watchLaunch(t, path)
			firstRequest := target.HardwareBreakpointRequest{Slot: 0, Address: symbols["execute_first"]}
			secondRequest := target.HardwareBreakpointRequest{Slot: 2, Address: symbols["execute_second"]}
			first := hardwareSet(t, s, watchThread(t, s).Token, firstRequest)
			dataRequest := target.WatchpointRequest{Slot: 1, Address: symbols["watched"], Size: 1, Access: target.WatchWrite}
			data := watchSet(t, s, first.Token, dataRequest)
			second := hardwareSet(t, s, data.Token, secondRequest)
			lastRequest := target.WatchpointRequest{Slot: 3, Address: symbols["watched"] + 8, Size: 1, Access: target.WatchWrite}
			last := watchSet(t, s, second.Token, lastRequest)
			token := last.Token
			before := threadSnapshot(t, s)
			crossWatch := dataRequest
			crossWatch.Slot = 0
			if _, err := threadCall(t, func() (target.WatchpointResult, error) { return s.SetWatchpoint(token, crossWatch) }); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("watchpoint replaced execution slot implicitly: %v", err)
			}
			crossExecute := firstRequest
			crossExecute.Slot = 1
			if _, err := threadCall(t, func() (target.HardwareBreakpointResult, error) { return s.SetHardwareBreakpoint(token, crossExecute) }); !errors.Is(err, target.ErrBusy) {
				t.Fatalf("execution breakpoint replaced watchpoint slot implicitly: %v", err)
			}
			forgedWatch := target.WatchpointRef{Thread: first.Ref.Thread, Slot: first.Ref.Slot, Generation: first.Ref.Generation}
			if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearWatchpoint(token, forgedWatch) }); !errors.Is(err, target.ErrStale) {
				t.Fatalf("forged watchpoint reference cleared execution slot: %v", err)
			}
			forgedExecute := target.HardwareBreakpointRef{Thread: data.Ref.Thread, Slot: data.Ref.Slot, Generation: data.Ref.Generation}
			if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearHardwareBreakpoint(token, forgedExecute) }); !errors.Is(err, target.ErrStale) {
				t.Fatalf("forged execution reference cleared watchpoint slot: %v", err)
			}
			invalid := []target.HardwareBreakpointRequest{{Slot: -1, Address: firstRequest.Address}, {Slot: 4, Address: firstRequest.Address}}
			if bits == 32 {
				invalid = append(invalid, target.HardwareBreakpointRequest{Slot: 0, Address: 1 << 32})
			}
			for _, request := range invalid {
				if _, err := threadCall(t, func() (target.HardwareBreakpointResult, error) { return s.SetHardwareBreakpoint(token, request) }); err == nil {
					t.Fatalf("invalid execution breakpoint accepted: %+v", request)
				}
			}
			if after := threadSnapshot(t, s); after.Memory != before.Memory || watchThread(t, s).Token != token {
				t.Fatalf("rejected slot operation mutated tokens: before=%+v after=%+v", before, after)
			}
			old := first.Ref
			first = hardwareSet(t, s, token, firstRequest)
			token = first.Token
			if first.Ref.Generation <= old.Generation {
				t.Fatal("execution slot replacement reused generation")
			}
			if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearHardwareBreakpoint(token, old) }); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old execution reference cleared replacement: %v", err)
			}
			token = hardwareClear(t, s, token, second.Ref)
			swapRequest := lastRequest
			swapRequest.Slot = 2
			swap := watchSet(t, s, token, swapRequest)
			if swap.Ref.Generation <= first.Ref.Generation {
				t.Fatal("execution/watchpoint generations are not shared")
			}
			token = watchClear(t, s, swap.Token, swap.Ref)
			second = hardwareSet(t, s, token, secondRequest)
			if second.Ref.Generation <= swap.Ref.Generation {
				t.Fatal("watchpoint/execution slot reuse lost shared generation")
			}
			if bits == 64 {
				before = threadSnapshot(t, s)
				_, err := threadCall(t, func() (target.HardwareBreakpointResult, error) {
					return s.SetHardwareBreakpoint(second.Token, target.HardwareBreakpointRequest{Slot: 2, Address: target.Address(math.MaxUint64)})
				})
				var partial *target.PartialError
				if err == nil || errors.As(err, &partial) {
					t.Fatalf("invalid kernel execution address did not roll back cleanly: %v", err)
				}
				if after := threadSnapshot(t, s); after.Memory != before.Memory || after.State != target.StateStopped {
					t.Fatalf("kernel-rejected slot lost stopped memory state: before=%+v after=%+v", before, after)
				}
			}
			hardwareStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), firstRequest.Address, target.HardwareBreakpointHit{Ref: first.Ref, Address: firstRequest.Address})
			watchStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), symbols["after_first"], false, watchHit(data.Ref, dataRequest))
			hardwareStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), secondRequest.Address, target.HardwareBreakpointHit{Ref: second.Ref, Address: secondRequest.Address})
			watchStop(t, s, hardwareStep(t, s, second.Ref.Thread), symbols["after_second"], true, watchHit(last.Ref, lastRequest))
			token = hardwareClear(t, s, watchThread(t, s).Token, first.Ref)
			token = watchClear(t, s, token, data.Ref)
			token = hardwareClear(t, s, token, second.Ref)
			watchClear(t, s, token, last.Ref)
			threadExit(t, s, 0)
		})
	}
}

func TestNativeHardwareBreakpointSoftwareAndData(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(fmt.Sprintf("bits%d", bits), func(t *testing.T) {
			body := fmt.Sprintf("nop\n.global execute_site\nexecute_site:\nincb %s\n.global execute_after\nexecute_after:\nnop\ncmpb $1, %s\nje verified\nud2\nverified:\n", watchOperand(bits, 0), watchOperand(bits, 0))
			path, symbols := watchAssembly(t, bits, body, false)
			s := watchLaunch(t, path)
			request := target.HardwareBreakpointRequest{Slot: 0, Address: symbols["execute_site"]}
			configured := hardwareSet(t, s, watchThread(t, s).Token, request)
			dataRequest := target.WatchpointRequest{Slot: 1, Address: symbols["watched"], Size: 1, Access: target.WatchWrite}
			data := watchSet(t, s, configured.Token, dataRequest)
			original := hardwareByte(t, s, request.Address)
			threadCommand(t, func() error { return s.AddBreakpoint(request.Address) })
			hit := target.HardwareBreakpointHit{Ref: configured.Ref, Address: request.Address}
			hardwareStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), request.Address, hit)
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), request.Address)
			hardwareStop(t, s, hardwareStep(t, s, configured.Ref.Thread), request.Address, hit)
			if value := hardwareByte(t, s, symbols["watched"]); value != 0 {
				t.Fatalf("SW step-over treated hardware fault as instruction completion: %d", value)
			}
			if code := hardwareByte(t, s, request.Address); code != original {
				t.Fatalf("uncompleted SW step-over lost restored instruction: got=%#x want=%#x", code, original)
			}
			watchStop(t, s, hardwareStep(t, s, configured.Ref.Thread), symbols["execute_after"], true, watchHit(data.Ref, dataRequest))
			if code, value := hardwareByte(t, s, request.Address), hardwareByte(t, s, symbols["watched"]); code != 0xcc || value != 1 {
				t.Fatalf("completed SW/HW/data step was not rearmed exactly once: code=%#x value=%d", code, value)
			}
			threadCommand(t, func() error { return s.RemoveBreakpoint(request.Address) })
			token := hardwareClear(t, s, watchThread(t, s).Token, configured.Ref)
			watchClear(t, s, token, data.Ref)
			threadExit(t, s, 0)
		})
	}
}

func TestNativeHardwareBreakpointIsThreadLocal(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "existing")
	snapshot, tids := threadInitial(t, s, f, 3)
	a, b := threadByTID(t, snapshot, tids[1]), threadByTID(t, snapshot, tids[2])
	request := target.HardwareBreakpointRequest{Slot: 0, Address: f.address(t, "watch_store")}
	configured := hardwareSet(t, s, a.Token, request)
	checkpoint, done := f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	threadCommand(t, func() error { return s.AddBreakpoint(checkpoint) })
	threadCommand(t, func() error { return s.AddBreakpoint(done) })
	f.send(t, 2, 'g')
	threadBreakpoint(t, threadRun(t, s, threadExact(b.Ref)), checkpoint)
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("unconfigured peer did not finish instruction: %d", value)
	}
	f.send(t, 1, 'g')
	result := threadRun(t, s, threadExact(a.Ref))
	hardwareStop(t, s, result, request.Address, target.HardwareBreakpointHit{Ref: configured.Ref, Address: request.Address})
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("configured thread executed past its fault: %d", value)
	}
	hardwareStepped(t, s, hardwareStep(t, s, a.Ref), f.address(t, "watch_after"))
	if value := watchSharedValue(t, s, f); value != 2 {
		t.Fatalf("thread-local resume instruction count: %d", value)
	}
	hardwareClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[1]).Token, configured.Ref)
	threadBreakpoint(t, threadRun(t, s, threadExact(a.Ref)), checkpoint)
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	for index := range f.inputs {
		f.send(t, index, 'g')
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	f.receive(t, "DONE")
	if value := watchSharedValue(t, s, f); value != 4 {
		t.Fatalf("thread-local execution breakpoint changed instruction count: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}

func TestNativeHardwareBreakpointNewbornIsUnconfigured(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "newborn")
	snapshot, tids := threadInitial(t, s, f, 2)
	parent := threadByTID(t, snapshot, tids[0])
	request := target.HardwareBreakpointRequest{Slot: 0, Address: f.address(t, "watch_store")}
	parentBreakpoint := hardwareSet(t, s, parent.Token, request)
	newborn, checkpoint, done := f.address(t, "newborn_checkpoint"), f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	for _, address := range []target.Address{newborn, checkpoint, done} {
		threadCommand(t, func() error { return s.AddBreakpoint(address) })
	}
	f.send(t, 0, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), newborn)
	tids = f.receive(t, "CREATED")
	child := threadByTID(t, threadStopped(t, s, 3), tids[2])
	threadCommand(t, func() error { return s.RemoveBreakpoint(newborn) })
	f.send(t, 2, 'g')
	threadBreakpoint(t, threadRun(t, s, threadExact(child.Ref)), checkpoint)
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("newborn inherited execution breakpoint: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	request.Slot = 2
	childBreakpoint := hardwareSet(t, s, threadByTID(t, threadSnapshot(t, s), tids[2]).Token, request)
	f.send(t, 2, 'g')
	hardwareStop(t, s, threadRun(t, s, threadExact(child.Ref)), request.Address, target.HardwareBreakpointHit{Ref: childBreakpoint.Ref, Address: request.Address})
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("newborn execution fault advanced instruction: %d", value)
	}
	hardwareClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[2]).Token, childBreakpoint.Ref)
	hardwareClear(t, s, threadByTID(t, threadSnapshot(t, s), tids[0]).Token, parentBreakpoint.Ref)
	f.send(t, 1, 'g')
	f.send(t, 1, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	f.receive(t, "DONE")
	if value := watchSharedValue(t, s, f); value != 4 {
		t.Fatalf("newborn execution count after clear/resume: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}

func TestNativeHardwareBreakpointExecInvalidation(t *testing.T) {
	f := newWatchThreadFixture(t)
	s := f.launch(t, "exec")
	snapshot, tids := threadInitial(t, s, f, 2)
	parent, execer := threadByTID(t, snapshot, tids[0]), threadByTID(t, snapshot, tids[1])
	request := target.HardwareBreakpointRequest{Slot: 1, Address: f.address(t, "watch_store")}
	hardwareSet(t, s, parent.Token, request)
	old := hardwareSet(t, s, execer.Token, request)
	f.send(t, 1, 'g')
	result := threadRun(t, s, threadExact(execer.Ref))
	if result.Stop.Reason != target.StopExec || len(result.Stop.HardwareBreakpoints) != 0 {
		t.Fatalf("exec inherited stale hardware execution stop: %+v", result)
	}
	execThread := watchThread(t, s)
	if execThread.TID != s.PID() {
		t.Fatalf("non-leader exec identity: %+v", execThread)
	}
	if _, err := threadCall(t, func() (target.ThreadToken, error) { return s.ClearHardwareBreakpoint(execThread.Token, old.Ref) }); !errors.Is(err, target.ErrStale) {
		t.Fatalf("exec retained old hardware execution reference: %v", err)
	}
	afterExec, checkpoint, done := f.address(t, "after_exec_checkpoint"), f.address(t, "worker_checkpoint"), f.address(t, "done_checkpoint")
	for _, address := range []target.Address{afterExec, checkpoint, done} {
		threadCommand(t, func() error { return s.AddBreakpoint(address) })
	}
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), afterExec)
	f.receive(t, "EXECREADY")
	threadCommand(t, func() error { return s.RemoveBreakpoint(afterExec) })
	f.send(t, 0, 'g')
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), checkpoint)
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("new image retained hardware execution breakpoint: %d", value)
	}
	threadCommand(t, func() error { return s.RemoveBreakpoint(checkpoint) })
	fresh := hardwareSet(t, s, watchThread(t, s).Token, request)
	if fresh.Ref.Thread == old.Ref.Thread && fresh.Ref.Generation <= old.Ref.Generation {
		t.Fatalf("exec reused hardware execution generation: old=%+v new=%+v", old.Ref, fresh.Ref)
	}
	f.send(t, 0, 'g')
	hardwareStop(t, s, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), request.Address, target.HardwareBreakpointHit{Ref: fresh.Ref, Address: request.Address})
	if value := watchSharedValue(t, s, f); value != 1 {
		t.Fatalf("new-image hardware execution fault advanced instruction: %d", value)
	}
	hardwareClear(t, s, watchThread(t, s).Token, fresh.Ref)
	threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), done)
	threadCommand(t, func() error { return s.RemoveBreakpoint(done) })
	threadExit(t, s, 0)
}

func TestNativeHardwareBreakpointDetach(t *testing.T) {
	f := newWatchThreadFixture(t)
	cmd := f.start(t, "existing")
	tids := f.receive(t, "READY")
	s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, s, false)
	snapshot := threadStopped(t, s, 3)
	a, b := threadByTID(t, snapshot, tids[1]), threadByTID(t, snapshot, tids[2])
	request := target.HardwareBreakpointRequest{Slot: 0, Address: f.address(t, "watch_store")}
	configured := hardwareSet(t, s, a.Token, request)
	peerRequest := request
	peerRequest.Slot = 3
	hardwareSet(t, s, b.Token, peerRequest)
	threadCommand(t, func() error { return s.AddBreakpoint(f.address(t, "worker_checkpoint")) })
	f.send(t, 1, 'g')
	hardwareStop(t, s, threadRun(t, s, threadExact(a.Ref)), request.Address, target.HardwareBreakpointHit{Ref: configured.Ref, Address: request.Address})
	threadCommand(t, s.Detach)
	if s.State() != target.StateDetached {
		t.Fatalf("attached hardware execution detach state: %s", s.State())
	}
	f.send(t, 0, 'g')
	f.send(t, 1, 'g')
	f.send(t, 2, 'g')
	f.send(t, 2, 'g')
	f.receive(t, "DONE")
	threadCommand(t, cmd.Wait)
}

func TestNativeHardwareBreakpointForeignBankIsPreserved(t *testing.T) {
	f := newWatchThreadFixture(t)
	cmd := &threadProcess{Cmd: exec.Command(f.path, f.args("existing")...), done: make(chan struct{})}
	cmd.SysProcAttr = &unix.SysProcAttr{Ptrace: true}
	address := uint64(f.address(t, "watch_store"))
	control := uint64(1)
	_, err := threadCall(t, func() (struct{}, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			return struct{}{}, err
		}
		t.Cleanup(func() {
			select {
			case <-cmd.done:
			default:
				_ = cmd.Process.Kill()
				_, _ = threadCall(t, func() (struct{}, error) { return struct{}{}, cmd.Wait() })
			}
		})
		if err := watchRawStop(cmd.Process.Pid); err != nil {
			return struct{}{}, err
		}
		if err := watchDebugWrite(cmd.Process.Pid, 0, address); err != nil {
			return struct{}{}, err
		}
		if err := watchDebugWrite(cmd.Process.Pid, 7, control); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, unix.PtraceDetach(cmd.Process.Pid)
	})
	if err != nil {
		t.Fatal(err)
	}
	tids := f.receive(t, "READY")
	s, err := threadCall(t, func() (*native.Session, error) { return native.Attach(cmd.Process.Pid) })
	if err != nil {
		t.Fatal(err)
	}
	threadSessionCleanup(t, s, false)
	before := threadStopped(t, s, 3)
	parent := threadByTID(t, before, tids[0])
	request := target.HardwareBreakpointRequest{Slot: 2, Address: target.Address(address)}
	if _, err := threadCall(t, func() (target.HardwareBreakpointResult, error) { return s.SetHardwareBreakpoint(parent.Token, request) }); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("foreign active execution bank was modified through a free slot: %v", err)
	}
	if after := threadSnapshot(t, s); after.Memory != before.Memory || threadByTID(t, after, tids[0]).Token != parent.Token {
		t.Fatalf("foreign execution-bank rejection modified tokens: before=%+v after=%+v", before, after)
	}
	threadCommand(t, s.Detach)
	_, err = threadCall(t, func() (struct{}, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		pid := cmd.Process.Pid
		if err := unix.PtraceSeize(pid); err != nil {
			return struct{}{}, err
		}
		if err := unix.PtraceInterrupt(pid); err != nil {
			return struct{}{}, err
		}
		if err := watchRawStop(pid); err != nil {
			return struct{}{}, err
		}
		defer unix.PtraceDetach(pid)
		for slot := 0; slot < 4; slot++ {
			actual, err := watchDebugRead(pid, slot)
			if err != nil {
				return struct{}{}, err
			}
			want := uint64(0)
			if slot == 0 {
				want = address
			}
			if actual != want {
				return struct{}{}, fmt.Errorf("foreign execution state changed: DR%d=%#x want=%#x", slot, actual, want)
			}
		}
		actual, err := watchDebugRead(pid, 7)
		if err != nil {
			return struct{}{}, err
		}
		if actual != control {
			return struct{}{}, fmt.Errorf("foreign execution state changed: DR7=%#x want=%#x", actual, control)
		}
		if err := watchDebugWrite(pid, 7, 0); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, watchDebugWrite(pid, 0, 0)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.send(t, 0, 'g')
	for index := 1; index <= 2; index++ {
		f.send(t, index, 'g')
		f.send(t, index, 'g')
	}
	f.receive(t, "DONE")
	threadCommand(t, cmd.Wait)
}
