package native

import (
	"errors"
	"fastdbg2/target"
	"fmt"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func launchInterruptModel() (*engine, *thread, waitResult) {
	e, tasks := controlModel(1)
	t := tasks[0]
	e.primary.owned = true
	e.life.launch = &launchGate{}
	e.life.initializing, e.life.launchReleased = true, true
	t.interruptDeferred, t.interruptResumed = true, true
	w := waitResult{pid: t.tid, status: unix.WaitStatus(unix.PTRACE_EVENT_STOP<<16 | int(unix.SIGTRAP)<<8 | 0x7f)}
	return e, t, w
}

func TestLaunchInterruptRetryRequiresHandshakeProof(t *testing.T) {
	e, task, w := launchInterruptModel()
	if !e.canRetryLaunchInterrupt(task, w) {
		t.Fatal("confirmed launch CONT ticket was rejected")
	}
	for name, mutate := range map[string]func(*engine, *thread, *waitResult){
		"no_gate":      func(e *engine, _ *thread, _ *waitResult) { e.life.launch = nil },
		"initialized":  func(e *engine, _ *thread, _ *waitResult) { e.life.initializing = false },
		"not_released": func(e *engine, _ *thread, _ *waitResult) { e.life.launchReleased = false },
		"exec_seen":    func(e *engine, _ *thread, _ *waitResult) { e.life.launchExec = true },
		"shutdown":     func(e *engine, _ *thread, _ *waitResult) { e.life.shutdownKind = "close" },
		"barrier":      func(e *engine, _ *thread, _ *waitResult) { e.barrier = &stopBarrier{} },
		"run":          func(e *engine, _ *thread, _ *waitResult) { e.run = &runOperation{} },
		"fault":        func(e *engine, _ *thread, _ *waitResult) { e.unsupported = target.ErrUnknown },
		"ownership": func(e *engine, task *thread, _ *waitResult) {
			e.life.lost = map[int]error{task.tid: target.ErrUnavailable}
		},
		"not_owned":      func(_ *engine, task *thread, _ *waitResult) { task.process.owned = false },
		"not_primary":    func(e *engine, _ *thread, _ *waitResult) { e.primary = &process{} },
		"not_leader":     func(_ *engine, task *thread, _ *waitResult) { task.process.tgid++ },
		"not_seized":     func(_ *engine, task *thread, _ *waitResult) { task.seized = false },
		"exiting":        func(_ *engine, task *thread, _ *waitResult) { task.exiting = true },
		"listening":      func(_ *engine, task *thread, _ *waitResult) { task.listening = true },
		"not_stopped":    func(_ *engine, task *thread, _ *waitResult) { task.state = target.StateRunning },
		"no_request":     func(_ *engine, task *thread, _ *waitResult) { task.interruptDeferred = false },
		"no_cont_commit": func(_ *engine, task *thread, _ *waitResult) { task.interruptResumed = false },
		"new_interrupt":  func(_ *engine, task *thread, _ *waitResult) { task.interruptRequested = true },
		"wait_error":     func(_ *engine, _ *thread, w *waitResult) { w.err = unix.ESRCH },
		"wrong_tid":      func(_ *engine, _ *thread, w *waitResult) { w.pid++ },
		"terminal":       func(_ *engine, _ *thread, w *waitResult) { w.status = 0 },
		"group_stop": func(_ *engine, _ *thread, w *waitResult) {
			w.status = unix.WaitStatus(unix.PTRACE_EVENT_STOP<<16 | int(unix.SIGSTOP)<<8 | 0x7f)
		},
		"signal":  func(_ *engine, _ *thread, w *waitResult) { w.status = unix.WaitStatus(int(unix.SIGUSR1)<<8 | 0x7f) },
		"sigtrap": func(_ *engine, _ *thread, w *waitResult) { w.status = unix.WaitStatus(int(unix.SIGTRAP)<<8 | 0x7f) },
		"exec": func(_ *engine, _ *thread, w *waitResult) {
			w.status = unix.WaitStatus(unix.PTRACE_EVENT_EXEC<<16 | int(unix.SIGTRAP)<<8 | 0x7f)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, task, w := launchInterruptModel()
			mutate(e, task, &w)
			deferred, resumed, requested := task.interruptDeferred, task.interruptResumed, task.interruptRequested
			if e.canRetryLaunchInterrupt(task, w) {
				t.Fatal("launch continuation accepted without the complete proof")
			}
			if task.interruptDeferred != deferred || task.interruptResumed != resumed || task.interruptRequested != requested {
				t.Fatal("rejected launch continuation changed its request history")
			}
		})
	}
}

func launchGateWait(tid int) (waitResult, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		w, ready := waitTask(tid)
		if ready {
			return w, w.err
		}
		if time.Now().After(deadline) {
			return waitResult{}, errors.New("launch gate did not report its requested stop")
		}
		runtime.Gosched()
	}
}

func TestLaunchGateDeferredInterrupt(t *testing.T) {
	for _, bits := range []int{64, 32} {
		t.Run(fmt.Sprintf("bits%d", bits), func(t *testing.T) {
			path, entry := coreAssembly(t, bits, ".text\n.global _start\n_start:\n nop\n jmp _start\n")
			s, err := coreCall(t, func() (*Session, error) {
				return openSession(func(e *engine) error {
					if err := e.launch(path, nil); err != nil {
						return err
					}
					task := e.threads[e.primary.tgid]
					first, err := launchGateWait(task.tid)
					if err != nil {
						return err
					}
					expected := unix.WaitStatus(unix.PTRACE_EVENT_STOP<<16 | int(unix.SIGTRAP)<<8 | 0x7f)
					if first.status != expected {
						return fmt.Errorf("first gate stop=%#x", uint32(first.status))
					}
					if err := unix.PtraceInterrupt(task.tid); err != nil {
						return err
					}
					e.handleWait(first)
					if !e.life.initializing || !e.life.launchReleased || e.life.launchExec || task.state != target.StateRunning || task.interruptRequested || !task.interruptDeferred || !task.interruptResumed {
						return errors.New("launch gate CONT lost the newer interrupt request")
					}
					second, err := launchGateWait(task.tid)
					if err != nil {
						return err
					}
					if second.status != expected {
						return fmt.Errorf("deferred gate stop=%#x", uint32(second.status))
					}
					e.handleWait(second)
					if !e.life.initializing || e.life.launchExec || task.state != target.StateRunning || task.interruptRequested || task.interruptDeferred || task.interruptResumed {
						return errors.New("deferred launch interrupt was not retired before CONT")
					}
					return nil
				})
			})
			if s != nil {
				coreOwnSession(t, s)
			}
			if err != nil {
				t.Fatal(err)
			}
			stop := s.LastStop()
			if s.State() != target.StateStopped || stop.Reason != target.StopExec || stop.RawPC == nil || *stop.RawPC != entry {
				t.Fatalf("launch passed the target entry: state=%v stop=%+v", s.State(), stop)
			}
		})
	}
}
