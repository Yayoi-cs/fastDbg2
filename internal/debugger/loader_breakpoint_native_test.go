package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

const loaderBreakpointNativeSource = `#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
volatile unsigned loader_stage;
void *volatile loader_pointer;
void *volatile loader_malloc_entry;
void *volatile loader_free_entry;
__attribute__((constructor)) static void prepare(void) {
    loader_malloc_entry = dlsym(RTLD_DEFAULT, "malloc");
    loader_free_entry = dlsym(RTLD_DEFAULT, "free");
    loader_stage = 1;
    loader_pointer = malloc(64);
    loader_stage = 2;
    free((void *)loader_pointer);
    loader_stage = 3;
}
int main(int argc, char **argv) {
    loader_stage = 4;
    loader_pointer = malloc(96);
    loader_stage = 5;
    free((void *)loader_pointer);
    loader_stage = 6;
    if (argc == 2 && !strcmp(argv[1], "reexec")) {
        execl(argv[0], argv[0], (char *)0);
        return 90;
    }
    if (argc == 3) {
        int ready = open(argv[2], O_WRONLY);
        if (ready < 0 || write(ready, "R", 1) != 1) return 91;
        close(ready);
        int gate = open(argv[1], O_RDONLY);
        char value;
        if (gate < 0 || read(gate, &value, 1) != 1) return 92;
        close(gate);
    }
    return 17;
}
`

type loaderBreakpointNativeFixture struct {
	controller *Controller
	output     bytes.Buffer
	ctx        context.Context
	directory  string
	stage      target.Address
	malloc     target.Address
	free       target.Address
	hook       target.Address
	hookByte   byte
}

func newLoaderBreakpointNativeFixture(t *testing.T, pie bool) *loaderBreakpointNativeFixture {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "loader-breakpoint-tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	source, path := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
	if err := os.WriteFile(source, []byte(loaderBreakpointNativeSource), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	flags := []string{"-O0", "-g", "-fno-builtin-malloc", "-fno-builtin-free", "-fno-pie", "-no-pie"}
	if pie {
		flags = []string{"-O0", "-g", "-fno-builtin-malloc", "-fno-builtin-free", "-fPIE", "-pie"}
	}
	command := exec.CommandContext(ctx, "cc", append(flags, "-o", path, source, "-ldl")...)
	command.Env = append(os.Environ(), "TMPDIR="+dir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, output)
	}
	fixture := &loaderBreakpointNativeFixture{ctx: ctx, directory: dir}
	fixture.controller = New(&fixture.output, display.Renderer{})
	fixture.controller.contextDisabled = true
	t.Cleanup(func() {
		if err := fixture.controller.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := fixture.controller.Configure(path, nil); err != nil {
		t.Fatal(err)
	}
	fixture.command(t, "start", "")
	fixture.refresh(t)
	return fixture
}

func (fixture *loaderBreakpointNativeFixture) refresh(t *testing.T) {
	t.Helper()
	snapshot, thread, err := fixture.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	image, err := readLiveImage(fixture.ctx, thread.TID)
	if err != nil {
		t.Fatal(err)
	}
	for name, destination := range map[string]*target.Address{"loader_stage": &fixture.stage, "loader_malloc_entry": &fixture.malloc, "loader_free_entry": &fixture.free} {
		address, err := image.resolveSymbol(name)
		if err != nil {
			t.Fatal(err)
		}
		*destination = target.Address(address)
	}
	info, err := fixture.controller.loaderRendezvous(fixture.ctx, snapshot, thread)
	if err != nil || info.Published {
		t.Fatalf("initial rendezvous=%+v error=%v", info, err)
	}
	fixture.hook = info.Hook
	fixture.hookByte = fixture.memory(t, info.Hook, 1)[0]
}

func (fixture *loaderBreakpointNativeFixture) command(t *testing.T, name, args string) {
	t.Helper()
	quit, err := fixture.controller.Execute(fixture.ctx, name, args)
	if err != nil || quit {
		t.Fatalf("%s %s: quit=%t error=%v\n%s", name, args, quit, err, fixture.output.String())
	}
}

func (fixture *loaderBreakpointNativeFixture) memory(t *testing.T, address target.Address, size int) []byte {
	t.Helper()
	snapshot, _, err := fixture.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	if n, err := fixture.controller.session.ReadSpaceMemory(snapshot.Memory, address, data); err != nil || n != len(data) {
		t.Fatalf("read %#x: n=%d error=%v", address, n, err)
	}
	return data
}

func TestLoaderBreakpointNativePendingHitsConstructorAndMain(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			fixture := newLoaderBreakpointNativeFixture(t, pie)
			c := fixture.controller
			fixture.command(t, "break", "malloc")
			fixture.command(t, "break", "free")
			for _, bp := range c.breakpoints {
				if !isPendingBreakpointError(bp.err) || bp.installed || bp.attempted {
					t.Fatalf("initial breakpoint is not pending: %+v", bp)
				}
			}
			fixture.command(t, "info", "breakpoints")
			if !strings.Contains(fixture.output.String(), "Pending:") {
				t.Fatalf("pending reason missing: %s", fixture.output.String())
			}
			seen := make(map[uint32]bool)
			for count := 0; count < 32 && len(seen) < 4; count++ {
				fixture.command(t, "continue", "")
				if c.session.State() != target.StateStopped {
					t.Fatalf("missed pending symbols; state=%v\n%s", c.session.State(), fixture.output.String())
				}
				snapshot, thread, err := c.stopped()
				if err != nil {
					t.Fatal(err)
				}
				location, err := c.session.ReadCodeLocation(thread.Token)
				if err != nil || location.Breakpoint == nil || location.RawPC != location.InstructionPC+1 {
					t.Fatalf("breakpoint location=%+v error=%v", location, err)
				}
				if location.InstructionPC == fixture.hook || c.loaderBreakpoint != nil || fixture.memory(t, fixture.hook, 1)[0] != fixture.hookByte {
					t.Fatalf("internal rendezvous escaped or was not restored: location=%+v state=%+v", location, c.loaderBreakpoint)
				}
				if fixture.memory(t, location.InstructionPC, 1)[0] != 0xcc {
					t.Fatal("user breakpoint is not physically armed")
				}
				var logical [1]byte
				if n, err := c.session.ReadCodeMemory(snapshot.Memory, location.InstructionPC, logical[:]); err != nil || n != 1 || logical[0] == 0xcc {
					t.Fatalf("logical opcode=%x n=%d error=%v", logical, n, err)
				}
				stage := binary.LittleEndian.Uint32(fixture.memory(t, fixture.stage, 4))
				if stage == 1 || stage == 2 || stage == 4 || stage == 5 {
					oracle := fixture.malloc
					if stage == 2 || stage == 5 {
						oracle = fixture.free
					}
					if address := target.Address(binary.LittleEndian.Uint64(fixture.memory(t, oracle, 8))); address != location.InstructionPC {
						t.Fatalf("stage=%d actual=%#x dlsym=%#x", stage, location.InstructionPC, address)
					}
					seen[stage] = true
				}
			}
			if len(seen) != 4 {
				t.Fatalf("constructor/main malloc/free coverage=%v\n%s", seen, fixture.output.String())
			}
			fixture.command(t, "delete", "all")
			fixture.command(t, "continue", "")
			if c.session.State() != target.StateExited || c.session.LastStop().ExitCode == nil || *c.session.LastStop().ExitCode != 17 {
				t.Fatalf("exit=%+v", c.session.LastStop())
			}
		})
	}
}

func TestLoaderBreakpointNativeMissingSymbolStopsHonestly(t *testing.T) {
	fixture := newLoaderBreakpointNativeFixture(t, true)
	c := fixture.controller
	fixture.command(t, "break", "fastdbg_symbol_that_does_not_exist")
	_, err := c.Execute(fixture.ctx, "continue", "")
	if !errors.Is(err, target.ErrNotFound) || c.session.State() != target.StateStopped || c.breakpoints[0].installed || isPendingBreakpointError(c.breakpoints[0].err) || c.loaderBreakpoint != nil {
		t.Fatalf("missing symbol error=%v bp=%+v loader=%+v state=%v\n%s", err, c.breakpoints[0], c.loaderBreakpoint, c.session.State(), fixture.output.String())
	}
	if stage := binary.LittleEndian.Uint32(fixture.memory(t, fixture.stage, 4)); stage != 0 || fixture.memory(t, fixture.hook, 1)[0] != fixture.hookByte {
		t.Fatalf("missing symbol continued past rendezvous or left patch: stage=%d", stage)
	}
	fixture.command(t, "delete", "all")
	fixture.command(t, "continue", "")
	if c.session.State() != target.StateExited {
		t.Fatal("could not recover from definitive missing symbol")
	}
}

func TestLoaderBreakpointNativeExecReinstallsInNewSpace(t *testing.T) {
	fixture := newLoaderBreakpointNativeFixture(t, true)
	c := fixture.controller
	fixture.command(t, "start", "reexec")
	fixture.refresh(t)
	fixture.command(t, "break", "malloc")
	oldSpace := c.snapshot.Memory.Space
	executed := false
	for count := 0; count < 32; count++ {
		fixture.command(t, "continue", "")
		if c.session.State() != target.StateStopped {
			t.Fatalf("target exited before reexec: %s", fixture.output.String())
		}
		if c.session.LastStop().Reason == target.StopExec {
			executed = true
			break
		}
	}
	if !executed {
		t.Fatal("no exec transition reached")
	}
	if c.snapshot.Memory.Space == oldSpace || c.loaderBreakpoint != nil || c.breakpoints[0].installed || c.breakpoints[0].attempted || c.breakpoints[0].err != nil {
		t.Fatalf("exec retained old ownership: space=%+v old=%+v bp=%+v internal=%+v", c.snapshot.Memory.Space, oldSpace, c.breakpoints[0], c.loaderBreakpoint)
	}
	fixture.refresh(t)
	fixture.command(t, "continue", "")
	if !c.breakpoints[0].installed || c.breakpoints[0].space == oldSpace || c.loaderBreakpoint != nil || c.session.LastStop().Reason != target.StopBreakpoint || c.session.LastStop().Breakpoint == nil || *c.session.LastStop().Breakpoint != c.breakpoints[0].address {
		t.Fatalf("exec did not reinstall user breakpoint: bp=%+v internal=%+v stop=%+v", c.breakpoints[0], c.loaderBreakpoint, c.session.LastStop())
	}
	fixture.command(t, "delete", "all")
	fixture.command(t, "continue", "")
	if c.session.State() != target.StateExited {
		t.Fatal("reexecuted process did not exit")
	}
}

type loaderBreakpointPausedRun struct {
	session
	started chan struct{}
	release chan struct{}
	wait    context.Context
	done    chan error
}

func (s *loaderBreakpointPausedRun) Run(request target.RunRequest) (operation, error) {
	op, err := s.session.Run(request)
	close(s.started)
	if s.done != nil {
		waitErr := err
		if op != nil && err == nil {
			_, waitErr = op.Wait(s.wait)
		}
		s.done <- waitErr
	}
	<-s.release
	return op, err
}

func (fixture *loaderBreakpointNativeFixture) canceledContinue(t *testing.T) {
	fixture.cancelAfterRun(t, false)
}

func (fixture *loaderBreakpointNativeFixture) cancelAfterRun(t *testing.T, completed bool) {
	t.Helper()
	c := fixture.controller
	base := c.session
	paused := &loaderBreakpointPausedRun{session: base, started: make(chan struct{}), release: make(chan struct{})}
	if completed {
		paused.wait, paused.done = fixture.ctx, make(chan error, 1)
	}
	c.session = paused
	ctx, cancel := context.WithCancel(fixture.ctx)
	done := make(chan error, 1)
	joined, released := false, false
	defer func() {
		cancel()
		if !released {
			close(paused.release)
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("canceled continue did not join")
			}
		}
		c.session = base
	}()
	go func() {
		_, err := c.Execute(ctx, "continue", "")
		done <- err
	}()
	select {
	case <-paused.started:
	case err := <-done:
		joined = true
		t.Fatalf("continue ended before native run: %v", err)
	case <-fixture.ctx.Done():
		t.Fatal("continue did not start")
	}
	if completed {
		select {
		case err := <-paused.done:
			if err != nil {
				t.Fatalf("native operation did not complete: %v", err)
			}
		case <-fixture.ctx.Done():
			t.Fatal("native operation did not reach its breakpoint")
		}
	}
	cancel()
	close(paused.release)
	released = true
	select {
	case err := <-done:
		joined = true
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel failed: %v", err)
		}
	case <-fixture.ctx.Done():
		t.Fatal("cancel did not confirm a stop")
	}
	if c.active != nil || c.session.State() != target.StateStopped || !c.hasPendingBreakpoints() || c.loaderBreakpoint == nil || !c.loaderBreakpoint.installed {
		t.Fatalf("cancel hid loader state: active=%v state=%v pending=%t internal=%+v", c.active, c.session.State(), c.hasPendingBreakpoints(), c.loaderBreakpoint)
	}
}

func TestLoaderBreakpointNativeCancelAtConsistentHookRetainsArrival(t *testing.T) {
	fixture := newLoaderBreakpointNativeFixture(t, true)
	c := fixture.controller
	fixture.command(t, "break", fmt.Sprintf("%#x", fixture.hook))
	fixture.command(t, "break", "malloc")
	fixture.command(t, "continue", "")
	snapshot, thread, err := c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.loaderRendezvous(fixture.ctx, snapshot, thread)
	if err != nil || !info.Published || info.Consistent {
		t.Fatalf("first shared hook=%+v error=%v", info, err)
	}
	fixture.command(t, "delete", "1")
	fixture.cancelAfterRun(t, true)
	snapshot, thread, err = c.stopped()
	if err != nil {
		t.Fatal(err)
	}
	info, err = c.loaderRendezvous(fixture.ctx, snapshot, thread)
	if err != nil || !info.Consistent || len(c.loaderBreakpoint.arrivals) == 0 || !c.hasPendingBreakpoints() {
		t.Fatalf("consistent event was lost by cancellation: info=%+v error=%v internal=%+v", info, err, c.loaderBreakpoint)
	}
	fixture.command(t, "continue", "")
	if c.loaderBreakpoint != nil || !c.breakpoints[0].installed || c.session.LastStop().Breakpoint == nil || *c.session.LastStop().Breakpoint != c.breakpoints[0].address {
		t.Fatalf("canceled consistent arrival was bypassed: bp=%+v stop=%+v", c.breakpoints[0], c.session.LastStop())
	}
}

func TestLoaderBreakpointNativeCancelAndStepRemainVisible(t *testing.T) {
	fixture := newLoaderBreakpointNativeFixture(t, false)
	c := fixture.controller
	fixture.command(t, "break", "malloc")
	fixture.canceledContinue(t)
	if binary.LittleEndian.Uint32(fixture.memory(t, fixture.stage, 4)) != 0 {
		t.Fatal("cancel crossed constructor")
	}
	fixture.command(t, "step", "")
	if c.session.LastStop().Reason != target.StopStep || !c.session.LastStop().StepCompleted || !c.hasPendingBreakpoints() || c.loaderBreakpoint == nil {
		t.Fatalf("step was swallowed: stop=%+v pending=%t internal=%+v", c.session.LastStop(), c.hasPendingBreakpoints(), c.loaderBreakpoint)
	}
	fixture.command(t, "continue", "")
	if c.loaderBreakpoint != nil || !c.breakpoints[0].installed || c.session.LastStop().Breakpoint == nil || *c.session.LastStop().Breakpoint != c.breakpoints[0].address {
		t.Fatalf("resume after cancel/step did not hit user BP: stop=%+v", c.session.LastStop())
	}
}

func TestLoaderBreakpointNativeDetachRestoresInternalPatch(t *testing.T) {
	fixture := newLoaderBreakpointNativeFixture(t, true)
	c := fixture.controller
	gateName, readyName := filepath.Join(fixture.directory, "gate"), filepath.Join(fixture.directory, "ready")
	for _, name := range []string{gateName, readyName} {
		if err := unix.Mkfifo(name, 0600); err != nil {
			t.Fatal(err)
		}
	}
	gate, err := os.OpenFile(gateName, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	ready, err := os.OpenFile(readyName, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	if err := ready.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	fixture.command(t, "start", fmt.Sprintf("%q %q", gateName, readyName))
	fixture.refresh(t)
	fixture.command(t, "break", "malloc")
	fixture.canceledContinue(t)
	pid := c.session.PID()
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	defer func() {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		for {
			var status unix.WaitStatus
			_, err := unix.Wait4(pid, &status, 0, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil && !errors.Is(err, unix.ECHILD) {
				t.Error(err)
			}
			break
		}
	}()
	fixture.command(t, "detach", "")
	if c.session != nil || c.loaderBreakpoint != nil {
		t.Fatal("detach retained internal ownership")
	}
	var notification [1]byte
	if n, err := ready.Read(notification[:]); err != nil || n != 1 || notification[0] != 'R' {
		t.Fatalf("detached inferior did not reach main: n=%d data=%q error=%v", n, notification, err)
	}
	memory, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	n, readErr := memory.ReadAt(value[:], int64(fixture.hook))
	closeErr := memory.Close()
	if n != 1 || readErr != nil || closeErr != nil || value[0] != fixture.hookByte {
		t.Fatalf("detached internal patch not restored: bytes=%x n=%d error=%v/%v", value, n, readErr, closeErr)
	}
	if _, err := gate.Write([]byte{'G'}); err != nil {
		t.Fatal(err)
	}
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 5000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("detached inferior did not exit: n=%d poll=%v error=%v", n, poll, err)
	}
}
