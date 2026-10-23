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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const expansionIntegrationSource = `#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile uint64_t expansion_words[3] = {0x8877665544332211ULL, 0xffffffffffffffffULL, 0};
char expansion_text[] = "native commands\n";
char *expansion_boundary;
int expansion_tids[3];
_Atomic int expansion_ready[3];
static int expansion_gate;

__attribute__((naked,noinline)) void expansion_point(void) {
    __asm__ volatile("nop\n\tnop\n\tret");
}

static void *expansion_worker(void *argument) {
    long index = (long)argument;
    register unsigned long marker __asm__("r15") = 0x12345000UL + (unsigned long)index;
    __asm__ volatile("" : "+r"(marker));
    expansion_tids[index] = (int)syscall(SYS_gettid);
    atomic_store_explicit(&expansion_ready[index], 1, memory_order_release);
    syscall(SYS_futex, &expansion_ready[index], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    char value;
    ssize_t result;
    do {
        result = read(expansion_gate, &value, 1);
    } while (result < 0 && errno == EINTR);
    __asm__ volatile("" : : "r"(marker));
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    expansion_gate = open(argv[1], O_RDONLY);
    if (expansion_gate < 0) return 91;
    long page = sysconf(_SC_PAGESIZE);
    char *mapping = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 92;
    expansion_boundary = mapping + page - 16;
    memset(expansion_boundary, 'Q', 16);
    expansion_tids[0] = (int)syscall(SYS_gettid);
    pthread_t workers[3];
    for (long index = 1; index <= 2; ++index) {
        if (pthread_create(&workers[index], 0, expansion_worker, (void *)index)) return 94;
        while (!atomic_load_explicit(&expansion_ready[index], memory_order_acquire))
            syscall(SYS_futex, &expansion_ready[index], FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    }
    if (munmap(mapping + page, (size_t)page)) return 93;
    expansion_point();
    expansion_words[0]++;
    expansion_point();
    return 17;
}
`

type expansionIntegration struct {
	controller *Controller
	output     bytes.Buffer
	pid        int
}

func newExpansionIntegration(t *testing.T, pie bool) *expansionIntegration {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native command expansion requires linux/amd64")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "command-expansion-tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	source, executable := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
	if err := os.WriteFile(source, []byte(expansionIntegrationSource), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"-fno-pie", "-no-pie"}
	if pie {
		flags = []string{"-fPIE", "-pie"}
	}
	args := append([]string{"-std=gnu11", "-O0", "-g", "-fcf-protection=none", "-pthread", "-Wl,--build-id=none"}, flags...)
	args = append(args, "-o", executable, source)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, output)
	}
	gate := filepath.Join(dir, "gate")
	if err := unix.Mkfifo(gate, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(gate, os.O_RDWR|unix.O_NONBLOCK, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	f := &expansionIntegration{}
	f.controller = New(&f.output, display.Renderer{})
	t.Cleanup(func() {
		fd := -1
		if f.controller.session != nil && f.controller.session.State() != target.StateExited {
			fd, _ = unix.PidfdOpen(f.controller.session.PID(), 0)
		}
		if fd >= 0 {
			defer unix.Close(fd)
		}
		done := make(chan error, 1)
		go func() { done <- f.controller.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			if fd >= 0 {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			t.Error("controller cleanup exceeded deadline")
		}
		if f.pid != 0 {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", f.pid)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("target %d remains after cleanup: %v", f.pid, err)
			}
		}
	})
	if err := f.controller.Configure(executable, []string{gate}); err != nil {
		t.Fatal(err)
	}
	f.command(t, "break expansion_point")
	f.command(t, "start")
	f.pid = f.controller.session.PID()
	return f
}

func (f *expansionIntegration) execute(command string) (string, error) {
	f.output.Reset()
	name, arguments, _ := strings.Cut(command, " ")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	quit, err := f.controller.Execute(ctx, name, arguments)
	if quit && err == nil {
		err = fmt.Errorf("unexpected quit from %q", command)
	}
	return f.output.String(), err
}

func (f *expansionIntegration) command(t *testing.T, command string) string {
	t.Helper()
	output, err := f.execute(command)
	if err != nil {
		t.Fatalf("%s: %v\n%s", command, err, output)
	}
	if strings.ContainsRune(output, '\x1b') {
		t.Fatalf("plain output contains escape: %q", output)
	}
	return output
}

func (f *expansionIntegration) reject(t *testing.T, command string) string {
	t.Helper()
	output, err := f.execute(command)
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded: %s", command, output)
	}
	return output
}

func (f *expansionIntegration) breakpoint(t *testing.T) {
	t.Helper()
	for range 12 {
		output := f.command(t, "continue")
		if f.controller.session.LastStop().Reason == target.StopBreakpoint {
			return
		}
		if f.controller.session.State() != target.StateStopped {
			t.Fatalf("target did not remain stopped: %s", output)
		}
	}
	t.Fatal("breakpoint not reached after 12 native events")
}

func (f *expansionIntegration) read(t *testing.T, expression string, size int) []byte {
	t.Helper()
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	address, err := f.controller.evaluate(context.Background(), expression, snapshot, thread)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	if n, err := f.controller.session.ReadSpaceMemory(snapshot.Memory, address, data); err != nil || n != size {
		t.Fatalf("read %s: %d, %v", expression, n, err)
	}
	return data
}

func TestCommandExpansionNativeInspection(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			f.breakpoint(t)
			for _, test := range []struct {
				command string
				needle  string
			}{
				{"print 0x2a", "HEX"},
				{"p/x 42", "2a"},
				{"p/d 0xffffffffffffffff", "-1"},
				{"p/u 0xffffffffffffffff", "18446744073709551615"},
				{"p/t 3", "11"},
				{"x/8xb expansion_words", "11"},
				{"x/1gx expansion_words", "8877665544332211"},
				{"x/1xg expansion_words", "8877665544332211"},
				{"x/1db expansion_words+7", "-120"},
				{"x/s expansion_text", "native commands"},
				{"hexdump qword --count 1 expansion_words", "8877665544332211"},
				{"dq expansion_words", "8877665544332211"},
				{"stack 1", "0x"},
				{"disass --count 2", "nop"},
				{"x/1i expansion_point", "nop"},
			} {
				output := f.command(t, test.command)
				if !strings.Contains(output, test.needle) {
					t.Errorf("%s missing %q: %s", test.command, test.needle, output)
				}
			}
			point := f.read(t, "expansion_point", 2)
			if !bytes.Equal(point, []byte{0xcc, 0x90}) {
				t.Fatalf("raw software breakpoint bytes: %x", point)
			}
			raw := f.command(t, "x/1xb expansion_point")
			if !strings.Contains(raw, "cc") {
				t.Fatalf("raw x display hid software breakpoint: %s", raw)
			}
			_, selected, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			location, err := f.controller.session.ReadCodeLocation(selected.Token)
			if err != nil || location.Breakpoint == nil || location.RawPC != location.InstructionPC+1 {
				t.Fatalf("software breakpoint location: %+v, %v", location, err)
			}
			logical := f.command(t, "disass --count 1")
			if !strings.Contains(logical, fmt.Sprintf("raw-pc=0x%016x instruction-pc=0x%016x", location.RawPC, location.InstructionPC)) {
				t.Fatalf("disassembly location provenance: %s", logical)
			}
			explicit := f.command(t, "x/1i $rip")
			if !strings.Contains(explicit, fmt.Sprintf("0x%016x", location.RawPC)) || strings.Contains(explicit, fmt.Sprintf("0x%016x", location.InstructionPC)) {
				t.Fatalf("explicit raw RIP was silently corrected: %s", explicit)
			}
			for _, command := range []string{"x", "x/0xb expansion_words", "x/4097xb expansion_words", "x/3q expansion_words", "p/z 1", "regs rip invalid_register", "disass --count 0", "hexdump qword --count 513 expansion_words", "stack 513"} {
				f.reject(t, command)
			}
			boundary := binary.LittleEndian.Uint64(f.read(t, "expansion_boundary", 8))
			partialString := f.reject(t, fmt.Sprintf("x/s %#x", boundary))
			if !strings.Contains(partialString, strings.Repeat("Q", 16)) || !strings.Contains(partialString, "unterminated") {
				t.Fatalf("partial string lost confirmed bytes or termination status: %s", partialString)
			}
			partial := f.reject(t, fmt.Sprintf("x/4gx %#x", boundary))
			if strings.Count(partial, "5151515151515151") != 2 {
				t.Fatalf("partial numeric display invented or lost confirmed units: %s", partial)
			}
			f.reject(t, "x/1gx 0")
			f.command(t, "regs rip rsp")
			f.command(t, "si")
			f.command(t, "x/1i $rip")
			f.command(t, "context regs code stack threads")
		})
	}
}

func TestCommandExpansionNativeThreadSelectionAndApply(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			f.breakpoint(t)
			_, eventThread, err := f.controller.stopped()
			if err != nil || eventThread.TID != f.pid {
				t.Fatalf("breakpoint event did not select main thread: %+v, %v", eventThread, err)
			}
			tids := f.read(t, "expansion_tids", 12)
			workerTID := int(binary.LittleEndian.Uint32(tids[4:8]))
			snapshot, err := f.controller.refresh()
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Threads) != 3 {
				t.Fatalf("threads: %+v", snapshot.Threads)
			}
			var selected target.ThreadRef
			for _, thread := range snapshot.Threads {
				if thread.TID == workerTID {
					selected = thread.Ref
				}
			}
			if selected == (target.ThreadRef{}) || selected.ID == uint64(workerTID) {
				t.Fatalf("invalid independent identity: %+v tid=%d", selected, workerTID)
			}
			f.command(t, fmt.Sprintf("thread %d", selected.ID))
			if got := f.command(t, "regs r15"); !strings.Contains(got, "12345001") {
				t.Fatalf("selected worker register: %s", got)
			}
			f.reject(t, "thread "+strconv.Itoa(workerTID))
			if f.controller.selected != selected {
				t.Fatal("unknown logical ID changed selection")
			}
			f.command(t, "thread tid "+strconv.Itoa(workerTID))
			f.command(t, "thread")
			f.command(t, "info threads")
			for _, test := range []struct {
				command string
				order   []int
			}{
				{"thread apply all regs r15 rip", []int{3, 2, 1}},
				{"thread apply 3 1 2 x/1gx expansion_words", []int{3, 1, 2}},
				{"thread apply all -ascending regs rip", []int{1, 2, 3}},
				{"thread apply all p/x $r15", []int{3, 2, 1}},
				{"thread apply all context regs threads", []int{3, 2, 1}},
			} {
				output := f.command(t, test.command)
				previous := -1
				for _, id := range test.order {
					index := strings.Index(output, fmt.Sprintf("\nThread %d (", id))
					if index <= previous {
						t.Fatalf("%s violated thread order %v: %s", test.command, test.order, output)
					}
					previous = index
				}
				if f.controller.selected != selected {
					t.Fatalf("%s changed selection to %+v", test.command, f.controller.selected)
				}
			}
			for _, command := range []string{"thread apply all x/1gx 0", "thread apply all regs invalid_register", "thread apply all continue", "thread apply all thread 1", "thread apply all delete all", "thread apply 1 999999 regs", "thread apply all set scheduler-locking on"} {
				f.reject(t, command)
				if f.controller.selected != selected {
					t.Fatalf("failed %s changed selection to %+v", command, f.controller.selected)
				}
			}
			for _, read := range []string{"x/1gx 0", "memory --count 8 0"} {
				for _, keepGoing := range []bool{false, true} {
					command, count := "thread apply all "+read, 1
					if keepGoing {
						command, count = "thread apply all -c "+read, 3
					}
					output := f.reject(t, command)
					if uiApplyHeaderCount(output) != count || f.controller.selected != selected {
						t.Fatalf("thread apply error continuation/restoration: %s", output)
					}
				}
			}
			_, thread, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			registers, err := f.controller.session.ReadThreadRegisters(thread.Token)
			if err != nil {
				t.Fatal(err)
			}
			var original target.Register
			for _, register := range registers {
				if register.Name == "rsp" {
					original = register
				}
			}
			if len(original.Data) != 8 {
				t.Fatalf("RSP unavailable: %+v", original)
			}
			backend := f.controller.session.(*nativeSession)
			unavailable := original
			unavailable.Data = make([]byte, 8)
			if err := backend.WriteThreadRegisters(thread.Token, []target.Register{unavailable}); err != nil {
				t.Fatal(err)
			}
			if _, err := backend.ReadThreadRegisters(thread.Token); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old register token after write: %v", err)
			}
			f.reject(t, "context stack")
			output := f.reject(t, "thread apply all -c context stack")
			if uiApplyHeaderCount(output) != 3 || f.controller.selected != selected {
				t.Fatalf("context read error continuation/restoration: %s", output)
			}
			_, refreshed, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			if err := backend.WriteThreadRegisters(refreshed.Token, []target.Register{original}); err != nil {
				t.Fatal(err)
			}
			f.command(t, "context stack")
			if got := f.command(t, "regs r15"); !strings.Contains(got, "12345001") {
				t.Fatalf("restored worker register: %s", got)
			}
		})
	}
}

func TestCommandExpansionNativeBreakpointLifecycle(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newExpansionIntegration(t, pie)
			for _, command := range []string{"disable 1", "enable 1", "disable 1", "enable 1"} {
				f.command(t, command)
				want := byte(0xcc)
				if strings.HasPrefix(command, "disable") {
					want = 0x90
				}
				if got := f.read(t, "expansion_point", 1)[0]; got != want {
					t.Fatalf("%s byte=%#x, want %#x", command, got, want)
				}
				f.command(t, "regs rip")
			}
			for _, command := range []string{"disable all", "enable all"} {
				f.reject(t, command)
				if got := f.read(t, "expansion_point", 1)[0]; got != 0xcc {
					t.Fatalf("%s mutated breakpoint despite rejection: %#x", command, got)
				}
			}
			f.command(t, "break expansion_point+1")
			f.reject(t, "disable 1 999999")
			if got := f.read(t, "expansion_point", 2); !bytes.Equal(got, []byte{0xcc, 0xcc}) {
				t.Fatalf("invalid batch partially mutated breakpoints: %x", got)
			}
			f.command(t, "disable 1 2")
			if got := f.read(t, "expansion_point", 2); !bytes.Equal(got, []byte{0x90, 0x90}) {
				t.Fatalf("disable batch bytes: %x", got)
			}
			f.command(t, "enable 1 2")
			f.command(t, "delete 2")
			f.breakpoint(t)
			f.command(t, "info breakpoints")
			f.command(t, "disable 1")
			f.command(t, "regs rip")
			f.command(t, "enable 1")
			f.command(t, "disass --count 1")
			f.command(t, "delete all")
			if got := f.read(t, "expansion_point", 2); !bytes.Equal(got, []byte{0x90, 0x90}) {
				t.Fatalf("delete all bytes: %x", got)
			}
			for range 12 {
				output := f.command(t, "continue")
				stop := f.controller.session.LastStop()
				if stop.Reason == target.StopExited {
					if f.controller.session.State() != target.StateExited || stop.ExitCode == nil || *stop.ExitCode != 17 {
						t.Fatalf("unexpected fixture exit: %s", output)
					}
					return
				}
			}
			t.Fatal("fixture did not exit after breakpoint deletion")
		})
	}
}
