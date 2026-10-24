package debugger

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

const uiIntegrationSource = `#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

uint64_t ui_value = 0x1122334455667788ULL;
const uint64_t ui_readonly = 0x8877665544332211ULL;
uintptr_t ui_chain[4];
uintptr_t ui_cycle[2];
uintptr_t ui_code[1];
uintptr_t ui_hole[1];
uintptr_t ui_edge[1];
static _Atomic int ui_ready;
static _Atomic int ui_gate;

__attribute__((naked,noinline)) void ui_point(void) {
    __asm__ volatile("nop\n\tinc %rax\n\tret");
}

static void *ui_worker(void *unused) {
    (void)unused;
    pthread_setname_np(pthread_self(), "ui-測試");
    atomic_store(&ui_ready, 1);
    syscall(SYS_futex, &ui_ready, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    for (;;) syscall(SYS_futex, &ui_gate, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
}

int main(void) {
    pthread_setname_np(pthread_self(), "ui-\033]0;bad\007");
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *mapping = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 90;
    mapping[page-4] = 0xd4;
    mapping[page-3] = 0xc3;
    mapping[page-2] = 0xb2;
    mapping[page-1] = 0xa1;
    ui_chain[0] = (uintptr_t)&ui_chain[1];
    ui_chain[1] = (uintptr_t)&ui_chain[2];
    ui_chain[2] = (uintptr_t)&ui_value;
    ui_cycle[0] = (uintptr_t)&ui_cycle[1];
    ui_cycle[1] = (uintptr_t)&ui_cycle[0];
    ui_code[0] = (uintptr_t)ui_point;
    ui_hole[0] = (uintptr_t)(mapping + page);
    ui_edge[0] = (uintptr_t)(mapping + page - 4);
    pthread_t worker;
    if (pthread_create(&worker, 0, ui_worker, 0)) return 91;
    while (!atomic_load(&ui_ready)) syscall(SYS_futex, &ui_ready, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    if (munmap(mapping + page, (size_t)page)) return 92;
    ui_point();
    return 29;
}
`

func newUIIntegration(t *testing.T, pie bool) *expansionIntegration {
	t.Helper()
	path := deterministicBuild(t, "cc", uiIntegrationSource, pie, "-O0")
	f := deterministicLaunch(t, path, "ui_point")
	f.breakpoint(t)
	return f
}

func uiBreakpointRowMatches(output string, id uint64, enabled bool, address, state, expression string, pie bool) bool {
	flag := "n"
	if enabled {
		flag = "y"
	}
	what := fmt.Sprintf("%q", expression)
	if pie {
		what += " (PIE offset)"
	}
	pattern := fmt.Sprintf(`(?m)^%d[\t ]+breakpoint[\t ]+%s[\t ]+%s[\t ]+%s[\t ]+%s$`, id, flag, regexp.QuoteMeta(address), regexp.QuoteMeta(state), regexp.QuoteMeta(what))
	return len(regexp.MustCompile(pattern).FindAllString(output, -1)) == 1
}

func uiWatchpointRowMatches(output string, thread uint64, slot int, access string, size int, address target.Address, state string, _ uint64) bool {
	pattern := fmt.Sprintf(`(?m)^#%d[\t ]+%d[\t ]+%s[\t ]+%d[\t ]+0x%016x[\t ]+%s$`, thread, slot, regexp.QuoteMeta(access), size, address, regexp.QuoteMeta(state))
	return len(regexp.MustCompile(pattern).FindAllString(output, -1)) == 1
}

func uiThreadRowMatches(output string, selected bool, thread target.ThreadInfo) bool {
	marker := " "
	if selected {
		marker = "*"
	}
	state := thread.State.String()
	if thread.Exiting {
		state += "/exiting"
	}
	if thread.Listening {
		state += "/listening"
	}
	pattern := fmt.Sprintf(`(?m)^%s[\t ]+%d[\t ]+%d[\t ]+%d[\t ]+%s[\t ]+%s[\t ]+%s$`, regexp.QuoteMeta(marker), thread.Ref.ID, thread.TID, thread.Process.ID, regexp.QuoteMeta(fmt.Sprintf("%q", thread.Name)), regexp.QuoteMeta(state), regexp.QuoteMeta(thread.Stop.Reason.String()))
	return len(regexp.MustCompile(pattern).FindAllString(output, -1)) == 1
}

func uiApplyHeaderCount(output string) int {
	return len(regexp.MustCompile(`(?m)^Thread [0-9]+ \(tid=[0-9]+ name="(?:[^"\\]|\\.)*"\):$`).FindAllString(output, -1))
}

func uiOutputHasLine(output, expected string) bool {
	words := strings.Fields(expected)
	for index := range words {
		words[index] = regexp.QuoteMeta(words[index])
	}
	pattern := `(?m)^[\t ]*` + strings.Join(words, `\s+`) + `[\t ]*$`
	return len(regexp.MustCompile(pattern).FindAllString(output, -1)) == 1
}

func TestUIIntegrationContextPreservesNativeFacts(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			f := newUIIntegration(t, pie)
			before, selected, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			registers, err := f.controller.session.ReadThreadRegisters(selected.Token)
			if err != nil {
				t.Fatal(err)
			}
			rip, err := contextRegisterValue(registers, "rip")
			if err != nil {
				t.Fatal(err)
			}
			rsp, err := contextRegisterValue(registers, "rsp")
			if err != nil {
				t.Fatal(err)
			}
			point := legacyNativeAddress(t, f, "ui_point")
			if target.Address(rip) != point+1 || f.controller.session.LastStop().Reason != target.StopBreakpoint {
				t.Fatalf("fixture lacks raw/logical software-breakpoint distinction: RIP=%#x point=%#x", rip, point)
			}
			f.command(t, "context on")
			output := f.command(t, "context")
			f.command(t, "context off")
			for _, pane := range []string{"registers", "stack", "code", "threads"} {
				pattern := regexp.MustCompile(`(?m)^-+\[` + pane + `\]-+$`)
				line := pattern.FindString(output)
				if line == "" || len(line) != 100 {
					t.Fatalf("default pane header %s: %q\n%s", pane, line, output)
				}
			}
			if !regexp.MustCompile(fmt.Sprintf(`(?m)^\$rip\s*:\s*0x%016x\b`, rip)).MatchString(output) {
				t.Fatalf("register RIP was replaced by logical code PC: %s", output)
			}
			if !regexp.MustCompile(fmt.Sprintf(`(?m)^\*->\s+0x%016x\b`, point)).MatchString(output) || !strings.Contains(output, "ui_point") {
				t.Fatalf("current code address/symbol not derived from core instruction PC: %s", output)
			}
			if !strings.Contains(output, fmt.Sprintf("0x%016x|+0x0000|+000:", rsp)) {
				t.Fatalf("raw stack slot/offset labels missing: %s", output)
			}
			if !strings.Contains(output, "$rsp>") {
				t.Fatalf("exact RSP label missing: %s", output)
			}
			if got := f.read(t, "ui_point", 1)[0]; got != 0xcc {
				t.Fatalf("UI mutated software-breakpoint byte: %#x", got)
			}
			registerOutput := f.command(t, "regs -s")
			matches := regexp.MustCompile(`(?m)^\$(\w+)\s*:`).FindAllStringSubmatch(registerOutput, -1)
			wanted := []string{"rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "orig_rax", "fs_base", "gs_base", "eflags", "cs"}
			if len(matches) != len(wanted) {
				t.Fatalf("register rows: %v\n%s", matches, registerOutput)
			}
			for index, name := range wanted {
				if matches[index][1] != name {
					t.Fatalf("register order at %d: %s, want %s", index, matches[index][1], name)
				}
			}
			flags, err := contextRegisterValue(registers, "eflags")
			if err != nil {
				t.Fatal(err)
			}
			flagLine := regexp.MustCompile(`(?m)^\$eflags[^\n]+`).FindString(registerOutput)
			for _, flag := range []struct {
				bit  uint
				name string
			}{{0, "cf"}, {2, "pf"}, {6, "zf"}, {7, "sf"}, {8, "tf"}, {9, "if"}, {10, "df"}, {11, "of"}} {
				name := flag.name
				if flags&(uint64(1)<<flag.bit) != 0 {
					name = strings.ToUpper(name)
				}
				if !regexp.MustCompile(`\b` + name + `\b`).MatchString(flagLine) {
					t.Fatalf("flag %s contradicts raw %#x: %s", name, flags, flagLine)
				}
			}
			threads := f.command(t, "threads")
			for _, label := range []string{"Id", "TID", "Name", "State", "Reason"} {
				if !strings.Contains(threads, label) {
					t.Fatalf("thread column %s missing: %s", label, threads)
				}
			}
			for _, thread := range before.Threads {
				pattern := regexp.MustCompile(fmt.Sprintf(`(?m)^.*\b%d\b[^\n]+`, thread.TID))
				row := pattern.FindString(threads)
				if row == "" || !strings.Contains(strings.ToLower(row), thread.Stop.Reason.String()) {
					t.Fatalf("thread-local reason lost: %+v\n%s", thread, threads)
				}
			}
			if strings.ContainsAny(output+registerOutput+threads, "\x1b\x07") || !strings.Contains(threads, `\x1b`) {
				t.Fatalf("untrusted thread text changed terminal state: %q", threads)
			}
			after, err := f.controller.session.Snapshot()
			if err != nil || before.Sequence != after.Sequence || before.Memory != after.Memory {
				t.Fatalf("read-only UI mutated snapshot: %v", err)
			}
		})
	}
}

type uiIntegrationMemoryAudit struct {
	session
	reads int
}

func (s *uiIntegrationMemoryAudit) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	s.reads++
	return s.session.ReadSpaceMemory(token, address, dst)
}

func (s *uiIntegrationMemoryAudit) ReadCodeMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	s.reads++
	return s.session.ReadCodeMemory(token, address, dst)
}

func TestUIIntegrationWalkerBoundariesAndSimpleRegisters(t *testing.T) {
	f := newUIIntegration(t, true)
	if output := f.command(t, "telescope ui_chain 1"); !strings.Contains(output, "0x1122334455667788") || !strings.Contains(output, " -> ") {
		t.Fatalf("bounded pointer walk lost raw values: %s", output)
	}
	if output := f.command(t, "telescope ui_cycle 1"); !strings.Contains(output, "[loop detected]") {
		t.Fatalf("cycle was not explicitly terminated: %s", output)
	}
	for _, name := range []string{"ui_hole", "ui_edge"} {
		value := binary.LittleEndian.Uint64(f.read(t, name, 8))
		if output := f.command(t, "telescope "+name+" 1"); !strings.Contains(output, fmt.Sprintf("0x%016x", value)) {
			t.Fatalf("non-dereferenceable scalar was lost: %s", output)
		}
	}
	edge := binary.LittleEndian.Uint64(f.read(t, "ui_edge", 8))
	output, err := f.execute(fmt.Sprintf("telescope %#x 1", edge))
	if !errors.Is(err, target.ErrPartial) || !strings.Contains(output, "d4 c3 b2 a1") || strings.Contains(output, "00000000a1b2c3d4") {
		t.Fatalf("partial explicit row invented bytes: %v\n%s", err, output)
	}
	real := f.controller.session
	audit := &uiIntegrationMemoryAudit{session: real}
	f.controller.session = audit
	output, err = f.execute("regs -s")
	f.controller.session = real
	if err != nil || audit.reads != 0 || strings.Contains(output, " -> ") {
		t.Fatalf("simple registers performed a chain read: reads=%d error=%v\n%s", audit.reads, err, output)
	}
	f.command(t, "regs -s rip")
}

func TestUIIntegrationModifiedRegisterAndColorPolicy(t *testing.T) {
	f := newUIIntegration(t, false)
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways, IsTerminal: true, Term: "xterm-256color"})
	if err != nil {
		t.Fatal(err)
	}
	f.controller.renderer = renderer
	check := func(command string) string {
		t.Helper()
		output, err := f.execute(command)
		if err != nil {
			t.Fatalf("%s: %v\n%s", command, err, output)
		}
		return output
	}
	check("regs -s r12")
	check("set r12 0x8877665544332211")
	for range 2 {
		output := check("regs -s r12")
		if !strings.Contains(output, renderer.Text(display.StyleChanged, "$r12")) || !strings.Contains(output, "0x8877665544332211") {
			t.Fatalf("current-revision modified register not highlighted: %q", output)
		}
	}
	check("set r11 0x1122334455667788")
	output := check("regs -s r12")
	if strings.Contains(output, renderer.Text(display.StyleChanged, "$r12")) || !strings.Contains(output, renderer.Text(display.StyleRegister, "$r12")) {
		t.Fatalf("unchanged register retained a stale highlight across revisions: %q", output)
	}
	plain, err := display.NewRenderer(display.Options{Mode: display.ColorAuto, IsTerminal: true, Term: "xterm-256color", NoColor: "1"})
	if err != nil {
		t.Fatal(err)
	}
	f.controller.renderer = plain
	if output := check("context"); strings.ContainsAny(output, "\x1b\x07") {
		t.Fatalf("NO_COLOR emitted terminal controls: %q", output)
	}
}
