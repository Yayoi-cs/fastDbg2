package debugger

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/target"
)

const addressTextNativeSource = `#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
char text_shell[] = "SHELL=/bin/bash";
char text_quote[] = "A'B\"C\\D";
char text_unicode[] = "日本語☃";
unsigned char text_one[] = {65,0,255,255,255,255,255,255};
unsigned char text_control[] = {65,65,27,91,51,49,109,0};
char text_cap[256];
char text_unterminated[256];
uintptr_t text_guard;
uintptr_t text_rows[8];
__attribute__((naked,noinline)) void text_probe_stop(void) {
    __asm__ volatile("push %r12; push %r13; push %r14; push %r15; lea text_shell(%rip), %r12; lea text_quote(%rip), %r13; lea text_unicode(%rip), %r14; mov text_guard(%rip), %r15; sub $64, %rsp; mov %r12, 0(%rsp); mov %r13, 8(%rsp); mov %r14, 16(%rsp); mov %r15, 24(%rsp); .globl text_probe_ready; text_probe_ready: nop; nop; add $64, %rsp; pop %r15; pop %r14; pop %r13; pop %r12; ret;");
}
int main(void) {
    long size = sysconf(_SC_PAGESIZE);
    if (size < 8) return 20;
    char *region = mmap(0, (size_t)size*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 21;
    memcpy(region+size-4, "END", 4);
    if (mprotect(region+size, (size_t)size, PROT_NONE)) return 22;
    text_guard = (uintptr_t)(region+size-4);
    memset(text_cap, 'A', 255);
    memset(text_unterminated, 'Q', 256);
    text_rows[0]=(uintptr_t)text_shell;
    text_rows[1]=(uintptr_t)text_quote;
    text_rows[2]=(uintptr_t)text_unicode;
    text_rows[3]=(uintptr_t)text_one;
    text_rows[4]=text_guard;
    text_rows[5]=(uintptr_t)text_control;
    text_rows[6]=(uintptr_t)text_unterminated;
    text_rows[7]=(uintptr_t)text_cap;
    text_probe_stop();
    return 41;
}
`

func TestAddressTextNativeSharedViewsKeepSnapshotAndRawWords(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie=%t", pie), func(t *testing.T) {
			path := deterministicBuild(t, "cc", addressTextNativeSource, pie, "-O0")
			fixture := deterministicLaunch(t, path, "text_probe_ready")
			fixture.command(t, "continue")
			before, err := fixture.controller.session.Snapshot()
			if err != nil || fixture.controller.session.LastStop().Reason != target.StopBreakpoint {
				t.Fatalf("native fixture stop: %+v %v", before, err)
			}
			selected := fixture.controller.selected
			fixture.command(t, "context on")
			for _, command := range []string{"regs r12 r13 r14 r15", "context regs", "context stack", "stack 4", "tel text_rows 5"} {
				output := fixture.command(t, command)
				for _, want := range []string{"0x622f3d4c4c454853", "'SHELL=/bin/bash'", `'A\'B"C\\D'`, "'日本語☃'", "'END'"} {
					if !strings.Contains(output, want) {
						t.Fatalf("%s missing %q: %s", command, want, output)
					}
				}
				if strings.Contains(output, "\x1b") {
					t.Fatalf("plain native text injected ANSI: %s", output)
				}
			}
			if output := fixture.command(t, "regs -s r12"); strings.Contains(output, "'") || strings.Contains(output, " -> ") {
				t.Fatalf("simple registers acquired text previews: %s", output)
			}
			if output := fixture.command(t, "tel text_shell 1"); !strings.Contains(output, "0x622f3d4c4c454853 'SHELL=/bin/bash'") || strings.Count(output, "\n") != 1 {
				t.Fatalf("direct telescope changed logical rows: %s", output)
			}
			output := fixture.command(t, "tel text_rows 8")
			rows := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
			if len(rows) != 8 || !strings.HasSuffix(rows[3], "'A'") || !strings.HasSuffix(rows[4], "'END'") || strings.Contains(rows[5], "'") || strings.Contains(rows[6], "'") || !strings.HasSuffix(rows[7], "'"+strings.Repeat("A", 59)+"'...") {
				t.Fatalf("native positive/negative text predicates: %s", output)
			}
			after, err := fixture.controller.session.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) || fixture.controller.selected != selected {
				t.Fatalf("annotations changed target/thread/memory facts: before=%+v after=%+v err=%v", before, after, err)
			}
			stop := fixture.controller.session.LastStop()
			var raw [1]byte
			if stop.Breakpoint == nil {
				t.Fatal("annotation lost software breakpoint stop")
			}
			if n, err := fixture.controller.session.ReadSpaceMemory(before.Memory, *stop.Breakpoint, raw[:]); err != nil || n != 1 || raw[0] != 0xcc {
				t.Fatalf("annotations changed raw breakpoint/token: %x count=%d error=%v", raw, n, err)
			}
			fixture.command(t, "context off")
			fixture.command(t, "delete all")
			fixture.command(t, "continue")
			stop = fixture.controller.session.LastStop()
			if fixture.controller.session.State() != target.StateExited || stop.ExitCode == nil || *stop.ExitCode != 41 {
				t.Fatalf("annotation reads changed target continuation: %+v", stop)
			}
		})
	}
}

func TestAddressTextHelpDescribesObservedBytesNotTypes(t *testing.T) {
	for _, name := range []string{"context", "regs", "stack", "telescope"} {
		controller, _, output := newAddressWalkTestController()
		if _, err := controller.Execute(context.Background(), "help", name); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"nonempty", "NUL-terminated", "exact source address", "256 bytes", "UTF-8", "unicode.IsPrint", "64 columns including quotes", "32 KiB", "2048 calls", "not a string-type guess", "stale/cancel"} {
			if !strings.Contains(output.String(), want) {
				t.Fatalf("%s help lacks %q: %s", name, want, output.String())
			}
		}
	}
}
