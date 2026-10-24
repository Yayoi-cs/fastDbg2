package debugger

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
)

const unwindAllocatorSource = `#include <stdint.h>
#include <stdlib.h>
volatile uintptr_t allocation_sink;
__attribute__((noinline)) void allocation_ready(void) { __asm__ volatile("nop" ::: "memory"); }
__attribute__((noinline)) int allocation_inner(int value) {
    void *p = malloc(128);
    if (!p) return 91;
    allocation_sink = (uintptr_t)p;
    __asm__ volatile("" : : "r"(p) : "memory");
    free(p);
    return value + 1;
}
__attribute__((noinline)) int allocation_outer(int value) { int result = allocation_inner(value); __asm__ volatile("" : "+r"(result)); return result + 1; }
int main(void) { allocation_ready(); return allocation_outer(4) != 6; }
`

func TestUnwindNativeDefaultAllocatorBreakpoints(t *testing.T) {
	for _, pie := range []bool{false, true} {
		for _, omit := range []bool{false, true} {
			t.Run(fmt.Sprintf("pie_%t_omit_%t", pie, omit), func(t *testing.T) {
				root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "unwind-native-fix"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				dir, err := os.MkdirTemp(root, "fixture-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(dir) })
				input, executable := filepath.Join(dir, "main.c"), filepath.Join(dir, "fixture")
				if err := os.WriteFile(input, []byte(unwindAllocatorSource), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				flags := []string{"-O2", "-g", "-fno-optimize-sibling-calls", "-fno-builtin-malloc", "-fno-builtin-free", "-fasynchronous-unwind-tables", "-fcf-protection=none"}
				if pie {
					flags = append(flags, "-fPIE", "-pie")
				} else {
					flags = append(flags, "-fno-pie", "-no-pie")
				}
				if omit {
					flags = append(flags, "-fomit-frame-pointer")
				} else {
					flags = append(flags, "-fno-omit-frame-pointer")
				}
				flags = append(flags, "-o", executable, input)
				compiler := exec.CommandContext(ctx, "cc", flags...)
				compiler.Env = append(os.Environ(), "TMPDIR="+dir)
				if text, err := compiler.CombinedOutput(); err != nil {
					t.Fatalf("compile: %v\n%s", err, text)
				}
				var output bytes.Buffer
				controller := New(&output, display.Renderer{})
				t.Cleanup(func() {
					if err := controller.Close(); err != nil {
						t.Error(err)
					}
				})
				if err := controller.Configure(executable, nil); err != nil {
					t.Fatal(err)
				}
				for _, command := range []struct{ name, args string }{{"context", "off"}, {"break", "allocation_ready"}, {"run", ""}, {"break", "malloc"}, {"break", "free"}} {
					if quit, err := controller.Execute(ctx, command.name, command.args); quit || err != nil {
						t.Fatalf("%+v: %v\n%s", command, err, output.String())
					}
				}
				adapter := controller.session.(*nativeSession)
				if adapter.uiSymbols.ready {
					t.Fatal("UI symbols were primed before first backtrace")
				}
				for _, name := range []string{"malloc", "free"} {
					if _, err := controller.Execute(ctx, "continue", ""); err != nil {
						t.Fatal(err)
					}
					snapshot, thread, err := controller.stopped()
					if err != nil {
						t.Fatal(err)
					}
					location, err := controller.session.ReadCodeLocation(thread.Token)
					if err != nil {
						t.Fatal(err)
					}
					if location.Breakpoint == nil || location.RawPC != location.InstructionPC+1 {
						t.Fatalf("location=%+v", location)
					}
					output.Reset()
					if err := controller.showBacktrace(ctx, ""); err != nil {
						t.Fatalf("default bt at %s: %v\n%s", name, err, output.String())
					}
					text := output.String()
					for _, want := range []string{"Thread ", name, "allocation_inner", "allocation_outer", "<main+", "[libc.so.6]", "[main]"} {
						if !strings.Contains(text, want) {
							t.Fatalf("%s missing %q:\n%s", name, want, text)
						}
					}
					seed, result, err := controller.collectUnwind(ctx, 32, inspect.UnwindSysVAMD64)
					if err != nil || !result.Complete || len(result.Frames) < 6 || result.Frames[0].PC != location.InstructionPC || result.Frames[0].RawPC != location.RawPC {
						t.Fatalf("seed=%+v result=%+v err=%v", seed.location, result, err)
					}
					if result.Frames[1].Registers.Known&1 != 0 {
						t.Fatal("caller RAX return value invented")
					}
					current, err := controller.session.Snapshot()
					if err != nil || current.Memory != snapshot.Memory || current.Sequence != snapshot.Sequence {
						t.Fatalf("bt changed target: %+v,%v", current, err)
					}
					var raw [1]byte
					if n, err := controller.session.ReadSpaceMemory(snapshot.Memory, location.InstructionPC, raw[:]); err != nil || n != 1 || raw[0] != 0xcc {
						t.Fatalf("bp changed: %x %d %v", raw, n, err)
					}
					t.Logf("%s:\n%s", name, text)
				}
			})
		}
	}
}
