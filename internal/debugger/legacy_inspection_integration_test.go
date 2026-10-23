package debugger

import (
	"bytes"
	"context"
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
)

const legacyInspectionAssembly = `.text
.global _start
.type _start,@function
_start:
call legacy_bounded
mov $60, %rax
xor %edi, %edi
syscall
.size _start, .-_start
.global legacy_bounded
.type legacy_bounded,@function
legacy_bounded:
nop
ret
nop
ret
.size legacy_bounded, .-legacy_bounded
.global legacy_zero_size
.type legacy_zero_size,@function
legacy_zero_size:
ret
.data
.global legacy_word
.type legacy_word,@object
legacy_word:
.quad 0x4847464544434241
.size legacy_word, .-legacy_word
.byte 0
.section .note.GNU-stack,"",@progbits
`

func TestLegacyInspectionNativeExactELFFunctions(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "fastdbg-amd64-command-port", "inspection-tests"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			dir, err := os.MkdirTemp(root, "native-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			source, object, executable := filepath.Join(dir, "fixture.s"), filepath.Join(dir, "fixture.o"), filepath.Join(dir, "fixture")
			if err := os.WriteFile(source, []byte(legacyInspectionAssembly), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			commands := [][]string{{"as", "--64", "-o", object, source}, {"ld", "-o", executable, object}}
			if pie {
				commands[1] = []string{"ld", "-pie", "--no-dynamic-linker", "-o", executable, object}
			}
			for _, argv := range commands {
				command := exec.CommandContext(ctx, argv[0], argv[1:]...)
				command.Env = append(os.Environ(), "TMPDIR="+dir)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("compile fixture: %v\n%s", err, output)
				}
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
			for _, command := range []struct{ name, args string }{{"context", "off"}, {"break", "legacy_bounded"}, {"run", ""}} {
				if quit, err := controller.Execute(ctx, command.name, command.args); err != nil || quit {
					t.Fatalf("%s %s: quit=%t error=%v\n%s", command.name, command.args, quit, err, output.String())
				}
			}
			output.Reset()
			if err := controller.showSymbols(ctx, "legacy_bounded"); err != nil || !strings.Contains(output.String(), `"legacy_bounded"`) || !strings.Contains(output.String(), "1 symbol(s)") || metadataJoinedField(output.String(), "Source proof") != `"proc-exe+auxv"` {
				t.Fatalf("symbols: error=%v output=%q", err, output.String())
			}
			for _, args := range []string{"func legacy_bounded", "f", "FUNC $rip", "func --module main legacy_bounded", "func --module main"} {
				output.Reset()
				if err := controller.showDisassemble(ctx, args); err != nil || strings.Count(output.String(), "  nop\n") != 2 || strings.Count(output.String(), "  ret\n") != 2 ||
					metadataJoinedField(output.String(), "Extent") != "4 bytes (ELF STT_FUNC extent)" || strings.Contains(output.String(), "int3") {
					t.Fatalf("disassemble %s: error=%v output=%q", args, err, output.String())
				}
			}
			output.Reset()
			if err := controller.showDisassemble(ctx, "func --module unknown-inspection-module legacy_bounded"); !errors.Is(err, target.ErrNotFound) || output.Len() != 0 {
				t.Fatalf("unknown module: error=%v output=%q", err, output.String())
			}
			output.Reset()
			if err := controller.showDisassemble(ctx, "func legacy_zero_size"); !errors.Is(err, target.ErrUnavailable) || output.Len() != 0 {
				t.Fatalf("zero-size function: error=%v output=%q", err, output.String())
			}
			output.Reset()
			if err := controller.showTelescope(ctx, "legacy_word 1"); err != nil || !strings.Contains(output.String(), "|+000: 0x4847464544434241") || !strings.Contains(output.String(), "'ABCDEFGH'") {
				t.Fatalf("raw telescope: error=%v output=%q", err, output.String())
			}
			output.Reset()
			if err := controller.showExamine(ctx, "1xb", "legacy_bounded"); err != nil || !strings.Contains(output.String(), "0xcc") {
				t.Fatalf("raw breakpoint byte: error=%v output=%q", err, output.String())
			}
		})
	}
}
