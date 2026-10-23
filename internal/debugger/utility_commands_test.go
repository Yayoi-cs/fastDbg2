package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

func TestUtilityCyclicGeneration(t *testing.T) {
	for _, test := range []struct {
		args string
		want string
	}{
		{"0", "\n"},
		{"1", "a\n"},
		{"0x10", "aaaabaaacaaadaaa\n"},
		{"32", "aaaabaaacaaadaaaeaaafaaagaaahaaa\n"},
	} {
		t.Run(test.args, func(t *testing.T) {
			var out bytes.Buffer
			controller := &Controller{out: &out}
			if err := controller.showCyclic(context.Background(), test.args); err != nil || out.String() != test.want {
				t.Fatalf("err=%v output=%q want=%q", err, out.String(), test.want)
			}
		})
	}
}

func TestUtilityCyclicFullSequenceIsDeBruijn(t *testing.T) {
	sequence, err := cyclicGenerate(context.Background(), cyclicSequenceLength)
	if err != nil || len(sequence) != cyclicSequenceLength || !bytes.HasSuffix(sequence, []byte("zzzz")) {
		t.Fatalf("length=%d error=%v", len(sequence), err)
	}
	seen := make(map[uint32]int, cyclicSequenceLength)
	wrapped := append(bytes.Clone(sequence), sequence[:3]...)
	for offset := range sequence {
		value := sequence[offset]
		if value < 'a' || value > 'z' {
			t.Fatalf("invalid byte at %d: %#x", offset, value)
		}
		key := binary.LittleEndian.Uint32(wrapped[offset : offset+4])
		if previous, exists := seen[key]; exists {
			t.Fatalf("duplicate %q at %d and %d", wrapped[offset:offset+4], previous, offset)
		}
		seen[key] = offset
	}
}

func TestUtilityCyclicExactSearch(t *testing.T) {
	for _, test := range []struct {
		args string
		want string
	}{
		{"-d baaa", "offset: 4 (0x4)  pattern: \"baaa\" [first exact match]\n"},
		{"-D 0x61616162", "offset: 4 (0x4)  pattern: \"baaa\" [first exact match]\n"},
		{"-d --size 4 0x61616162", "offset: 4 (0x4)  pattern: \"baaa\" [first exact match]\n"},
		{"-d --endian big --size 4 0x62616161", "offset: 4 (0x4)  pattern: \"baaa\" [first exact match]\n"},
		{"-d --size 4 --endian little 0x61616162", "offset: 4 (0x4)  pattern: \"baaa\" [first exact match]\n"},
		{"-d 0x616161", "offset: 0 (0x0)  pattern: \"aaa\" [first exact match; short patterns may be nonunique]\n"},
		{"-d a", "offset: 0 (0x0)  pattern: \"a\" [first exact match; short patterns may be nonunique]\n"},
		{"-d zzzz", fmt.Sprintf("offset: %d (0x%x)  pattern: \"zzzz\" [first exact match]\n", cyclicSequenceLength-4, cyclicSequenceLength-4)},
	} {
		t.Run(test.args, func(t *testing.T) {
			var out bytes.Buffer
			controller := &Controller{out: &out}
			if err := controller.showCyclic(context.Background(), test.args); err != nil || out.String() != test.want {
				t.Fatalf("err=%v output=%q want=%q", err, out.String(), test.want)
			}
		})
	}
	sequence, err := cyclicGenerate(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	pattern := sequence[17:29]
	var out bytes.Buffer
	controller := &Controller{out: &out}
	if err := controller.showCyclic(context.Background(), "-d "+string(pattern)); err != nil ||
		out.String() != fmt.Sprintf("offset: 17 (0x11)  pattern: %q [first exact match]\n", pattern) {
		t.Fatalf("long pattern was truncated: error=%v output=%q", err, out.String())
	}
}

func TestUtilityCyclicPatterns(t *testing.T) {
	for _, test := range []struct {
		args []string
		want []byte
	}{
		{[]string{"0x0"}, []byte{0}},
		{[]string{"0x123456"}, []byte{0x56, 0x34, 0x12}},
		{[]string{"--size", "4", "0x123456"}, []byte{0x56, 0x34, 0x12, 0}},
		{[]string{"--size", "4", "--endian", "big", "0x123456"}, []byte{0, 0x12, 0x34, 0x56}},
		{[]string{"--size", "8", "0xffffffffffffffff"}, bytes.Repeat([]byte{0xff}, 8)},
		{[]string{"0X61"}, []byte{'a'}},
		{[]string{"1234"}, []byte("1234")},
	} {
		pattern, err := cyclicPattern(test.args)
		if err != nil || !bytes.Equal(pattern, test.want) {
			t.Fatalf("%q: got %x error=%v want=%x", test.args, pattern, err, test.want)
		}
	}
}

func TestUtilityCyclicInvalidArguments(t *testing.T) {
	for _, test := range []struct {
		args string
		want error
	}{
		{"", target.ErrInvalidArgument},
		{"-1", target.ErrInvalidArgument},
		{"+1", target.ErrInvalidArgument},
		{"1 2", target.ErrInvalidArgument},
		{"456977", target.ErrInvalidArgument},
		{"18446744073709551616", target.ErrOverflow},
		{"-d", target.ErrInvalidArgument},
		{"-d ''", target.ErrInvalidArgument},
		{"-d --size", target.ErrInvalidArgument},
		{"-d --size 0 aaaa", target.ErrInvalidArgument},
		{"-d --size 9 0x61", target.ErrInvalidArgument},
		{"-d --size 1 --size 1 0x61", target.ErrInvalidArgument},
		{"-d --endian wrong 0x61", target.ErrInvalidArgument},
		{"-d --endian little --endian little 0x61", target.ErrInvalidArgument},
		{"-d --endian big baaa", target.ErrInvalidArgument},
		{"-d --size 4 baaa", target.ErrInvalidArgument},
		{"-d --size 1 0x6161", target.ErrOverflow},
		{"-d 0x10000000000000000", target.ErrOverflow},
		{"-d 0xwrong", target.ErrInvalidArgument},
		{"-d --wrong aaaa", target.ErrInvalidArgument},
		{"-d aaaa bbbb", target.ErrInvalidArgument},
		{"-d '", target.ErrInvalidArgument},
		{"-d a\x00aaa", target.ErrInvalidArgument},
		{"-d ABCD", target.ErrNotFound},
		{"-d zzzza", target.ErrNotFound},
		{"-d --size 4 0x616161", target.ErrNotFound},
		{"-d " + strings.Repeat("a", cyclicSequenceLength+1), target.ErrInvalidArgument},
		{strings.Repeat("a", 2*cyclicSequenceLength+129), target.ErrInvalidArgument},
	} {
		name := test.args
		if len(name) > 80 {
			name = fmt.Sprintf("input-length-%d", len(name))
		}
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			controller := &Controller{out: &out}
			if err := controller.showCyclic(context.Background(), test.args); !errors.Is(err, test.want) || out.Len() != 0 {
				t.Fatalf("error=%v want=%v output=%q", err, test.want, out.String())
			}
		})
	}
}

func utilityWorkingDirectory(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	parent := filepath.Join(filepath.Dir(source), "..", "..", ".cache", "fastdbg-amd64-command-port", "utilities")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, "test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	t.Chdir(directory)
	return directory
}

func utilityAssertAssemblyClean(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(assemblyCache)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("assembler left temporary files: %v", entries)
	}
}

func TestUtilityAssemblyExactBytes(t *testing.T) {
	utilityWorkingDirectory(t)
	for _, test := range []struct {
		source string
		hex    string
	}{
		{"syscall", "0f05"},
		{"pop rdi; ret", "5fc3"},
		{"mov rax, 0x3b; mov rdi, rsi; syscall", "48c7c03b0000004889f70f05"},
		{"lea rax, [rip + done]; done: ret", "488d0500000000c3"},
		{"1: nop; jmp 1b", "90ebfd"},
		{"jmp 2f\nnop\n2: ret", "eb0190c3"},
		{".Lfoo: nop; jmp .Lfoo", "90ebfd"},
		{"mov eax, dword ptr fs:[0x28]", "648b042528000000"},
	} {
		t.Run(test.source, func(t *testing.T) {
			data, err := assembleAMD64(context.Background(), test.source)
			if err != nil || hex.EncodeToString(data) != test.hex {
				t.Fatalf("bytes=%x error=%v want=%s", data, err, test.hex)
			}
			utilityAssertAssemblyClean(t)
		})
	}
}

func TestUtilityAssemblyPresentation(t *testing.T) {
	utilityWorkingDirectory(t)
	for _, args := range []string{"syscall", "'pop rdi; ret'", "\"pop rdi; ret\""} {
		var out bytes.Buffer
		controller := &Controller{out: &out}
		if err := controller.showAssembly(context.Background(), args); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "2 bytes: ") || !strings.Contains(out.String(), "0x0000000000000000:") ||
			!strings.Contains(out.String(), " |") || strings.Contains(out.String(), "\x1b") {
			t.Fatalf("unexpected assembly output: %q", out.String())
		}
		utilityAssertAssemblyClean(t)
	}
}

func TestUtilityAssemblyRejectsDirectivesAndInputExtensions(t *testing.T) {
	utilityWorkingDirectory(t)
	for _, source := range []string{
		".include secret", ".incbin secret", ".macro foo\nnop\n.endm", ".space 10000000",
		"label: .include secret", "1: .incbin secret", ".Llocal: .byte 0x90", "nop; .byte 0x90",
		"nop\n.include secret", "nop # comment", "nop /* comment */", "nop // comment", "eax=1",
		"mov al, 'a'", "mov al, \"a\"", "nop\\\n.include secret",
	} {
		t.Run(source, func(t *testing.T) {
			data, err := assembleAMD64(context.Background(), source)
			if !errors.Is(err, target.ErrUnsupported) || data != nil {
				t.Fatalf("bytes=%x error=%v", data, err)
			}
			utilityAssertAssemblyClean(t)
		})
	}
	for _, source := range []string{"", " \t;\n", "only_label:", "1: 2:", "\x00nop", "nop\r.include secret", "nöp", "nop\x1b", strings.Repeat("n", maxAssemblySource+1)} {
		data, err := assembleAMD64(context.Background(), source)
		if !errors.Is(err, target.ErrInvalidArgument) || data != nil {
			t.Fatalf("length=%d bytes=%x error=%v", len(source), data, err)
		}
	}
	for _, args := range []string{"", "mov rax, 1", "''", "'", strings.Repeat("n", 2*maxAssemblySource+3)} {
		var out bytes.Buffer
		controller := &Controller{out: &out}
		if err := controller.showAssembly(context.Background(), args); !errors.Is(err, target.ErrInvalidArgument) || out.Len() != 0 {
			t.Fatalf("args length=%d error=%v output=%q", len(args), err, out.String())
		}
	}
}

func TestUtilityAssemblyRejectsRelocationsAndWarnings(t *testing.T) {
	utilityWorkingDirectory(t)
	for _, source := range []string{"call missing_symbol", "call 0x1234", "mov rax, offset local; local: ret", "mov eax, [rip + external]"} {
		data, err := assembleAMD64(context.Background(), source)
		if !errors.Is(err, target.ErrUnsupported) || data != nil || !strings.Contains(err.Error(), "relocations") {
			t.Fatalf("%q: bytes=%x error=%v", source, data, err)
		}
		utilityAssertAssemblyClean(t)
	}
	for _, source := range []string{"not_an_instruction rax", "mov al, 0x100", "mov eax, 0x100000000"} {
		data, err := assembleAMD64(context.Background(), source)
		if !errors.Is(err, target.ErrInvalidArgument) || data != nil {
			t.Fatalf("%q: bytes=%x error=%v", source, data, err)
		}
		utilityAssertAssemblyClean(t)
	}
}

func TestUtilityAssemblyMissingToolAndConfinedOutput(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	t.Run("missing-tool", func(t *testing.T) {
		t.Setenv("PATH", directory)
		if data, err := assembleAMD64(context.Background(), "nop"); !errors.Is(err, target.ErrUnavailable) || data != nil {
			t.Fatalf("bytes=%x error=%v", data, err)
		}
		utilityAssertAssemblyClean(t)
	})
	t.Run("escaped-cache", func(t *testing.T) {
		outside := filepath.Join(filepath.Dir(directory), filepath.Base(directory)+"-outside")
		if err := os.Mkdir(outside, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(outside) })
		if err := os.Symlink(outside, ".cache"); err != nil {
			t.Fatal(err)
		}
		data, err := assembleAMD64(context.Background(), "nop")
		if err == nil || data != nil {
			t.Fatalf("escaped cache accepted: bytes=%x error=%v", data, err)
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("escaped cache changed: entries=%v error=%v", entries, err)
		}
	})
}

func utilityFakeAssembler(t *testing.T, source string) {
	t.Helper()
	if err := os.Mkdir("bin", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("bin/as", []byte("#!/bin/sh\n"+source), 0700); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Abs("bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", path)
}

func TestUtilityAssemblyCanceledChildIsReapedAndCleaned(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	readyName, blockName := filepath.Join(directory, "ready"), filepath.Join(directory, "block")
	for _, name := range []string{readyName, blockName} {
		if err := unix.Mkfifo(name, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := os.OpenFile(readyName, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FASTDBG_UTILITY_READY", readyName)
	t.Setenv("FASTDBG_UTILITY_BLOCK", blockName)
	utilityFakeAssembler(t, "printf R > \"$FASTDBG_UTILITY_READY\"\nexec /bin/cat < \"$FASTDBG_UTILITY_BLOCK\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := assembleAMD64(ctx, "nop")
		done <- err
	}()
	var notification [1]byte
	if _, err := io.ReadFull(ready, notification[:]); err != nil || notification[0] != 'R' {
		t.Fatalf("assembler readiness: %q error=%v", notification, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("assembler cancellation did not join its child")
	}
	utilityAssertAssemblyClean(t)
}

func TestUtilityAssemblyDiagnosticsAreBoundedAndEscaped(t *testing.T) {
	utilityWorkingDirectory(t)
	utilityFakeAssembler(t, "printf '\\033[31muntrusted\\n' >&2\nexit 7\n")
	data, err := assembleAMD64(context.Background(), "nop")
	if data != nil || !errors.Is(err, target.ErrInvalidArgument) || strings.ContainsAny(err.Error(), "\x1b\n") || !strings.Contains(err.Error(), "\\x1b") {
		t.Fatalf("bytes=%x error=%v", data, err)
	}
	utilityAssertAssemblyClean(t)
	diagnostic := &assemblyDiagnostics{}
	input := bytes.Repeat([]byte{'a'}, 20000)
	if n, err := diagnostic.Write(input); n != len(input) || err != nil || len(diagnostic.data) != 16<<10 || !diagnostic.truncated {
		t.Fatalf("bounded diagnostic n=%d err=%v length=%d truncated=%t", n, err, len(diagnostic.data), diagnostic.truncated)
	}
	if n, err := diagnostic.Write(input); n != len(input) || err != nil || len(diagnostic.data) != 16<<10 {
		t.Fatalf("second bounded diagnostic n=%d error=%v length=%d", n, err, len(diagnostic.data))
	}
}

func utilityAssemblyObject() []byte {
	names := []byte("\x00.text\x00.rela.text\x00.shstrtab\x00")
	sectionOffset := uint64(96 + len(names))
	data := make([]byte, int(sectionOffset)+4*64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_REL))
	binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[40:], sectionOffset)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[58:], 64)
	binary.LittleEndian.PutUint16(data[60:], 4)
	binary.LittleEndian.PutUint16(data[62:], 3)
	data[64] = 0x90
	copy(data[96:], names)
	text := data[sectionOffset+64:]
	binary.LittleEndian.PutUint32(text, 1)
	binary.LittleEndian.PutUint32(text[4:], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(text[8:], uint64(elf.SHF_ALLOC|elf.SHF_EXECINSTR))
	binary.LittleEndian.PutUint64(text[24:], 64)
	binary.LittleEndian.PutUint64(text[32:], 1)
	relocations := data[sectionOffset+128:]
	binary.LittleEndian.PutUint32(relocations, 7)
	binary.LittleEndian.PutUint32(relocations[4:], uint32(elf.SHT_RELA))
	binary.LittleEndian.PutUint64(relocations[24:], 72)
	binary.LittleEndian.PutUint32(relocations[44:], 1)
	namesSection := data[sectionOffset+192:]
	binary.LittleEndian.PutUint32(namesSection, 18)
	binary.LittleEndian.PutUint32(namesSection[4:], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(namesSection[24:], 96)
	binary.LittleEndian.PutUint64(namesSection[32:], uint64(len(names)))
	return data
}

func TestUtilityAssemblyObjectValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte, []byte, []byte)
		want   error
	}{
		{"valid", func([]byte, []byte, []byte) {}, nil},
		{"wrong-machine", func(data, _, _ []byte) { binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_AARCH64)) }, target.ErrUnsupported},
		{"wrong-type", func(data, _, _ []byte) { binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_EXEC)) }, target.ErrUnsupported},
		{"empty", func(_, text, _ []byte) { binary.LittleEndian.PutUint64(text[32:], 0) }, target.ErrInvalidArgument},
		{"oversized", func(_, text, _ []byte) { binary.LittleEndian.PutUint64(text[32:], maxAssemblyBytes+1) }, target.ErrInvalidArgument},
		{"non-executable", func(_, text, _ []byte) { binary.LittleEndian.PutUint64(text[8:], uint64(elf.SHF_ALLOC)) }, target.ErrUnsupported},
		{"nobits", func(_, text, _ []byte) { binary.LittleEndian.PutUint32(text[4:], uint32(elf.SHT_NOBITS)) }, target.ErrUnsupported},
		{"rela-text", func(_, _, relocations []byte) { binary.LittleEndian.PutUint64(relocations[32:], 24) }, target.ErrUnsupported},
		{"rel-text", func(_, _, relocations []byte) {
			binary.LittleEndian.PutUint32(relocations[4:], uint32(elf.SHT_REL))
			binary.LittleEndian.PutUint64(relocations[32:], 16)
		}, target.ErrUnsupported},
		{"other-relocations", func(_, _, relocations []byte) {
			binary.LittleEndian.PutUint64(relocations[32:], 24)
			binary.LittleEndian.PutUint32(relocations[44:], 3)
		}, nil},
		{"duplicate-text", func(_, _, relocations []byte) { binary.LittleEndian.PutUint32(relocations, 1) }, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := utilityAssemblyObject()
			offset := binary.LittleEndian.Uint64(data[40:])
			test.mutate(data, data[offset+64:], data[offset+128:])
			assembled, err := readAssemblyObject(bytes.NewReader(data))
			if test.want == nil {
				if err != nil || !bytes.Equal(assembled, []byte{0x90}) {
					t.Fatalf("bytes=%x error=%v", assembled, err)
				}
			} else if !errors.Is(err, test.want) || assembled != nil {
				t.Fatalf("bytes=%x error=%v want=%v", assembled, err, test.want)
			}
		})
	}
	if data, err := readAssemblyObject(bytes.NewReader([]byte("not ELF"))); err == nil || data != nil {
		t.Fatalf("non-ELF accepted: bytes=%x error=%v", data, err)
	}
	truncated := utilityAssemblyObject()
	offset := binary.LittleEndian.Uint64(truncated[40:])
	binary.LittleEndian.PutUint64(truncated[offset+64+24:], uint64(len(truncated)))
	if data, err := readAssemblyObject(bytes.NewReader(truncated)); err == nil || data != nil {
		t.Fatalf("truncated .text accepted: bytes=%x error=%v", data, err)
	}
}

func TestUtilityCancellationAndOutputErrors(t *testing.T) {
	utilityWorkingDirectory(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		want := target.ErrInvalidArgument
		if ctx != nil {
			want = context.Canceled
		}
		var out bytes.Buffer
		controller := &Controller{out: &out}
		for _, err := range []error{
			controller.showCyclic(ctx, "32"), controller.showAssembly(ctx, "syscall"),
		} {
			if !errors.Is(err, want) || out.Len() != 0 {
				t.Fatalf("error=%v want=%v output=%q", err, want, out.String())
			}
		}
	}
	for _, length := range []int{-1, cyclicSequenceLength + 1} {
		if data, err := cyclicGenerate(context.Background(), length); !errors.Is(err, target.ErrInvalidArgument) || data != nil {
			t.Fatalf("invalid generation length=%d data=%x error=%v", length, data, err)
		}
	}
	for _, short := range []bool{false, true} {
		failure := errors.New("utility output failed")
		controller := &Controller{out: controllerTestWriter(func([]byte) (int, error) {
			if short {
				return 0, nil
			}
			return 0, failure
		})}
		want := failure
		if short {
			want = io.ErrShortWrite
		}
		for _, err := range []error{
			controller.showCyclic(context.Background(), "32"),
			controller.showCyclic(context.Background(), "-d baaa"),
			controller.showAssembly(context.Background(), "syscall"),
		} {
			var outputError *OutputError
			if !errors.As(err, &outputError) || !errors.Is(err, want) {
				t.Fatalf("output error=%v want=%v", err, want)
			}
		}
	}
	utilityAssertAssemblyClean(t)
}

type utilityCancelContext struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (ctx *utilityCancelContext) Err() error {
	ctx.calls++
	if ctx.calls == 20 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestUtilityCyclicCancellationDuringGeneration(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &utilityCancelContext{Context: base, cancel: cancel}
	data, err := cyclicGenerate(ctx, cyclicSequenceLength)
	if !errors.Is(err, context.Canceled) || data != nil || ctx.calls < 20 {
		t.Fatalf("data length=%d error=%v calls=%d", len(data), err, ctx.calls)
	}
}

func TestUtilityAssemblyCancellationDuringOutput(t *testing.T) {
	utilityWorkingDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	controller := &Controller{out: controllerTestWriter(func(data []byte) (int, error) {
		cancel()
		return output.Write(data)
	})}
	err := controller.showAssembly(ctx, "syscall")
	if !errors.Is(err, context.Canceled) || output.String() != "2 bytes: 0f05\n" {
		t.Fatalf("error=%v output=%q", err, output.String())
	}
	utilityAssertAssemblyClean(t)
}

func TestUtilityAssemblyCancellationReapsWrapperDescendants(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	readyName := filepath.Join(directory, "ready")
	blockName := filepath.Join(directory, "child-block")
	parentBlockName := filepath.Join(directory, "parent-block")
	for _, name := range []string{readyName, blockName, parentBlockName} {
		if err := unix.Mkfifo(name, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := os.OpenFile(readyName, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	if err := ready.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FASTDBG_UTILITY_READY", readyName)
	t.Setenv("FASTDBG_UTILITY_BLOCK", blockName)
	t.Setenv("FASTDBG_UTILITY_PARENT_BLOCK", parentBlockName)
	utilityFakeAssembler(t, "/bin/cat < \"$FASTDBG_UTILITY_BLOCK\" &\nprintf '%d %d\\n' \"$$\" \"$!\" > \"$FASTDBG_UTILITY_READY\"\nexec /bin/cat < \"$FASTDBG_UTILITY_PARENT_BLOCK\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := assembleAMD64(ctx, "nop")
		done <- err
	}()
	joined := false
	var handles []int
	defer func() {
		cancel()
		if !joined {
			for _, handle := range handles {
				unix.PidfdSendSignal(handle, unix.SIGKILL, nil, 0)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("assembler supervisor cleanup did not finish")
			}
		}
		for _, handle := range handles {
			unix.Close(handle)
		}
	}()
	var parent, child int
	if _, err := fmt.Fscan(ready, &parent, &child); err != nil || parent <= 0 || child <= 0 {
		t.Fatalf("wrapper identities parent=%d child=%d error=%v", parent, child, err)
	}
	for _, pid := range []int{parent, child} {
		handle, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, handle)
	}
	cancel()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("assembler waited for descendant-held stdout after cancellation")
	}
	for _, pid := range []int{parent, child} {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned assembler descendant %d was not reaped: %q error=%v", pid, data, err)
		}
	}
	utilityAssertAssemblyClean(t)
}

const utilityAssemblyDescriptorProbe = `#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    struct stat input, object;
    if (fstat(0, &input) || fstat(3, &object) || !S_ISREG(input.st_mode) || !S_ISREG(object.st_mode)) return 91;
    if (fcntl(3, F_GETFD) != 0) return 92;
    DIR *descriptors = opendir("/proc/self/fd");
    if (!descriptors) return 93;
    struct dirent *entry;
    while ((entry = readdir(descriptors))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*end == 0 && fd > 3 && fd != dirfd(descriptors)) return 94;
    }
    closedir(descriptors);
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return 95;
    const char *names[] = {"TMPDIR", "TMP", "TEMP"};
    for (int i = 0; i < 3; i++) {
        const char *value = getenv(names[i]);
        if (!value || strcmp(cwd, value)) return 96;
    }
    FILE *ready = fopen(getenv("FASTDBG_UTILITY_READY"), "w");
    if (!ready) return 97;
    fprintf(ready, "%d\n", getpid());
    fclose(ready);
    int release = open(getenv("FASTDBG_UTILITY_RELEASE"), O_RDONLY);
    char value;
    if (release < 0 || read(release, &value, 1) != 1) return 98;
    close(release);
    argv[0] = getenv("FASTDBG_UTILITY_REAL_AS");
    execv(argv[0], argv);
    return 99;
}
`

func TestUtilityAssemblyObjectDescriptorHandoffAndConfinement(t *testing.T) {
	directory := utilityWorkingDirectory(t)
	assembler, err := exec.LookPath("as")
	if err != nil {
		t.Fatal(err)
	}
	assembler, err = filepath.Abs(assembler)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("bin", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("descriptor-probe.c", []byte(utilityAssemblyDescriptorProbe), 0600); err != nil {
		t.Fatal(err)
	}
	compileContext, compileCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer compileCancel()
	compile := exec.CommandContext(compileContext, "cc", "-Wall", "-Wextra", "-Werror", "descriptor-probe.c", "-o", "bin/as")
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile descriptor probe: %v: %s", err, output)
	}
	readyName, releaseName := filepath.Join(directory, "ready"), filepath.Join(directory, "release")
	for _, name := range []string{readyName, releaseName} {
		if err := unix.Mkfifo(name, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := os.OpenFile(readyName, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	if err := ready.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(releaseName, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	t.Setenv("FASTDBG_UTILITY_REAL_AS", assembler)
	t.Setenv("FASTDBG_UTILITY_READY", readyName)
	t.Setenv("FASTDBG_UTILITY_RELEASE", releaseName)
	t.Setenv("PATH", filepath.Join(directory, "bin"))
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, "untrusted inherited temporary directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := assembleAMD64(ctx, "nop; ret")
		done <- result{data, err}
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("descriptor probe cleanup did not finish")
			}
		}
	}()
	var pid int
	if _, err := fmt.Fscan(ready, &pid); err != nil || pid <= 0 {
		select {
		case outcome := <-done:
			joined = true
			t.Fatalf("descriptor probe exited before readiness: %v", outcome.err)
		default:
			t.Fatalf("descriptor probe readiness pid=%d error=%v", pid, err)
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var objects, sources int
	prefix := filepath.Join(directory, assemblyCache, "snippet-")
	for _, entry := range entries {
		name, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil || !strings.HasPrefix(name, prefix) {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("assembler parent FD %d (%q) is inheritable: flags=%d error=%v", fd, name, flags, err)
		}
		switch filepath.Ext(name) {
		case ".o":
			objects++
		case ".s":
			sources++
		}
	}
	if objects != 1 || sources != 1 {
		t.Fatalf("rooted temporary descriptors objects=%d sources=%d", objects, sources)
	}
	if _, err := release.Write([]byte{'R'}); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-done:
		joined = true
		if outcome.err != nil || !bytes.Equal(outcome.data, []byte{0x90, 0xc3}) {
			t.Fatalf("descriptor handoff bytes=%x error=%v", outcome.data, outcome.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("descriptor probe did not finish")
	}
	utilityAssertAssemblyClean(t)
}
