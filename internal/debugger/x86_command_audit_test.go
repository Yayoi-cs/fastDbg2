package debugger

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

func TestX86EveryRegisteredCommand(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			profile, err := parseAllocatorProfile([]byte(builtInX86AllocatorProfile))
			if err != nil {
				t.Fatal(err)
			}
			debugRoot := t.TempDir()
			for _, id := range []string{profile.LibcBuildID, profile.LoaderBuildID} {
				source, err := filepath.Abs(filepath.Join("..", "..", ".cache", "debug-info", ".build-id", id[:2], id[2:]+".debug"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(source); err != nil {
					t.Fatalf("audit requires matching local debug fixture %s: %v", id, err)
				}
				directory := filepath.Join(debugRoot, id)
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(source, filepath.Join(directory, "debuginfo")); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("DEBUGINFOD_CACHE_PATH", debugRoot)
			source, err := os.ReadFile("testdata/x86_heap.c")
			if err != nil {
				t.Fatal(err)
			}
			code := "#include <stdio.h>\n#include <unistd.h>\nunsigned char audit_bytes[32];\nunsigned int audit_words[4]={0x11223344,0x55667788,0,0};\nchar audit_text[]=\"AUDIT-X86\";\nunsigned int audit_zeros[1024];\n" + string(source)
			code = strings.Replace(code, "int main(void){", "int main(int argc,char **argv){if(argc>1){puts(\"ready\");fflush(stdout);while(access(argv[1],F_OK))usleep(1000);return 0;}", 1)
			f, _ := newLegacyFixture(t, pie, false, code, "checkpoint", false, "-m32", "-pthread", "-O1", "-fomit-frame-pointer")
			covered := make(map[string]int)
			run := func(command string) string {
				t.Helper()
				name, args := cli.SplitCommand(command)
				spec, ok := canonicalCommand(name)
				if !ok {
					t.Fatal(command)
				}
				f.output.Reset()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				quit, err := f.controller.Execute(ctx, name, args)
				output := f.output.String()
				if err != nil || quit != (spec.name == "quit") {
					t.Fatalf("%s: quit=%t err=%v\n%s", command, quit, err, output)
				}
				if strings.ContainsRune(output, '\x1b') {
					t.Fatalf("plain command emitted escapes: %q", command)
				}
				covered[spec.name]++
				t.Logf("EXEC %s (%d output bytes)", command, len(output))
				return output
			}
			run("context off")
			chunk := binary.LittleEndian.Uint32(f.read(t, "guards", 4)) - 8
			cases := map[string][]string{
				"context": {"regs stack code threads", "off"}, "regs": {"-s eax esp eip"}, "print": {"$eax", "audit_words+4"},
				"memory": {"--count 16 audit_words"}, "x": {"audit_words"}, "disassemble": {"--count 2 checkpoint", "func checkpoint"},
				"stack": {"4"}, "backtrace": {""}, "stackframe": {"0"}, "hexdump": {"byte --count 16 audit_words", "word --count 4 audit_words", "dword --count 4 audit_words", "qword --count 2 audit_words"},
				"db": {"--count 16 audit_words"}, "dw": {"--count 4 audit_words"}, "dd": {"--count 4 audit_words"}, "dq": {"--count 2 audit_words"}, "xxd": {"audit_words 16", "dword audit_words 4", "qword audit_words 2"},
				"set8": {"audit_bytes 0x41"}, "set16": {"audit_bytes+2 0x4243"}, "set32": {"audit_bytes+4 0x44454647"}, "xor": {"audit_bytes+8 0x1234"}, "wp": {"audit_bytes --size 4 --access write", "list", "d 0"},
				"simd": {""}, "xmm": {"7"}, "ymm": {"7"}, "vmmap": {"", "[stack]"}, "proc-info": {""}, "fd": {"", "0"}, "sym": {"checkpoint"}, "got": {"", "all"}, "checksec": {"", "all"}, "stdio": {""}, "gs_base": {""}, "fs_base": {""},
				"telescope": {"audit_words 4"}, "search-string": {"AUDIT-X86 audit_text audit_text+10"}, "search-value": {"--size 4 0x11223344 audit_words audit_words+16"}, "findruction": {"-n nop checkpoint checkpoint+1"}, "cyclic": {"16", "-d aaaa"}, "asm": {"\"inc eax; ret\""},
				"chunk": {fmt.Sprintf("--layout glibc-x86 %#x", chunk)}, "arena": {"--all -n"}, "bins": {"--all -n"}, "visual-heap": {"-n"}, "color": {""}, "!": {"printf audit-shell"},
				"threads": {""}, "thread": {"1", "apply all regs -s eip", "apply all gs_base"}, "info": {"threads", "registers eip esp", "breakpoints"}, "set": {"audit_bytes+12 0x11223344", "scheduler-locking step", "scheduler-locking replay"}, "show": {"scheduler-locking"}, "help": {""},
			}
			for _, spec := range commandSpecs {
				args, ok := cases[spec.name]
				if !ok {
					continue
				}
				if spec.name == "context" {
					run("context on")
				}
				for _, arg := range args {
					run(strings.TrimSpace(spec.name + " " + arg))
				}
				for _, alias := range spec.aliases {
					run(strings.TrimSpace(alias + " " + args[len(args)-1]))
				}
				run("help " + spec.name)
			}
			layoutData, err := json.Marshal(profile.Layout)
			if err != nil {
				t.Fatal(err)
			}
			layoutPath := filepath.Join(t.TempDir(), "layout.json")
			if err := os.WriteFile(layoutPath, layoutData, 0600); err != nil {
				t.Fatal(err)
			}
			snapshot, thread, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			var arena, cache target.Address
			if err := f.controller.withAllocatorContext(context.Background(), snapshot, thread, func(info *allocatorContext) error { arena, cache = info.MainArena, info.Tcache; return nil }); err != nil {
				t.Fatal(err)
			}
			run(fmt.Sprintf("arena --layout-file %s %#x", layoutPath, arena))
			run(fmt.Sprintf("bins --layout-file %s --tcache %#x %#x", layoutPath, cache, arena))
			run(fmt.Sprintf("vis --layout glibc-x86 %#x %#x", chunk, chunk+0x30))
			debugFile := filepath.Join(debugRoot, profile.LibcBuildID, "debuginfo")
			run("arena --module libc.so.6 --debug-file " + debugFile + " --fast-link plain")
			for _, command := range []string{"x/4wx audit_words", "x/2gx audit_words", "x/2i checkpoint", "x/s audit_text", "p/x $eip", "p/d 42", "p/u 42", "p/o 42", "p/t 42", "checksec --file " + f.controller.path} {
				run(command)
			}
			if output := run("tel audit_zeros 1024"); strings.Count(output, "|+0x") != 1024 {
				t.Fatalf("32-bit telescope limit: %d", strings.Count(output, "|+0x"))
			}
			for _, command := range []string{"tel audit_zeros 1025", "xmm 8", "ymm 8", "wp audit_bytes --size 8", "memory 0x100000000"} {
				if _, err := f.execute(command); err == nil {
					t.Fatalf("invalid x86 request accepted: %s", command)
				}
			}
			run("break checkpoint+1")
			id := f.controller.breakpoints[len(f.controller.breakpoints)-1].id
			run(fmt.Sprintf("disable %d", id))
			run(fmt.Sprintf("enable %d", id))
			address := legacyNativeAddress(t, f, "checkpoint+1")
			if output := run("break list"); !strings.Contains(output, fmt.Sprintf("0x%08x", address)) || strings.Contains(output, fmt.Sprintf("0x%016x", address)) {
				t.Fatalf("x86 breakpoint address width: %s", output)
			}
			run(fmt.Sprintf("delete %d", id))
			run("step")
			run("break free")
			run("continue")
			run("delete all")
			run("kill")
			path := f.controller.path
			run("file " + path)
			run("break checkpoint")
			run("start")
			run("run")
			f.pid = f.controller.session.PID()
			run("detach")
			deadline := time.Now().Add(5 * time.Second)
			for {
				_, err := os.Stat(fmt.Sprintf("/proc/%d", f.pid))
				if os.IsNotExist(err) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("detached launched target not reclaimed")
				}
				time.Sleep(time.Millisecond)
			}
			gate := filepath.Join(t.TempDir(), "release")
			attachCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(attachCtx, path, gate)
			stdout, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if child.ProcessState == nil {
					child.Process.Kill()
					child.Wait()
				}
			}()
			ready, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || ready != "ready\n" {
				t.Fatalf("attach target: %q %v", ready, err)
			}
			run(fmt.Sprintf("attach %d", child.Process.Pid))
			run("regs -s eip esp")
			snapshot, _, err = f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			op, err := f.controller.session.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}})
			if err != nil {
				t.Fatal(err)
			}
			f.controller.active = op
			run("interrupt")
			run("detach")
			if err := os.WriteFile(gate, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := child.Wait(); err != nil {
				t.Fatal(err)
			}
			run("run")
			f.pid = f.controller.session.PID()
			run("quit")
			for _, spec := range commandSpecs {
				if covered[spec.name] == 0 {
					t.Errorf("registered command not executed on x86: %s", spec.name)
				}
			}
			names := make([]string, 0, len(covered))
			for name := range covered {
				names = append(names, name)
			}
			sort.Strings(names)
			t.Logf("COVERAGE %d/%d: %s", len(covered), len(commandSpecs), strings.Join(names, ", "))
		})
	}
}

func TestX86VMMapMatchesKernelAndFastDbgColors(t *testing.T) {
	f, _ := newLegacyFixture(t, true, false, x86CommandFixture, "x86_point", false, "-m32", "-pthread")
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", f.pid))
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := parseProcMaps(data)
	if err != nil {
		t.Fatal(err)
	}
	plain := f.command(t, "vmmap")
	for _, m := range mappings {
		prefix := fmt.Sprintf("0x%08x 0x%08x", m.Start, m.End)
		if !strings.Contains(plain, prefix) {
			t.Fatalf("kernel mapping missing: %s", prefix)
		}
	}
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	f.controller.renderer = renderer
	f.output.Reset()
	if err := f.controller.showVMMap(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	colored := f.output.String()
	for _, m := range mappings {
		color := ""
		switch {
		case m.Read && m.Write && m.Execute:
			color = "33"
		case m.Execute:
			color = "35"
		case m.Read && m.Write:
			color = "36"
		case m.Read:
			color = "34"
		case m.Write:
			color = "32"
		}
		prefix := fmt.Sprintf("0x%08x", m.Start)
		if color != "" {
			prefix = "\x1b[" + color + "m" + prefix
		}
		if !strings.Contains(colored, prefix) {
			t.Fatalf("permission color %s absent for %#x", color, m.Start)
		}
	}
	if err := f.controller.verifyProcSnapshot(snapshot, thread); err != nil {
		t.Fatal(err)
	}
	f.output.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.controller.showVMMap(ctx, ""); !errors.Is(err, context.Canceled) || f.output.Len() != 0 {
		t.Fatalf("cancelled map published: %v", err)
	}
}
