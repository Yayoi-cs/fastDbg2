package main

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const commandIntegrationSource = `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

volatile unsigned long long command_fixture_data = 0x1020304050607080ULL;

__attribute__((naked, noinline)) void command_fixture_point(void) {
    __asm__ volatile("nop\n\tinc %rax\n\tret");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "stdin") == 0) {
        char data[128];
        if (write(1, "COMMAND_FIXTURE_READY\n", 22) != 22)
            return 90;
        ssize_t count;
        do {
            count = read(0, data, sizeof(data));
        } while (count < 0 && errno == EINTR);
        if (count <= 0)
            return 91;
        if (write(1, "COMMAND_FIXTURE_ACK:", 20) != 20)
            return 92;
        if (write(1, data, (size_t)count) != count)
            return 93;
    }
    if (argc > 3 && strcmp(argv[1], "attach") == 0) {
        if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) != 0)
            return 94;
        int ready = open(argv[2], O_WRONLY);
        if (ready < 0 || write(ready, "R", 1) != 1)
            return 95;
        close(ready);
        int gate = open(argv[3], O_RDONLY);
        char byte;
        if (gate < 0 || read(gate, &byte, 1) != 1)
            return 96;
        close(gate);
    }
    if (argc > 1 && strcmp(argv[1], "signal") == 0) {
        if (raise(SIGUSR1) != 0)
            return 100;
    }
    if (argc > 1 && strcmp(argv[1], "sigpipe") == 0) {
        struct sigaction action;
        sigset_t mask;
        if (sigaction(SIGPIPE, NULL, &action) != 0 || action.sa_handler != SIG_DFL)
            return 101;
        if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 || sigismember(&mask, SIGPIPE))
            return 102;
        if (raise(SIGPIPE) != 0)
            return 103;
        return 104;
    }
    command_fixture_point();
    if (argc > 2 && strcmp(argv[1], "record") == 0) {
        FILE *record = fopen(argv[2], "wb");
        if (record == NULL)
            return 97;
        for (int index = 3; index < argc; index++) {
            size_t length = strlen(argv[index]);
            if (fwrite(argv[index], 1, length + 1, record) != length + 1)
                return 98;
        }
        if (fclose(record) != 0)
            return 99;
    }
    return 17;
}
`

type commandIntegrationImage struct {
	path    string
	dir     string
	symbols map[string]uint64
}

func commandIntegrationDirectory(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native command integration requires linux/amd64")
	}
	root, err := filepath.Abs(filepath.Join(".cache", "command-integration", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, strings.ReplaceAll(t.Name(), "/", "-")+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func commandIntegrationFixture(t *testing.T, pie bool) commandIntegrationImage {
	t.Helper()
	dir := commandIntegrationDirectory(t)
	path := filepath.Join(dir, "fixture with spaces")
	source := filepath.Join(dir, "fixture.c")
	if err := os.WriteFile(source, []byte(commandIntegrationSource), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-O0", "-g", "-fcf-protection=none", "-fno-stack-protector", "-Wl,--build-id=none", "-o", path, source}
	if pie {
		args = append([]string{"-fPIE", "-pie"}, args...)
	} else {
		args = append([]string{"-fno-pie", "-no-pie"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "cc", args...)
	command.Env = append(os.Environ(), "TMPDIR="+dir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile command fixture: %v\n%s", err, output)
	}
	file, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	symbols, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	image := commandIntegrationImage{path: path, dir: dir, symbols: make(map[string]uint64)}
	for _, symbol := range symbols {
		image.symbols[symbol.Name] = symbol.Value
	}
	return image
}

func commandIntegrationRun(t *testing.T, args []string, input string) string {
	t.Helper()
	var output bytes.Buffer
	if err := runCLIInput(args, strings.NewReader(input), &output); err != nil {
		t.Fatalf("command console failed: %v\n%s", err, output.String())
	}
	got := output.String()
	if strings.ContainsRune(got, '\x1b') || strings.Contains(got, "fastDbg2> ") {
		t.Fatalf("stream command output contains terminal formatting: %q", got)
	}
	return got
}

func commandIntegrationRequire(t *testing.T, output string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(output, needle) {
			t.Fatalf("missing %q:\n%s", needle, output)
		}
	}
}

func commandIntegrationStopPattern(reason string) *regexp.Regexp {
	if reason == "exited" {
		return regexp.MustCompile(`(?m)^Process [1-9][0-9]* exited \(code 17\)\.$`)
	}
	if reason == "step" {
		reason = "instruction step"
	}
	return regexp.MustCompile(`(?m)^Thread(?: #[1-9][0-9]*)? \(TID [1-9][0-9]*\) stopped at 0x([0-9a-f]{16}) \(` + regexp.QuoteMeta(reason) + `\)\.$`)
}

func commandIntegrationSignalPattern(name string, number int, exited bool) *regexp.Regexp {
	signal := regexp.QuoteMeta(fmt.Sprintf("%s (%d)", name, number))
	if exited {
		return regexp.MustCompile(`(?m)^Process [1-9][0-9]* exited \(` + signal + `\)\.$`)
	}
	return regexp.MustCompile(`(?m)^Thread #[1-9][0-9]* \(TID [1-9][0-9]*\) stopped by ` + signal + ` at 0x[0-9a-f]{16}\.$`)
}

func commandIntegrationRequireStops(t *testing.T, output string, reasons ...string) {
	t.Helper()
	for _, reason := range reasons {
		if !commandIntegrationStopPattern(reason).MatchString(output) {
			t.Fatalf("missing exact %s stop summary:\n%s", reason, output)
		}
	}
}

func commandIntegrationClean(t *testing.T, output string) {
	t.Helper()
	if strings.Contains(output, "error: ") || strings.Contains(output, "unavailable: ") {
		t.Fatalf("valid debug flow reported an error:\n%s", output)
	}
}

func TestCommandIntegrationAMD64DebugFlow(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			image := commandIntegrationFixture(t, pie)
			script := "break command_fixture_point\nbreak list\nstart\ncontinue\nregs\ncontext\nmemory --count 4 command_fixture_point\nmemory --count 8 command_fixture_data\nthreads\nstep\ncontext\ncontinue\nquit\n"
			output := commandIntegrationRun(t, []string{"-f", image.path}, script)
			commandIntegrationClean(t, output)
			commandIntegrationRequire(t, output,
				"command_fixture_point", "[registers]", "[code]", "[stack]", "[threads]", "Started native amd64",
			)
			commandIntegrationRequireStops(t, output, "exec", "breakpoint", "step", "exited")
			if !regexp.MustCompile(`(?m)^Thread #[1-9][0-9]* \(TID [1-9][0-9]*\) "(?:[^"\\]|\\.)*" — stopped: breakpoint$`).MatchString(output) {
				t.Fatalf("compact context omitted selected thread and reason:\n%s", output)
			}
			marker := regexp.MustCompile(`(?m)^\*-> 0x([0-9a-f]{16})`).FindStringSubmatchIndex(output)
			var location []string
			if len(marker) == 4 {
				registers := regexp.MustCompile(`(?m)^\$rip\s*: 0x([0-9a-f]{16})`).FindAllStringSubmatch(output[:marker[0]], -1)
				if len(registers) != 0 {
					location = []string{"", output[marker[2]:marker[3]], registers[len(registers)-1][1]}
				}
			}
			stopped := commandIntegrationStopPattern("breakpoint").FindStringSubmatch(output)
			if len(location) != 3 || len(stopped) != 2 {
				t.Fatalf("breakpoint context lacks raw and instruction addresses:\n%s", output)
			}
			instruction, _ := strconv.ParseUint(location[1], 16, 64)
			raw, _ := strconv.ParseUint(location[2], 16, 64)
			breakpoint, _ := strconv.ParseUint(stopped[1], 16, 64)
			if raw != instruction+1 || instruction != breakpoint {
				t.Fatalf("breakpoint context changed raw RIP: raw=%#x instruction=%#x breakpoint=%#x\n%s", raw, instruction, breakpoint, output)
			}
			rawRegister := regexp.MustCompile(`(?m)^\$rip[\t ]*:[\t ]*0x` + fmt.Sprintf("%016x", raw) + `\b`)
			if !rawRegister.MatchString(output) {
				t.Fatalf("register view does not report raw RIP %#x:\n%s", raw, output)
			}
			originalCode := regexp.MustCompile(`(?m)^\*->[\t ]+0x` + fmt.Sprintf("%016x", instruction) + `\s+90\s+.*(?i:nop)`)
			if !originalCode.MatchString(output) {
				t.Fatalf("breakpoint instruction did not retain original NOP byte:\n%s", output)
			}
			rawCode := regexp.MustCompile(`(?m)^0x` + fmt.Sprintf("%016x", instruction) + `\s+cc 48 ff c0$`)
			if !rawCode.MatchString(output) {
				t.Fatalf("raw memory view did not retain the installed trap byte:\n%s", output)
			}
			commandIntegrationRequire(t, output, "80 70 60 50 40 30 20 10")
		})
	}
}

func TestCommandIntegrationAddressBreakpoint(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	address := image.symbols["command_fixture_point"]
	if address == 0 {
		t.Fatal("fixture breakpoint symbol missing")
	}
	output := commandIntegrationRun(t, []string{"-f", image.path}, fmt.Sprintf("break %#x\nrun\nstep\ncontinue\nquit\n", address))
	commandIntegrationClean(t, output)
	commandIntegrationRequireStops(t, output, "breakpoint", "step", "exited")
}

func TestCommandIntegrationRestartRebindAndDelete(t *testing.T) {
	image := commandIntegrationFixture(t, true)
	output := commandIntegrationRun(t, []string{"-f", image.path}, "break command_fixture_point\nrun\ncontinue\nrun\nbreak list\ndelete 1\ncontinue\nrun\nquit\n")
	commandIntegrationClean(t, output)
	stops := commandIntegrationStopPattern("breakpoint").FindAllString(output, -1)
	if len(stops) != 2 {
		t.Fatalf("pending breakpoint was not rebound exactly twice: %d\n%s", len(stops), output)
	}
	exits := commandIntegrationStopPattern("exited").FindAllString(output, -1)
	if len(exits) != 3 {
		t.Fatalf("restart/delete exit sequence differs: %d\n%s", len(exits), output)
	}
}

func TestCommandIntegrationRestartStoppedTarget(t *testing.T) {
	image := commandIntegrationFixture(t, true)
	output := commandIntegrationRun(t, []string{"-f", image.path}, "break command_fixture_point\nrun\nrun\ncontinue\nquit\n")
	commandIntegrationClean(t, output)
	starts := regexp.MustCompile(`Started native amd64 pid=([0-9]+)`).FindAllStringSubmatch(output, -1)
	if len(starts) != 2 || starts[0][1] == starts[1][1] {
		t.Fatalf("run did not replace the stopped owned process:\n%s", output)
	}
	if len(commandIntegrationStopPattern("breakpoint").FindAllString(output, -1)) != 2 {
		t.Fatalf("replacement process did not rebind its breakpoint:\n%s", output)
	}
	commandIntegrationNoProcesses(t, output)
}

func TestCommandIntegrationStartDoesNotRunUserCode(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	record := filepath.Join(image.dir, "not-created-at-exec-stop")
	output := commandIntegrationRun(t, []string{"-f", image.path, "--", "record", record, "value"}, "start\nquit\n")
	commandIntegrationClean(t, output)
	commandIntegrationRequireStops(t, output, "exec")
	if _, err := os.Stat(record); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("start executed the program body: %v\n%s", err, output)
	}
	commandIntegrationNoProcesses(t, output)
}

func TestCommandIntegrationLiteralArguments(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	for _, startup := range []bool{false, true} {
		t.Run(fmt.Sprintf("startup_%t", startup), func(t *testing.T) {
			record := filepath.Join(image.dir, fmt.Sprintf("arguments-%t", startup))
			marker := filepath.Join(image.dir, "must-not-be-created")
			values := []string{"a b", "", "$HOME", "*", "$(touch " + marker + ")", ";touch " + marker, "日本語", `back\slash`}
			args := []string{"-f", image.path, "--", "record", record}
			args = append(args, values...)
			script := "run\nquit\n"
			if !startup {
				all := append([]string{image.path, "record", record}, values...)
				for index := range all {
					all[index] = "'" + strings.ReplaceAll(all[index], "'", "'\\''") + "'"
				}
				script = "file " + strings.Join(all, " ") + "\n" + script
				args = []string{"--interactive"}
			}
			output := commandIntegrationRun(t, args, script)
			commandIntegrationClean(t, output)
			commandIntegrationRequireStops(t, output, "exited")
			data, err := os.ReadFile(record)
			if err != nil {
				t.Fatalf("read literal argument record: %v\n%s", err, output)
			}
			want := []byte(strings.Join(values, "\x00") + "\x00")
			if !bytes.Equal(data, want) {
				t.Fatalf("argument expansion or splitting: got %q want %q", data, want)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("argument text executed as shell input: %v", err)
			}
		})
	}
}

func TestCommandIntegrationInvalidCommandsPreserveStop(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	output := commandIntegrationRun(t, []string{"-f", image.path}, "break command_fixture_point\nrun\nregs\ncontinue --invalid\nstep --deliver --suppress\nmemory --count 0 command_fixture_data\nthread 0\ndelete 999\nstart 'unterminated\nregs\nstep\ncontinue\nquit\n")
	step := commandIntegrationStopPattern("step").FindStringIndex(output)
	if step == nil {
		t.Fatalf("valid step did not follow invalid commands:\n%s", output)
	}
	registers := regexp.MustCompile(`(?m)^\$rip[\t ]*:[\t ]*(0x[0-9a-f]+)\b`).FindAllStringSubmatch(output[:step[0]], -1)
	if len(registers) != 3 {
		t.Fatalf("missing before/after register views:\n%s", output)
	}
	raw := fmt.Sprintf("0x%016x", image.symbols["command_fixture_point"]+1)
	for _, register := range registers {
		if register[1] != raw {
			t.Fatalf("invalid command changed stopped RIP: %v\n%s", registers, output)
		}
	}
	if strings.Count(output, "error: ") != 6 {
		t.Fatalf("invalid arguments were not all rejected:\n%s", output)
	}
	commandIntegrationRequireStops(t, output, "step", "exited")
}

func TestCommandIntegrationPartialBreakpointInstallIsStoppedAndRecoverable(t *testing.T) {
	image := commandIntegrationFixture(t, true)
	source := filepath.Join(image.dir, "fixture.c")
	withConstructor := commandIntegrationSource + `
volatile unsigned command_constructor_marker;
__attribute__((constructor)) static void command_constructor_probe(void) {
    command_constructor_marker = 1;
}
`
	if err := os.WriteFile(source, []byte(withConstructor), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "cc", "-fPIE", "-pie", "-O0", "-g", "-fcf-protection=none", "-fno-stack-protector", "-Wl,--build-id=none", "-o", image.path, source)
	build.Env = append(os.Environ(), "TMPDIR="+image.dir)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile constructor observation: %v\n%s", err, output)
	}
	record := filepath.Join(image.dir, "partial-install-body")
	args := []string{"-f", image.path, "--", "record", record, "ran"}
	setup := "break command_fixture_point\nbreak absent_command_fixture_symbol\nrun\nbreak list\np/x command_constructor_marker\nmemory --count 4 command_constructor_marker\nmemory --count 1 command_fixture_point\n"
	assertLoaderFailure := func(output string) (uint64, uint64) {
		t.Helper()
		commandIntegrationRequire(t, output, "error: ", "absent_command_fixture_symbol", "in loaded scope: not found")
		if strings.Count(output, "error: ") != 1 {
			t.Fatalf("definitive lookup error was not isolated: %s", output)
		}
		installed := regexp.MustCompile(`(?m)^Breakpoint 1 installed address=0x([0-9a-f]+) expression="command_fixture_point"$`).FindStringSubmatch(output)
		stops := commandIntegrationStopPattern("breakpoint").FindAllStringSubmatch(output, -1)
		marker := regexp.MustCompile(`(?m)^0x([0-9a-f]+)$`).FindStringSubmatch(output)
		if len(installed) != 2 || len(stops) == 0 || len(marker) != 2 {
			t.Fatalf("loader failure lacked confirmed addresses: %s", output)
		}
		point, _ := strconv.ParseUint(installed[1], 16, 64)
		hook, _ := strconv.ParseUint(stops[0][1], 16, 64)
		constructor, _ := strconv.ParseUint(marker[1], 16, 64)
		hookSymbols := regexp.MustCompile(fmt.Sprintf(`(?m)^\$rip[\t ]*:[\t ]*0x%016x\b[^<\n]*<([^>\n]+)>`, hook)).FindStringSubmatch(output)
		if len(hookSymbols) != 2 || !slices.Contains(strings.Split(hookSymbols[1], " | "), "_dl_debug_state") {
			t.Fatalf("loader hook address lacked the exact _dl_debug_state alias: %s", output)
		}
		for _, pattern := range []string{
			fmt.Sprintf(`(?m)^1[\t ]+breakpoint[\t ]+y[\t ]+0x%016x[\t ]+installed[\t ]+"command_fixture_point"$`, point),
			`(?m)^2[\t ]+breakpoint[\t ]+y[\t ]+<pending>[\t ]+error[\t ]+"absent_command_fixture_symbol"$`,
			fmt.Sprintf(`(?m)^0x%016x[\t ]+cc$`, point),
			fmt.Sprintf(`(?m)^0x%016x[\t ]+00 00 00 00$`, constructor),
		} {
			if !regexp.MustCompile(pattern).MatchString(output) {
				t.Fatalf("missing stopped/ownership/constructor fact %q: %s", pattern, output)
			}
		}
		if hook == point {
			t.Fatalf("definitive lookup failure reached the user breakpoint: %s", output)
		}
		return point, constructor
	}
	output := commandIntegrationRun(t, args, setup+"quit\n")
	assertLoaderFailure(output)
	if _, err := os.Stat(record); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partially failed run executed user code: %v\n%s", err, output)
	}
	commandIntegrationNoProcesses(t, output)
	output = commandIntegrationRun(t, args, setup+"delete 2\ncontinue\nmemory --count 4 command_constructor_marker\nmemory --count 1 command_fixture_point\nstep\ndisable 1\nmemory --count 1 command_fixture_point\ncontinue\nquit\n")
	point, constructor := assertLoaderFailure(output)
	commandIntegrationRequireStops(t, output, "breakpoint", "step", "exited")
	stops := commandIntegrationStopPattern("breakpoint").FindAllStringSubmatch(output, -1)
	if len(stops) != 2 || stops[1][1] != fmt.Sprintf("%016x", point) ||
		!regexp.MustCompile(fmt.Sprintf(`(?m)^0x%016x[\t ]+01 00 00 00$`, constructor)).MatchString(output) ||
		!regexp.MustCompile(fmt.Sprintf(`(?m)^0x%016x[\t ]+90$`, point)).MatchString(output) {
		t.Fatalf("delete/recovery lost constructor, user breakpoint, or byte restoration: %s", output)
	}
	data, err := os.ReadFile(record)
	if err != nil || string(data) != "ran\x00" {
		t.Fatalf("recovering partial breakpoint installation failed: %q %v\n%s", data, err, output)
	}
	commandIntegrationNoProcesses(t, output)
}

func TestCommandIntegrationSignalDeliveryRequiresDecision(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	for _, option := range []string{"--suppress", "--deliver"} {
		t.Run(strings.TrimPrefix(option, "--"), func(t *testing.T) {
			output := commandIntegrationRun(t, []string{"-f", image.path, "--", "signal"}, "run\ncontinue\ncontinue "+option+"\nquit\n")
			commandIntegrationRequire(t, output, "require --deliver or --suppress")
			if !commandIntegrationSignalPattern("SIGUSR1", 10, false).MatchString(output) {
				t.Fatalf("pending SIGUSR1 was not reported exactly:\n%s", output)
			}
			if option == "--suppress" {
				commandIntegrationRequireStops(t, output, "exited")
			} else if !commandIntegrationSignalPattern("SIGUSR1", 10, true).MatchString(output) {
				t.Fatalf("delivered SIGUSR1 was not reported as process termination:\n%s", output)
			}
			commandIntegrationNoProcesses(t, output)
		})
	}
}

func TestCommandIntegrationLaunchesX86(t *testing.T) {
	dir := commandIntegrationDirectory(t)
	path := filepath.Join(dir, "fixture-x86")
	source := path + ".s"
	if err := os.WriteFile(source, []byte(".text\n.global _start\n_start:\nmov $1, %eax\nmov $47, %ebx\nint $0x80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, args := range [][]string{{"as", "--32", "-o", path + ".o", source}, {"ld", "-m", "elf_i386", "-o", path, path + ".o"}} {
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Env = append(os.Environ(), "TMPDIR="+dir)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("compile negative architecture fixture: %v\n%s", err, output)
		}
	}
	before := commandIntegrationChildren(t)
	var output bytes.Buffer
	err := runCLIInput([]string{"-f", path}, strings.NewReader("run\nquit\n"), &output)
	if err != nil || !strings.Contains(output.String(), "native x86") || !strings.Contains(output.String(), "code 47") {
		t.Fatalf("x86 startup/exit failed: %v\n%s", err, output.String())
	}
	if after := commandIntegrationChildren(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("unsupported startup changed child set: before=%v after=%v", before, after)
	}
}

func TestCommandIntegrationQuitEOFAndKillReapLaunch(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	for _, script := range []string{"start\nquit\n", "start\n", "start\nkill\nquit\n"} {
		t.Run(strings.ReplaceAll(script, "\n", "_"), func(t *testing.T) {
			before := commandIntegrationChildren(t)
			output := commandIntegrationRun(t, []string{"-f", image.path}, script)
			commandIntegrationClean(t, output)
			commandIntegrationNoProcesses(t, output)
			if after := commandIntegrationChildren(t); !reflect.DeepEqual(before, after) {
				t.Fatalf("command shutdown leaked children: before=%v after=%v\n%s", before, after, output)
			}
		})
	}
}

func commandIntegrationChildren(t *testing.T) []int {
	t.Helper()
	paths, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		t.Fatal(err)
	}
	children := make(map[int]struct{})
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				t.Fatal(err)
			}
			children[pid] = struct{}{}
		}
	}
	var result []int
	for pid := range children {
		result = append(result, pid)
	}
	slices.Sort(result)
	return result
}

func commandIntegrationNoProcesses(t *testing.T, output string) {
	t.Helper()
	for _, match := range regexp.MustCompile(`\bpid=([0-9]+)\b`).FindAllStringSubmatch(output, -1) {
		pid, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Errorf("launched process %d remains after console shutdown: %v", pid, err)
		}
	}
}

func TestCommandIntegrationRepeatedSessionFDs(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	script := "break command_fixture_point\nrun\nstep\ncontinue\nquit\n"
	commandIntegrationRun(t, []string{"-f", image.path}, script)
	before := commandIntegrationFDs(t)
	children := commandIntegrationChildren(t)
	for range 6 {
		output := commandIntegrationRun(t, []string{"-f", image.path}, script)
		commandIntegrationClean(t, output)
		commandIntegrationNoProcesses(t, output)
		if after := commandIntegrationFDs(t); !reflect.DeepEqual(before, after) {
			t.Fatalf("command sessions changed descriptor identities:\nbefore=%v\nafter=%v", before, after)
		}
		if after := commandIntegrationChildren(t); !reflect.DeepEqual(children, after) {
			t.Fatalf("command sessions changed children: before=%v after=%v", children, after)
		}
	}
}

func commandIntegrationFDs(t *testing.T) map[int]string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[int]string)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); errors.Is(err, syscall.EBADF) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		result[fd] = fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, stat.Mode)
	}
	return result
}

type commandIntegrationFailWriter struct {
	bytes.Buffer
	err    error
	failed bool
}

func (w *commandIntegrationFailWriter) Write(data []byte) (int, error) {
	if w.failed {
		return 0, w.err
	}
	n, err := w.Buffer.Write(data)
	if commandIntegrationStopPattern("exec").Match(w.Buffer.Bytes()) {
		w.failed = true
	}
	return n, err
}

func (w *commandIntegrationFailWriter) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func TestCommandIntegrationOutputFailureReapsLaunch(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	want := errors.New("command integration output failure")
	output := &commandIntegrationFailWriter{err: want}
	before := commandIntegrationChildren(t)
	err := runCLIInput([]string{"-f", image.path}, strings.NewReader("start\nregs\nquit\n"), output)
	if !errors.Is(err, want) {
		t.Fatalf("output failure was lost: %v\n%s", err, output.String())
	}
	commandIntegrationNoProcesses(t, output.String())
	if after := commandIntegrationChildren(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("output failure leaked a child: before=%v after=%v", before, after)
	}
}

func TestCommandIntegrationBrokenPipeRestoresAttachedBreakpoint(t *testing.T) {
	if os.Getenv("FASTDBG2_COMMAND_BROKEN_PIPE_HELPER") == "1" {
		for index, arg := range os.Args {
			if arg != "--" {
				continue
			}
			if err := runCLIInput(os.Args[index+1:], os.Stdin, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "fastDbg2:", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		os.Exit(125)
	}
	image := commandIntegrationFixture(t, false)
	var pipes []*os.File
	for _, name := range []string{"ready", "gate"} {
		path := filepath.Join(image.dir, name)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		pipes = append(pipes, file)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	inferior := exec.CommandContext(ctx, image.path, "attach", pipes[0].Name(), pipes[1].Name())
	if err := inferior.Start(); err != nil {
		t.Fatal(err)
	}
	inferiorWaited := false
	defer func() {
		if !inferiorWaited {
			inferior.Process.Kill()
			inferior.Wait()
		}
	}()
	if err := pipes[0].SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(pipes[0], ready[:]); err != nil || ready[0] != 'R' {
		t.Fatalf("attached fixture readiness: %q %v", ready, err)
	}
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCommandIntegrationBrokenPipeRestoresAttachedBreakpoint$", "--", "-p", strconv.Itoa(inferior.Process.Pid))
	command.Env = append(os.Environ(), "FASTDBG2_COMMAND_BROKEN_PIPE_HELPER=1", "TERM=dumb", "NO_COLOR=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	commandWaited := false
	defer func() {
		if !commandWaited {
			command.Process.Kill()
			command.Wait()
		}
	}()
	if err := output.(*os.File).SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(input, "break command_fixture_point\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	var captured strings.Builder
	for {
		line, err := reader.ReadString('\n')
		captured.WriteString(line)
		if err != nil {
			t.Fatalf("breakpoint installation output: %v\n%s", err, captured.String())
		}
		if strings.Contains(line, "Breakpoint 1 installed") {
			break
		}
	}
	memory, err := os.Open(fmt.Sprintf("/proc/%d/mem", inferior.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	address := int64(image.symbols["command_fixture_point"])
	var code [1]byte
	if _, err := memory.ReadAt(code[:], address); err != nil || code[0] != 0xcc {
		t.Fatalf("software breakpoint was not installed: %x %v", code, err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(input, "context\n"); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	commandWaited = true
	if command.ProcessState.ExitCode() != 1 || !strings.Contains(stderr.String(), "broken pipe") {
		t.Fatalf("broken stdout did not use the ordinary error path: %v stderr=%q", err, stderr.String())
	}
	if _, err := memory.ReadAt(code[:], address); err != nil || code[0] != 0x90 {
		t.Fatalf("broken stdout left a patched attached process: %x %v", code, err)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", inferior.Process.Pid))
	if err != nil || !regexp.MustCompile(`(?m)^TracerPid:\s+0$`).Match(status) {
		t.Fatalf("attached target did not survive untraced: %v\n%s", err, status)
	}
	if _, err := pipes[1].Write([]byte{'G'}); err != nil {
		t.Fatal(err)
	}
	err = inferior.Wait()
	inferiorWaited = true
	if inferior.ProcessState.ExitCode() != 17 {
		t.Fatalf("restored attached target did not run to completion: %v", err)
	}
}

func TestCommandIntegrationInferiorSIGPIPERemainsDefault(t *testing.T) {
	image := commandIntegrationFixture(t, false)
	output := commandIntegrationRun(t, []string{"-f", image.path, "--", "sigpipe"}, "run\ncontinue --deliver\nquit\n")
	commandIntegrationClean(t, output)
	if !commandIntegrationSignalPattern("SIGPIPE", 13, false).MatchString(output) || !commandIntegrationSignalPattern("SIGPIPE", 13, true).MatchString(output) {
		t.Fatalf("SIGPIPE stop/termination facts missing:\n%s", output)
	}
	commandIntegrationNoProcesses(t, output)
}

var _ io.Writer = (*commandIntegrationFailWriter)(nil)
