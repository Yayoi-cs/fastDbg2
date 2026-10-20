package launch

import (
	"bytes"
	"encoding/binary"
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

	"golang.org/x/sys/unix"
)

func launchFixture(t *testing.T, dir string) string {
	t.Helper()
	source, path := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
	code := `#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
int main(int argc, char **argv) {
    if (argc != 4) return 90;
    int marker = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (marker < 0) return 91;
    if (write(marker, "ran", 3) != 3 || close(marker)) return 92;
    for (int fd = 3; fd <= 6; ++fd) {
        errno = 0;
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 93;
    }
    for (int i = 0; i < argc; ++i) printf("argv%d=%s\n", i, argv[i]);
    const char *value = getenv("FASTDBG2_LAUNCH_TEST");
    printf("env=%s\n", value ? value : "missing");
    char input[128];
    if (!fgets(input, sizeof(input), stdin)) return 94;
    printf("stdin=%s", input);
    fputs("stderr payload\n", stderr);
    return 23;
}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O0", "-o", path, source).CombinedOutput(); err != nil {
		t.Fatalf("fixture compile: %v\n%s", err, out)
	}
	return path
}

func openLaunchFile(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func launchStdio(t *testing.T, dir, name string) ([3]*os.File, [2]string) {
	t.Helper()
	input := filepath.Join(dir, name+".stdin")
	if err := os.WriteFile(input, []byte("stdin payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	files := [3]*os.File{openLaunchFile(t, input)}
	paths := [2]string{filepath.Join(dir, name+".stdout"), filepath.Join(dir, name+".stderr")}
	for i, path := range paths {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		files[i+1] = f
	}
	return files, paths
}

func cleanupLaunch(t *testing.T, p *Process) {
	t.Helper()
	t.Cleanup(func() {
		p.Close()
		if p.Process != nil {
			p.Process.Kill()
			p.Process.Wait()
			p.Process.Release()
			p.Process = nil
		}
		if p.PIDFD >= 0 {
			unix.Close(p.PIDFD)
			p.PIDFD = -1
		}
	})
}

func requireNoMarker(t *testing.T, marker string) {
	t.Helper()
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target ran before exec was continued: %v", err)
	}
}

func launchWait(t *testing.T, pid int) unix.WaitStatus {
	t.Helper()
	for {
		var status unix.WaitStatus
		n, err := unix.Wait4(pid, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n != pid {
			t.Fatalf("wait4=%d error=%v", n, err)
		}
		return status
	}
}

func seizeLaunch(t *testing.T, p *Process) {
	t.Helper()
	options := unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL
	_, _, err := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SEIZE, uintptr(p.Process.Pid), 0, uintptr(options), 0, 0)
	if err != 0 {
		t.Fatal(err)
	}
	if err := unix.PtraceInterrupt(p.Process.Pid); err != nil {
		t.Fatal(err)
	}
	status := launchWait(t, p.Process.Pid)
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP || status.TrapCause() != unix.PTRACE_EVENT_STOP {
		t.Fatalf("bootstrap first stop=%#x", status)
	}
}

func execLaunch(t *testing.T, p *Process) {
	t.Helper()
	if err := p.Release(); err != nil {
		t.Fatal(err)
	}
	if err := unix.PtraceCont(p.Process.Pid, 0); err != nil {
		t.Fatal(err)
	}
	status := launchWait(t, p.Process.Pid)
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP || status.TrapCause() != unix.PTRACE_EVENT_EXEC {
		t.Fatalf("target exec stop=%#x error=%v", status, p.ExecError())
	}
	if err := p.ExecError(); err != nil {
		t.Fatal(err)
	}
}

func releaseReapedLaunch(t *testing.T, p *Process) {
	t.Helper()
	if err := p.Process.Release(); err != nil {
		t.Fatal(err)
	}
	p.Process = nil
	if err := unix.Close(p.PIDFD); err != nil {
		t.Fatal(err)
	}
	p.PIDFD = -1
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestControlledLaunchParity(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir := launchTempDir(t)
	path := launchFixture(t, dir)
	marker := filepath.Join(dir, "marker")
	argv := []string{path, marker, "argument with spaces", ""}
	t.Setenv("FASTDBG2_LAUNCH_TEST", "value with spaces")
	directStdio, directPaths := launchStdio(t, dir, "direct")
	direct := exec.Command(path, argv[1:]...)
	direct.Stdin, direct.Stdout, direct.Stderr = directStdio[0], directStdio[1], directStdio[2]
	if err := direct.Run(); err == nil || direct.ProcessState.ExitCode() != 23 {
		t.Fatalf("direct run=%v state=%v", err, direct.ProcessState)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	stdio, paths := launchStdio(t, dir, "controlled")
	p, err := Start(openLaunchFile(t, path), argv, stdio)
	if err != nil {
		t.Fatal(err)
	}
	cleanupLaunch(t, p)
	if p.PIDFD < 0 {
		t.Fatal("missing atomic pidfd")
	}
	requireNoMarker(t, marker)
	if err := p.ExecError(); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("pre-exec error pipe must not block or report success: %v", err)
	}
	for _, fd := range []int{3, 5} {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", p.Process.Pid, fd))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "flags:" {
				flags, err := strconv.ParseUint(fields[1], 8, 64)
				if err != nil || flags&unix.O_CLOEXEC == 0 {
					t.Fatalf("bootstrap descriptor %d flags=%s error=%v", fd, fields[1], err)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("missing descriptor flags for %d", fd)
		}
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/fd/6", p.Process.Pid)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap memfd leaked: %v", err)
	}
	seizeLaunch(t, p)
	requireNoMarker(t, marker)
	execLaunch(t, p)
	requireNoMarker(t, marker)
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Name() != "0" || entries[1].Name() != "1" || entries[2].Name() != "2" {
		t.Fatalf("descriptors at exec=%v", entries)
	}
	if err := unix.PtraceCont(p.Process.Pid, 0); err != nil {
		t.Fatal(err)
	}
	status := launchWait(t, p.Process.Pid)
	if !status.Exited() || status.ExitStatus() != 23 {
		t.Fatalf("target exit=%#x", status)
	}
	releaseReapedLaunch(t, p)
	for i, path := range paths {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(directPaths[i])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("stdio %d differs: got %q want %q", i+1, got, want)
		}
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "ran" {
		t.Fatalf("marker=%q error=%v", data, err)
	}
}

func TestLaunchUsesValidatedFile(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir := launchTempDir(t)
	path := launchFixture(t, dir)
	f := openLaunchFile(t, path)
	original, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Start(f, []string{path}, [3]*os.File{})
	if err != nil {
		t.Fatal(err)
	}
	cleanupLaunch(t, p)
	if err := os.Rename(path, path+".validated"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not the validated ELF"), 0700); err != nil {
		t.Fatal(err)
	}
	seizeLaunch(t, p)
	execLaunch(t, p)
	actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", p.Process.Pid))
	if err != nil || !os.SameFile(original, actual) {
		t.Fatalf("executed wrong file: %v", err)
	}
}

func TestLaunchI386(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir := launchTempDir(t)
	source, object, path := filepath.Join(dir, "i386.s"), filepath.Join(dir, "i386.o"), filepath.Join(dir, "i386")
	code := ".text\n.global _start\n_start:\nmov $1, %eax\nmov $42, %ebx\nint $0x80\n"
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("as", "--32", "-o", object, source).CombinedOutput(); err != nil {
		t.Fatalf("assemble i386: %v\n%s", err, out)
	}
	if out, err := exec.Command("ld", "-m", "elf_i386", "-o", path, object).CombinedOutput(); err != nil {
		t.Fatalf("link i386: %v\n%s", err, out)
	}
	p, err := Start(openLaunchFile(t, path), []string{path}, [3]*os.File{})
	if err != nil {
		t.Fatal(err)
	}
	cleanupLaunch(t, p)
	seizeLaunch(t, p)
	execLaunch(t, p)
	if err := unix.PtraceCont(p.Process.Pid, 0); err != nil {
		t.Fatal(err)
	}
	status := launchWait(t, p.Process.Pid)
	if !status.Exited() || status.ExitStatus() != 42 {
		t.Fatalf("i386 exit=%#x", status)
	}
	releaseReapedLaunch(t, p)
}

func TestLaunchExecFailure(t *testing.T) {
	dir := launchTempDir(t)
	path := launchFixture(t, dir)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Start(openLaunchFile(t, path), []string{path}, [3]*os.File{})
	if err != nil {
		t.Fatal(err)
	}
	cleanupLaunch(t, p)
	if err := p.Release(); err != nil {
		t.Fatal(err)
	}
	state, err := p.Process.Wait()
	if err != nil || state.ExitCode() != 127 {
		t.Fatalf("exec failure state=%v error=%v", state, err)
	}
	for i := 0; i < 2; i++ {
		if err := p.ExecError(); !errors.Is(err, unix.EACCES) {
			t.Fatalf("exec failure errno=%v", err)
		}
	}
}

func TestLaunchCancelAndReleaseFailure(t *testing.T) {
	dir := launchTempDir(t)
	path := launchFixture(t, dir)
	marker := filepath.Join(dir, "marker")
	for _, kill := range []bool{false, true} {
		p, err := Start(openLaunchFile(t, path), []string{path, marker, "arg", ""}, [3]*os.File{})
		if err != nil {
			t.Fatal(err)
		}
		cleanupLaunch(t, p)
		if kill {
			if err := p.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		} else if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Process.Wait(); err != nil {
			t.Fatal(err)
		}
		if kill {
			if err := p.Release(); !errors.Is(err, unix.EPIPE) {
				t.Fatalf("release killed bootstrap=%v", err)
			}
		} else {
			if err := p.Release(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("release cancelled bootstrap=%v", err)
			}
			if err := p.ExecError(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("cancelled bootstrap error pipe=%v", err)
			}
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		requireNoMarker(t, marker)
	}
}

func testBootstrap(t *testing.T, code []byte) *os.File {
	t.Helper()
	image := bootstrapImage()
	image = image[:176]
	image = append(image, code...)
	binary.LittleEndian.PutUint64(image[96:], uint64(len(image)))
	binary.LittleEndian.PutUint64(image[104:], uint64(len(image)))
	fd, err := unix.MemfdCreate("fastdbg2-launch-test", unix.MFD_CLOEXEC|unix.MFD_EXEC)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "bootstrap-test")
	t.Cleanup(func() { f.Close() })
	if _, err := f.Write(image); err != nil {
		t.Fatal(err)
	}
	return f
}

func children(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/children", unix.Gettid()))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLaunchReadyTimeoutReapsChild(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	launchTempDir(t)
	target := openLaunchFile(t, "/proc/self/exe")
	bootstrap := testBootstrap(t, []byte{0xb8, 0x22, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xf7})
	before := children(t)
	p, err := start(target, []string{"target"}, [3]*os.File{}, bootstrap, 20*time.Millisecond)
	if p != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ready timeout process=%v error=%v", p, err)
	}
	if after := children(t); after != before {
		t.Fatalf("unreaped child before=%q after=%q", before, after)
	}
}

func TestLaunchReadyFailureReapsChild(t *testing.T) {
	launchTempDir(t)
	target := openLaunchFile(t, "/proc/self/exe")
	for _, tc := range []struct {
		name   string
		value  uint32
		length byte
		want   error
	}{
		{"setup", uint32(unix.EACCES), 4, unix.EACCES},
		{"invalid", 4096, 4, unix.EPROTO},
		{"partial", 0, 1, io.ErrUnexpectedEOF},
		{"missing", 0, 0, io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			code := []byte{0x68, 0, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xbf, 5, 0, 0, 0, 0x48, 0x89, 0xe6, 0xba, tc.length, 0, 0, 0, 0x0f, 0x05, 0xb8, 60, 0, 0, 0, 0xbf, 127, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b}
			binary.LittleEndian.PutUint32(code[1:], tc.value)
			bootstrap := testBootstrap(t, code)
			before := children(t)
			p, err := start(target, []string{"target"}, [3]*os.File{}, bootstrap, time.Second)
			if p != nil || !errors.Is(err, tc.want) {
				t.Fatalf("ready failure process=%v error=%v", p, err)
			}
			if after := children(t); after != before {
				t.Fatalf("unreaped child before=%q after=%q", before, after)
			}
		})
	}
}

func descriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestLaunchRepeatCleanup(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	launchTempDir(t)
	f := openLaunchFile(t, "/proc/self/exe")
	warm, err := Start(f, []string{"target"}, [3]*os.File{})
	if err != nil {
		t.Fatal(err)
	}
	if err := warm.Close(); err != nil {
		t.Fatal(err)
	}
	if err := warm.abort(); err != nil {
		t.Fatal(err)
	}
	beforeFD, beforeChildren := descriptorCount(t), children(t)
	for i := 0; i < 25; i++ {
		p, err := Start(f, []string{"target"}, [3]*os.File{})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		if err := p.abort(); err != nil {
			t.Fatal(err)
		}
	}
	if after := descriptorCount(t); after != beforeFD {
		t.Fatalf("descriptor leak before=%d after=%d", beforeFD, after)
	}
	if after := children(t); after != beforeChildren {
		t.Fatalf("child leak before=%q after=%q", beforeChildren, after)
	}
}

func TestLaunchReadyRecordValidation(t *testing.T) {
	for _, value := range []uint32{1, 4095, 0, 4096, ^uint32(0)} {
		err := recordError(value)
		if value >= 1 && value <= 4095 {
			if !errors.Is(err, unix.Errno(value)) {
				t.Fatalf("errno %d: %v", value, err)
			}
		} else if !errors.Is(err, unix.EPROTO) {
			t.Fatalf("invalid errno %d: %v", value, err)
		}
	}
}
