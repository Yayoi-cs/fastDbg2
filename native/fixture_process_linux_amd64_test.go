package native_test

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fixtureFDIdentity struct {
	fd     int
	device uint64
	inode  uint64
}

func fixtureProcessFDs(t *testing.T, pid int) []fixtureFDIdentity {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var identities []fixtureFDIdentity
	for _, entry := range entries {
		info, err := os.ReadFile("/proc/self/fdinfo/" + entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(info), fmt.Sprintf("\nPid:\t%d\n", pid)) {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			t.Fatal(err)
		}
		identities = append(identities, fixtureFDIdentity{fd, stat.Dev, stat.Ino})
	}
	if len(identities) == 0 {
		t.Fatal("fixture has no pidfd-backed process handle")
	}
	return identities
}

func TestNativeFixtureWaitReleasesProcessHandleAfterExternalReap(t *testing.T) {
	guardRead, guardWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer guardRead.Close()
	defer guardWrite.Close()
	var guards []fixtureFDIdentity
	for _, file := range []*os.File{guardRead, guardWrite} {
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			t.Fatal(err)
		}
		guards = append(guards, fixtureFDIdentity{int(file.Fd()), stat.Dev, stat.Ino})
	}
	path, _ := nativeFixture(t, `
.section .rodata
ready: .byte 82
.section .bss
buffer: .skip 1
.text
.global _start
_start:
    mov $1, %eax
    mov $1, %edi
    lea ready(%rip), %rsi
    mov $1, %edx
    syscall
    xor %eax, %eax
    xor %edi, %edi
    lea buffer(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failure
    mov $60, %eax
    xor %edi, %edi
    syscall
failure:
    mov $60, %eax
    mov $42, %edi
    syscall
`)
	p := nativeStartProcess(t, path)
	defer runtime.KeepAlive(p.command.Process)
	pid := p.command.Process.Pid
	handles := fixtureProcessFDs(t, pid)
	if n, err := p.input.Write([]byte{'x'}); n != 1 || err != nil {
		t.Fatalf("release fixture: n=%d error=%v", n, err)
	}
	nativeCommand(t, func() error {
		for {
			var status unix.WaitStatus
			got, err := unix.Wait4(pid, &status, 0, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return err
			}
			if got != pid || !status.Exited() || status.ExitStatus() != 0 {
				return fmt.Errorf("external fixture reap: pid=%d status=%#x", got, status)
			}
			return nil
		}
	})
	p.beginWait()
	select {
	case <-p.waited:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture Wait did not finish after external reap")
	}
	if !errors.Is(p.err, unix.ECHILD) {
		t.Fatalf("fixture Wait error=%v", p.err)
	}
	if _, ok := p.err.(*os.SyscallError); !ok {
		t.Fatalf("fixture Wait error type changed: %T", p.err)
	}
	for _, identity := range handles {
		var stat unix.Stat_t
		err := unix.Fstat(identity.fd, &stat)
		if err == nil && stat.Dev == identity.device && stat.Ino == identity.inode {
			t.Errorf("fixture signaled completion before releasing pidfd: fd=%d device=%d inode=%d", identity.fd, identity.device, identity.inode)
		} else if err != nil && !errors.Is(err, unix.EBADF) {
			t.Errorf("inspect released fixture handle: %v", err)
		}
	}
	for _, identity := range guards {
		var stat unix.Stat_t
		if err := unix.Fstat(identity.fd, &stat); err != nil || stat.Dev != identity.device || stat.Ino != identity.inode {
			t.Errorf("fixture cleanup changed unrelated descriptor: fd=%d device=%d inode=%d error=%v", identity.fd, stat.Dev, stat.Ino, err)
		}
	}
}
