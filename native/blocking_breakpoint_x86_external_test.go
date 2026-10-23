package native_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const blockingX86Program = `
.text
.global _start, initial_checkpoint, blocking_site, after_blocking_site, after_completion, owner_checkpoint, peer_gate_read
_start:
    cmpl $3, (%esp)
    jne failure
    mov 8(%esp), %ebx
    mov $5, %eax
    xor %ecx, %ecx
    int $0x80
    test %eax, %eax
    js failure
    mov %eax, gate_fd
    mov 12(%esp), %ebx
    mov $5, %eax
    mov $1, %ecx
    int $0x80
    test %eax, %eax
    js failure
    mov %eax, ack_fd
    mov $42, %eax
    mov $data_fds, %ebx
    int $0x80
    test %eax, %eax
    js failure
    mov $120, %eax
    mov $0x50f00, %ebx
    mov $peer_stack_end, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi
    int $0x80
    test %eax, %eax
    js failure
    jz peer_start
    mov %eax, peer_tid
ready_wait:
    cmpl $1, peer_ready
    jne ready_wait
initial_checkpoint:
    nop
OWNER_ARGUMENTS
blocking_site:
    int $0x80
 after_blocking_site:
    lock incl returned
 after_completion:
    mov %eax, owner_result
owner_checkpoint:
    nop
peer_done_wait:
    cmpl $1, peer_done
    jne peer_done_wait
    cmpl $1, returned
    jne failure
    cmpl $1, release_count
    jne failure
    cmpl $0xcc, observed_site
    jne failure
VERIFY_RESULT
peer_finished_wait:
    cmpl $1, peer_finished
    jne peer_finished_wait
    xor %ebx, %ebx
    mov $252, %eax
    int $0x80
    ud2
peer_start:
    movl $1, peer_ready
    mov $3, %eax
    mov gate_fd, %ebx
    mov $gate_byte, %ecx
    mov $1, %edx
peer_gate_read:
    int $0x80
    cmp $1, %eax
    jne failure
    cmpb $103, gate_byte
    jne failure
    movzbl blocking_site, %eax
    mov %eax, observed_site
    lock incl release_count
    mov $4, %eax
    mov ack_fd, %ebx
    mov $ack_byte, %ecx
    mov $1, %edx
    int $0x80
    cmp $1, %eax
    jne failure
PEER_RELEASE
    movl $1, peer_done
    mov $3, %eax
    mov gate_fd, %ebx
    mov $gate_byte, %ecx
    mov $1, %edx
    int $0x80
    cmp $1, %eax
    jne failure
    cmpb $102, gate_byte
    jne failure
    movl $1, peer_finished
    xor %ebx, %ebx
    mov $1, %eax
    int $0x80
    ud2
failure:
    mov $91, %ebx
    mov $252, %eax
    int $0x80
    ud2
.section .rodata
ack_byte: .byte 65
packet: .byte 65, 90
.bss
.balign 4
gate_fd: .zero 4
ack_fd: .zero 4
data_fds: .zero 8
peer_tid: .zero 4
peer_ready: .zero 4
peer_done: .zero 4
peer_finished: .zero 4
returned: .zero 4
release_count: .zero 4
observed_site: .zero 4
owner_result: .zero 4
wake_result: .zero 4
futex_word: .zero 4
received: .zero 1
gate_byte: .zero 1
tail: .zero 2
.balign 16
peer_stack: .zero 65536
peer_stack_end:
.section .note.GNU-stack,"",@progbits
`

type blockingX86Fixture struct {
	path    string
	symbols map[string]target.Address
	gate    *os.File
	ack     *os.File
	paths   [2]string
	futex   bool
}

func newBlockingX86Fixture(t *testing.T, futex bool) *blockingX86Fixture {
	t.Helper()
	arguments := "mov $3, %eax\nmov data_fds, %ebx\nmov $received, %ecx\nmov $1, %edx"
	release := "mov $4, %eax\nmov data_fds+4, %ebx\nmov $packet, %ecx\nmov $2, %edx\nint $0x80\ncmp $2, %eax\njne failure"
	verify := `cmpl $1, owner_result
    jne failure
    cmpb $65, received
    jne failure
    mov $55, %eax
    mov data_fds, %ebx
    mov $4, %ecx
    mov $0x800, %edx
    int $0x80
    test %eax, %eax
    js failure
    mov $3, %eax
    mov data_fds, %ebx
    mov $tail, %ecx
    mov $2, %edx
    int $0x80
    cmp $1, %eax
    jne failure
    cmpb $90, tail
    jne failure`
	if futex {
		arguments = "mov $240, %eax\nmov $futex_word, %ebx\nmov $128, %ecx\nxor %edx, %edx\nxor %esi, %esi\nxor %edi, %edi\nxor %ebp, %ebp"
		release = "wake_wait:\nmov $240, %eax\nmov $futex_word, %ebx\nmov $129, %ecx\nmov $1, %edx\nxor %esi, %esi\nxor %edi, %edi\nxor %ebp, %ebp\nint $0x80\ntest %eax, %eax\nje wake_wait\ncmp $1, %eax\njne failure\nmov %eax, wake_result"
		verify = "cmpl $0, owner_result\njne failure\ncmpl $1, wake_result\njne failure"
	}
	program := strings.NewReplacer("OWNER_ARGUMENTS", arguments, "PEER_RELEASE", release, "VERIFY_RESULT", verify).Replace(blockingX86Program)
	path, symbols := x86Fixture(t, program, false)
	f := &blockingX86Fixture{path: path, symbols: symbols, futex: futex}
	for index := range f.paths {
		f.paths[index] = filepath.Join(filepath.Dir(path), fmt.Sprintf("gate-%d", index))
		if err := unix.Mkfifo(f.paths[index], 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(f.paths[index], os.O_RDWR|unix.O_NONBLOCK, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		if index == 0 {
			f.gate = file
		} else {
			f.ack = file
		}
	}
	return f
}

func (f *blockingX86Fixture) send(t *testing.T, value byte) {
	t.Helper()
	if err := f.gate.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.gate.Write([]byte{value}); err != nil || n != 1 {
		t.Fatalf("i386 peer gate: n=%d error=%v", n, err)
	}
}

func (f *blockingX86Fixture) acknowledge(t *testing.T) {
	t.Helper()
	if err := f.ack.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	if n, err := io.ReadFull(f.ack, value[:]); err != nil || n != 1 || value[0] != 'A' {
		t.Fatalf("i386 peer acknowledgement=%q n=%d error=%v", value, n, err)
	}
}

func (f *blockingX86Fixture) word(t *testing.T, s *native.Session, name string) uint32 {
	t.Helper()
	return binary.LittleEndian.Uint32(blockingRead(t, s, f.symbols[name], 4))
}

func blockingX86KernelWait(t *testing.T, pid, tid int, number uint64, args [3]uint64, pc target.Address) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last string
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/syscall", pid, tid))
		if err != nil {
			t.Fatal(err)
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", pid, tid))
		if err != nil {
			t.Fatal(err)
		}
		state := ""
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "State:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					state = fields[1]
				}
			}
		}
		fields := strings.Fields(string(data))
		if len(fields) == 9 {
			var values [9]uint64
			valid := true
			for index, field := range fields {
				values[index], err = strconv.ParseUint(field, 0, 64)
				valid = valid && err == nil
			}
			if valid && values[0] == number && values[1] == args[0] && values[2] == args[1] && values[3] == args[2] && values[8] == uint64(pc) && (state == "S" || state == "D") {
				return
			}
		}
		last = fmt.Sprintf("TID=%d state=%s syscall=%s", tid, state, data)
		if time.Now().After(deadline) {
			t.Fatalf("i386 kernel blocking proof was not observed: %s", last)
		}
		runtime.Gosched()
	}
}

func TestNativeX86BlockingBreakpointPeerProgress(t *testing.T) {
	for _, futex := range []bool{false, true} {
		name := "read"
		if futex {
			name = "futex"
		}
		t.Run(name, func(t *testing.T) {
			f := newBlockingX86Fixture(t, futex)
			s, err := native.Launch(f.path, f.paths[0], f.paths[1])
			if err != nil {
				t.Fatal(err)
			}
			owned := []int{s.PID()}
			t.Cleanup(func() {
				for _, tid := range owned {
					var status unix.WaitStatus
					if pid, err := unix.Wait4(tid, &status, unix.WALL|unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
						t.Errorf("i386 blocking TID %d remained waitable: pid=%d status=%#x error=%v", tid, pid, uint32(status), err)
					}
				}
			})
			threadSessionCleanup(t, s, true)
			if s.Architecture() != target.X86 {
				t.Fatalf("fixture architecture=%s", s.Architecture())
			}
			for _, label := range []string{"initial_checkpoint", "blocking_site", "owner_checkpoint"} {
				threadCommand(t, func() error { return s.AddBreakpoint(f.symbols[label]) })
			}
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), f.symbols["initial_checkpoint"])
			snapshot := threadStopped(t, s, 2)
			owner := threadByTID(t, snapshot, s.PID())
			peer := threadByTID(t, snapshot, int(f.word(t, s, "peer_tid")))
			owned = append(owned, peer.TID)
			dataFD := uint64(f.word(t, s, "data_fds"))
			gateFD := uint64(f.word(t, s, "gate_fd"))
			threadCommand(t, func() error { return s.RemoveBreakpoint(f.symbols["initial_checkpoint"]) })
			threadBreakpoint(t, threadRun(t, s, threadExact(owner.Ref)), f.symbols["blocking_site"])
			run := blockingStep(t, s, target.StepRequest{Thread: owner.Ref, Continue: threadExact(peer.Ref)})
			number, args := uint64(3), [3]uint64{dataFD, uint64(f.symbols["received"]), 1}
			if futex {
				number, args = 240, [3]uint64{uint64(f.symbols["futex_word"]), 128, 0}
			}
			blockingX86KernelWait(t, s.PID(), owner.TID, number, args, f.symbols["after_blocking_site"])
			blockingX86KernelWait(t, s.PID(), peer.TID, 3, [3]uint64{gateFD, uint64(f.symbols["gate_byte"]), 1}, f.symbols["peer_gate_read"]+2)
			f.send(t, 'g')
			f.acknowledge(t)
			result := threadWait(t, run)
			blockingTypedExit(t, result, owner.Ref, f.symbols["after_blocking_site"])
			if !strings.Contains(result.Stop.Raw, "syscall_op=2") || !strings.Contains(result.Stop.Raw, "arch=0x40000003") {
				t.Fatalf("i386 step did not expose its typed compat EXIT: %+v", result.Stop)
			}
			if got := f.word(t, s, "returned"); got != 0 {
				t.Fatalf("INT80 step executed the following instruction: %d", got)
			}
			if got := f.word(t, s, "observed_site"); got != 0xcc {
				t.Fatalf("peer ran before INT80 site was rearmed: %#x", got)
			}
			if got := f.word(t, s, "release_count"); got != 1 {
				t.Fatalf("peer release count=%d", got)
			}
			threadStopped(t, s, 2)
			result = threadWait(t, blockingStep(t, s, target.StepRequest{Thread: owner.Ref}))
			if result.Stop.Reason != target.StopStep || !result.Stop.StepCompleted || result.Stop.RawPC == nil || *result.Stop.RawPC != f.symbols["after_completion"] || f.word(t, s, "returned") != 1 {
				t.Fatalf("following i386 instruction was not executed exactly once: %+v", result)
			}
			threadBreakpoint(t, threadRun(t, s, threadProcessSet(threadSnapshot(t, s))), f.symbols["owner_checkpoint"])
			for _, label := range []string{"blocking_site", "owner_checkpoint"} {
				threadCommand(t, func() error { return s.RemoveBreakpoint(f.symbols[label]) })
			}
			if instruction := blockingRead(t, s, f.symbols["blocking_site"], 2); instruction[0] != 0xcd || instruction[1] != 0x80 {
				t.Fatalf("INT80 instruction was not restored: %x", instruction)
			}
			f.send(t, 'f')
			threadExit(t, s, 0)
		})
	}
}
