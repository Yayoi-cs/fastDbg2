package native_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"fastdbg2/native"
	"fastdbg2/target"

	"golang.org/x/sys/unix"
)

const extendedRegisterProgram = `
.text
.global _start, extended_ready, extended_features, extended_cpuid1, extended_cpuid7, extended_xcr0, extended_cpu_xfeatures
_start:
CLONE_SETUP
    cld
    mov $1, %eax
    xor %ecx, %ecx
    cpuid
    mov %ecx, extended_cpuid1__MEM__
    mov %edx, %eax
    and $0x04000001, %eax
    cmp $0x04000001, %eax
    jne fail_features
    movl $3, extended_features__MEM__
    and $0x1c000000, %ecx
    cmp $0x1c000000, %ecx
    jne initialize
    xor %ecx, %ecx
    xgetbv
    mov %eax, extended_xcr0__MEM__
    mov %edx, extended_xcr0+4__MEM__
    mov %eax, %esi
    and $6, %eax
    cmp $6, %eax
    jne initialize
    orl $4, extended_features__MEM__
    mov $7, %eax
    xor %ecx, %ecx
    cpuid
    mov %ebx, extended_cpuid7__MEM__
    bt $16, %ebx
    jnc initialize
    and $0xe6, %esi
    cmp $0xe6, %esi
    jne initialize
    orl $0xe0, extended_features__MEM__
initialize:
    testl $0x04000000, extended_cpuid1__MEM__
    jz initialize_fp
    mov $13, %eax
    xor %ecx, %ecx
    cpuid
    mov %eax, extended_cpu_xfeatures__MEM__
    mov %edx, extended_cpu_xfeatures+4__MEM__
initialize_fp:
    fninit
    fldt x87_seed__MEM__
    ldmxcsr mxcsr_seed__MEM__
    testl $0xe0, extended_features__MEM__
    jz initialize_avx
    vmovdqu64 vector_seed__MEM__, %zmm0
    mov $0x1357, %eax
    kmovw %eax, %k1
HIGH_INITIALIZE
    jmp extended_ready
initialize_avx:
    testl $4, extended_features__MEM__
    jz initialize_sse
    vmovdqu vector_seed__MEM__, %ymm0
    jmp extended_ready
initialize_sse:
    movdqu vector_seed__MEM__, %xmm0
extended_ready:
    int3
    fstpt x87_output__MEM__
    fnstcw cw_output__MEM__
    stmxcsr mxcsr_output__MEM__
    testl $0xe0, extended_features__MEM__
    jz capture_avx
    vmovdqu64 %zmm0, extended_output__MEM__
    kmovw %k1, %eax
    movw %ax, mask_output__MEM__
HIGH_CAPTURE
    mov $64, %ebp
    jmp verify
capture_avx:
    testl $4, extended_features__MEM__
    jz capture_sse
    vmovdqu %ymm0, extended_output__MEM__
    mov $32, %ebp
    jmp verify
capture_sse:
    movdqu %xmm0, extended_output__MEM__
    mov $16, %ebp
verify:
COMPARE_X87
    cmpw $0x077f, cw_output__MEM__
    jne fail_x87
    cmpl $0x3f80, mxcsr_output__MEM__
    jne fail_mxcsr
VECTOR_OUTPUT_POINTER
VECTOR_EXPECTED_POINTER
    mov %ebp, %ecx
    repe cmpsb
    jne fail_vector
    testl $0xe0, extended_features__MEM__
    jz success
    cmpw $0x2468, mask_output__MEM__
    jne fail_mask
COMPARE_HIGH
success:
VERIFY_WORKER
    xor %ebx, %ebx
    jmp terminate
fail_x87:
    mov $1, %ebx
    jmp terminate
fail_vector:
    mov $2, %ebx
    jmp terminate
fail_mask:
    mov $3, %ebx
    jmp terminate
fail_high:
    mov $4, %ebx
    jmp terminate
fail_mxcsr:
    mov $5, %ebx
    jmp terminate
fail_features:
    mov $77, %ebx
terminate:
EXIT_INSTRUCTION
    ud2
WORKER_PROGRAM
.section .rodata
x87_seed:
    .quad 0x8000000000000000
    .word 0x3fff
x87_expected:
    .quad 0x8000000000000000
    .word 0x4000
mxcsr_seed:
    .long 0x1f80
vector_seed:
    .byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
vector_expected:
    .byte 160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223
high_seed:
    .byte 96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159
high_expected:
    .byte 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95
worker_x87_seed:
    .quad 0xc000000000000000
    .word 0x4000
worker_vector_seed:
    .byte 64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79
.data
extended_features:
    .long 0
extended_cpuid1:
    .long 0
extended_cpuid7:
    .long 0
extended_xcr0:
    .quad 0
extended_cpu_xfeatures:
    .quad 0
.bss
.balign 64
extended_output:
    .zero 64
high_output:
    .zero 64
x87_output:
    .zero 10
cw_output:
    .zero 2
mxcsr_output:
    .zero 4
mask_output:
    .zero 2
worker_ready:
    .zero 4
worker_capture:
    .zero 4
worker_x87_output:
    .zero 10
worker_vector_output:
    .zero 16
.balign 16
worker_stack:
    .zero 65536
worker_stack_end:
.section .note.GNU-stack,"",@progbits
`

type extendedFixture struct {
	bits    int
	path    string
	symbols map[string]target.Address
}

func extendedProgram(bits int, threaded bool) string {
	memory := "(%rip)"
	pointer := func(name, register string) string { return "lea " + name + "(%rip), %r" + register }
	exit := "mov %ebx, %edi\nmov $231, %eax\nsyscall"
	clone := "mov $56, %eax\nmov $0x50f00, %edi\nlea worker_stack_end(%rip), %rsi\nxor %edx, %edx\nxor %r10d, %r10d\nxor %r8d, %r8d\nsyscall\n"
	if bits == 32 {
		memory = ""
		pointer = func(name, register string) string { return "mov $" + name + ", %e" + register }
		exit = "mov $252, %eax\nint $0x80"
		clone = "mov $120, %eax\nmov $0x50f00, %ebx\nmov $worker_stack_end, %ecx\nxor %edx, %edx\nxor %esi, %esi\nxor %edi, %edi\nint $0x80\n"
	}
	compare := func(left, right string, count int, failure string) string {
		return pointer(left, "si") + "\n" + pointer(right, "di") + fmt.Sprintf("\nmov $%d, %%ecx\nrepe cmpsb\njne %s", count, failure)
	}
	var highInitialize, highCapture, highCompare, worker, verifyWorker string
	if bits == 64 {
		highInitialize = "vmovdqu64 high_seed__MEM__, %zmm16"
		highCapture = "vmovdqu64 %zmm16, high_output__MEM__"
		highCompare = compare("high_output", "high_expected", 64, "fail_high")
	}
	if threaded {
		clone += "test %eax, %eax\njs fail_features\njz worker_start\nworker_started_wait:\ncmpl $1, worker_ready__MEM__\njne worker_started_wait\n"
		worker = `worker_start:
    fninit
    fldt worker_x87_seed__MEM__
    movdqu worker_vector_seed__MEM__, %xmm0
    movl $1, worker_ready__MEM__
worker_wait:
    cmpl $1, worker_capture__MEM__
    je worker_store
    pause
    jmp worker_wait
worker_store:
    fstpt worker_x87_output__MEM__
    movdqu %xmm0, worker_vector_output__MEM__
    movl $2, worker_ready__MEM__
worker_done:
    pause
    jmp worker_done
`
		verifyWorker = "movl $1, worker_capture__MEM__\nworker_capture_wait:\ncmpl $2, worker_ready__MEM__\njne worker_capture_wait\n" +
			compare("worker_x87_output", "worker_x87_seed", 10, "fail_high") + "\n" +
			compare("worker_vector_output", "worker_vector_seed", 16, "fail_high")
	} else {
		clone = ""
	}
	program := strings.NewReplacer(
		"CLONE_SETUP", clone,
		"HIGH_INITIALIZE", highInitialize,
		"HIGH_CAPTURE", highCapture,
		"COMPARE_X87", compare("x87_output", "x87_expected", 10, "fail_x87"),
		"VECTOR_OUTPUT_POINTER", pointer("extended_output", "si"),
		"VECTOR_EXPECTED_POINTER", pointer("vector_expected", "di"),
		"COMPARE_HIGH", highCompare,
		"VERIFY_WORKER", verifyWorker,
		"EXIT_INSTRUCTION", exit,
		"WORKER_PROGRAM", worker,
	).Replace(extendedRegisterProgram)
	return strings.ReplaceAll(program, "__MEM__", memory)
}

func newExtendedFixture(t *testing.T, bits int, threaded bool) extendedFixture {
	t.Helper()
	f := extendedFixture{bits: bits}
	if bits == 32 {
		f.path, f.symbols = x86Fixture(t, extendedProgram(bits, threaded), false)
	} else {
		f.path, f.symbols = nativeFixture(t, extendedProgram(bits, threaded))
	}
	return f
}

func extendedLaunch(t *testing.T, path string) *native.Session {
	t.Helper()
	s, err := native.Launch(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var status unix.WaitStatus
		if pid, err := unix.Wait4(s.PID(), &status, unix.WALL|unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
			t.Errorf("extended fixture was not reaped: pid=%d status=%#x error=%v", pid, uint32(status), err)
		}
	})
	nativeSessionCleanup(t, s, true)
	return s
}

func extendedSnapshot(t *testing.T, s *native.Session) target.Snapshot {
	t.Helper()
	snapshot, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func extendedThread(t *testing.T, snapshot target.Snapshot, ref target.ThreadRef) target.ThreadInfo {
	t.Helper()
	for _, info := range snapshot.Threads {
		if info.Ref == ref {
			return info
		}
	}
	t.Fatalf("missing thread %+v in %+v", ref, snapshot)
	return target.ThreadInfo{}
}

func extendedRun(t *testing.T, s *native.Session) target.RunResult {
	t.Helper()
	snapshot := extendedSnapshot(t, s)
	request := target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}}
	for _, info := range snapshot.Threads {
		if info.Process == snapshot.Process && info.State == target.StateStopped && !info.Exiting {
			request.Signals = append(request.Signals, target.ThreadSignal{Thread: info.Ref, Stop: info.Token.Stop})
		}
	}
	run, err := s.Run(request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := run.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func extendedReady(t *testing.T, s *native.Session, f extendedFixture, count int) target.ThreadInfo {
	t.Helper()
	result := extendedRun(t, s)
	if result.Stop.Reason != target.StopSignal || result.Stop.Signal.Number != uint32(unix.SIGTRAP) || result.Stop.RawPC == nil || *result.Stop.RawPC != f.symbols["extended_ready"]+1 {
		t.Fatalf("extended fixture did not reach its initialized trap: %+v", result)
	}
	snapshot := extendedSnapshot(t, s)
	if snapshot.State != target.StateStopped || len(snapshot.Threads) != count {
		t.Fatalf("extended fixture closure: %+v", snapshot)
	}
	var selected target.ThreadInfo
	for _, info := range snapshot.Threads {
		if info.State != target.StateStopped || info.Exiting || info.Listening {
			t.Fatalf("extended fixture thread is not stopped: %+v", info)
		}
		if info.TID == s.PID() {
			selected = info
		}
	}
	if selected.Ref.ID == 0 {
		t.Fatal("extended fixture has no leader")
	}
	return selected
}

func extendedRead(t *testing.T, s *native.Session, token target.ThreadToken) target.ExtendedRegisterState {
	t.Helper()
	state, err := s.ReadExtendedRegisters(token)
	if err != nil {
		t.Fatal(err)
	}
	if state.Token != token {
		t.Fatalf("read changed thread token: got=%+v want=%+v", state.Token, token)
	}
	return state
}

func extendedCopy(state target.ExtendedRegisterState) target.ExtendedRegisterState {
	state.Data = slices.Clone(state.Data)
	if state.XState != nil {
		info := *state.XState
		info.ExtendedComponents = slices.Clone(info.ExtendedComponents)
		state.XState = &info
	}
	return state
}

func extendedComponent(t *testing.T, state target.ExtendedRegisterState, id uint8, size int) int {
	t.Helper()
	if state.XState != nil {
		for _, component := range state.XState.ExtendedComponents {
			if component.ID == id {
				if int(component.Size) < size || uint64(component.Offset)+uint64(component.Size) > uint64(len(state.Data)) {
					t.Fatalf("invalid component layout: %+v length=%d", component, len(state.Data))
				}
				return int(component.Offset)
			}
		}
	}
	t.Fatalf("missing component %d: %+v", id, state.XState)
	return 0
}

func extendedMemory(t *testing.T, s *native.Session, address target.Address, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if n, err := s.ReadMemory(address, data); err != nil || n != size {
		t.Fatalf("fixture data at %#x: n=%d error=%v", address, n, err)
	}
	return data
}

func extendedFeatures(t *testing.T, s *native.Session, f extendedFixture, state target.ExtendedRegisterState) uint64 {
	t.Helper()
	features := uint64(binary.LittleEndian.Uint32(extendedMemory(t, s, f.symbols["extended_features"], 4)))
	cpuid1 := binary.LittleEndian.Uint32(extendedMemory(t, s, f.symbols["extended_cpuid1"], 4))
	cpuid7 := binary.LittleEndian.Uint32(extendedMemory(t, s, f.symbols["extended_cpuid7"], 4))
	xcr0 := binary.LittleEndian.Uint64(extendedMemory(t, s, f.symbols["extended_xcr0"], 8))
	cpuFeatures := binary.LittleEndian.Uint64(extendedMemory(t, s, f.symbols["extended_cpu_xfeatures"], 8))
	if features&3 != 3 || features&^uint64(0xe7) != 0 {
		t.Fatalf("unexpected exercised features: %#x", features)
	}
	if features&4 != 0 && (cpuid1&0x1c000000 != 0x1c000000 || xcr0&6 != 6 || cpuFeatures&7 != 7) {
		t.Fatalf("AVX executed without authoritative support: cpuid1=%#x xcr0=%#x cpu_features=%#x", cpuid1, xcr0, cpuFeatures)
	}
	if features&0xe0 != 0 {
		if features&0xe0 != 0xe0 || cpuid7&(1<<16) == 0 || xcr0&0xe6 != 0xe6 || cpuFeatures&0xe7 != 0xe7 {
			t.Fatalf("AVX512 executed without authoritative support: cpuid7=%#x xcr0=%#x cpu_features=%#x", cpuid7, xcr0, cpuFeatures)
		}
	} else {
		if cpuid7&(1<<16) != 0 && xcr0&0xe6 == 0xe6 && features&4 != 0 {
			t.Fatal("fixture omitted supported AVX512 execution")
		}
		t.Logf("target AVX512 unavailable: CPUID.7.EBX=%#x XCR0=%#x CPU_XFEATURES=%#x", cpuid7, xcr0, cpuFeatures)
	}
	switch state.Format {
	case target.ExtendedFormatXSave:
		if len(state.Data) < 576 || state.XState == nil || state.XState.KernelFeatures&^cpuFeatures != 0 || state.XState.KernelFeatures&features != features {
			t.Fatalf("XSAVE layout does not describe the executing target: %+v bytes=%d cpu=%#x features=%#x", state.XState, len(state.Data), cpuFeatures, features)
		}
		if binary.LittleEndian.Uint64(state.Data[464:472]) != state.XState.KernelFeatures || binary.LittleEndian.Uint64(state.Data[512:520]) != state.XState.Present || binary.LittleEndian.Uint64(state.Data[520:528]) != 0 {
			t.Fatalf("XSAVE metadata disagrees with kernel bytes: %+v", state.XState)
		}
	case target.ExtendedFormatFXSave:
		if len(state.Data) != 512 || state.XState != nil {
			t.Fatalf("invalid FXSAVE fallback: bytes=%d metadata=%+v", len(state.Data), state.XState)
		}
		features = 3
		if n, err := s.WriteMemory(f.symbols["extended_features"], []byte{3, 0, 0, 0}); err != nil || n != 4 {
			t.Fatalf("select FXSAVE target verification: n=%d error=%v", n, err)
		}
	default:
		t.Fatalf("unsupported returned extended format: %v", state.Format)
	}
	return features
}

func extendedPatch(t *testing.T, state target.ExtendedRegisterState, bits int, features uint64) target.ExtendedRegisterState {
	t.Helper()
	result := extendedCopy(state)
	if len(result.Data) < 512 {
		t.Fatalf("short legacy area: %d", len(result.Data))
	}
	binary.LittleEndian.PutUint16(result.Data[0:2], 0x077f)
	binary.LittleEndian.PutUint32(result.Data[24:28], 0x3f80)
	binary.LittleEndian.PutUint16(result.Data[40:42], 0x4000)
	fill := func(offset, first, count int) {
		for i := 0; i < count; i++ {
			result.Data[offset+i] = byte(first + i)
		}
	}
	fill(160, 0xa0, 16)
	if features&4 != 0 {
		fill(extendedComponent(t, result, 2, 16), 0xb0, 16)
	}
	if features&0xe0 != 0 {
		binary.LittleEndian.PutUint64(result.Data[extendedComponent(t, result, 5, 16)+8:], 0x2468)
		fill(extendedComponent(t, result, 6, 32), 0xc0, 32)
		if bits == 64 {
			fill(extendedComponent(t, result, 7, 64), 0x20, 64)
		}
	}
	if result.Format == target.ExtendedFormatXSave {
		present := features
		if bits == 32 {
			present &^= 1 << 7
		}
		binary.LittleEndian.PutUint64(result.Data[512:520], binary.LittleEndian.Uint64(result.Data[512:520])|present)
	}
	return result
}

func extendedExit(t *testing.T, s *native.Session) {
	t.Helper()
	result := extendedRun(t, s)
	if result.Stop.Reason != target.StopExited || result.Stop.ExitCode == nil || *result.Stop.ExitCode != 0 {
		t.Fatalf("target instructions rejected modified extended registers: %+v", result)
	}
}

func extendedWritten(t *testing.T, s *native.Session, before, request target.ExtendedRegisterState) target.ExtendedRegisterState {
	t.Helper()
	memory := extendedSnapshot(t, s).Memory
	post, err := s.WriteExtendedRegisters(before.Token, request)
	if err != nil {
		t.Fatal(err)
	}
	if post.Token.Thread != before.Token.Thread || post.Token.Stop != before.Token.Stop || post.Token.Registers == before.Token.Registers {
		t.Fatalf("write did not advance exactly the selected register context: before=%+v after=%+v", before.Token, post.Token)
	}
	if post.Architecture != before.Architecture || post.Format != before.Format || len(post.Data) != len(before.Data) {
		t.Fatalf("write changed the register ABI: before=%+v after=%+v", before, post)
	}
	if _, err := s.ReadExtendedRegisters(before.Token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old extended token after write: %v", err)
	}
	if _, err := s.ReadThreadRegisters(before.Token); !errors.Is(err, target.ErrStale) {
		t.Fatalf("old GPR token after extended write: %v", err)
	}
	if _, err := s.ReadThreadRegisters(post.Token); err != nil {
		t.Fatalf("new GPR token after extended write: %v", err)
	}
	snapshot := extendedSnapshot(t, s)
	if snapshot.Memory != memory || extendedThread(t, snapshot, post.Token.Thread).Token != post.Token {
		t.Fatalf("extended write changed memory identity or returned a noncurrent token: snapshot=%+v post=%+v", snapshot, post.Token)
	}
	actual := extendedRead(t, s, post.Token)
	if !reflect.DeepEqual(actual, post) {
		t.Fatalf("write did not return authoritative post-state: post=%+v actual=%+v", post, actual)
	}
	return post
}

func extendedCheckPatched(t *testing.T, state target.ExtendedRegisterState, bits int, features uint64) {
	t.Helper()
	if binary.LittleEndian.Uint16(state.Data[0:2]) != 0x077f || binary.LittleEndian.Uint32(state.Data[24:28]) != 0x3f80 || binary.LittleEndian.Uint64(state.Data[32:40]) != 0x8000000000000000 || binary.LittleEndian.Uint16(state.Data[40:42]) != 0x4000 {
		t.Fatalf("x87/MXCSR changes did not read back: %x", state.Data[:48])
	}
	check := func(offset, first, count int) {
		for i := 0; i < count; i++ {
			if state.Data[offset+i] != byte(first+i) {
				t.Fatalf("vector byte %d: got=%#x want=%#x", offset+i, state.Data[offset+i], byte(first+i))
			}
		}
	}
	check(160, 0xa0, 16)
	if features&4 != 0 {
		check(extendedComponent(t, state, 2, 16), 0xb0, 16)
	}
	if features&0xe0 != 0 {
		if value := binary.LittleEndian.Uint64(state.Data[extendedComponent(t, state, 5, 16)+8:]); value != 0x2468 {
			t.Fatalf("opmask k1=%#x", value)
		}
		check(extendedComponent(t, state, 6, 32), 0xc0, 32)
		if bits == 64 {
			check(extendedComponent(t, state, 7, 64), 0x20, 64)
		}
	}
}

func extendedCheckOpaque(t *testing.T, before, after target.ExtendedRegisterState, bits int, features uint64) {
	t.Helper()
	if before.XState == nil {
		return
	}
	if after.XState == nil || after.XState.KernelFeatures != before.XState.KernelFeatures || !reflect.DeepEqual(after.XState.ExtendedComponents, before.XState.ExtendedComponents) {
		t.Fatalf("metadata was accepted from caller instead of kernel: before=%+v after=%+v", before.XState, after.XState)
	}
	modified := features
	if bits == 32 {
		modified &^= 1 << 7
	}
	if before.XState.Present&^modified != after.XState.Present&^modified {
		t.Fatalf("unrelated component presence changed: before=%#x after=%#x", before.XState.Present, after.XState.Present)
	}
	for _, component := range before.XState.ExtendedComponents {
		if modified&(uint64(1)<<component.ID) != 0 {
			continue
		}
		start, end := int(component.Offset), int(component.Offset+component.Size)
		if !bytes.Equal(before.Data[start:end], after.Data[start:end]) {
			t.Fatalf("opaque component %d changed during FP/vector update", component.ID)
		}
	}
}

func extendedPKRURoundTrip(t *testing.T, s *native.Session, before target.ExtendedRegisterState) target.ExtendedRegisterState {
	t.Helper()
	if before.XState == nil || before.XState.KernelFeatures&(1<<9) == 0 || before.XState.Present&(1<<9) == 0 {
		t.Log("kernel image has no active PKRU component; opaque components remain covered by preservation checks")
		return before
	}
	offset := extendedComponent(t, before, 9, 8)
	request := extendedCopy(before)
	request.Data[offset+3] ^= 0x80
	changed := extendedWritten(t, s, before, request)
	if !bytes.Equal(changed.Data[offset:offset+8], request.Data[offset:offset+8]) {
		t.Fatalf("kernel did not accept raw PKRU payload: got=%x want=%x", changed.Data[offset:offset+8], request.Data[offset:offset+8])
	}
	request = extendedCopy(changed)
	copy(request.Data[offset:offset+8], before.Data[offset:offset+8])
	restored := extendedWritten(t, s, changed, request)
	if !bytes.Equal(restored.Data[offset:offset+8], before.Data[offset:offset+8]) {
		t.Fatalf("PKRU was not restored before target execution: got=%x want=%x", restored.Data[offset:offset+8], before.Data[offset:offset+8])
	}
	return restored
}

func TestNativeExtendedRegisterTargetRoundTrip(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for _, threaded := range []bool{false, true} {
			t.Run(fmt.Sprintf("bits_%d/threaded_%t", bits, threaded), func(t *testing.T) {
				f := newExtendedFixture(t, bits, threaded)
				s := extendedLaunch(t, f.path)
				initial := extendedSnapshot(t, s)
				count := 1
				if threaded {
					count = 2
				}
				selected := extendedReady(t, s, f, count)
				if _, err := s.ReadExtendedRegisters(initial.Threads[0].Token); !errors.Is(err, target.ErrStale) {
					t.Fatalf("resume retained old extended token: %v", err)
				}
				before := extendedRead(t, s, selected.Token)
				wantArchitecture := target.AMD64
				if bits == 32 {
					wantArchitecture = target.X86
				}
				if before.Architecture != wantArchitecture || len(before.Data) < 512 {
					t.Fatalf("wrong target register ABI: %+v", before)
				}
				if binary.LittleEndian.Uint64(before.Data[32:40]) != 0x8000000000000000 || binary.LittleEndian.Uint16(before.Data[40:42]) != 0x3fff {
					t.Fatalf("target x87 seed missing: %x", before.Data[32:42])
				}
				for i, value := range before.Data[160:176] {
					if value != byte(i) {
						t.Fatalf("target XMM seed byte %d=%#x", i, value)
					}
				}
				features := extendedFeatures(t, s, f, before)
				peers := make(map[target.ThreadRef]target.ExtendedRegisterState)
				for _, info := range extendedSnapshot(t, s).Threads {
					if info.Ref != selected.Ref {
						peer := extendedRead(t, s, info.Token)
						if binary.LittleEndian.Uint64(peer.Data[32:40]) != 0xc000000000000000 || binary.LittleEndian.Uint16(peer.Data[40:42]) != 0x4000 || peer.Data[160] != 64 {
							t.Fatalf("peer extended state was selected incorrectly: %x %x", peer.Data[32:42], peer.Data[160:176])
						}
						peers[info.Ref] = peer
					}
				}
				request := extendedPatch(t, before, bits, features)
				if request.XState != nil {
					request.XState.KernelFeatures = ^uint64(0)
					request.XState.Present = ^uint64(0)
					request.XState.ExtendedComponents = []target.XStateComponent{{ID: 63, Offset: 1, Size: ^uint32(0)}}
				}
				post := extendedWritten(t, s, before, request)
				extendedCheckPatched(t, post, bits, features)
				extendedCheckOpaque(t, before, post, bits, features)
				request.Data[0] ^= 0xff
				if post.Data[0] != 0x7f {
					t.Fatal("post-state aliases caller write bytes")
				}
				post = extendedPKRURoundTrip(t, s, post)
				extendedCheckPatched(t, post, bits, features)
				for ref, peer := range peers {
					if current := extendedRead(t, s, peer.Token); !reflect.DeepEqual(current, peer) || extendedThread(t, extendedSnapshot(t, s), ref).Token != peer.Token {
						t.Fatalf("extended write changed unselected thread %+v", ref)
					}
				}
				first := extendedRead(t, s, post.Token)
				second := extendedRead(t, s, post.Token)
				first.Data[32] ^= 0xff
				if first.XState != nil {
					first.XState.Present ^= 1
					if len(first.XState.ExtendedComponents) != 0 {
						first.XState.ExtendedComponents[0].Offset++
					}
				}
				if !reflect.DeepEqual(second, post) || !reflect.DeepEqual(extendedRead(t, s, post.Token), post) {
					t.Fatal("extended read results or nested metadata alias target state")
				}
				extendedExit(t, s)
				if _, err := s.ReadExtendedRegisters(post.Token); !errors.Is(err, target.ErrExited) {
					t.Fatalf("extended registers after target exit: %v", err)
				}
			})
		}
	}
}

func TestNativeExtendedRegisterInvalidImagesAreAtomic(t *testing.T) {
	for _, bits := range []int{32, 64} {
		t.Run(fmt.Sprintf("bits_%d", bits), func(t *testing.T) {
			f := newExtendedFixture(t, bits, false)
			s := extendedLaunch(t, f.path)
			selected := extendedReady(t, s, f, 1)
			before := extendedRead(t, s, selected.Token)
			features := extendedFeatures(t, s, f, before)
			type invalidImage struct {
				name   string
				modify func(*target.ExtendedRegisterState)
				want   error
			}
			cases := []invalidImage{
				{"missing_data", func(state *target.ExtendedRegisterState) { state.Data = nil }, target.ErrInvalidArgument},
				{"short_data", func(state *target.ExtendedRegisterState) { state.Data = state.Data[:len(state.Data)-1] }, target.ErrInvalidArgument},
				{"long_data", func(state *target.ExtendedRegisterState) { state.Data = append(state.Data, make([]byte, 8)...) }, target.ErrInvalidArgument},
				{"unknown_format", func(state *target.ExtendedRegisterState) { state.Format = target.ExtendedFormatUnknown }, target.ErrInvalidArgument},
				{"different_format", func(state *target.ExtendedRegisterState) {
					state.Format = target.ExtendedFormatXSave
					if before.Format == target.ExtendedFormatXSave {
						state.Format = target.ExtendedFormatFXSave
					}
				}, target.ErrInvalidArgument},
				{"different_architecture", func(state *target.ExtendedRegisterState) { state.Architecture = target.AArch64 }, target.ErrInvalidArgument},
				{"state_token", func(state *target.ExtendedRegisterState) { state.Token.Registers++ }, target.ErrStale},
				{"legacy_reserved", func(state *target.ExtendedRegisterState) { state.Data[5] ^= 1 }, target.ErrInvalidArgument},
				{"x87_reserved", func(state *target.ExtendedRegisterState) { state.Data[42] ^= 1 }, target.ErrInvalidArgument},
				{"legacy_padding", func(state *target.ExtendedRegisterState) { state.Data[416] ^= 1 }, target.ErrInvalidArgument},
				{"fop_reserved", func(state *target.ExtendedRegisterState) { state.Data[7] ^= 0x80 }, target.ErrInvalidArgument},
				{"mxcsr_mask", func(state *target.ExtendedRegisterState) { state.Data[28] ^= 1 }, target.ErrInvalidArgument},
				{"mxcsr_reserved", func(state *target.ExtendedRegisterState) { state.Data[27] |= 0x80 }, target.ErrInvalidArgument},
			}
			if before.Format == target.ExtendedFormatXSave {
				cases = append(cases,
					invalidImage{"xcomp_bv", func(state *target.ExtendedRegisterState) { binary.LittleEndian.PutUint64(state.Data[520:528], 1) }, target.ErrUnsupported},
					invalidImage{"header_reserved", func(state *target.ExtendedRegisterState) { state.Data[528] ^= 1 }, target.ErrInvalidArgument},
					invalidImage{"software_metadata", func(state *target.ExtendedRegisterState) { state.Data[464] ^= 1 }, target.ErrInvalidArgument},
				)
				for id := uint8(0); id < 64; id++ {
					if before.XState.KernelFeatures&(uint64(1)<<id) == 0 {
						mask := uint64(1) << id
						cases = append(cases, invalidImage{"unavailable_component", func(state *target.ExtendedRegisterState) {
							binary.LittleEndian.PutUint64(state.Data[512:520], before.XState.Present|mask)
						}, target.ErrInvalidArgument})
						break
					}
				}
				for id := uint8(5); id <= 7; id++ {
					if before.XState.KernelFeatures&(uint64(1)<<id) == 0 {
						mask := uint64(1) << id
						cases = append(cases, invalidImage{"avx512_unavailable_component", func(state *target.ExtendedRegisterState) {
							binary.LittleEndian.PutUint64(state.Data[512:520], before.XState.Present|mask)
						}, target.ErrInvalidArgument})
						break
					}
				}
				for offset := 576; offset < len(before.Data); offset++ {
					covered := false
					for _, component := range before.XState.ExtendedComponents {
						covered = covered || uint64(offset) >= uint64(component.Offset) && uint64(offset) < uint64(component.Offset)+uint64(component.Size)
					}
					if !covered {
						cases = append(cases, invalidImage{"component_padding", func(state *target.ExtendedRegisterState) { state.Data[offset] ^= 1 }, target.ErrInvalidArgument})
						break
					}
				}
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					request := extendedCopy(before)
					test.modify(&request)
					if _, err := s.WriteExtendedRegisters(before.Token, request); !errors.Is(err, test.want) {
						t.Fatalf("invalid image: got=%v want=%v", err, test.want)
					}
					if actual := extendedRead(t, s, before.Token); !reflect.DeepEqual(actual, before) {
						t.Fatal("prevalidation changed raw state or its token")
					}
				})
			}
			stale := before.Token
			stale.Stop++
			if _, err := s.ReadExtendedRegisters(stale); !errors.Is(err, target.ErrStale) {
				t.Fatalf("stale read token: %v", err)
			}
			if _, err := s.WriteExtendedRegisters(stale, before); !errors.Is(err, target.ErrStale) {
				t.Fatalf("stale write token: %v", err)
			}
			foreign := before.Token
			foreign.Thread.Session++
			if _, err := s.ReadExtendedRegisters(foreign); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("foreign session token: %v", err)
			}
			request := extendedPatch(t, before, bits, features)
			request.XState = nil
			post := extendedWritten(t, s, before, request)
			extendedCheckPatched(t, post, bits, features)
			extendedExit(t, s)
		})
	}
}

func TestNativeExtendedRegisterExecChangesArchitecture(t *testing.T) {
	for _, fromBits := range []int{32, 64} {
		t.Run(fmt.Sprintf("from_%d", fromBits), func(t *testing.T) {
			toBits := 96 - fromBits
			f := newExtendedFixture(t, toBits, false)
			program := ".text\n.global _start\n_start:\n"
			if fromBits == 32 {
				program += "mov $11, %eax\nmov $destination, %ebx\nxor %ecx, %ecx\nxor %edx, %edx\nint $0x80\nud2\n"
			} else {
				program += "mov $59, %eax\nlea destination(%rip), %rdi\nxor %esi, %esi\nxor %edx, %edx\nsyscall\nud2\n"
			}
			program += fmt.Sprintf(".section .rodata\ndestination: .asciz %q\n.section .note.GNU-stack,\"\",@progbits\n", f.path)
			var path string
			if fromBits == 32 {
				path, _ = x86Fixture(t, program, false)
			} else {
				path, _ = nativeFixture(t, program)
			}
			s := extendedLaunch(t, path)
			initial := extendedSnapshot(t, s)
			old := extendedRead(t, s, initial.Threads[0].Token)
			result := extendedRun(t, s)
			if result.Stop.Reason != target.StopExec {
				t.Fatalf("architecture-changing exec stop=%+v", result)
			}
			after := extendedSnapshot(t, s)
			if len(after.Threads) != 1 || after.Threads[0].Ref != initial.Threads[0].Ref || after.Process != initial.Process || after.Memory.Space == initial.Memory.Space {
				t.Fatalf("exec identity=%+v before=%+v", after, initial)
			}
			current := extendedRead(t, s, after.Threads[0].Token)
			if current.Architecture == old.Architecture || current.Architecture != after.Architecture {
				t.Fatalf("exec retained old extended ABI: before=%s after=%s snapshot=%s", old.Architecture, current.Architecture, after.Architecture)
			}
			if _, err := s.ReadExtendedRegisters(old.Token); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old exec token read: %v", err)
			}
			if _, err := s.WriteExtendedRegisters(current.Token, old); !errors.Is(err, target.ErrStale) {
				t.Fatalf("old exec image token write: %v", err)
			}
			old.Token = current.Token
			if _, err := s.WriteExtendedRegisters(current.Token, old); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("old architecture blob write: %v", err)
			}
			if !reflect.DeepEqual(extendedRead(t, s, current.Token), current) {
				t.Fatal("rejected old image changed the new image's state")
			}
			selected := extendedReady(t, s, f, 1)
			state := extendedRead(t, s, selected.Token)
			features := extendedFeatures(t, s, f, state)
			post := extendedWritten(t, s, state, extendedPatch(t, state, toBits, features))
			extendedCheckPatched(t, post, toBits, features)
			extendedExit(t, s)
		})
	}
}
