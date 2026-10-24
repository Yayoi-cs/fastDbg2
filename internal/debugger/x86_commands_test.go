package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"fastdbg2/target"
)

const x86CommandFixture = `#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
volatile uint32_t x86_words[4]={0x11223344,0x55667788,0,0};
char x86_text[]="x86 pointer walk";
uintptr_t x86_chain[2];
extern void x86_point(void);
__asm__(".text\n.global x86_point\n.type x86_point,@function\nx86_point:\ninc %eax\nnop\nret\n.size x86_point,.-x86_point\n");
void *x86_worker(void *p){x86_point();return p;}
int main(void){
 void *p=malloc(64);
 x86_chain[0]=(uintptr_t)x86_text;x86_chain[1]=(uintptr_t)x86_chain;
 x86_point();x86_words[0]++;
 pthread_t thread;pthread_create(&thread,0,x86_worker,0);pthread_join(thread,0);
 free(p);return 31;
}`

func TestX86NativeCommands(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			f, _ := newLegacyFixture(t, pie, false, x86CommandFixture, "x86_point", false, "-m32", "-pthread")
			if f.controller.abi().arch != target.X86 {
				t.Fatal("not x86")
			}
			for _, check := range []struct{ command, want string }{
				{"regs -s eip esp eax", "$eip"}, {"context code", "inc eax"}, {"disasm --count 3", "inc eax"},
				{"disass func x86_point", "ret"}, {"stack 3", "|+0x0004|+001:"}, {"tel x86_chain 2", "'x86 pointer walk'"},
				{"vmmap", "r-x"}, {"sym x86_point", "STT_FUNC"}, {"got", "R_386_JMP_SLOT"}, {"checksec", "RELRO"},
				{"findruction -n \"inc eax; nop; ret\" x86_point x86_point+3", "1 match(es)"},
				{"asm \"inc eax; ret\"", "40 c3"}, {"p __kernel_vsyscall", "HEX:"},
			} {
				output := f.command(t, check.command)
				if !strings.Contains(output, check.want) {
					t.Fatalf("%s missing %q: %s", check.command, check.want, output)
				}
			}
			if output := f.command(t, "stack"); strings.Count(output, "|+0x") != 8 {
				t.Fatalf("default stack row count: %s", output)
			}

			f.command(t, "set x86_words 0xaabbccdd")
			data := f.read(t, "x86_words", 8)
			if binary.LittleEndian.Uint32(data) != 0xaabbccdd || binary.LittleEndian.Uint32(data[4:]) != 0x55667788 {
				t.Fatalf("native-word write corrupts neighbor: %x", data)
			}
			f.command(t, "xor x86_words 0xff")
			data = f.read(t, "x86_words", 8)
			if binary.LittleEndian.Uint32(data) != 0xaabbcc22 || binary.LittleEndian.Uint32(data[4:]) != 0x55667788 {
				t.Fatalf("native-word XOR corrupts neighbor: %x", data)
			}
			f.command(t, "set $eax 0x1234")
			if output := f.command(t, "regs -s eax"); !strings.Contains(output, "0x00001234") {
				t.Fatal(output)
			}
			f.command(t, "step")
			if output := f.command(t, "regs -s eax"); !strings.Contains(output, "0x00001235") {
				t.Fatal(output)
			}
			if output := f.command(t, "simd"); !strings.Contains(output, "XMM7") || strings.Contains(output, "XMM8") || strings.Contains(output, "YMM8") {
				t.Fatal(output)
			}
			f.reject(t, "xmm 8")
			f.reject(t, "db 0x100000000")
			f.reject(t, "set x86_words 0x100000000")
			f.reject(t, "wp x86_words --size 8")
			f.reject(t, "wp 0x100000000 --size 4")
			f.command(t, "wp x86_words --size 4 --access write")
			if output := f.command(t, "continue"); !strings.Contains(output, "Watchpoint") {
				t.Fatal(output)
			}
			f.command(t, "wp d 0")
			f.command(t, "continue")
			snapshot, err := f.controller.session.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Threads) < 2 {
				t.Fatalf("x86 thread not discovered: %+v", snapshot)
			}
			f.command(t, "threads")
			f.command(t, "thread apply all regs -s eip esp")
		})
	}
}

func TestX86LoaderBreakpointsBeforePublication(t *testing.T) {
	f, _ := newLegacyFixture(t, true, false, x86CommandFixture, "x86_point", false, "-m32", "-pthread")
	f.command(t, "delete all")
	f.command(t, "kill")
	f.command(t, "b malloc")
	f.command(t, "b free")
	output := f.command(t, "run")
	if !strings.Contains(output, "Breakpoint") || !strings.Contains(output, "installed") {
		t.Fatal(output)
	}
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	address, err := f.controller.evaluate(context.Background(), "malloc", snapshot, thread)
	if err != nil {
		t.Fatal(err)
	}
	location, err := f.controller.session.ReadCodeLocation(thread.Token)
	if err != nil || location.InstructionPC != address {
		t.Fatalf("malloc not hit: %+v %v %#x", location, err, address)
	}
	f.command(t, "continue")
	snapshot, thread, err = f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	address, err = f.controller.evaluate(context.Background(), "free", snapshot, thread)
	if err != nil {
		t.Fatal(err)
	}
	location, err = f.controller.session.ReadCodeLocation(thread.Token)
	if err != nil || location.InstructionPC != address {
		t.Fatalf("free not hit: %+v %v %#x", location, err, address)
	}
	f.pid = f.controller.session.PID()
}

func TestX86LoaderLayouts(t *testing.T) {
	data := make([]byte, 0x1000)
	put := func(offset int, v uint32) { binary.LittleEndian.PutUint32(data[offset:], v) }
	put(0, 1)
	put(4, 0x1040)
	put(8, 0x1100)
	put(0x40, 0x400000)
	put(0x44, 0x1080)
	put(0x48, 0x402000)
	copy(data[0x80:], "lib.so\x00")
	memory, err := newRuntimeELFMemory(context.Background(), []procMap{{Start: 0x1000, End: 0x2000, Read: true, Execute: true}}, searchSliceReader(0x1000, data))
	if err != nil {
		t.Fatal(err)
	}
	links, err := runtimeELFLinkMaps(memory, 0x1000, 4)
	if err != nil || len(links) != 1 || links[0].bias != 0x400000 || links[0].dynamic != 0x402000 || links[0].name != "lib.so" {
		t.Fatalf("32bit link_map: %+v %v", links, err)
	}
	info, err := readLoaderRendezvous(memory, 0x1000, 4)
	if err != nil || info.Hook != 0x1100 || !info.Consistent {
		t.Fatalf("32bit r_debug: %+v %v", info, err)
	}
	put(12, 1)
	if _, err := runtimeELFLinkMaps(memory, 0x1000, 4); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
	put(12, 0)
	put(0x4c, 0x1040)
	if _, err := runtimeELFLinkMaps(memory, 0x1000, 4); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestX86AssemblyAndSIMDLayout(t *testing.T) {
	code, err := assembleNative(context.Background(), "inc eax; ret", target.X86)
	if err != nil || string(code) != "\x40\xc3" {
		t.Fatalf("%x %v", code, err)
	}
	data := make([]byte, 512)
	binary.LittleEndian.PutUint32(data[8:], 0x12345678)
	binary.LittleEndian.PutUint16(data[12:], 0x23)
	binary.LittleEndian.PutUint32(data[16:], 0xabcdef00)
	binary.LittleEndian.PutUint16(data[20:], 0x2b)
	state, err := decodeSIMDState(target.ExtendedRegisterState{Architecture: target.X86, Format: target.ExtendedFormatFXSave, Data: data})
	if err != nil || state.vectorCount() != 8 || state.fip != 0x12345678 || state.fdp != 0xabcdef00 || state.fcs != 0x23 || state.fds != 0x2b {
		t.Fatalf("x86 FXSAVE: %+v %v", state, err)
	}
}
