package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

func loaderRendezvousTestMemory(t *testing.T) runtimeELFTestSetup {
	t.Helper()
	fixture := runtimeELFTestLoader(t, true)
	fixture.memory.mappings[0].Execute = true
	binary.LittleEndian.PutUint64(fixture.state[16:], 0x400900)
	return fixture
}

func TestLoaderRendezvousReadsOnlyPublishedProtocolAndStates(t *testing.T) {
	for _, state := range []uint32{0, 1, 2} {
		fixture := loaderRendezvousTestMemory(t)
		binary.LittleEndian.PutUint32(fixture.state[24:], state)
		info, err := readLoaderRendezvous(fixture.memory, 0x900000)
		if err != nil || info.Hook != 0x400900 || info.Debug != 0x900000 || !info.Published || info.Consistent != (state == 0) {
			t.Fatalf("state=%d info=%+v error=%v", state, info, err)
		}
	}
}

func TestLoaderRendezvousRejectsUnknownBrokenOrNonExecutableHooks(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(runtimeELFTestSetup)
		err  error
	}{
		{"version", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint32(f.state, 3) }, target.ErrUnsupported},
		{"state", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint32(f.state[24:], 3) }, target.ErrInvalidArgument},
		{"zero hook", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.state[16:], 0) }, target.ErrUnavailable},
		{"unmapped hook", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.state[16:], 0x500000) }, target.ErrUnavailable},
		{"non executable", func(f runtimeELFTestSetup) { f.memory.mappings[0].Execute = false }, target.ErrUnsupported},
		{"namespace cycle", func(f runtimeELFTestSetup) {
			binary.LittleEndian.PutUint32(f.state, 2)
			binary.LittleEndian.PutUint64(f.state[40:], 0x900000)
		}, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := loaderRendezvousTestMemory(t)
			test.edit(fixture)
			info, err := readLoaderRendezvous(fixture.memory, 0x900000)
			if !errors.Is(err, test.err) || info != (loaderRendezvousInfo{}) {
				t.Fatalf("info=%+v error=%v", info, err)
			}
		})
	}
}

func TestLoaderRendezvousNamespacesRequireOneHookAndAllConsistent(t *testing.T) {
	fixture := loaderRendezvousTestMemory(t)
	binary.LittleEndian.PutUint32(fixture.state, 2)
	binary.LittleEndian.PutUint64(fixture.state[40:], 0x900800)
	copy(fixture.state[0x800:], fixture.state[:40])
	binary.LittleEndian.PutUint32(fixture.state[0x818:], 1)
	info, err := readLoaderRendezvous(fixture.memory, 0x900000)
	if err != nil || info.Consistent || info.Hook != 0x400900 {
		t.Fatalf("info=%+v error=%v", info, err)
	}
	binary.LittleEndian.PutUint64(fixture.state[0x810:], 0x400901)
	if _, err := readLoaderRendezvous(fixture.memory, 0x900000); !errors.Is(err, target.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestLoaderRendezvousWitnessChangesInvalidateResult(t *testing.T) {
	fixture := loaderRendezvousTestMemory(t)
	read := fixture.memory.read
	count := 0
	fixture.memory.read = func(address target.Address, data []byte) (int, error) {
		if address == 0x900000 {
			count++
			if count == 2 {
				binary.LittleEndian.PutUint32(fixture.state[24:], 1)
			}
		}
		return read(address, data)
	}
	if info, err := readLoaderRendezvous(fixture.memory, 0x900000); !errors.Is(err, target.ErrStale) || info != (loaderRendezvousInfo{}) {
		t.Fatalf("info=%+v error=%v", info, err)
	}
}

func TestLoaderBootstrapRequiresUniqueExactVersionedExecutableFunction(t *testing.T) {
	fixture := loaderRendezvousTestMemory(t)
	image, err := runtimeELFZeroOrigin(fixture.memory, 0x400000, nil)
	if err != nil {
		t.Fatal(err)
	}
	symbol := inspect.Symbol{Name: "_dl_debug_state", Version: "GLIBC_PRIVATE", Value: 0x900, Address: 0x400900, AddressKnown: true, Size: 5, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL, Section: 1}
	if address, err := loaderBootstrapHook(fixture.memory, image, []inspect.Symbol{symbol, symbol}); err != nil || address != symbol.Address {
		t.Fatalf("address=%#x error=%v", address, err)
	}
	for _, edit := range []func(*inspect.Symbol){
		func(s *inspect.Symbol) { s.Version = "" }, func(s *inspect.Symbol) { s.Name = "main" },
		func(s *inspect.Symbol) { s.Type = elf.STT_GNU_IFUNC }, func(s *inspect.Symbol) { s.Binding = elf.STB_WEAK },
		func(s *inspect.Symbol) { s.AddressKnown = false }, func(s *inspect.Symbol) { s.Section = elf.SHN_ABS },
		func(s *inspect.Symbol) { s.Size = 0 }, func(s *inspect.Symbol) { s.Address++ },
		func(s *inspect.Symbol) { s.Value, s.Address = 0x3000, 0x403000 },
	} {
		changed := symbol
		edit(&changed)
		if address, err := loaderBootstrapHook(fixture.memory, image, []inspect.Symbol{changed}); err == nil || address != 0 {
			t.Fatalf("accepted symbol=%+v address=%#x error=%v", changed, address, err)
		}
	}
	other := symbol
	other.Value++
	other.Address++
	if _, err := loaderBootstrapHook(fixture.memory, image, []inspect.Symbol{symbol, other}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
}

const loaderRendezvousConstructorSource = `#include <stdlib.h>
volatile unsigned loader_constructor_started;
void *volatile loader_allocation;
__attribute__((naked,noinline)) void loader_constructor_marker(void) { __asm__ volatile("nop\n\tret"); }
__attribute__((constructor)) static void loader_constructor(void) {
    loader_constructor_started = 1;
    loader_constructor_marker();
    loader_allocation = malloc(64);
    free((void *)loader_allocation);
}
int main(void) { return 11; }
`

func TestLoaderRendezvousNativeConsistentPrecedesNormalConstructor(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "loader-rendezvous"))
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
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			source, path := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
			if err := os.WriteFile(source, []byte(loaderRendezvousConstructorSource), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			flags := []string{"-O0", "-g", "-fcf-protection=none", "-fno-pie", "-no-pie"}
			if pie {
				flags = []string{"-O0", "-g", "-fcf-protection=none", "-fPIE", "-pie"}
			}
			command := exec.CommandContext(ctx, "cc", append(flags, "-o", path, source)...)
			command.Env = append(os.Environ(), "TMPDIR="+dir)
			if data, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile: %v\n%s", err, data)
			}
			var output bytes.Buffer
			controller := New(&output, display.Renderer{})
			controller.contextDisabled = true
			t.Cleanup(func() {
				if err := controller.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := controller.Configure(path, nil); err != nil {
				t.Fatal(err)
			}
			if err := controller.start(ctx, "", false); err != nil {
				t.Fatal(err)
			}
			snapshot, thread, err := controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			image, err := readLiveImage(ctx, thread.TID)
			if err != nil {
				t.Fatal(err)
			}
			flag, err := image.resolveSymbol("loader_constructor_started")
			if err != nil {
				t.Fatal(err)
			}
			marker, err := image.resolveSymbol("loader_constructor_marker")
			if err != nil {
				t.Fatal(err)
			}
			initial, err := controller.loaderRendezvous(ctx, snapshot, thread)
			if err != nil || initial.Published || initial.Consistent || initial.Debug != 0 || initial.Hook == 0 || initial.Space != snapshot.Memory.Space {
				t.Fatalf("initial=%+v error=%v", initial, err)
			}
			if err := controller.session.AddBreakpoint(initial.Hook); err != nil {
				t.Fatal(err)
			}
			consistent, adding := false, false
			for range 16 {
				snapshot, thread, err = controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				operation, err := controller.session.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}})
				if err != nil {
					t.Fatal(err)
				}
				result, err := operation.Wait(ctx)
				if err != nil || result.Stop.Reason != target.StopBreakpoint || result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != initial.Hook {
					t.Fatalf("rendezvous event=%+v error=%v", result, err)
				}
				snapshot, thread, err = controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				current, err := controller.loaderRendezvous(ctx, snapshot, thread)
				if err != nil || !current.Published || current.Hook != initial.Hook || current.Debug == 0 {
					t.Fatalf("published=%+v initial=%+v error=%v", current, initial, err)
				}
				var bytes [4]byte
				if _, err := controller.session.ReadSpaceMemory(snapshot.Memory, target.Address(flag), bytes[:]); err != nil || binary.LittleEndian.Uint32(bytes[:]) != 0 {
					t.Fatalf("normal constructor ran before stable rendezvous: flag=%x error=%v", bytes, err)
				}
				if current.Consistent {
					consistent = true
					break
				}
				adding = true
			}
			if !consistent || !adding {
				t.Fatalf("missing startup state transitions: adding=%t consistent=%t", adding, consistent)
			}
			if err := controller.session.RemoveBreakpoint(initial.Hook); err != nil {
				t.Fatal(err)
			}
			if err := controller.session.AddBreakpoint(target.Address(marker)); err != nil {
				t.Fatal(err)
			}
			operation, err := controller.session.Run(target.RunRequest{Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := operation.Wait(ctx)
			if err != nil || result.Stop.Reason != target.StopBreakpoint || result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != target.Address(marker) {
				t.Fatalf("constructor marker event=%+v error=%v", result, err)
			}
			snapshot, _, err = controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			var bytes [4]byte
			if _, err := controller.session.ReadSpaceMemory(snapshot.Memory, target.Address(flag), bytes[:]); err != nil || binary.LittleEndian.Uint32(bytes[:]) != 1 {
				t.Fatalf("constructor marker flag=%x error=%v", bytes, err)
			}
		})
	}
}
