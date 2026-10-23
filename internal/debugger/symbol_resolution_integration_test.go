package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"fastdbg2/target"
)

const symbolResolutionNativeSource = `#include <stdlib.h>
volatile void *symbol_allocation;
__attribute__((naked,noinline)) void symbol_ready(void) {
    __asm__ volatile("nop\n\tnop\n\tret");
}
int main(void) {
    symbol_ready();
    void *allocation = malloc(37);
    symbol_allocation = allocation;
    __asm__ volatile("" : : "r"(allocation) : "memory");
    free(allocation);
    symbol_allocation = 0;
    return 0;
}
`

func TestGlobalSymbolNativeMallocFreeBreakpoints(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			fixture, _ := newLegacyFixture(t, pie, false, symbolResolutionNativeSource, "`main!symbol_ready`", false)
			controller := fixture.controller
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			snapshot, thread, err := controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			scope, err := controller.loadStoppedSymbolScope(ctx, snapshot, thread)
			if err != nil || scope.err != nil {
				t.Fatalf("scope=%+v error=%v", scope, err)
			}
			imports := map[string]bool{}
			for _, module := range scope.modules {
				if module.id != "main" {
					continue
				}
				for _, symbol := range module.symbols {
					if symbol.Name == "malloc" || symbol.Name == "free" {
						if symbol.Section != elf.SHN_UNDEF {
							t.Fatalf("fixture does not import %s: %+v", symbol.Name, symbol)
						}
						imports[symbol.Name] = true
					}
				}
			}
			if !imports["malloc"] || !imports["free"] {
				t.Fatalf("fixture imports=%v", imports)
			}
			addresses := map[string]target.Address{}
			original := map[string]byte{}
			for _, name := range []string{"malloc", "free"} {
				symbol, err := scope.resolve(symbolQuery{name: name})
				if err != nil || !symbol.AddressKnown || symbol.ModuleID == "main" || symbol.Type != elf.STT_FUNC {
					t.Fatalf("%s symbol=%+v error=%v", name, symbol, err)
				}
				addresses[name] = symbol.Address
				output := fixture.command(t, "p/x "+name)
				if !strings.Contains(output, fmt.Sprintf("0x%x", symbol.Address)) {
					t.Fatalf("%s print=%q", name, output)
				}
				qualified := symbol.ModuleID + "!" + name
				if symbol.Version != "" {
					qualified += "@" + symbol.Version
				}
				output = fixture.command(t, "p/x `"+qualified+"`")
				if !strings.Contains(output, fmt.Sprintf("0x%x", symbol.Address)) {
					t.Fatalf("%s qualified print=%q", name, output)
				}
				buffer := make([]byte, 1)
				if n, err := controller.session.ReadSpaceMemory(snapshot.Memory, symbol.Address, buffer); err != nil || n != 1 {
					t.Fatalf("%s original byte: n=%d error=%v", name, n, err)
				}
				original[name] = buffer[0]
			}
			if value, err := controller.evaluate(ctx, "malloc + free - malloc", snapshot, thread); err != nil || value != addresses["free"] {
				t.Fatalf("global arithmetic=%#x error=%v", value, err)
			}
			cache := controller.newStoppedSymbolResolver(ctx, snapshot, thread)
			if _, err := cache.Resolve("malloc"); err != nil {
				t.Fatal(err)
			}
			fixture.command(t, "b malloc")
			if _, err := cache.Resolve("free"); !errors.Is(err, target.ErrStale) {
				t.Fatalf("cached scope survived memory revision change: %v", err)
			}
			fixture.command(t, "b free")
			for _, name := range []string{"malloc", "free"} {
				current, _, err := controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1)
				if n, err := controller.session.ReadSpaceMemory(current.Memory, addresses[name], buffer); err != nil || n != 1 || buffer[0] != 0xcc {
					t.Fatalf("%s breakpoint byte=%x n=%d error=%v", name, buffer, n, err)
				}
			}
			for _, test := range []struct {
				name string
				id   int
			}{{"malloc", 2}, {"free", 3}} {
				fixture.command(t, "continue")
				current, selected, err := controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				location, err := controller.session.ReadCodeLocation(selected.Token)
				if err != nil || location.InstructionPC != addresses[test.name] || location.Breakpoint == nil || *location.Breakpoint != addresses[test.name] {
					t.Fatalf("%s did not hit exact libc definition: location=%+v error=%v", test.name, location, err)
				}
				if current.Memory.Space != snapshot.Memory.Space {
					t.Fatal("unexpected address-space replacement")
				}
				fixture.command(t, fmt.Sprintf("delete %d", test.id))
				current, _, err = controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1)
				if n, err := controller.session.ReadSpaceMemory(current.Memory, addresses[test.name], buffer); err != nil || n != 1 || buffer[0] != original[test.name] {
					t.Fatalf("%s restore byte=%x want=%x n=%d error=%v", test.name, buffer, original[test.name], n, err)
				}
			}
		})
	}
}
