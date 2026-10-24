package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestUINativeLibcSymbolAnnotationsUseVerifiedLoadedFacts(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			fixture, _ := newLegacyFixture(t, pie, false, symbolResolutionNativeSource, "`main!symbol_ready`", false)
			controller := fixture.controller
			adapter := controller.session.(*nativeSession)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			snapshot, thread, err := controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			scope, err := controller.loadStoppedSymbolScope(ctx, snapshot, thread)
			if err != nil || scope == nil || scope.err != nil {
				t.Fatalf("verified loaded scope: %v %+v", err, scope)
			}
			addresses := make(map[string]target.Address)
			for _, name := range []string{"malloc", "free"} {
				symbol, err := scope.resolve(symbolQuery{name: name})
				if err != nil || symbol.ModuleID == "main" || !symbol.AddressKnown {
					t.Fatalf("%s libc definition: %v %+v", name, err, symbol)
				}
				addresses[name] = symbol.Address
				fixture.command(t, "b "+name)
			}
			for index, name := range []string{"malloc", "free"} {
				fixture.command(t, "continue")
				snapshot, thread, err = controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				location, err := controller.session.ReadCodeLocation(thread.Token)
				if err != nil || location.InstructionPC != addresses[name] || location.RawPC != addresses[name]+1 {
					t.Fatalf("%s raw/logical PC: %v %+v", name, err, location)
				}
				registers, err := controller.session.ReadThreadRegisters(thread.Token)
				if err != nil {
					t.Fatal(err)
				}
				walker, err := controller.newAddressView(ctx, snapshot, thread, registers)
				if err != nil || walker == nil || walker.symbol == nil {
					t.Fatalf("%s address annotations unavailable: %v", name, err)
				}
				label := walker.symbol(location.InstructionPC)
				if label != name {
					t.Fatalf("%s exact libc label absent: %q", name, label)
				}
				if label := walker.symbol(0); label != "" {
					t.Fatalf("NULL acquired absolute-constant labels: %q", label)
				}
				nullView, err := walker.Value(ctx, 0, defaultAddressWalkDepth)
				if err != nil || nullView != "0x0000000000000000" {
					t.Fatalf("NULL address view: %q error=%v", nullView, err)
				}
				first, err := adapter.addressWalkSymbols(ctx, snapshot, thread)
				if err != nil || len(first) == 0 || !adapter.uiSymbols.ready || adapter.uiSymbols.key != newUISymbolCacheKey(snapshot, thread) {
					t.Fatalf("%s verified symbol cache unavailable: %v", name, err)
				}
				if !slices.ContainsFunc(first, func(symbol inspect.Symbol) bool {
					return symbol.Section == elf.SHN_ABS && symbol.AddressKnown && symbol.Address == 0
				}) {
					t.Fatal("absolute zero symbol facts were removed from the shared UI cache")
				}
				storage := &adapter.uiSymbols.symbols[0]
				second, err := adapter.addressWalkSymbols(ctx, snapshot, thread)
				if err != nil || len(first) != len(second) || storage != &adapter.uiSymbols.symbols[0] {
					t.Fatalf("%s repeated view reparsed symbol metadata: %v", name, err)
				}
				code := fixture.command(t, "context code")
				registerView := fixture.command(t, "regs rip")
				if !strings.Contains(code, "*->") || !strings.Contains(code, "<"+label+">") || !strings.Contains(registerView, fmt.Sprintf("0x%016x", location.RawPC)) || !strings.Contains(registerView, name+"+0x1") {
					t.Fatalf("%s code/register label or raw PC missing:\n%s\n%s", name, code, registerView)
				}
				directory := filepath.Join("..", "..", ".cache", "ui-global-symbols")
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("libc-%s-pie-%t.txt", name, pie)), []byte(code+registerView+"NULL: "+nullView+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				fixture.command(t, fmt.Sprintf("delete %d", index+2))
				if stale, err := adapter.addressWalkSymbols(ctx, snapshot, thread); !errors.Is(err, target.ErrStale) || len(stale) != 0 || adapter.uiSymbols.ready {
					t.Fatalf("%s obsolete memory revision exposed annotations: %v %+v", name, err, stale)
				}
			}
		})
	}
}
