package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func uiCacheTestScope() *stoppedSymbolScope {
	return &stoppedSymbolScope{modules: []moduleSymbolFacts{{id: "main", symbols: []inspect.Symbol{{
		ModuleID: "main", Name: "proven", Address: 0x401000, AddressKnown: true, Size: 32,
	}}}}}
}

func TestUISymbolCacheReusesOnlyTheSameVerifiedSnapshot(t *testing.T) {
	_, snapshot, thread := newContextFixture()
	key := newUISymbolCacheKey(snapshot, thread)
	var cache uiSymbolCache
	loads, validations := 0, 0
	scope := uiCacheTestScope()
	load := func() (*stoppedSymbolScope, error) { loads++; return scope, nil }
	validate := func() error { validations++; return nil }
	first, err := cache.read(context.Background(), key, validate, load)
	if err != nil || len(first) != 1 || loads != 1 || validations != 1 {
		t.Fatalf("initial load: %v %+v loads=%d validations=%d", err, first, loads, validations)
	}
	first[0].Name = "changed returned slice"
	scope.modules[0].symbols[0].Name = "changed loaded slice"
	second, err := cache.read(context.Background(), key, validate, load)
	if err != nil || len(second) != 1 || second[0].Name != "proven" || loads != 1 || validations != 2 {
		t.Fatalf("cache reused mutable/unvalidated data: %v %+v loads=%d validations=%d", err, second, loads, validations)
	}
	for _, change := range []struct {
		name string
		key  func(*uiSymbolCacheKey)
	}{
		{"sequence", func(key *uiSymbolCacheKey) { key.sequence++ }},
		{"process", func(key *uiSymbolCacheKey) { key.process.ID++ }},
		{"memory-revision", func(key *uiSymbolCacheKey) { key.memory.Revision++ }},
		{"exec-space", func(key *uiSymbolCacheKey) { key.memory.Space.ID++ }},
		{"thread", func(key *uiSymbolCacheKey) { key.thread.Thread.ID++ }},
		{"stop", func(key *uiSymbolCacheKey) { key.thread.Stop++ }},
		{"register-revision", func(key *uiSymbolCacheKey) { key.thread.Registers++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			change.key(&key)
			before := loads
			if symbols, err := cache.read(context.Background(), key, validate, load); err != nil || len(symbols) != 1 || loads != before+1 || !cache.ready || cache.key != key {
				t.Fatalf("changed identity reused stale facts: %v loads=%d/%d", err, loads, before)
			}
		})
	}
}

func TestUISymbolCacheValidationFailuresDiscardHitsAndLoads(t *testing.T) {
	_, snapshot, thread := newContextFixture()
	key := newUISymbolCacheKey(snapshot, thread)
	for _, cached := range []bool{false, true} {
		for _, failure := range []error{target.ErrStale, target.ErrUnavailable, context.Canceled, context.DeadlineExceeded} {
			t.Run(fmt.Sprintf("cached_%t/%v", cached, failure), func(t *testing.T) {
				var cache uiSymbolCache
				loads := 0
				load := func() (*stoppedSymbolScope, error) { loads++; return uiCacheTestScope(), nil }
				if cached {
					if _, err := cache.read(context.Background(), key, func() error { return nil }, load); err != nil {
						t.Fatal(err)
					}
				}
				symbols, err := cache.read(context.Background(), key, func() error { return failure }, load)
				if !errors.Is(err, failure) || len(symbols) != 0 || cache.ready || cache.symbols != nil || loads != 1 {
					t.Fatalf("invalid proof retained facts: %v %+v ready=%t loads=%d", err, symbols, cache.ready, loads)
				}
			})
		}
	}
}

func TestUISymbolCacheCancellationAndLoadFailureClearPriorFacts(t *testing.T) {
	_, snapshot, thread := newContextFixture()
	key := newUISymbolCacheKey(snapshot, thread)
	for _, failure := range []string{"load", "during-load", "during-validation", "before-hit", "nil-context"} {
		t.Run(failure, func(t *testing.T) {
			var cache uiSymbolCache
			load := func() (*stoppedSymbolScope, error) { return uiCacheTestScope(), nil }
			validate := func() error { return nil }
			if _, err := cache.read(context.Background(), key, validate, load); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			requestKey := key
			var requestContext context.Context = ctx
			want := error(context.Canceled)
			switch failure {
			case "load":
				requestKey.sequence++
				load = func() (*stoppedSymbolScope, error) { return uiCacheTestScope(), target.ErrStale }
				want = target.ErrStale
			case "during-load":
				requestKey.sequence++
				load = func() (*stoppedSymbolScope, error) { cancel(); return uiCacheTestScope(), nil }
			case "during-validation":
				validate = func() error { cancel(); return nil }
			case "before-hit":
				cancel()
			case "nil-context":
				requestContext = nil
				want = target.ErrInvalidArgument
			}
			symbols, err := cache.read(requestContext, requestKey, validate, load)
			if !errors.Is(err, want) || len(symbols) != 0 || cache.ready || cache.symbols != nil {
				t.Fatalf("cancelled/failed request retained facts: %v %+v ready=%t", err, symbols, cache.ready)
			}
		})
	}
}

func TestUISymbolFactsPreserveProvenPartialModulesAndRejectFatalErrors(t *testing.T) {
	for _, failure := range []error{target.ErrUnavailable, &runtimeLoaderPendingError{}, target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		for _, location := range []string{"scope", "module"} {
			t.Run(fmt.Sprintf("%s/%v", location, failure), func(t *testing.T) {
				scope := uiCacheTestScope()
				if location == "scope" {
					scope.err = failure
				} else {
					scope.modules = append(scope.modules, moduleSymbolFacts{id: "failed", err: failure, symbols: []inspect.Symbol{{Name: "unverified"}}})
				}
				symbols, err := uiScopeSymbolFacts(scope)
				if !errors.Is(err, failure) {
					t.Fatalf("partial/fatal error lost: %v", err)
				}
				if uiDisplayFatal(failure) {
					if len(symbols) != 0 {
						t.Fatalf("fatal scope published %+v", symbols)
					}
				} else if len(symbols) != 1 || symbols[0].Name != "proven" {
					t.Fatalf("partial scope hid known facts or exposed unverified facts: %+v", symbols)
				}
			})
		}
	}
}

func TestUISymbolCacheConcurrentViewsUseOneImmutableLoad(t *testing.T) {
	_, snapshot, thread := newContextFixture()
	var cache uiSymbolCache
	loads, validations := 0, 0
	var done sync.WaitGroup
	for range 16 {
		done.Go(func() {
			symbols, err := cache.read(context.Background(), newUISymbolCacheKey(snapshot, thread),
				func() error { validations++; return nil },
				func() (*stoppedSymbolScope, error) { loads++; return uiCacheTestScope(), nil })
			if err != nil || len(symbols) != 1 || symbols[0].Name != "proven" {
				t.Errorf("concurrent view: %v %+v", err, symbols)
				return
			}
			symbols[0].Name = "private mutation"
		})
	}
	done.Wait()
	if loads != 1 || validations != 16 || cache.symbols[0].Name != "proven" {
		t.Fatalf("shared mutation or duplicate loading: loads=%d validations=%d facts=%+v", loads, validations, cache.symbols)
	}
}

type uiPartialSymbolFixture struct {
	*uiReadFixture
	err error
}

func (fixture *uiPartialSymbolFixture) addressWalkSymbols(context.Context, target.Snapshot, target.ThreadInfo) ([]inspect.Symbol, error) {
	fixture.symbolCalls++
	return slices.Clone(fixture.symbols), fixture.err
}

func TestUISymbolAnnotationsKeepProvenPartialFactsAndDiscardFatalViews(t *testing.T) {
	for _, failure := range []error{target.ErrUnavailable, &runtimeLoaderPendingError{}, target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			fixture, thread := newUIFixture()
			var output bytes.Buffer
			controller := &Controller{session: &uiPartialSymbolFixture{fixture, failure}, selected: thread.Ref, out: &output}
			err := controller.showContext(context.Background())
			if uiDisplayFatal(failure) {
				if !errors.Is(err, failure) || output.Len() != 0 || len(controller.registerHistory) != 0 {
					t.Fatalf("fatal optional symbols published view: %v %q", err, output.String())
				}
			} else if err != nil || !strings.Contains(output.String(), "<ui_probe>") || !strings.Contains(output.String(), "<writable_value>") {
				t.Fatalf("known partial symbols were hidden: %v %q", err, output.String())
			}
		})
	}
}

func TestUISymbolAnnotationsExcludeAbsoluteConstantsOnly(t *testing.T) {
	for _, test := range []struct {
		name          string
		value         target.Address
		address       target.Address
		size          uint64
		runtimeSymbol bool
		want          string
	}{
		{"absolute-zero", 0, 0, 0, false, ""},
		{"absolute-nonzero", 0x500000, 0x500000, 0, false, ""},
		{"absolute-interior", 0x500000, 0x500004, 8, false, ""},
		{"runtime-zero", 0, 0, 0, true, "GLIBC_2.10"},
		{"runtime-nonzero", 0x500000, 0x500000, 0, true, "GLIBC_2.10"},
		{"runtime-interior", 0x500000, 0x500004, 8, true, "GLIBC_2.10+0x4"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, thread := newUIFixture()
			fixture.symbols = []inspect.Symbol{{
				ModuleID: "main", Name: "absolute_constant", Value: uint64(test.value), Address: test.value,
				AddressKnown: true, Size: test.size, Type: elf.STT_OBJECT, Binding: elf.STB_GLOBAL, Section: elf.SHN_ABS,
			}}
			if test.runtimeSymbol {
				runtime := fixture.symbols[0]
				runtime.Name = "GLIBC_2.10"
				runtime.Section = 1
				fixture.symbols = append(fixture.symbols, runtime)
			}
			scope := &stoppedSymbolScope{modules: []moduleSymbolFacts{{id: "main", symbols: fixture.symbols}}}
			facts, err := uiScopeSymbolFacts(scope)
			if err != nil || len(facts) != len(fixture.symbols) || facts[0].Section != elf.SHN_ABS {
				t.Fatalf("absolute symbol facts were removed: %v %+v", err, facts)
			}
			resolved, err := scope.resolve(symbolQuery{name: "absolute_constant"})
			if err != nil || resolved.Address != test.value || resolved.Section != elf.SHN_ABS {
				t.Fatalf("absolute constant resolution changed: %v %+v", err, resolved)
			}
			controller := &Controller{session: fixture}
			walker := &addressWalker{}
			if err := controller.addAddressSymbols(context.Background(), fixture.snapshot, thread, walker); err != nil {
				t.Fatal(err)
			}
			if label := walker.symbol(test.address); label != test.want {
				t.Fatalf("runtime label=%q want %q", label, test.want)
			}
		})
	}
}
