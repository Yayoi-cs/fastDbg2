package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func symbolResolutionFixture() *stoppedSymbolScope {
	return &stoppedSymbolScope{modules: []moduleSymbolFacts{
		{id: "main", path: "/owned/program", symbols: []inspect.Symbol{
			{ModuleID: "main", Name: "malloc", Section: elf.SHN_UNDEF, Binding: elf.STB_GLOBAL},
			{ModuleID: "main", Name: "entry", Section: 1, Address: 0x401000, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL},
			{ModuleID: "main", Name: "local", Section: 1, Address: 0x401100, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_LOCAL},
		}},
		{id: "libc-id", path: "/runtime/libc.so.6", symbols: []inspect.Symbol{
			{ModuleID: "libc-id", Name: "malloc", Section: 1, Address: 0x701000, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL, Version: "VER_1"},
			{ModuleID: "libc-id", Name: "malloc", Section: 1, Address: 0x701000, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL},
			{ModuleID: "libc-id", Name: "free", Section: 1, Address: 0x702000, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL, Version: "VER_1"},
			{ModuleID: "libc-id", Name: "private", Section: 1, Address: 0x703000, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_LOCAL},
			{ModuleID: "libc-id", Name: "ifunc", Section: 1, Type: elf.STT_GNU_IFUNC, Binding: elf.STB_GLOBAL},
			{ModuleID: "libc-id", Name: "tls", Section: 1, Type: elf.STT_TLS, Binding: elf.STB_GLOBAL},
		}},
	}}
}

func TestGlobalSymbolOptionalDisplayDebugCannotChangeResolution(t *testing.T) {
	scope := symbolResolutionFixture()
	scope.displaySymbols = []inspect.Symbol{{ModuleID: "libc-id", Name: "malloc", Address: 0xdead000, AddressKnown: true, Section: 1, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL}}
	for _, err := range []error{nil, target.ErrAmbiguous, target.ErrInvalidArgument, target.ErrUnavailable} {
		scope.displayErr = err
		symbol, resolveErr := scope.resolve(symbolQuery{name: "malloc"})
		if resolveErr != nil || symbol.Address != 0x701000 {
			t.Fatalf("display error %v changed resolution: %+v,%v", err, symbol, resolveErr)
		}
		symbols, displayErr := uiScopeSymbolFacts(scope)
		if !errors.Is(displayErr, err) {
			t.Fatalf("display error lost: %v", displayErr)
		}
		found := false
		for _, symbol := range symbols {
			if symbol.Address == 0xdead000 {
				found = true
			}
		}
		if !found {
			t.Fatal("display-only symbols unavailable to display")
		}
	}
	scope.displayErr = target.ErrStale
	if symbols, err := uiScopeSymbolFacts(scope); !errors.Is(err, target.ErrStale) || len(symbols) != 0 {
		t.Fatalf("stale optional metadata leaked: %+v,%v", symbols, err)
	}
}

func TestGlobalSymbolResolutionSkipsImportsAndDeduplicatesAddresses(t *testing.T) {
	scope := symbolResolutionFixture()
	for _, test := range []struct {
		name string
		want target.Address
		err  error
	}{
		{"malloc", 0x701000, nil},
		{"free", 0x702000, nil},
		{"entry", 0x401000, nil},
		{"local", 0x401100, nil},
		{"libc-id!malloc", 0x701000, nil},
		{"libc.so.6!malloc", 0x701000, nil},
		{"/runtime/libc.so.6!malloc@VER_1", 0x701000, nil},
		{"malloc@VER_2", 0, target.ErrNotFound},
		{"main!malloc", 0, target.ErrUnavailable},
		{"private", 0, target.ErrNotFound},
		{"libc-id!private", 0x703000, nil},
		{"ifunc", 0, target.ErrUnsupported},
		{"tls", 0, target.ErrUnsupported},
		{"Malloc", 0, target.ErrNotFound},
		{"libc!malloc", 0, target.ErrNotFound},
		{"missing!malloc", 0, target.ErrNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			query, err := parseSymbolQuery(test.name)
			if err != nil {
				t.Fatal(err)
			}
			symbol, err := scope.resolve(query)
			if symbol.Address != test.want || !errors.Is(err, test.err) || isSymbolPending(err) {
				t.Fatalf("symbol=%+v error=%v", symbol, err)
			}
		})
	}
}

func TestGlobalSymbolResolutionDoesNotPreferMainOrWeakByGuess(t *testing.T) {
	scope := symbolResolutionFixture()
	scope.modules[0].symbols = append(scope.modules[0].symbols, inspect.Symbol{
		ModuleID: "main", Name: "malloc", Section: 1, Address: 0x402000, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_WEAK,
	})
	if _, err := scope.resolve(symbolQuery{name: "malloc"}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
	symbol, err := scope.resolve(symbolQuery{module: "main", name: "malloc"})
	if err != nil || symbol.Address != 0x402000 {
		t.Fatalf("symbol=%+v error=%v", symbol, err)
	}
	scope.modules[1].symbols = append(scope.modules[1].symbols, inspect.Symbol{
		ModuleID: "libc-id", Name: "free", Section: 1, Address: 0x702100, AddressKnown: true, Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL, Version: "VER_2",
	})
	if _, err := scope.resolve(symbolQuery{name: "free"}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
	symbol, err = scope.resolve(symbolQuery{name: "free", version: "VER_2"})
	if err != nil || symbol.Address != 0x702100 {
		t.Fatalf("symbol=%+v error=%v", symbol, err)
	}
}

func TestGlobalSymbolModuleBasenameAmbiguityIsExplicit(t *testing.T) {
	scope := symbolResolutionFixture()
	other := scope.modules[1]
	other.id, other.path = "other-libc-id", "/other/libc.so.6"
	scope.modules = append(scope.modules, other)
	if _, err := scope.resolve(symbolQuery{module: "libc.so.6", name: "malloc"}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
	if symbol, err := scope.resolve(symbolQuery{module: "libc-id", name: "malloc"}); err != nil || symbol.Address != 0x701000 {
		t.Fatalf("symbol=%+v error=%v", symbol, err)
	}
}

func TestGlobalSymbolPendingRequiresOnlyUnpublishedLoaderEvidence(t *testing.T) {
	pending := &mappedELFPartialError{Err: fmt.Errorf("scope: %w", &runtimeLoaderPendingError{})}
	scope := symbolResolutionFixture()
	scope.err = pending
	if _, err := scope.resolve(symbolQuery{name: "malloc"}); !isSymbolPending(err) || !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
	if symbol, err := scope.resolve(symbolQuery{module: "main", name: "entry"}); err != nil || symbol.Address != 0x401000 {
		t.Fatalf("qualified proven main: symbol=%+v error=%v", symbol, err)
	}
	if symbol, err := scope.resolve(symbolQuery{name: "entry"}); err != nil || symbol.Address != 0x401000 {
		t.Fatalf("unpublished loader invalidated a proven main definition: symbol=%+v error=%v", symbol, err)
	}
	for _, hard := range []error{target.ErrUnavailable, target.ErrUnsupported, target.ErrInvalidArgument, target.ErrAmbiguous, target.ErrStale, context.Canceled} {
		scope.err = &mappedELFPartialError{Err: errors.Join(pending, hard)}
		if _, err := scope.resolve(symbolQuery{name: "malloc"}); isSymbolPending(err) || !errors.Is(err, hard) {
			t.Fatalf("hard failure downgraded to pending: %v", err)
		}
	}
	scope.err = pending
	scope.modules[1].err = target.ErrInvalidArgument
	if _, err := scope.resolve(symbolQuery{name: "malloc"}); isSymbolPending(err) || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestGlobalSymbolExpressionCachesOnlyWithinVerifiedEvaluation(t *testing.T) {
	loads, validations := 0, 0
	resolver := &stoppedSymbolResolver{
		ctx:      context.Background(),
		load:     func() (*stoppedSymbolScope, error) { loads++; return symbolResolutionFixture(), nil },
		validate: func() error { validations++; return nil },
	}
	value, err := inspect.EvalExpression("malloc + free - malloc", expressionResolver{symbols: resolver.Resolve})
	if err != nil || value != 0x702000 || loads != 1 || validations != 2 {
		t.Fatalf("value=%#x loads=%d validations=%d error=%v", value, loads, validations, err)
	}
	resolver.validate = func() error { validations++; return target.ErrStale }
	if _, err := resolver.Resolve("free"); !errors.Is(err, target.ErrStale) || resolver.scope != nil {
		t.Fatal(err)
	}
	before := validations
	resolver.validate = func() error { t.Fatal("invalidated scope was retried"); return nil }
	if _, err := resolver.Resolve("malloc"); !errors.Is(err, target.ErrStale) || loads != 1 || validations != before {
		t.Fatal(err)
	}
	fresh := &stoppedSymbolResolver{ctx: context.Background(), load: resolver.load}
	if _, err := fresh.Resolve("malloc"); err != nil || loads != 2 {
		t.Fatalf("fresh expression reused prior invalid cache: loads=%d error=%v", loads, err)
	}
}

func TestGlobalSymbolInvalidSyntaxAndCancellationAreLazy(t *testing.T) {
	calls := 0
	resolver := &stoppedSymbolResolver{ctx: context.Background(), load: func() (*stoppedSymbolScope, error) { calls++; return symbolResolutionFixture(), nil }}
	for _, name := range []string{"", "!malloc", "main!", "malloc@", "@VER", "malloc@@VER", "a\x00b"} {
		if _, err := resolver.Resolve(name); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%q: %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver.ctx = ctx
	if _, err := resolver.Resolve("malloc"); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("loads=%d error=%v", calls, err)
	}
}
