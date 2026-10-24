package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type symbolPendingError struct {
	Name string
	Err  error
}

func (err *symbolPendingError) Error() string {
	return fmt.Sprintf("symbol %q awaits loader publication: %v", err.Name, err.Err)
}

func (err *symbolPendingError) Unwrap() error { return err.Err }

func (err *symbolPendingError) Is(other error) bool { return other == target.ErrUnavailable }

func isSymbolPending(err error) bool {
	var pending *symbolPendingError
	return errors.As(err, &pending)
}

type stoppedSymbolScope struct {
	modules        []moduleSymbolFacts
	err            error
	displaySymbols []inspect.Symbol
	displayErr     error
}

type stoppedSymbolResolver struct {
	ctx      context.Context
	scope    *stoppedSymbolScope
	err      error
	loaded   bool
	load     func() (*stoppedSymbolScope, error)
	validate func() error
}

type symbolQuery struct {
	module  string
	name    string
	version string
}

func parseSymbolQuery(name string) (symbolQuery, error) {
	query := symbolQuery{name: name}
	if module, symbol, qualified := strings.Cut(name, "!"); qualified {
		if module == "" || symbol == "" {
			return symbolQuery{}, fmt.Errorf("symbol qualifier requires MODULE!NAME: %w", target.ErrInvalidArgument)
		}
		query.module, query.name = module, symbol
	}
	if index := strings.LastIndexByte(query.name, '@'); index >= 0 {
		if index == 0 || index == len(query.name)-1 || query.name[index-1] == '@' {
			return symbolQuery{}, fmt.Errorf("use NAME@VERSION with an exact version: %w", target.ErrInvalidArgument)
		}
		query.name, query.version = query.name[:index], query.name[index+1:]
	}
	if query.name == "" || strings.ContainsRune(name, 0) {
		return symbolQuery{}, target.ErrInvalidArgument
	}
	return query, nil
}

func (c *Controller) newStoppedSymbolResolver(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) *stoppedSymbolResolver {
	return &stoppedSymbolResolver{
		ctx:  ctx,
		load: func() (*stoppedSymbolScope, error) { return c.loadStoppedSymbolScope(ctx, snapshot, thread) },
		validate: func() error {
			if err := contextReady(ctx); err != nil {
				return err
			}
			return c.verifyProcSnapshot(snapshot, thread)
		},
	}
}

func (c *Controller) loadStoppedSymbolScope(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (*stoppedSymbolScope, error) {
	return c.loadStoppedSymbolScopeWithDebug(ctx, snapshot, thread, false)
}

func (c *Controller) loadStoppedSymbolDisplayScope(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (*stoppedSymbolScope, error) {
	return c.loadStoppedSymbolScopeWithDebug(ctx, snapshot, thread, true)
}

func (c *Controller) loadStoppedSymbolScopeWithDebug(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, debug bool) (*stoppedSymbolScope, error) {
	if _, ok := c.session.(*qemuSession); ok {
		return c.kernelScope(ctx, snapshot, thread)
	}
	scope := &stoppedSymbolScope{}
	err := c.withELFModules(ctx, snapshot, thread, elfModuleSelection{All: true}, func(modules []*mappedELF) error {
		for _, module := range modules {
			if err := contextReady(ctx); err != nil {
				return err
			}
			scope.modules = append(scope.modules, readMappedSymbolFacts(ctx, module))
		}
		if debug {
			return c.withStoppedProc(ctx, snapshot, thread, func(proc *stoppedProc) error {
				for i, module := range modules {
					if module.File == nil {
						continue
					}
					symbols, symbolErr := readAssociatedDisplaySymbols(ctx, proc, module, scope.modules[i])
					if uiDisplayFatal(symbolErr) {
						return symbolErr
					}
					scope.displayErr = errors.Join(scope.displayErr, symbolErr)
					scope.displaySymbols = append(scope.displaySymbols, symbols...)
				}
				return nil
			})
		}
		return nil
	})
	if !mappedELFResultUsable(err) {
		return nil, err
	}
	scope.err = err
	return scope, nil
}

func readAssociatedDisplaySymbols(ctx context.Context, proc *stoppedProc, module *mappedELF, facts moduleSymbolFacts) (symbols []inspect.Symbol, err error) {
	debug, err := findELFDebugFile(ctx, proc, module)
	if elfDebugLookupMissing(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("debug symbols for module %q: %w", module.ID, err)
	}
	defer func() {
		err = errors.Join(err, debug.Source.Close(), ctx.Err())
		if err != nil {
			symbols = nil
		}
	}()
	index, err := inspect.LoadSymbols(ctx, []inspect.Module{{ID: module.ID, Path: fmt.Sprintf("/proc/self/fd/%d", debug.Source.Fd()), LoadBias: module.LoadBias}}, 1)
	if err != nil {
		return nil, err
	}
	all, err := index.Symbols(module.ID)
	if err != nil {
		return nil, err
	}
	for _, symbol := range all {
		if !symbol.AddressKnown || symbol.Type != elf.STT_FUNC || symbol.Section == elf.SHN_ABS {
			continue
		}
		contained := false
		for _, span := range facts.executable {
			if span.contains(symbol.Address) && (symbol.Size == 0 || symbol.Size <= span.size-uint64(symbol.Address-span.address)) {
				contained = true
				break
			}
		}
		if !contained {
			return nil, fmt.Errorf("associated debug function %q exceeds module %q executable bounds: %w", symbol.Name, module.ID, target.ErrInvalidArgument)
		}
		symbols = append(symbols, symbol)
	}
	return symbols, nil
}

func (resolver *stoppedSymbolResolver) Resolve(name string) (uint64, error) {
	if err := contextReady(resolver.ctx); err != nil {
		return 0, err
	}
	query, err := parseSymbolQuery(name)
	if err != nil {
		return 0, err
	}
	if resolver.loaded && resolver.err != nil {
		return 0, resolver.err
	}
	if !resolver.loaded {
		resolver.loaded = true
		if resolver.load == nil {
			return 0, target.ErrUnavailable
		}
		resolver.scope, resolver.err = resolver.load()
	} else if resolver.validate != nil {
		if err := resolver.validate(); err != nil {
			resolver.scope, resolver.err = nil, err
			return 0, err
		}
	}
	if resolver.err != nil {
		return 0, resolver.err
	}
	if resolver.scope == nil {
		return 0, target.ErrUnavailable
	}
	if err := contextReady(resolver.ctx); err != nil {
		return 0, err
	}
	symbol, err := resolver.scope.resolve(query)
	return uint64(symbol.Address), err
}

func (scope *stoppedSymbolScope) selectedModules(query symbolQuery) ([]moduleSymbolFacts, bool, error) {
	if query.module == "" {
		return scope.modules, false, nil
	}
	var matches []moduleSymbolFacts
	for _, module := range scope.modules {
		if module.id == query.module {
			matches = append(matches, module)
		}
	}
	canonical := len(matches) != 0
	if !canonical {
		for _, module := range scope.modules {
			if module.path == query.module || filepath.Base(module.path) == query.module {
				matches = append(matches, module)
			}
		}
	}
	if len(matches) > 1 {
		return nil, false, fmt.Errorf("module %q matches %d loaded images: %w", query.module, len(matches), target.ErrAmbiguous)
	}
	if len(matches) == 0 {
		if scope.err != nil {
			return nil, false, scope.resolutionScopeError(query.name)
		}
		return nil, false, fmt.Errorf("loaded module %q: %w", query.module, target.ErrNotFound)
	}
	return matches, canonical, nil
}

func (scope *stoppedSymbolScope) resolutionScopeError(name string) error {
	if onlyLoaderPublicationPending(scope.err) {
		return &symbolPendingError{Name: name, Err: scope.err}
	}
	return fmt.Errorf("loaded symbol scope is incomplete: %w", errors.Join(target.ErrUnavailable, scope.err))
}

func (scope *stoppedSymbolScope) resolve(query symbolQuery) (inspect.Symbol, error) {
	modules, canonical, err := scope.selectedModules(query)
	if err != nil {
		return inspect.Symbol{}, err
	}
	var metadataErr error
	for _, module := range modules {
		metadataErr = errors.Join(metadataErr, module.err)
	}
	if metadataErr != nil {
		return inspect.Symbol{}, fmt.Errorf("symbol metadata is unavailable: %w", errors.Join(target.ErrUnavailable, metadataErr))
	}
	pendingScope := onlyLoaderPublicationPending(scope.err)
	if scope.err != nil && !canonical && !pendingScope {
		return inspect.Symbol{}, scope.resolutionScopeError(query.name)
	}
	var candidates []inspect.Symbol
	undefined := false
	for _, module := range modules {
		for _, symbol := range module.symbols {
			if symbol.Name != query.name || query.version != "" && symbol.Version != query.version {
				continue
			}
			if symbol.Section == elf.SHN_UNDEF {
				undefined = true
				continue
			}
			if query.module == "" && module.id != "main" && symbol.Binding == elf.STB_LOCAL {
				continue
			}
			if query.module == "" && symbol.Binding != elf.STB_LOCAL && symbol.Binding != elf.STB_GLOBAL && symbol.Binding != elf.STB_WEAK && symbol.Binding != elf.SymBind(10) {
				continue
			}
			duplicate := false
			for _, previous := range candidates {
				if symbol.AddressKnown && previous.AddressKnown && symbol.Address == previous.Address {
					duplicate = true
					break
				}
			}
			if !duplicate {
				candidates = append(candidates, symbol)
			}
		}
	}
	if len(candidates) == 0 {
		if pendingScope && !canonical {
			return inspect.Symbol{}, scope.resolutionScopeError(query.name)
		}
		cause := target.ErrNotFound
		if undefined {
			cause = target.ErrUnavailable
		}
		return inspect.Symbol{}, fmt.Errorf("defined symbol %q in loaded scope: %w", query.name, cause)
	}
	if len(candidates) > 1 {
		var locations []string
		for _, symbol := range candidates[:min(16, len(candidates))] {
			locations = append(locations, fmt.Sprintf("%q value=%#x address=%#x known=%t binding=%s version=%q", symbol.ModuleID+"!"+symbol.Name, symbol.Value, symbol.Address, symbol.AddressKnown, symbol.Binding, symbol.Version))
		}
		return inspect.Symbol{}, fmt.Errorf("symbol %q has %d distinct definitions; use a backtick-quoted MODULE!NAME or NAME@VERSION: %s: %w", query.name, len(candidates), strings.Join(locations, "; "), target.ErrAmbiguous)
	}
	symbol := candidates[0]
	if !symbol.AddressKnown {
		cause := target.ErrUnavailable
		if symbol.Type == elf.STT_GNU_IFUNC || symbol.Type == elf.STT_TLS || symbol.Section >= elf.SHN_LORESERVE && symbol.Section != elf.SHN_ABS {
			cause = target.ErrUnsupported
		}
		return inspect.Symbol{}, fmt.Errorf("symbol %q (%s) has no supported runtime address: %w", query.name, symbol.Type, cause)
	}
	if pendingScope && !canonical && symbol.ModuleID != "main" {
		return inspect.Symbol{}, scope.resolutionScopeError(query.name)
	}
	return symbol, nil
}

func onlyLoaderPublicationPending(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*runtimeLoaderPendingError); ok {
		return true
	}
	if multiple, ok := err.(interface{ Unwrap() []error }); ok {
		found := false
		for _, child := range multiple.Unwrap() {
			if child == nil {
				continue
			}
			if !onlyLoaderPublicationPending(child) {
				return false
			}
			found = true
		}
		return found
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyLoaderPublicationPending(wrapped.Unwrap())
	}
	return false
}
