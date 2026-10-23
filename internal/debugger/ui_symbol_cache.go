package debugger

import (
	"context"
	"errors"
	"slices"
	"sync"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type uiSymbolCacheKey struct {
	process  target.ProcessRef
	sequence uint64
	memory   target.MemoryToken
	thread   target.ThreadToken
}

func newUISymbolCacheKey(snapshot target.Snapshot, thread target.ThreadInfo) uiSymbolCacheKey {
	return uiSymbolCacheKey{snapshot.Process, snapshot.Sequence, snapshot.Memory, thread.Token}
}

type uiSymbolCache struct {
	mu      sync.Mutex
	key     uiSymbolCacheKey
	symbols []inspect.Symbol
	err     error
	ready   bool
}

func (cache *uiSymbolCache) clear() {
	cache.key = uiSymbolCacheKey{}
	cache.symbols = nil
	cache.err = nil
	cache.ready = false
}

func (cache *uiSymbolCache) read(ctx context.Context, key uiSymbolCacheKey, validate func() error, load func() (*stoppedSymbolScope, error)) ([]inspect.Symbol, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if err := contextReady(ctx); err != nil {
		cache.clear()
		return nil, err
	}
	if validate == nil || load == nil {
		cache.clear()
		return nil, target.ErrInvalidArgument
	}
	if cache.ready && cache.key == key {
		if err := errors.Join(validate(), ctx.Err()); err != nil {
			cache.clear()
			return nil, err
		}
		return slices.Clone(cache.symbols), cache.err
	}
	cache.clear()
	scope, err := load()
	if err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	symbols, symbolErr := uiScopeSymbolFacts(scope)
	if err := errors.Join(symbolErr, ctx.Err()); uiDisplayFatal(err) {
		return nil, err
	}
	if scope == nil {
		return nil, symbolErr
	}
	if err := errors.Join(validate(), ctx.Err()); err != nil {
		return nil, errors.Join(symbolErr, err)
	}
	cache.key = key
	cache.symbols = slices.Clone(symbols)
	cache.err = symbolErr
	cache.ready = true
	return slices.Clone(cache.symbols), cache.err
}

func uiScopeSymbolFacts(scope *stoppedSymbolScope) ([]inspect.Symbol, error) {
	if scope == nil {
		return nil, target.ErrUnavailable
	}
	var symbols []inspect.Symbol
	err := errors.Join(scope.err, scope.displayErr)
	for _, module := range scope.modules {
		err = errors.Join(err, module.err)
		if module.err == nil {
			symbols = append(symbols, module.symbols...)
		}
	}
	if uiDisplayFatal(err) {
		return nil, err
	}
	symbols = append(symbols, scope.displaySymbols...)
	return symbols, err
}
