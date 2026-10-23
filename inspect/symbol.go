package inspect

import (
	"cmp"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"sync"

	"fastdbg2/target"
)

type Module struct {
	ID       string
	Path     string
	LoadBias uint64
}

type Symbol struct {
	ModuleID     string
	Name         string
	Version      string
	Value        uint64
	Address      target.Address
	AddressKnown bool
	Size         uint64
	Type         elf.SymType
	Binding      elf.SymBind
	Section      elf.SectionIndex
}

type SymbolMatch struct {
	Symbol Symbol
	Offset uint64
}

type AmbiguousSymbolError struct {
	Candidates []Symbol
}

func (e *AmbiguousSymbolError) Error() string {
	return fmt.Sprintf("%v: %d symbol definitions", target.ErrAmbiguous, len(e.Candidates))
}

func (e *AmbiguousSymbolError) Unwrap() error {
	return target.ErrAmbiguous
}

type symbolRecord struct {
	symbol    Symbol
	raw       elf.Symbol
	undefined bool
	err       error
}

type SymbolIndex struct {
	modules map[string]struct{}
	byName  map[string][]int
	records []symbolRecord
}

func LoadSymbols(ctx context.Context, modules []Module, workers int) (*SymbolIndex, error) {
	if ctx == nil || workers < 0 {
		return nil, fmt.Errorf("load symbols: %w", target.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	modules = slices.Clone(modules)
	slices.SortFunc(modules, func(a, b Module) int { return cmp.Compare(a.ID, b.ID) })
	index := &SymbolIndex{
		modules: make(map[string]struct{}, len(modules)),
		byName:  make(map[string][]int),
	}
	for _, module := range modules {
		if module.ID == "" || module.Path == "" {
			return nil, fmt.Errorf("module ID and path are required: %w", target.ErrInvalidArgument)
		}
		if _, exists := index.modules[module.ID]; exists {
			return nil, fmt.Errorf("duplicate module ID %q: %w", module.ID, target.ErrInvalidArgument)
		}
		index.modules[module.ID] = struct{}{}
	}
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, len(modules))
	results := make([][]symbolRecord, len(modules))
	errs := make([]error, len(modules))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i], errs[i] = loadModuleSymbols(ctx, modules[i])
			}
		}()
	}
	for i := range modules {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("module %q: %w", modules[i].ID, err)
		}
		index.records = append(index.records, results[i]...)
	}
	slices.SortFunc(index.records, compareSymbolRecords)
	for i, record := range index.records {
		index.byName[record.symbol.Name] = append(index.byName[record.symbol.Name], i)
	}
	return index, nil
}

func loadModuleSymbols(ctx context.Context, module Module) ([]symbolRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := elf.Open(module.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return nil, fmt.Errorf("ELF type %s: %w", file.Type, target.ErrUnsupported)
	}
	static, staticErr := file.Symbols()
	if staticErr != nil && !errors.Is(staticErr, elf.ErrNoSymbols) {
		return nil, staticErr
	}
	dynamic, dynamicErr := file.DynamicSymbols()
	if dynamicErr != nil && !errors.Is(dynamicErr, elf.ErrNoSymbols) {
		return nil, dynamicErr
	}
	if errors.Is(staticErr, elf.ErrNoSymbols) && errors.Is(dynamicErr, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("ELF symbol tables: %w", target.ErrUnavailable)
	}
	seen := make(map[elf.Symbol]struct{}, len(static)+len(dynamic))
	var records []symbolRecord
	for _, table := range [][]elf.Symbol{static, dynamic} {
		for _, raw := range table {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if raw.Name == "" {
				continue
			}
			if _, exists := seen[raw]; exists {
				continue
			}
			seen[raw] = struct{}{}
			record, err := makeSymbolRecord(module, file, raw)
			if err != nil {
				return nil, fmt.Errorf("symbol %q: %w", raw.Name, err)
			}
			records = append(records, record)
		}
	}
	return records, nil
}

func makeSymbolRecord(module Module, file *elf.File, raw elf.Symbol) (symbolRecord, error) {
	record := symbolRecord{
		symbol: Symbol{
			ModuleID: module.ID,
			Name:     raw.Name,
			Version:  raw.Version,
			Value:    raw.Value,
			Size:     raw.Size,
			Type:     elf.ST_TYPE(raw.Info),
			Binding:  elf.ST_BIND(raw.Info),
			Section:  raw.Section,
		},
		raw: raw,
	}
	if raw.Section == elf.SHN_UNDEF {
		record.undefined = true
		record.err = target.ErrUnavailable
		return record, nil
	}
	switch record.symbol.Type {
	case elf.STT_NOTYPE, elf.STT_OBJECT, elf.STT_FUNC:
	default:
		record.err = target.ErrUnsupported
		return record, nil
	}
	address := raw.Value
	if raw.Section != elf.SHN_ABS {
		if raw.Section >= elf.SHN_LORESERVE {
			record.err = target.ErrUnsupported
			return record, nil
		}
		if int(raw.Section) >= len(file.Sections) {
			return record, fmt.Errorf("invalid section %d: %w", raw.Section, target.ErrInvalidArgument)
		}
		if file.Sections[raw.Section].Flags&elf.SHF_ALLOC == 0 {
			record.err = target.ErrUnsupported
			return record, nil
		}
		if module.LoadBias > math.MaxUint64-address {
			return record, fmt.Errorf("load bias plus symbol value: %w", target.ErrOverflow)
		}
		address += module.LoadBias
	}
	if raw.Size > 0 && raw.Size-1 > math.MaxUint64-address {
		return record, fmt.Errorf("symbol range: %w", target.ErrOverflow)
	}
	record.symbol.Address = target.Address(address)
	record.symbol.AddressKnown = true
	return record, nil
}

func compareSymbolRecords(a, b symbolRecord) int {
	if order := cmp.Or(
		cmp.Compare(a.symbol.ModuleID, b.symbol.ModuleID),
		cmp.Compare(a.symbol.Name, b.symbol.Name),
		cmp.Compare(a.symbol.Version, b.symbol.Version),
		cmp.Compare(a.symbol.Value, b.symbol.Value),
		cmp.Compare(a.symbol.Size, b.symbol.Size),
		cmp.Compare(a.raw.Info, b.raw.Info),
		cmp.Compare(a.raw.Other, b.raw.Other),
		cmp.Compare(a.raw.Section, b.raw.Section),
		cmp.Compare(a.raw.VersionIndex, b.raw.VersionIndex),
		cmp.Compare(a.raw.Library, b.raw.Library),
	); order != 0 {
		return order
	}
	if a.raw.HasVersion == b.raw.HasVersion {
		return 0
	}
	if !a.raw.HasVersion {
		return -1
	}
	return 1
}

func (index *SymbolIndex) checkModule(moduleID string) error {
	if index == nil {
		return target.ErrUnavailable
	}
	if moduleID != "" {
		if _, exists := index.modules[moduleID]; !exists {
			return fmt.Errorf("module %q: %w", moduleID, target.ErrNotFound)
		}
	}
	return nil
}

func (index *SymbolIndex) Symbols(moduleID string) ([]Symbol, error) {
	if err := index.checkModule(moduleID); err != nil {
		return nil, err
	}
	var symbols []Symbol
	for _, record := range index.records {
		if moduleID == "" || record.symbol.ModuleID == moduleID {
			symbols = append(symbols, record.symbol)
		}
	}
	return symbols, nil
}

func (index *SymbolIndex) ResolveName(moduleID, name string) (Symbol, error) {
	if name == "" {
		return Symbol{}, fmt.Errorf("empty symbol name: %w", target.ErrInvalidArgument)
	}
	if err := index.checkModule(moduleID); err != nil {
		return Symbol{}, err
	}
	var matches []symbolRecord
	undefined := false
	for _, i := range index.byName[name] {
		record := index.records[i]
		if moduleID != "" && record.symbol.ModuleID != moduleID {
			continue
		}
		if record.undefined {
			undefined = true
			continue
		}
		matches = append(matches, record)
	}
	if len(matches) == 0 {
		err := target.ErrNotFound
		if undefined {
			err = target.ErrUnavailable
		}
		return Symbol{}, fmt.Errorf("symbol %q in module %q: %w", name, moduleID, err)
	}
	if len(matches) > 1 {
		return Symbol{}, ambiguousSymbols(matches)
	}
	record := matches[0]
	if record.err != nil {
		return record.symbol, fmt.Errorf("symbol %s:%s (%s, %s): %w", record.symbol.ModuleID, name, record.symbol.Type, record.symbol.Section, record.err)
	}
	return record.symbol, nil
}

func (index *SymbolIndex) ResolveAddress(moduleID string, address target.Address) (SymbolMatch, error) {
	if err := index.checkModule(moduleID); err != nil {
		return SymbolMatch{}, err
	}
	var matches []symbolRecord
	for _, record := range index.records {
		symbol := record.symbol
		if !symbol.AddressKnown || (moduleID != "" && symbol.ModuleID != moduleID) {
			continue
		}
		if address == symbol.Address || (address > symbol.Address && uint64(address-symbol.Address) < symbol.Size) {
			matches = append(matches, record)
		}
	}
	if len(matches) == 0 {
		return SymbolMatch{}, fmt.Errorf("address %#x in module %q: %w", address, moduleID, target.ErrNotFound)
	}
	if len(matches) > 1 {
		return SymbolMatch{}, ambiguousSymbols(matches)
	}
	symbol := matches[0].symbol
	return SymbolMatch{Symbol: symbol, Offset: uint64(address - symbol.Address)}, nil
}

func ambiguousSymbols(records []symbolRecord) error {
	candidates := make([]Symbol, len(records))
	for i, record := range records {
		candidates[i] = record.symbol
	}
	return &AmbiguousSymbolError{Candidates: candidates}
}
