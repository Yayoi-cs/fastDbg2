package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"fastdbg2/target"
)

func inspectMappedELFSecurity(module *mappedELF) (elfSecurityFacts, error) {
	if module.Runtime == nil {
		return inspectELFSecurity(module.File)
	}
	metadata := module.Runtime
	if !metadata.SymbolsComplete {
		return elfSecurityFacts{}, target.ErrUnavailable
	}
	dynamic := metadata.Dynamic
	facts := elfSecurityFacts{
		kind: metadata.Header.Type, dynamic: dynamic.present, symbols: true, runtimeOnly: true,
		pieFlag: elfHasDynamicFlag(dynamic, elf.DT_FLAGS_1, uint64(elf.DF_1_PIE)),
		bindNow: len(dynamic.values[elf.DT_BIND_NOW]) != 0 || elfHasDynamicFlag(dynamic, elf.DT_FLAGS, uint64(elf.DF_BIND_NOW)) || elfHasDynamicFlag(dynamic, elf.DT_FLAGS_1, uint64(elf.DF_1_NOW)),
	}
	for _, program := range metadata.Programs {
		switch program.Type {
		case elf.PT_GNU_STACK:
			if facts.stackKnown {
				return elfSecurityFacts{}, target.ErrAmbiguous
			}
			facts.stackKnown, facts.stackExec = true, program.Flags&elf.PF_X != 0
		case elf.PT_GNU_RELRO:
			facts.relro = true
		case elf.PT_LOAD:
			if program.Memsz > math.MaxUint64-program.Vaddr {
				return elfSecurityFacts{}, target.ErrOverflow
			}
			if program.Flags&(elf.PF_R|elf.PF_W|elf.PF_X) == elf.PF_R|elf.PF_W|elf.PF_X {
				facts.rwx = append(facts.rwx, [2]uint64{program.Vaddr, program.Vaddr + program.Memsz})
			}
		}
	}
	for _, symbol := range metadata.Symbols {
		if (symbol.Name == "__stack_chk_fail" || symbol.Name == "__stack_chk_fail_local") && !slices.Contains(facts.canary, symbol.Name) {
			facts.canary = append(facts.canary, symbol.Name)
		}
		if strings.HasPrefix(symbol.Name, "__") && strings.HasSuffix(symbol.Name, "_chk") && !slices.Contains(facts.fortify, symbol.Name) {
			facts.fortify = append(facts.fortify, symbol.Name)
		}
	}
	slices.Sort(facts.canary)
	slices.Sort(facts.fortify)
	return facts, nil
}

func mappedELFPointerRelocations(module *mappedELF) ([]elfPointerRelocation, error) {
	if module.Runtime != nil {
		if !module.Runtime.SymbolsComplete {
			return nil, target.ErrUnavailable
		}
		declared, err := runtimeVDSORelocations(module.Runtime.Dynamic)
		if err != nil {
			return nil, err
		}
		if declared != module.Runtime.RelocationsDeclared || len(module.Runtime.PointerRelocations) != 0 {
			return nil, fmt.Errorf("runtime relocation metadata does not match the supported no-relocation ABI: %w", target.ErrInvalidArgument)
		}
		return slices.Clone(module.Runtime.PointerRelocations), nil
	}
	return elfPointerRelocations(module.File, module.LoadBias)
}

func runtimeStdioObject(module *mappedELF, name string) (target.Address, uint64, error) {
	metadata := module.Runtime
	if !metadata.SymbolsComplete {
		return 0, 0, target.ErrUnavailable
	}
	var matches []elf.Symbol
	for _, symbol := range metadata.Symbols {
		if symbol.Name == name && symbol.Section != elf.SHN_UNDEF && !slices.Contains(matches, symbol) {
			matches = append(matches, symbol)
		}
	}
	if len(matches) == 0 {
		return 0, 0, target.ErrNotFound
	}
	if len(matches) != 1 {
		return 0, 0, target.ErrAmbiguous
	}
	symbol, err := runtimeVDSOSymbol(metadata, module.ID, matches[0])
	if err != nil {
		return 0, 0, err
	}
	if symbol.Type != elf.STT_OBJECT || !symbol.AddressKnown || symbol.Size == 0 || symbol.Size > maxMemoryBytes {
		return 0, 0, fmt.Errorf("runtime symbol %q has no supported declared object extent: %w", name, target.ErrUnsupported)
	}
	return symbol.Address, symbol.Size, nil
}

func readRuntimeSymbolFacts(ctx context.Context, module *mappedELF) moduleSymbolFacts {
	facts := moduleSymbolFacts{id: module.ID, path: module.Path, proof: module.Proof, metadata: mappedELFSourceDescription(module) + "; runtime dynamic symbols only; static symbols and debug metadata unavailable"}
	metadata := module.Runtime
	if !metadata.SymbolsComplete {
		facts.err = target.ErrUnavailable
		return facts
	}
	for _, program := range metadata.Programs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 || program.Memsz == 0 {
			continue
		}
		if program.Vaddr > math.MaxUint64-module.LoadBias || program.Memsz-1 > math.MaxUint64-(program.Vaddr+module.LoadBias) {
			facts.err = target.ErrOverflow
			return facts
		}
		facts.executable = append(facts.executable, executableSymbolRange{target.Address(module.LoadBias + program.Vaddr), program.Memsz})
	}
	for _, raw := range metadata.Symbols {
		if err := contextReady(ctx); err != nil {
			facts.err = err
			return facts
		}
		if raw.Name == "" {
			continue
		}
		symbol, err := runtimeVDSOSymbol(metadata, module.ID, raw)
		if err != nil && !errors.Is(err, target.ErrUnsupported) && !errors.Is(err, target.ErrUnavailable) {
			facts.err = err
			return facts
		}
		facts.symbols = append(facts.symbols, symbol)
	}
	return facts
}
