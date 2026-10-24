package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type loaderRendezvousInfo struct {
	Space      target.SpaceRef
	Hook       target.Address
	Debug      target.Address
	Published  bool
	Consistent bool
}

func (c *Controller) loaderRendezvous(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (loaderRendezvousInfo, error) {
	if snapshot.Architecture == target.X86 {
		return c.x86LoaderRendezvous(ctx, snapshot, thread)
	}
	var info loaderRendezvousInfo
	err := c.withStoppedProc(ctx, snapshot, thread, func(proc *stoppedProc) (err error) {
		mappings, err := proc.maps()
		if err != nil {
			return err
		}
		auxv, err := proc.readFile("auxv")
		if err != nil {
			return err
		}
		values, err := runtimeAuxiliary(auxv)
		if err != nil {
			return err
		}
		source, err := openMainELF(proc, mappings, uint64(os.Getpagesize()))
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, source.Source.Close()) }()
		memory, err := newRuntimeELFMemory(ctx, mappings, func(address target.Address, data []byte) (int, error) {
			return c.session.ReadSpaceMemory(snapshot.Memory, address, data)
		})
		if err != nil {
			return err
		}
		defer memory.close()
		main, err := runtimeELFMainWithSource(memory, values, source)
		if err != nil {
			return err
		}
		if main.Dynamic.Size == 0 {
			return fmt.Errorf("main image has no loader rendezvous declaration: %w", target.ErrUnsupported)
		}
		debug, present, err := runtimeELFDebugEntry(memory, main.Dynamic)
		if err != nil {
			return err
		}
		if !present {
			return fmt.Errorf("main image has no DT_DEBUG declaration: %w", target.ErrUnsupported)
		}
		if debug != 0 {
			info, err = readLoaderRendezvous(memory, debug)
			return err
		}
		if values[7] == 0 || !slices.ContainsFunc(main.Programs, func(program elf.ProgHeader) bool { return program.Type == elf.PT_INTERP }) {
			return fmt.Errorf("loader bootstrap requires a declared interpreter and exact AT_BASE: %w", target.ErrUnsupported)
		}
		interpreter, err := runtimeELFZeroOrigin(memory, target.Address(values[7]), nil)
		if err != nil {
			return err
		}
		module, err := openRuntimeMappedELF(proc, interpreter)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, module.Source.Close()) }()
		facts := readMappedSymbolFacts(ctx, module)
		if facts.err != nil {
			return facts.err
		}
		info.Hook, err = loaderBootstrapHook(memory, interpreter, facts.symbols)
		return err
	})
	if err != nil {
		return loaderRendezvousInfo{}, err
	}
	info.Space = snapshot.Memory.Space
	return info, nil
}

func loaderBootstrapHook(memory *runtimeELFMemory, interpreter *runtimeELFModule, symbols []inspect.Symbol) (target.Address, error) {
	if memory == nil || interpreter == nil {
		return 0, target.ErrInvalidArgument
	}
	var matches []inspect.Symbol
	for _, symbol := range symbols {
		if symbol.Name != "_dl_debug_state" || symbol.Version != "GLIBC_PRIVATE" {
			continue
		}
		if symbol.Type != elf.STT_FUNC || symbol.Binding != elf.STB_GLOBAL || !symbol.AddressKnown || symbol.Section == elf.SHN_UNDEF || symbol.Section >= elf.SHN_LORESERVE || symbol.Size == 0 {
			return 0, fmt.Errorf("loader bootstrap symbol is not a defined global function: %w", target.ErrUnsupported)
		}
		if !slices.Contains(matches, symbol) {
			matches = append(matches, symbol)
		}
	}
	if len(matches) == 0 {
		return 0, fmt.Errorf("verified interpreter has no _dl_debug_state@GLIBC_PRIVATE bootstrap hook: %w", target.ErrUnsupported)
	}
	if len(matches) != 1 {
		return 0, fmt.Errorf("multiple loader bootstrap hook definitions: %w", target.ErrAmbiguous)
	}
	symbol := matches[0]
	if interpreter.LoadBias > math.MaxUint64-symbol.Value || target.Address(interpreter.LoadBias+symbol.Value) != symbol.Address {
		return 0, fmt.Errorf("loader bootstrap symbol coordinate mismatch: %w", target.ErrInvalidArgument)
	}
	executable := false
	for _, program := range interpreter.Programs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 || symbol.Value < program.Vaddr || symbol.Value-program.Vaddr > program.Memsz {
			continue
		}
		if symbol.Size <= program.Memsz-(symbol.Value-program.Vaddr) {
			executable = true
		}
	}
	if !executable {
		return 0, fmt.Errorf("loader bootstrap function is outside interpreter executable PT_LOAD: %w", target.ErrUnsupported)
	}
	if err := loaderExecutable(memory, symbol.Address, symbol.Size); err != nil {
		return 0, err
	}
	return symbol.Address, nil
}

func loaderExecutable(memory *runtimeELFMemory, address target.Address, size uint64) error {
	if memory == nil || size == 0 || size > math.MaxUint64-uint64(address) {
		return target.ErrInvalidArgument
	}
	if err := memory.covers(address, size, true); err != nil {
		return err
	}
	end := address + target.Address(size)
	index := sort.Search(len(memory.mappings), func(index int) bool { return memory.mappings[index].End > address })
	for address < end {
		mapping := memory.mappings[index]
		if !mapping.Execute {
			return fmt.Errorf("loader rendezvous hook is not executable: %w", target.ErrUnsupported)
		}
		address = min(end, mapping.End)
		index++
	}
	return nil
}

func readLoaderRendezvous(memory *runtimeELFMemory, address target.Address, widths ...int) (loaderRendezvousInfo, error) {
	word := 8
	if len(widths) > 0 {
		word = widths[0]
	}
	if word != 4 && word != 8 {
		return loaderRendezvousInfo{}, target.ErrInvalidArgument
	}
	info := loaderRendezvousInfo{Debug: address, Published: true, Consistent: true}
	if memory == nil || address == 0 {
		return loaderRendezvousInfo{}, target.ErrInvalidArgument
	}
	seen := make(map[target.Address]bool)
	var witnesses []runtimeELFWitness
	for address != 0 {
		if seen[address] {
			return loaderRendezvousInfo{}, fmt.Errorf("cyclic loader rendezvous namespace chain: %w", target.ErrInvalidArgument)
		}
		if len(seen) == maxRuntimeELFNamespaces {
			return loaderRendezvousInfo{}, fmt.Errorf("loader rendezvous namespace limit: %w", target.ErrOverflow)
		}
		seen[address] = true
		data, err := memory.bytes(address, uint64(word*5))
		if err != nil {
			return loaderRendezvousInfo{}, err
		}
		version := binary.LittleEndian.Uint32(data)
		if version != 1 && version != 2 {
			return loaderRendezvousInfo{}, fmt.Errorf("loader rendezvous version %d: %w", version, target.ErrUnsupported)
		}
		state := binary.LittleEndian.Uint32(data[3*word:])
		if state > 2 {
			return loaderRendezvousInfo{}, fmt.Errorf("unknown loader rendezvous state %d: %w", state, target.ErrInvalidArgument)
		}
		info.Consistent = info.Consistent && state == 0
		hook := target.Address(inspectionWord(data[2*word : 3*word]))
		if hook == 0 {
			return loaderRendezvousInfo{}, fmt.Errorf("published loader rendezvous has no r_brk: %w", target.ErrUnavailable)
		}
		if info.Hook != 0 && info.Hook != hook {
			return loaderRendezvousInfo{}, fmt.Errorf("loader namespaces require distinct rendezvous hooks: %w", target.ErrUnsupported)
		}
		if err := loaderExecutable(memory, hook, 1); err != nil {
			return loaderRendezvousInfo{}, err
		}
		info.Hook = hook
		next := target.Address(0)
		if version == 2 {
			if uint64(address) > math.MaxUint64-uint64(word*5) {
				return loaderRendezvousInfo{}, target.ErrOverflow
			}
			tail, err := memory.bytes(address+target.Address(word*5), uint64(word))
			if err != nil {
				return loaderRendezvousInfo{}, err
			}
			data = append(data, tail...)
			next = target.Address(inspectionWord(tail))
		}
		witnesses = append(witnesses, runtimeELFWitness{address, data})
		address = next
	}
	for _, witness := range witnesses {
		current, err := memory.bytes(witness.address, uint64(len(witness.data)))
		if err != nil {
			return loaderRendezvousInfo{}, err
		}
		if !bytes.Equal(current, witness.data) {
			return loaderRendezvousInfo{}, fmt.Errorf("loader rendezvous changed while reading: %w", target.ErrStale)
		}
	}
	return info, nil
}
