package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"os"

	"fastdbg2/target"
)

func x86DebugAddress(memory *runtimeELFMemory, main *mappedELF) (target.Address, bool, error) {
	var dynamic *elf.Prog
	for _, p := range main.File.Progs {
		if p.Type == elf.PT_DYNAMIC {
			if dynamic != nil {
				return 0, false, target.ErrAmbiguous
			}
			dynamic = p
		}
	}
	if dynamic == nil {
		return 0, false, nil
	}
	if dynamic.Memsz == 0 || dynamic.Memsz%8 != 0 || dynamic.Memsz > maxELFCommandMetadata || dynamic.Vaddr+main.LoadBias > math.MaxUint32 {
		return 0, false, target.ErrInvalidArgument
	}
	data, err := memory.bytes(target.Address(dynamic.Vaddr+main.LoadBias), dynamic.Memsz)
	if err != nil {
		return 0, false, err
	}
	var address target.Address
	found, terminated := false, false
	for offset := 0; offset < len(data); offset += 8 {
		tag := elf.DynTag(inspectionWord(data[offset : offset+4]))
		if tag == elf.DT_NULL {
			terminated = true
			break
		}
		if tag == elf.DT_DEBUG {
			if found {
				return 0, false, target.ErrAmbiguous
			}
			found = true
			address = target.Address(inspectionWord(data[offset+4 : offset+8]))
		}
	}
	if !terminated {
		return 0, false, target.ErrInvalidArgument
	}
	if found && address == 0 {
		return 0, true, &runtimeLoaderPendingError{}
	}
	return address, found, nil
}

func openX86MappedAnchor(proc *stoppedProc, mappings []procMap, address target.Address) (*mappedELF, error) {
	var identity mappedELFIdentity
	found := false
	for _, m := range mappings {
		if address >= m.Start && address < m.End {
			if m.Inode == 0 {
				return nil, target.ErrUnavailable
			}
			identity = elfMapIdentity(m)
			found = true
			break
		}
	}
	if !found {
		return nil, target.ErrUnavailable
	}
	var group []procMap
	for _, m := range mappings {
		if elfMapIdentity(m) == identity {
			group = append(group, m)
		}
	}
	module, err := openMappedELF(proc, group, identity, uint64(os.Getpagesize()))
	if err != nil {
		return nil, err
	}
	if module == nil {
		return nil, target.ErrUnavailable
	}
	if arch, err := nativeELFArchitecture(module.File); err != nil || arch != target.X86 {
		module.Source.Close()
		return nil, target.ErrUnsupported
	}
	return module, nil
}

func x86Auxiliary(proc *stoppedProc) (map[uint64]uint64, error) {
	data, err := proc.readFile("auxv")
	if err != nil {
		return nil, err
	}
	return runtimeAuxiliary(data, 4)
}

func (c *Controller) x86MappedModules(ctx context.Context, snapshot target.Snapshot, proc *stoppedProc, main *mappedELF, mappings []procMap) ([]*mappedELF, error) {
	memory, err := newRuntimeELFMemory(ctx, mappings, func(address target.Address, data []byte) (int, error) {
		return c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	})
	if err != nil {
		return nil, err
	}
	defer memory.close()
	debug, present, debugErr := x86DebugAddress(memory, main)
	if !present {
		if debugErr == nil && x86HasInterpreter(main) {
			debugErr = fmt.Errorf("i386 interpreter has no DT_DEBUG declaration: %w", target.ErrUnavailable)
		}
		return nil, debugErr
	}
	values, err := x86Auxiliary(proc)
	if err != nil {
		return nil, err
	}
	if debugErr != nil {
		if !runtimeELFLoaderPending(debugErr) {
			return nil, debugErr
		}
		if values[7] == 0 || !x86HasInterpreter(main) {
			return nil, errors.Join(debugErr, target.ErrUnsupported)
		}
		interpreter, err := openX86MappedAnchor(proc, mappings, target.Address(values[7]))
		if err != nil {
			return nil, errors.Join(debugErr, err)
		}
		if interpreter.LoadBias != values[7] {
			interpreter.Source.Close()
			return nil, target.ErrStale
		}
		return []*mappedELF{interpreter}, debugErr
	}
	links, err := runtimeELFLinkMaps(memory, debug, 4)
	if err != nil {
		return nil, err
	}
	mainDynamic, err := mappedELFDynamicAddress(main)
	if err != nil {
		return nil, err
	}
	mainSeen := false
	var modules []*mappedELF
	var failures error
	seen := make(map[uint64]target.Address)
	for _, link := range links {
		if link.bias == main.LoadBias && link.dynamic == mainDynamic {
			mainSeen = true
			continue
		}
		if prior, ok := seen[link.bias]; ok {
			if prior != link.dynamic {
				failures = errors.Join(failures, target.ErrAmbiguous)
			}
			continue
		}
		seen[link.bias] = link.dynamic
		if values[33] != 0 && link.bias == values[33] {
			module, err := x86VDSO(memory, target.Address(values[33]), link.dynamic)
			if err != nil {
				failures = errors.Join(failures, err)
			} else {
				modules = append(modules, module)
			}
			continue
		}
		module, err := openX86MappedAnchor(proc, mappings, link.dynamic)
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		dynamic, dynamicErr := mappedELFDynamicAddress(module)
		if dynamicErr != nil || module.LoadBias != link.bias || dynamic != link.dynamic {
			module.Source.Close()
			failures = errors.Join(failures, dynamicErr, target.ErrStale)
			continue
		}
		module.Scope = "loader"
		modules = append(modules, module)
	}
	if !mainSeen {
		failures = errors.Join(failures, fmt.Errorf("main ELF absent from i386 link_map: %w", target.ErrStale))
	}
	return modules, failures
}

func x86VDSO(memory *runtimeELFMemory, address, dynamic target.Address) (*mappedELF, error) {
	var length uint64
	for _, m := range memory.mappings {
		if address == m.Start && m.Inode == 0 {
			length = uint64(m.End - m.Start)
			break
		}
	}
	if length < 52 || length > maxRuntimeELFNotes {
		return nil, target.ErrUnavailable
	}
	data, err := memory.bytes(address, length)
	if err != nil {
		return nil, err
	}
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if file.Class != elf.ELFCLASS32 || file.Machine != elf.EM_386 || file.Data != elf.ELFDATA2LSB || file.Type != elf.ET_DYN {
		return nil, target.ErrUnsupported
	}
	metadata := &runtimeVDSOMetadata{Header: file.FileHeader, LoadBias: uint64(address), SymbolCountSource: "auxv-vdso-ELF32-sections"}
	found := false
	for _, p := range file.Progs {
		if p.Off > length || p.Filesz > length-p.Off {
			return nil, target.ErrInvalidArgument
		}
		metadata.Programs = append(metadata.Programs, p.ProgHeader)
		if p.Type == elf.PT_LOAD {
			if p.Off != p.Vaddr || p.Memsz > length-p.Vaddr {
				return nil, target.ErrUnsupported
			}
			metadata.Loads = append(metadata.Loads, runtimeELFSpan{address + target.Address(p.Vaddr), p.Memsz})
		}
		if p.Type == elf.PT_DYNAMIC {
			if found || address+target.Address(p.Vaddr) != dynamic {
				return nil, target.ErrStale
			}
			found = true
		}
	}
	if !found {
		return nil, target.ErrUnavailable
	}
	for _, section := range file.Sections {
		if section.Type != elf.SHT_NOBITS && (section.Offset > length || section.Size > length-section.Offset) {
			return nil, target.ErrUnavailable
		}
	}
	metadata.Symbols, err = file.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	metadata.Dynamic, err = elfCommandDynamic(file)
	if err != nil {
		return nil, err
	}
	metadata.RelocationsDeclared, err = runtimeVDSORelocations(metadata.Dynamic)
	if err != nil {
		return nil, err
	}
	metadata.SymbolsComplete = true
	return &mappedELF{ID: "[vdso]", Path: "[vdso]", LoadBias: uint64(address), Proof: "auxv-vdso+ELF32-metadata", Scope: "loader", Runtime: metadata}, nil
}

func (c *Controller) x86LoaderRendezvous(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (loaderRendezvousInfo, error) {
	var info loaderRendezvousInfo
	err := c.withStoppedProc(ctx, snapshot, thread, func(proc *stoppedProc) error {
		mappings, err := proc.maps()
		if err != nil {
			return err
		}
		main, err := openMainELF(proc, mappings, uint64(os.Getpagesize()))
		if err != nil {
			return err
		}
		defer main.Source.Close()
		memory, err := newRuntimeELFMemory(ctx, mappings, func(address target.Address, data []byte) (int, error) {
			return c.session.ReadSpaceMemory(snapshot.Memory, address, data)
		})
		if err != nil {
			return err
		}
		defer memory.close()
		address, present, err := x86DebugAddress(memory, main)
		if !present {
			return errors.Join(err, target.ErrUnsupported)
		}
		if err == nil {
			info, err = readLoaderRendezvous(memory, address, 4)
			return err
		}
		if !runtimeELFLoaderPending(err) {
			return err
		}
		values, err := x86Auxiliary(proc)
		if err != nil {
			return err
		}
		if values[7] == 0 || !x86HasInterpreter(main) {
			return target.ErrUnsupported
		}
		interpreter, err := openX86MappedAnchor(proc, mappings, target.Address(values[7]))
		if err != nil {
			return err
		}
		defer interpreter.Source.Close()
		if interpreter.LoadBias != values[7] {
			return target.ErrStale
		}
		runtime := &runtimeELFModule{LoadBias: interpreter.LoadBias}
		for _, p := range interpreter.File.Progs {
			runtime.Programs = append(runtime.Programs, p.ProgHeader)
		}
		facts := readMappedSymbolFacts(ctx, interpreter)
		if facts.err != nil {
			return facts.err
		}
		info.Hook, err = loaderBootstrapHook(memory, runtime, facts.symbols)
		return err
	})
	info.Space = snapshot.Memory.Space
	return info, err
}

func x86HasInterpreter(module *mappedELF) bool {
	for _, p := range module.File.Progs {
		if p.Type == elf.PT_INTERP {
			return true
		}
	}
	return false
}
