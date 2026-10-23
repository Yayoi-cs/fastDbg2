package debugger

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fastdbg2/inspect"
	"fastdbg2/target"
	"fmt"
	"math"
	"os"
	"slices"
)

type allocatorParameters struct {
	SbrkBase        target.Address
	TcacheSmallBins uint64
	TcacheMaxBytes  uint64
	TcacheCount     uint64
	HPPageSize      uint64
}

type allocatorHeapExtent struct {
	Base              target.Address
	Start             target.Address
	End               target.Address
	Top               target.Address
	Arena             target.Address
	TerminalFencepost target.Address
	Label             string
}

type allocatorContext struct {
	Layout              inspect.HeapLayout
	MallocPar           inspect.HeapRecord
	HeapInfo            inspect.HeapRecord
	MainArena           target.Address
	ThreadArena         target.Address
	Tcache              target.Address
	TcacheState         string
	Parameters          allocatorParameters
	Alignment           uint64
	MinChunkSize        uint64
	ChunkHeaderSize     uint64
	SizeFlags           uint64
	HeapMaxSize         uint64
	TcacheSmallBinCount uint64
	TcacheLargeBinCount uint64
	SmallBinCount       uint64
	NormalBinCount      uint64
	FastBinShift        uint64
	Semantics           allocatorSemantics
	ModuleID            string
	ModulePath          string
	Proof               string
	LibcBuildID         string
	LoaderBuildID       string
	ThreadRef           target.ThreadRef
	TID                 int
	memory              *runtimeELFMemory
}

func (c *Controller) withAllocatorContext(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, visit func(*allocatorContext) error) error {
	if visit == nil {
		return target.ErrInvalidArgument
	}
	return c.withStoppedProc(ctx, snapshot, thread, func(proc *stoppedProc) (err error) {
		mappings, err := proc.maps()
		if err != nil {
			return err
		}
		main, err := openMainELF(proc, mappings, uint64(os.Getpagesize()))
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, main.Source.Close()) }()
		view, err := c.runtimeELFModulesWithMain(ctx, snapshot, proc, main)
		if view != nil {
			defer view.Memory.close()
		}
		if err != nil {
			return err
		}
		if view == nil || !view.LoaderComplete {
			return fmt.Errorf("allocator discovery requires a consistent published loader: %w", target.ErrUnavailable)
		}
		profile, libc, loader, err := selectAllocatorProfileWithRegistry(ctx, view)
		if err != nil {
			return err
		}
		libcSource, err := openRuntimeMappedELF(proc, libc)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, libcSource.Source.Close()) }()
		loaderSource, err := openRuntimeMappedELF(proc, loader)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, loaderSource.Source.Close()) }()
		registers, err := c.session.ReadThreadRegisters(thread.Token)
		if err != nil {
			return err
		}
		info, err := collectAllocatorContext(view.Memory, profile, libc, loader, thread, registers)
		if err != nil {
			return err
		}
		info.ModuleID, info.ModulePath = libcSource.ID, libcSource.Path
		info.Proof = fmt.Sprintf("exact-build-profile=%q source=%q libc=%s loader=%s; allocator=%q; module-proof=%s; loader-proof=%s; selected-thread-TLS", profile.Name, profile.SourceRevision, profile.LibcBuildID, profile.LoaderBuildID, libcSource.Path, libcSource.Proof, loaderSource.Proof)
		return visit(info)
	})
}

func selectAllocatorProfile(view *runtimeELFView) (allocatorProfile, *runtimeELFModule, *runtimeELFModule, error) {
	return selectAllocatorProfileWithRegistry(context.Background(), view)
}

func selectAllocatorProfileWithRegistry(ctx context.Context, view *runtimeELFView) (allocatorProfile, *runtimeELFModule, *runtimeELFModule, error) {
	if view == nil || ctx == nil {
		return allocatorProfile{}, nil, nil, target.ErrInvalidArgument
	}
	profiles, err := knownAllocatorProfiles()
	if err != nil {
		return allocatorProfile{}, nil, nil, err
	}
	var loader *runtimeELFModule
	for _, module := range view.Modules {
		if module.AuxiliaryTag != 7 || module.AuxiliaryAddress == 0 || module.Header != module.AuxiliaryAddress {
			continue
		}
		if loader != nil {
			return allocatorProfile{}, nil, nil, fmt.Errorf("multiple exact interpreter anchors: %w", target.ErrAmbiguous)
		}
		loader = module
	}
	if loader == nil || loader.BuildIDErr != nil || len(loader.BuildID) < 16 || len(loader.BuildID) > 128 {
		return allocatorProfile{}, nil, nil, fmt.Errorf("allocator TLS requires an exact interpreter build ID: %w", target.ErrUnsupported)
	}
	loaderID := hex.EncodeToString(loader.BuildID)
	var selected *runtimeELFModule
	var selectedProfile allocatorProfile
	for _, module := range view.Modules {
		if module.BuildIDErr != nil || len(module.BuildID) < 16 || len(module.BuildID) > 128 {
			continue
		}
		id := hex.EncodeToString(module.BuildID)
		var candidate *allocatorProfile
		for _, profile := range profiles {
			if profile.LibcBuildID != id || profile.LoaderBuildID != loaderID {
				continue
			}
			copy := profile
			candidate = &copy
		}
		if candidate == nil {
			loaded, err := loadAllocatorRegistryProfile(ctx, id, loaderID)
			if err != nil && !errors.Is(err, target.ErrNotFound) {
				return allocatorProfile{}, nil, nil, err
			}
			candidate = loaded
		}
		if candidate != nil {
			if selected != nil {
				return allocatorProfile{}, nil, nil, fmt.Errorf("multiple matching allocator instances or namespaces; select an explicit allocator: %w", target.ErrAmbiguous)
			}
			selected, selectedProfile = module, *candidate
		}
	}
	if selected == nil {
		return allocatorProfile{}, nil, nil, fmt.Errorf("loaded allocator/interpreter build IDs have no verified automatic profile (interpreter %s); offsets are not inferred: %w", loaderID, target.ErrUnsupported)
	}
	if len(selected.Links) != 1 {
		return allocatorProfile{}, nil, nil, fmt.Errorf("allocator TLS module identity is not unique: %w", target.ErrAmbiguous)
	}
	return selectedProfile, selected, loader, nil
}

func allocatorObjectAddress(memory *runtimeELFMemory, module *runtimeELFModule, symbol allocatorSymbol) (target.Address, error) {
	if symbol.Type != uint64(elf.STT_OBJECT) || symbol.Size == 0 || symbol.Value > math.MaxUint64-module.LoadBias {
		return 0, target.ErrInvalidArgument
	}
	address := target.Address(module.LoadBias + symbol.Value)
	if !runtimeELFLoaded(module, address, symbol.Size) {
		return 0, fmt.Errorf("profile object is outside its verified module: %w", target.ErrInvalidArgument)
	}
	if err := memory.covers(address, symbol.Size, true); err != nil {
		return 0, err
	}
	return address, nil
}

func collectAllocatorContext(memory *runtimeELFMemory, profile allocatorProfile, libc, loader *runtimeELFModule, thread target.ThreadInfo, registers []target.Register) (*allocatorContext, error) {
	mainArena, err := allocatorObjectAddress(memory, libc, profile.Symbols["main_arena"])
	if err != nil {
		return nil, err
	}
	parameters, err := allocatorObjectAddress(memory, libc, profile.Symbols["mp_"])
	if err != nil {
		return nil, err
	}
	data, err := memory.bytes(parameters, profile.MallocPar.Size)
	if err != nil {
		return nil, err
	}
	values := make(map[string]uint64)
	for _, name := range []string{"sbrk_base", profile.Semantics.TcacheSmallBinsField, "tcache_max_bytes", "tcache_count"} {
		values[name], err = allocatorFieldValue(data, profile.MallocPar, name)
		if err != nil {
			return nil, err
		}
	}
	if values[profile.Semantics.TcacheSmallBinsField] > profile.Constants.TcacheSmallBinCount || values["tcache_count"] > math.MaxUint16 {
		return nil, fmt.Errorf("allocator tunables exceed the exact profile field bounds: %w", target.ErrInvalidArgument)
	}
	if _, exists := profile.MallocPar.Fields["hp_pagesize"]; exists {
		values["hp_pagesize"], err = allocatorFieldValue(data, profile.MallocPar, "hp_pagesize")
		if err != nil {
			return nil, err
		}
	}
	heapMax := profile.Constants.HeapMaxSize
	if profile.Semantics.HeapMaxMode == "huge-pages-times-four" && values["hp_pagesize"] != 0 {
		if values["hp_pagesize"] > math.MaxUint64/4 {
			return nil, target.ErrOverflow
		}
		heapMax = values["hp_pagesize"] * 4
		if heapMax == 0 || heapMax&(heapMax-1) != 0 || heapMax < profile.HeapInfo.Size {
			return nil, fmt.Errorf("huge-page heap maximum is invalid: %w", target.ErrInvalidArgument)
		}
	}
	tls, err := allocatorTLSBase(memory, profile, libc, loader, thread, registers)
	if err != nil {
		return nil, err
	}
	threadArena, err := allocatorTLSVariable(memory, libc, tls, profile.Symbols["thread_arena"])
	if err != nil {
		return nil, err
	}
	tcache, err := allocatorTLSVariable(memory, libc, tls, profile.Symbols["tcache"])
	if err != nil {
		return nil, err
	}
	state := "active"
	if profile.Semantics.TcacheStateMode == "dummy" {
		dummy, err := allocatorObjectAddress(memory, libc, profile.Symbols["__tcache_dummy"])
		if err != nil {
			return nil, err
		}
		inactive, err := allocatorAddress(dummy, profile.DummyInactiveOffset)
		if err != nil {
			return nil, err
		}
		disabled, err := allocatorAddress(dummy, profile.DummyDisabledOffset)
		if err != nil {
			return nil, err
		}
		switch tcache {
		case 0:
			state = "null"
		case inactive:
			state = "inactive"
		case disabled:
			state = "disabled"
		}
	} else {
		shutdown, err := allocatorTLSScalar(memory, libc, tls, profile.Symbols["tcache_shutting_down"])
		if err != nil {
			return nil, err
		}
		if shutdown > 1 {
			return nil, fmt.Errorf("tcache shutdown flag is not a boolean: %w", target.ErrInvalidArgument)
		}
		if tcache == 0 {
			state = "inactive"
			if shutdown != 0 {
				state = "disabled"
			}
		} else if shutdown != 0 {
			state = "shutting-down"
		}
	}
	if state == "active" {
		if err := memory.covers(tcache, profile.Layout.Tcache.Size, true); err != nil {
			return nil, err
		}
	}
	constants := profile.Constants
	return &allocatorContext{
		Layout: cloneAllocatorLayout(profile.Layout), MallocPar: cloneAllocatorRecord(profile.MallocPar), HeapInfo: cloneAllocatorRecord(profile.HeapInfo),
		MainArena: mainArena, ThreadArena: threadArena, Tcache: tcache, TcacheState: state,
		Parameters: allocatorParameters{SbrkBase: target.Address(values["sbrk_base"]), TcacheSmallBins: values[profile.Semantics.TcacheSmallBinsField], TcacheMaxBytes: values["tcache_max_bytes"], TcacheCount: values["tcache_count"], HPPageSize: values["hp_pagesize"]},
		Alignment:  constants.Alignment, MinChunkSize: constants.MinChunkSize, ChunkHeaderSize: constants.ChunkHeaderSize, SizeFlags: constants.SizeFlags,
		HeapMaxSize: heapMax, TcacheSmallBinCount: constants.TcacheSmallBinCount, TcacheLargeBinCount: constants.TcacheLargeBinCount,
		SmallBinCount: constants.SmallBinCount, NormalBinCount: constants.NormalBinCount, FastBinShift: constants.FastBinShift, Semantics: profile.Semantics,
		LibcBuildID: profile.LibcBuildID, LoaderBuildID: profile.LoaderBuildID, ThreadRef: thread.Ref, TID: thread.TID, memory: memory,
	}, nil
}

func allocatorFieldValue(data []byte, record inspect.HeapRecord, name string) (uint64, error) {
	field, ok := record.Fields[name]
	if !ok || field.Count != 1 || field.Width == 0 || field.Width > 8 || field.Offset > uint64(len(data)) || field.Width > uint64(len(data))-field.Offset {
		return 0, fmt.Errorf("allocator record field %q is unavailable or invalid: %w", name, target.ErrInvalidArgument)
	}
	var value uint64
	for index, part := range data[field.Offset : field.Offset+field.Width] {
		value |= uint64(part) << (8 * index)
	}
	return value, nil
}

func allocatorAddress(address target.Address, offset uint64) (target.Address, error) {
	if offset > math.MaxUint64-uint64(address) {
		return 0, target.ErrOverflow
	}
	return address + target.Address(offset), nil
}

func allocatorReadWord(memory *runtimeELFMemory, address target.Address, offset uint64, size uint64) (uint64, error) {
	actual, err := allocatorAddress(address, offset)
	if err != nil {
		return 0, err
	}
	data, err := memory.bytes(actual, size)
	if err != nil {
		return 0, err
	}
	if size == 8 {
		return binary.LittleEndian.Uint64(data), nil
	}
	if size == 4 {
		return uint64(binary.LittleEndian.Uint32(data)), nil
	}
	if size == 1 {
		return uint64(data[0]), nil
	}
	return 0, target.ErrInvalidArgument
}

func allocatorTLSProgram(module *runtimeELFModule) (elf.ProgHeader, error) {
	var result elf.ProgHeader
	found := false
	for _, program := range module.Programs {
		if program.Type != elf.PT_TLS {
			continue
		}
		if found || program.Memsz == 0 || program.Filesz > program.Memsz {
			return elf.ProgHeader{}, fmt.Errorf("allocator PT_TLS is not unique and valid: %w", target.ErrInvalidArgument)
		}
		result, found = program, true
	}
	if !found {
		return elf.ProgHeader{}, fmt.Errorf("allocator has no PT_TLS: %w", target.ErrUnavailable)
	}
	return result, nil
}

func allocatorTLSVariable(memory *runtimeELFMemory, module *runtimeELFModule, base target.Address, symbol allocatorSymbol) (target.Address, error) {
	if symbol.Size != 8 {
		return 0, target.ErrInvalidArgument
	}
	value, err := allocatorTLSScalar(memory, module, base, symbol)
	return target.Address(value), err
}

func allocatorTLSScalar(memory *runtimeELFMemory, module *runtimeELFModule, base target.Address, symbol allocatorSymbol) (uint64, error) {
	program, err := allocatorTLSProgram(module)
	if err != nil {
		return 0, err
	}
	if symbol.Type != uint64(elf.STT_TLS) || symbol.Size != 8 && symbol.Size != 1 || symbol.Value > program.Memsz || symbol.Size > program.Memsz-symbol.Value {
		return 0, fmt.Errorf("allocator variable has no exact TLS extent: %w", target.ErrInvalidArgument)
	}
	return allocatorReadWord(memory, base, symbol.Value, symbol.Size)
}

func allocatorTLSBase(memory *runtimeELFMemory, profile allocatorProfile, libc, loader *runtimeELFModule, thread target.ThreadInfo, registers []target.Register) (target.Address, error) {
	if len(libc.Links) != 1 {
		return 0, target.ErrAmbiguous
	}
	fsbase, err := (expressionResolver{registers: registers}).ResolveRegister("fs_base")
	if err != nil {
		return 0, err
	}
	if fsbase == 0 {
		return 0, fmt.Errorf("selected thread TLS is not initialized: %w", target.ErrUnavailable)
	}
	pd := target.Address(fsbase)
	tls := profile.TLS
	for _, offset := range []uint64{tls.ThreadSelfOffset, tls.ThreadTCBOffset} {
		value, err := allocatorReadWord(memory, pd, offset, 8)
		if err != nil {
			return 0, err
		}
		if value != fsbase {
			return 0, fmt.Errorf("selected FS_BASE does not identify the exact profiled TCB: %w", target.ErrInvalidArgument)
		}
	}
	tid, err := allocatorReadWord(memory, pd, tls.ThreadTIDOffset, 4)
	if err != nil {
		return 0, err
	}
	if tid != uint64(thread.TID) {
		return 0, fmt.Errorf("selected TCB tid %d differs from thread %d: %w", tid, thread.TID, target.ErrStale)
	}
	link := libc.Links[0].Address
	modid, err := allocatorReadWord(memory, link, tls.LinkMapModIDOffset, 8)
	if err != nil {
		return 0, err
	}
	if modid == 0 || modid > 1<<20 {
		return 0, fmt.Errorf("allocator TLS module ID is zero or exceeds inspection limit: %w", target.ErrUnavailable)
	}
	program, err := allocatorTLSProgram(libc)
	if err != nil {
		return 0, err
	}
	blockSize, err := allocatorReadWord(memory, link, tls.LinkMapBlockSizeOffset, 8)
	if err != nil {
		return 0, err
	}
	if blockSize != program.Memsz {
		return 0, fmt.Errorf("loader TLS block size differs from allocator PT_TLS: %w", target.ErrInvalidArgument)
	}
	global, err := allocatorObjectAddress(memory, loader, profile.Symbols["_rtld_global"])
	if err != nil {
		return 0, err
	}
	globalGeneration, err := allocatorReadWord(memory, global, tls.RTLDGenerationOffset, 8)
	if err != nil {
		return 0, err
	}
	head, err := allocatorReadWord(memory, global, tls.RTLDSlotInfoOffset, 8)
	if err != nil {
		return 0, err
	}
	slot, err := allocatorTLSSlot(memory, tls, target.Address(head), modid)
	if err != nil {
		return 0, err
	}
	mapAddress, err := allocatorReadWord(memory, slot, tls.SlotMapOffset, 8)
	if err != nil {
		return 0, err
	}
	if target.Address(mapAddress) != link {
		return 0, fmt.Errorf("TLS slotinfo module differs from exact allocator link_map: %w", target.ErrStale)
	}
	moduleGeneration, err := allocatorReadWord(memory, slot, tls.SlotGenerationOffset, 8)
	if err != nil {
		return 0, err
	}
	dtv, err := allocatorReadWord(memory, pd, tls.ThreadDTVOffset, 8)
	if err != nil {
		return 0, err
	}
	if dtv < tls.DTVEntrySize {
		return 0, fmt.Errorf("selected thread DTV is not initialized: %w", target.ErrUnavailable)
	}
	dtvGeneration, err := allocatorReadWord(memory, target.Address(dtv), tls.DTVGenerationOffset, 8)
	if err != nil {
		return 0, err
	}
	if moduleGeneration > globalGeneration || dtvGeneration > globalGeneration {
		return 0, fmt.Errorf("TLS generation metadata is inconsistent: %w", target.ErrInvalidArgument)
	}
	staticOffset, err := allocatorReadWord(memory, link, tls.LinkMapStaticOffset, 8)
	if err != nil {
		return 0, err
	}
	staticBase := target.Address(0)
	if staticOffset != 0 && staticOffset != math.MaxUint64 {
		if staticOffset > fsbase {
			return 0, target.ErrOverflow
		}
		staticBase = target.Address(fsbase - staticOffset)
	}
	base := staticBase
	if dtvGeneration >= moduleGeneration {
		capacity, err := allocatorReadWord(memory, target.Address(dtv-tls.DTVEntrySize), tls.DTVGenerationOffset, 8)
		if err != nil {
			return 0, err
		}
		if capacity < modid {
			return 0, fmt.Errorf("current DTV capacity is below allocator module ID: %w", target.ErrInvalidArgument)
		}
		if modid > math.MaxUint64/tls.DTVEntrySize {
			return 0, target.ErrOverflow
		}
		entry, err := allocatorAddress(target.Address(dtv), modid*tls.DTVEntrySize)
		if err != nil {
			return 0, err
		}
		value, err := allocatorReadWord(memory, entry, tls.DTVPointerOffset, 8)
		if err != nil {
			return 0, err
		}
		if value&1 == 0 {
			base = target.Address(value)
			if staticBase != 0 && base != staticBase {
				return 0, fmt.Errorf("DTV and static TLS coordinates disagree: %w", target.ErrInvalidArgument)
			}
		}
	}
	if base == 0 {
		return 0, fmt.Errorf("allocator TLS allocation is deferred for the selected thread: %w", target.ErrUnavailable)
	}
	if err := memory.covers(base, program.Memsz, true); err != nil {
		return 0, err
	}
	return base, nil
}

func allocatorTLSSlot(memory *runtimeELFMemory, profile allocatorTLSProfile, head target.Address, modid uint64) (target.Address, error) {
	seen := make(map[target.Address]bool)
	var first uint64
	for head != 0 {
		if seen[head] || len(seen) >= 256 {
			return 0, fmt.Errorf("TLS slotinfo list is cyclic or exceeds inspection limit: %w", target.ErrInvalidArgument)
		}
		seen[head] = true
		length, err := allocatorReadWord(memory, head, profile.SlotListLengthOffset, 8)
		if err != nil {
			return 0, err
		}
		if length == 0 || length > 1<<20 || length > math.MaxUint64-first {
			return 0, fmt.Errorf("invalid TLS slotinfo length: %w", target.ErrInvalidArgument)
		}
		if modid >= first && modid-first < length {
			index := modid - first
			if index > (math.MaxUint64-profile.SlotListEntriesOffset)/profile.SlotEntrySize {
				return 0, target.ErrOverflow
			}
			return allocatorAddress(head, profile.SlotListEntriesOffset+index*profile.SlotEntrySize)
		}
		first += length
		next, err := allocatorReadWord(memory, head, profile.SlotListNextOffset, 8)
		if err != nil {
			return 0, err
		}
		head = target.Address(next)
	}
	return 0, fmt.Errorf("allocator module has no TLS slotinfo entry: %w", target.ErrUnavailable)
}

func (info *allocatorContext) HeapExtents(arena target.Address) ([]allocatorHeapExtent, error) {
	if info == nil || info.memory == nil || arena == 0 {
		return nil, target.ErrInvalidArgument
	}
	data, err := info.memory.bytes(arena, info.Layout.Arena.Size)
	if err != nil {
		return nil, err
	}
	topValue, err := allocatorFieldValue(data, info.Layout.Arena, "top")
	if err != nil {
		return nil, err
	}
	systemMemory, err := allocatorFieldValue(data, info.Layout.Arena, "system_mem")
	if err != nil {
		return nil, err
	}
	top := target.Address(topValue)
	if systemMemory == 0 {
		initialTop := arena + target.Address(info.Layout.Arena.Fields["bins"].Offset-info.Layout.Chunk.Fields["fd"].Offset)
		if top == 0 || top == initialTop {
			return nil, nil
		}
		return nil, fmt.Errorf("zero-sized arena has an unexpected top pointer: %w", target.ErrInvalidArgument)
	}
	if top == 0 {
		return nil, fmt.Errorf("allocated arena has no top chunk: %w", target.ErrUnavailable)
	}
	topSize, err := allocatorReadWord(info.memory, top, info.Layout.Chunk.Fields["mchunk_size"].Offset, 8)
	if err != nil {
		return nil, err
	}
	topSize &^= info.SizeFlags
	if topSize < info.MinChunkSize || topSize%info.Alignment != 0 {
		return nil, fmt.Errorf("arena top chunk has an invalid extent: %w", target.ErrInvalidArgument)
	}
	topEnd, err := allocatorAddress(top, topSize)
	if err != nil {
		return nil, err
	}
	if arena == info.MainArena {
		base := info.Parameters.SbrkBase
		if base == 0 || base > top || topEnd < base || uint64(topEnd-base) > systemMemory {
			return nil, fmt.Errorf("main arena sbrk/top/system_mem coordinates do not prove a contiguous visualization extent: %w", target.ErrUnavailable)
		}
		start, err := allocatorAlignedChunk(base, info.Alignment, info.ChunkHeaderSize)
		if err != nil {
			return nil, err
		}
		if start > top {
			return nil, target.ErrInvalidArgument
		}
		if err := info.memory.covers(start, uint64(topEnd-start), true); err != nil {
			return nil, err
		}
		return []allocatorHeapExtent{{Base: base, Start: start, End: topEnd, Top: top, Arena: arena, Label: "main arena: exact sbrk_base to current top; traversal stops at source-defined fenceposts"}}, nil
	}
	head := target.Address(uint64(top) &^ (info.HeapMaxSize - 1))
	seen := make(map[target.Address]bool)
	var result []allocatorHeapExtent
	for head != 0 {
		if seen[head] || len(seen) >= heapGraphMaxArenas {
			return nil, fmt.Errorf("arena heap_info chain is cyclic or exceeds inspection limit: %w", target.ErrInvalidArgument)
		}
		seen[head] = true
		if uint64(head)%info.HeapMaxSize != 0 {
			return nil, fmt.Errorf("heap_info is not aligned to exact profile HEAP_MAX_SIZE: %w", target.ErrInvalidArgument)
		}
		heapData, err := info.memory.bytes(head, info.HeapInfo.Size)
		if err != nil {
			return nil, err
		}
		fields := make(map[string]uint64)
		for _, name := range []string{"ar_ptr", "prev", "size", "mprotect_size", "pagesize"} {
			fields[name], err = allocatorFieldValue(heapData, info.HeapInfo, name)
			if err != nil {
				return nil, err
			}
		}
		size, protected, page := fields["size"], fields["mprotect_size"], fields["pagesize"]
		if target.Address(fields["ar_ptr"]) != arena || size < info.HeapInfo.Size || size > info.HeapMaxSize || protected < size || protected > info.HeapMaxSize || page == 0 || page&(page-1) != 0 || size%page != 0 {
			return nil, fmt.Errorf("heap_info extent or arena identity is invalid: %w", target.ErrInvalidArgument)
		}
		end, err := allocatorAddress(head, size)
		if err != nil {
			return nil, err
		}
		start, err := allocatorAddress(head, info.HeapInfo.Size)
		if err != nil {
			return nil, err
		}
		if fields["prev"] == 0 {
			if start != arena {
				return nil, fmt.Errorf("first arena heap does not contain its allocator state at the source-defined location: %w", target.ErrInvalidArgument)
			}
			start, err = allocatorAddress(start, info.Layout.Arena.Size)
			if err != nil {
				return nil, err
			}
		}
		start, err = allocatorAlignedChunk(start, info.Alignment, info.ChunkHeaderSize)
		if err != nil || start >= end {
			return nil, errors.Join(err, target.ErrInvalidArgument)
		}
		currentTop := target.Address(0)
		terminal := target.Address(0)
		if len(result) == 0 {
			if top < start || topEnd != end {
				return nil, fmt.Errorf("arena top is outside its exact heap_info extent: %w", target.ErrInvalidArgument)
			}
			currentTop = top
		} else {
			terminal, err = info.closedHeapFencepost(start, end)
			if err != nil {
				return nil, err
			}
		}
		if err := info.memory.covers(start, uint64(end-start), true); err != nil {
			return nil, err
		}
		result = append(result, allocatorHeapExtent{Base: head, Start: start, End: end, Top: currentTop, Arena: arena, TerminalFencepost: terminal, Label: "non-main arena: source-defined HEAP_MAX_SIZE and validated heap_info chain"})
		head = target.Address(fields["prev"])
	}
	slices.Reverse(result)
	return result, nil
}

func (info *allocatorContext) closedHeapFencepost(start, end target.Address) (target.Address, error) {
	if info.ChunkHeaderSize != 16 || info.MinChunkSize != 32 || info.Alignment != 16 || end < start || uint64(end-start) < 2*info.ChunkHeaderSize {
		return 0, fmt.Errorf("closed heap fencepost geometry is unsupported: %w", target.ErrUnsupported)
	}
	terminal := end - target.Address(info.MinChunkSize-info.ChunkHeaderSize)
	data, err := info.memory.bytes(terminal, info.ChunkHeaderSize)
	if err != nil {
		return 0, err
	}
	previous := binary.LittleEndian.Uint64(data)
	if binary.LittleEndian.Uint64(data[8:]) != 1 || previous != info.ChunkHeaderSize && previous != info.MinChunkSize || previous > uint64(terminal-start) {
		return 0, fmt.Errorf("closed heap terminal fencepost differs from exact allocator source: %w", target.ErrInvalidArgument)
	}
	predecessor := terminal - target.Address(previous)
	rawSize, err := allocatorReadWord(info.memory, predecessor, info.Layout.Chunk.Fields["mchunk_size"].Offset, 8)
	if err != nil {
		return 0, err
	}
	if rawSize&^uint64(1) != previous {
		return 0, fmt.Errorf("closed heap predecessor fencepost differs from its exact footer: %w", target.ErrInvalidArgument)
	}
	return terminal, nil
}

func allocatorAlignedChunk(address target.Address, alignment, header uint64) (target.Address, error) {
	if alignment == 0 || alignment&(alignment-1) != 0 || header > math.MaxUint64-uint64(address) {
		return 0, target.ErrInvalidArgument
	}
	user := uint64(address) + header
	if user > math.MaxUint64-(alignment-1) {
		return 0, target.ErrOverflow
	}
	return target.Address((user+alignment-1)&^(alignment-1) - header), nil
}
