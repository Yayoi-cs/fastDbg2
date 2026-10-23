package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"sync"

	"fastdbg2/target"
)

const (
	maxRuntimeELFRead       = 64 << 20
	maxRuntimeELFPrograms   = 4096
	maxRuntimeELFModules    = 4096
	maxRuntimeELFNamespaces = 64
	maxRuntimeELFString     = 64 << 10
	maxRuntimeELFNotes      = 1 << 20
)

type runtimeELFSpan struct {
	Address target.Address
	Size    uint64
}

type runtimeELFLink struct {
	Namespace target.Address
	Address   target.Address
	Name      string
}

type runtimeELFModule struct {
	ID               string
	Name             string
	Proof            string
	Main             bool
	Header           target.Address
	AuxiliaryTag     uint64
	AuxiliaryAddress target.Address
	LoadBias         uint64
	Programs         []elf.ProgHeader
	Loads            []runtimeELFSpan
	Dynamic          runtimeELFSpan
	EHFrameHeader    runtimeELFSpan
	BuildID          []byte
	BuildIDErr       error
	Links            []runtimeELFLink
}

type runtimeELFView struct {
	Modules        []*runtimeELFModule
	Memory         *runtimeELFMemory
	Loader         []runtimeLinkMap
	LoaderComplete bool
}

type runtimeELFPartialError struct {
	Err error
}

type runtimeLoaderPendingError struct{}

func (*runtimeLoaderPendingError) Error() string {
	return "runtime loader rendezvous is not published (DT_DEBUG): unavailable"
}

func (*runtimeLoaderPendingError) Unwrap() error { return target.ErrUnavailable }

func runtimeELFLoaderPending(err error) bool {
	var pending *runtimeLoaderPendingError
	return !runtimeELFFatal(err) && errors.As(err, &pending)
}

func (err *runtimeELFPartialError) Error() string {
	return fmt.Sprintf("runtime ELF discovery incomplete: %v", err.Err)
}

func (err *runtimeELFPartialError) Unwrap() error { return err.Err }

func (err *runtimeELFPartialError) Is(other error) bool { return other == target.ErrPartial }

func runtimeELFResultUsable(err error) bool {
	if err == nil {
		return true
	}
	if runtimeELFFatal(err) {
		return false
	}
	_, ok := err.(*runtimeELFPartialError)
	return ok
}

func runtimeELFFatal(err error) bool {
	return errors.Is(err, target.ErrStale) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type runtimeELFMemory struct {
	mu        sync.Mutex
	ctx       context.Context
	mappings  []procMap
	read      func(target.Address, []byte) (int, error)
	remaining uint64
	closed    bool
}

func newRuntimeELFMemory(ctx context.Context, mappings []procMap, read func(target.Address, []byte) (int, error)) (*runtimeELFMemory, error) {
	if ctx == nil || read == nil {
		return nil, target.ErrInvalidArgument
	}
	for index, mapping := range mappings {
		if mapping.Start >= mapping.End || index > 0 && mappings[index-1].End > mapping.Start {
			return nil, fmt.Errorf("invalid runtime ELF mapping intervals: %w", target.ErrInvalidArgument)
		}
	}
	return &runtimeELFMemory{ctx: ctx, mappings: slices.Clone(mappings), read: read, remaining: maxRuntimeELFRead}, nil
}

func (memory *runtimeELFMemory) Read(ctx context.Context, address target.Address, data []byte) (int, error) {
	if memory == nil || ctx == nil {
		return 0, target.ErrInvalidArgument
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if memory.closed {
		return 0, target.ErrInvalidState
	}
	if err := errors.Join(contextReady(ctx), contextReady(memory.ctx)); err != nil {
		return 0, err
	}
	if uint64(len(data)) > memory.remaining {
		return 0, fmt.Errorf("runtime ELF read budget exhausted: %w", target.ErrOverflow)
	}
	if err := memory.covers(address, uint64(len(data)), true); err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	memory.remaining -= uint64(len(data))
	n, err := memory.read(address, data)
	if n < 0 || n > len(data) {
		return 0, fmt.Errorf("invalid runtime ELF read count %d: %w", n, target.ErrInvalidArgument)
	}
	if n != len(data) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	return n, errors.Join(err, contextReady(ctx), contextReady(memory.ctx))
}

func (memory *runtimeELFMemory) close() {
	memory.mu.Lock()
	memory.closed = true
	memory.mu.Unlock()
}

func (memory *runtimeELFMemory) covers(address target.Address, size uint64, readable bool) error {
	if size > math.MaxUint64-uint64(address) {
		return target.ErrOverflow
	}
	if size == 0 {
		return nil
	}
	end := uint64(address) + size
	index := sort.Search(len(memory.mappings), func(index int) bool { return memory.mappings[index].End > address })
	cursor := uint64(address)
	for index < len(memory.mappings) && cursor < end {
		mapping := memory.mappings[index]
		if uint64(mapping.Start) > cursor || readable && !mapping.Read {
			break
		}
		cursor = min(end, uint64(mapping.End))
		index++
	}
	if cursor != end {
		permission := ""
		if readable {
			permission = " readable"
		}
		return fmt.Errorf("runtime ELF range %#x+%#x is not mapped%s: %w", address, size, permission, target.ErrUnavailable)
	}
	return nil
}

func (memory *runtimeELFMemory) bytes(address target.Address, size uint64) ([]byte, error) {
	if size > maxRuntimeELFRead {
		return nil, target.ErrOverflow
	}
	data := make([]byte, int(size))
	_, err := memory.Read(memory.ctx, address, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Controller) withRuntimeELFModules(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, visit func(*runtimeELFView) error) error {
	if visit == nil {
		return target.ErrInvalidArgument
	}
	var discoveryErr error
	err := c.withStoppedProc(ctx, snapshot, thread, func(proc *stoppedProc) error {
		view, readErr := c.runtimeELFModules(ctx, snapshot, proc)
		if view == nil {
			return readErr
		}
		defer view.Memory.close()
		discoveryErr = readErr
		return visit(view)
	})
	if err != nil {
		return err
	}
	if discoveryErr != nil {
		return &runtimeELFPartialError{Err: discoveryErr}
	}
	return nil
}

func (c *Controller) runtimeELFModules(ctx context.Context, snapshot target.Snapshot, proc *stoppedProc) (*runtimeELFView, error) {
	return c.runtimeELFModulesWithMain(ctx, snapshot, proc, nil)
}

func (c *Controller) runtimeELFModulesWithMain(ctx context.Context, snapshot target.Snapshot, proc *stoppedProc, main *mappedELF) (*runtimeELFView, error) {
	if c == nil || c.session == nil || ctx == nil || proc == nil {
		return nil, target.ErrInvalidArgument
	}
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if snapshot.Architecture != target.AMD64 || snapshot.State != target.StateStopped {
		return nil, target.ErrUnsupported
	}
	mappings, err := proc.maps()
	if err != nil {
		return nil, err
	}
	auxv, err := proc.readFile("auxv")
	if err != nil {
		return nil, err
	}
	memory, err := newRuntimeELFMemory(ctx, mappings, func(address target.Address, data []byte) (int, error) {
		return c.session.ReadSpaceMemory(snapshot.Memory, address, data)
	})
	if err != nil {
		return nil, err
	}
	view, err := discoverRuntimeELFWithMain(memory, auxv, main)
	if view == nil || runtimeELFFatal(err) {
		memory.close()
		return nil, err
	}
	return view, err
}

func runtimeAuxiliary(data []byte) (map[uint64]uint64, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, target.ErrInvalidArgument
	}
	values := make(map[uint64]uint64)
	terminated := false
	for offset := 0; offset < len(data); offset += 16 {
		key := binary.LittleEndian.Uint64(data[offset:])
		value := binary.LittleEndian.Uint64(data[offset+8:])
		if terminated {
			if key != 0 || value != 0 {
				return nil, fmt.Errorf("nonzero data after AT_NULL: %w", target.ErrInvalidArgument)
			}
			continue
		}
		if key == 0 {
			if value != 0 {
				return nil, target.ErrInvalidArgument
			}
			terminated = true
			continue
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("duplicate auxiliary tag %d: %w", key, target.ErrInvalidArgument)
		}
		values[key] = value
	}
	if !terminated {
		return nil, fmt.Errorf("auxv has no AT_NULL: %w", target.ErrInvalidArgument)
	}
	return values, nil
}

func discoverRuntimeELF(memory *runtimeELFMemory, auxv []byte) (*runtimeELFView, error) {
	return discoverRuntimeELFWithMain(memory, auxv, nil)
}

func discoverRuntimeELFWithMain(memory *runtimeELFMemory, auxv []byte, source *mappedELF) (*runtimeELFView, error) {
	if memory == nil {
		return nil, target.ErrInvalidArgument
	}
	values, err := runtimeAuxiliary(auxv)
	if err != nil {
		return nil, err
	}
	view := &runtimeELFView{Memory: memory}
	var discoveryErr error
	main, err := runtimeELFMainWithSource(memory, values, source)
	if err == nil {
		view.Modules = append(view.Modules, main)
	} else {
		discoveryErr = errors.Join(discoveryErr, fmt.Errorf("main runtime headers: %w", err))
	}
	if runtimeELFFatal(err) {
		return nil, err
	}
	for _, anchor := range []struct {
		tag  uint64
		id   string
		name string
	}{{7, "interpreter", "AT_BASE"}, {33, "vdso", "AT_SYSINFO_EHDR"}} {
		address := values[anchor.tag]
		if address == 0 {
			continue
		}
		module, err := runtimeELFZeroOrigin(memory, target.Address(address), nil)
		if err != nil {
			if runtimeELFFatal(err) {
				return nil, err
			}
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s runtime headers: %w", anchor.name, err))
			continue
		}
		module.ID, module.Name, module.Proof = anchor.id, anchor.id, "auxv-"+anchor.name+"+runtime-zero-origin-elf"
		module.AuxiliaryTag, module.AuxiliaryAddress = anchor.tag, target.Address(address)
		view.Modules = append(view.Modules, module)
	}
	if main == nil {
		return view, discoveryErr
	}
	if main.Dynamic.Size == 0 {
		return view, discoveryErr
	}
	debugAddress, debugPresent, err := runtimeELFDebugEntry(memory, main.Dynamic)
	if err != nil {
		if runtimeELFFatal(err) {
			return nil, err
		}
		return view, errors.Join(discoveryErr, err)
	}
	if debugAddress == 0 {
		hasInterpreter := slices.ContainsFunc(main.Programs, func(program elf.ProgHeader) bool { return program.Type == elf.PT_INTERP })
		if !hasInterpreter && values[7] == 0 {
			return view, discoveryErr
		}
		if debugPresent {
			return view, errors.Join(discoveryErr, &runtimeLoaderPendingError{})
		}
		return view, errors.Join(discoveryErr, fmt.Errorf("runtime loader DT_DEBUG entry is absent: %w", target.ErrUnavailable))
	}
	links, err := runtimeELFLinkMaps(memory, debugAddress)
	if err != nil {
		if runtimeELFFatal(err) {
			return nil, err
		}
		return view, errors.Join(discoveryErr, err)
	}
	mainCount := 0
	for _, link := range links {
		if link.namespace == debugAddress && link.bias == main.LoadBias && link.dynamic == main.Dynamic.Address {
			mainCount++
		}
	}
	if mainCount != 1 {
		return view, errors.Join(discoveryErr, fmt.Errorf("runtime loader list does not uniquely contain the auxiliary main image: %w", target.ErrUnavailable))
	}
	view.Loader, view.LoaderComplete = links, true
	type imageKey struct {
		bias    uint64
		dynamic target.Address
	}
	images := make(map[imageKey]*runtimeELFModule)
	for _, module := range view.Modules {
		key := imageKey{module.LoadBias, module.Dynamic.Address}
		if images[key] != nil {
			return view, errors.Join(discoveryErr, fmt.Errorf("duplicate runtime image anchors: %w", target.ErrAmbiguous))
		}
		images[key] = module
	}
	for _, link := range links {
		key := imageKey{link.bias, link.dynamic}
		existing := images[key]
		identity := runtimeELFLink{Namespace: link.namespace, Address: link.address, Name: link.name}
		if existing != nil {
			existing.Links = append(existing.Links, identity)
			if link.name != "" {
				existing.Name = link.name
			}
			continue
		}
		module, err := runtimeELFZeroOrigin(memory, target.Address(link.bias), &link.dynamic)
		if err != nil {
			if runtimeELFFatal(err) {
				return nil, err
			}
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("link_map %#x %q: %w", link.address, link.name, err))
			continue
		}
		module.ID = fmt.Sprintf("runtime@%#x", module.Header)
		module.Name, module.Proof, module.Links = link.name, "link-map+runtime-zero-origin-elf", []runtimeELFLink{identity}
		view.Modules = append(view.Modules, module)
		images[key] = module
	}
	return view, discoveryErr
}

func runtimeELFPrograms(memory *runtimeELFMemory, address target.Address, count uint64) ([]elf.ProgHeader, error) {
	if count == 0 || count > maxRuntimeELFPrograms {
		return nil, fmt.Errorf("runtime ELF program header count %d: %w", count, target.ErrUnsupported)
	}
	data, err := memory.bytes(address, count*56)
	if err != nil {
		return nil, err
	}
	return decodeRuntimeELFPrograms(data), nil
}

func decodeRuntimeELFPrograms(data []byte) []elf.ProgHeader {
	programs := make([]elf.ProgHeader, len(data)/56)
	for index := range programs {
		entry := data[index*56:]
		programs[index] = elf.ProgHeader{
			Type: elf.ProgType(binary.LittleEndian.Uint32(entry)), Flags: elf.ProgFlag(binary.LittleEndian.Uint32(entry[4:])),
			Off: binary.LittleEndian.Uint64(entry[8:]), Vaddr: binary.LittleEndian.Uint64(entry[16:]),
			Paddr: binary.LittleEndian.Uint64(entry[24:]), Filesz: binary.LittleEndian.Uint64(entry[32:]),
			Memsz: binary.LittleEndian.Uint64(entry[40:]), Align: binary.LittleEndian.Uint64(entry[48:]),
		}
	}
	return programs
}

func runtimeELFMain(memory *runtimeELFMemory, auxv map[uint64]uint64) (*runtimeELFModule, error) {
	return runtimeELFMainWithSource(memory, auxv, nil)
}

func runtimeELFMainWithSource(memory *runtimeELFMemory, auxv map[uint64]uint64, source *mappedELF) (*runtimeELFModule, error) {
	address, count, entrySize := auxv[3], auxv[5], auxv[4]
	if address == 0 || entrySize != 56 {
		return nil, fmt.Errorf("AT_PHDR/AT_PHENT unavailable or unsupported: %w", target.ErrUnavailable)
	}
	programs, err := runtimeELFPrograms(memory, target.Address(address), count)
	if err != nil {
		return nil, err
	}
	var bias uint64
	found := false
	for _, program := range programs {
		if program.Type != elf.PT_PHDR {
			continue
		}
		if found {
			return nil, fmt.Errorf("multiple PT_PHDR entries: %w", target.ErrAmbiguous)
		}
		if program.Vaddr > address || program.Filesz != count*56 || program.Memsz != count*56 {
			return nil, fmt.Errorf("PT_PHDR differs from auxiliary table: %w", target.ErrInvalidArgument)
		}
		bias, found = address-program.Vaddr, true
	}
	if !found {
		if source == nil {
			return nil, fmt.Errorf("no PT_PHDR load-bias anchor: %w", target.ErrUnsupported)
		}
		bias, err = runtimeELFMainSourceBias(memory, auxv, programs, source)
		if err != nil {
			return nil, err
		}
	}
	module, err := runtimeELFDescribe(memory, programs, bias)
	if err != nil {
		return nil, err
	}
	if !runtimeELFLoaded(module, target.Address(address), count*56) {
		return nil, fmt.Errorf("main PHDR table is outside PT_LOAD: %w", target.ErrInvalidArgument)
	}
	module.ID, module.Name, module.Proof, module.Main = "main", "main", "auxv-AT_PHDR+PT_PHDR+runtime-headers", true
	if !found {
		module.Proof = "proc-exe+auxv-AT_ENTRY+runtime-AT_PHDR"
	}
	module.AuxiliaryTag, module.AuxiliaryAddress = 3, target.Address(address)
	return module, nil
}

func runtimeELFMainSourceBias(memory *runtimeELFMemory, auxv map[uint64]uint64, programs []elf.ProgHeader, source *mappedELF) (uint64, error) {
	if source == nil || !source.Main || source.Proof != "proc-exe+auxv" || source.File == nil || source.Source == nil {
		return 0, fmt.Errorf("pinned executable source required for main PHDR verification: %w", target.ErrInvalidArgument)
	}
	if err := validateAMD64ELF(source.File); err != nil {
		return 0, err
	}
	if err := contextReady(memory.ctx); err != nil {
		return 0, err
	}
	var header [64]byte
	if _, err := source.Source.ReadAt(header[:], 0); err != nil {
		return 0, fmt.Errorf("read pinned main ELF header: %w", err)
	}
	if string(header[:4]) != elf.ELFMAG || header[elf.EI_CLASS] != byte(elf.ELFCLASS64) || header[elf.EI_DATA] != byte(elf.ELFDATA2LSB) ||
		header[elf.EI_VERSION] != byte(elf.EV_CURRENT) || binary.LittleEndian.Uint16(header[16:]) != uint16(source.File.Type) ||
		binary.LittleEndian.Uint16(header[18:]) != uint16(elf.EM_X86_64) || binary.LittleEndian.Uint32(header[20:]) != uint32(elf.EV_CURRENT) ||
		binary.LittleEndian.Uint64(header[24:]) != source.File.Entry || binary.LittleEndian.Uint16(header[52:]) != 64 ||
		binary.LittleEndian.Uint16(header[54:]) != 56 || int(binary.LittleEndian.Uint16(header[56:])) != len(programs) || len(source.File.Progs) != len(programs) {
		return 0, fmt.Errorf("pinned main ELF header differs from executable metadata: %w", target.ErrStale)
	}
	entry, present := auxv[9]
	if !present {
		return 0, fmt.Errorf("main load-bias source requires AT_ENTRY: %w", target.ErrUnavailable)
	}
	if entry < source.File.Entry {
		return 0, fmt.Errorf("main AT_ENTRY is below ELF entry: %w", target.ErrStale)
	}
	bias := entry - source.File.Entry
	if bias != source.LoadBias || source.File.Type == elf.ET_EXEC && bias != 0 {
		return 0, fmt.Errorf("main AT_ENTRY differs from verified load bias: %w", target.ErrStale)
	}
	offset := binary.LittleEndian.Uint64(header[32:])
	size := uint64(len(programs)) * 56
	if offset > math.MaxInt64 || size > math.MaxInt64-offset {
		return 0, target.ErrOverflow
	}
	data := make([]byte, int(size))
	if _, err := source.Source.ReadAt(data, int64(offset)); err != nil {
		return 0, fmt.Errorf("read pinned main PHDR table: %w", err)
	}
	if !slices.Equal(programs, decodeRuntimeELFPrograms(data)) {
		return 0, fmt.Errorf("AT_PHDR bytes differ from pinned main ELF: %w", target.ErrStale)
	}
	for index, program := range source.File.Progs {
		if program == nil || program.ProgHeader != programs[index] {
			return 0, fmt.Errorf("pinned main PHDR table changed: %w", target.ErrStale)
		}
	}
	covered, entryCovered := false, false
	for _, program := range programs {
		if program.Type != elf.PT_LOAD || program.Vaddr > math.MaxUint64-bias {
			continue
		}
		start := bias + program.Vaddr
		if entry >= start && entry-start < program.Memsz {
			entryCovered = true
		}
		if offset < program.Off || offset-program.Off > program.Filesz || size > program.Filesz-(offset-program.Off) {
			continue
		}
		delta := offset - program.Off
		if delta <= math.MaxUint64-start && start+delta == auxv[3] {
			covered = true
		}
	}
	if !covered || !entryCovered {
		return 0, fmt.Errorf("main auxiliary PHDR/entry does not match pinned PT_LOAD coordinates: %w", target.ErrStale)
	}
	if err := contextReady(memory.ctx); err != nil {
		return 0, err
	}
	return bias, nil
}

func runtimeELFZeroOrigin(memory *runtimeELFMemory, address target.Address, expectedDynamic *target.Address) (*runtimeELFModule, error) {
	if address == 0 {
		return nil, fmt.Errorf("zero-origin runtime ELF header unavailable: %w", target.ErrUnavailable)
	}
	header, err := memory.bytes(address, 64)
	if err != nil {
		return nil, err
	}
	if string(header[:4]) != elf.ELFMAG || header[elf.EI_CLASS] != byte(elf.ELFCLASS64) || header[elf.EI_DATA] != byte(elf.ELFDATA2LSB) ||
		header[elf.EI_VERSION] != byte(elf.EV_CURRENT) || binary.LittleEndian.Uint16(header[16:]) != uint16(elf.ET_DYN) ||
		binary.LittleEndian.Uint16(header[18:]) != uint16(elf.EM_X86_64) || binary.LittleEndian.Uint32(header[20:]) != uint32(elf.EV_CURRENT) ||
		binary.LittleEndian.Uint16(header[52:]) != 64 || binary.LittleEndian.Uint16(header[54:]) != 56 {
		return nil, fmt.Errorf("runtime anchor is not a supported AMD64 ET_DYN header: %w", target.ErrUnsupported)
	}
	count, offset := uint64(binary.LittleEndian.Uint16(header[56:])), binary.LittleEndian.Uint64(header[32:])
	if offset < 64 || offset > math.MaxUint64-uint64(address) || count*56 > math.MaxUint64-offset {
		return nil, target.ErrOverflow
	}
	programs, err := runtimeELFPrograms(memory, target.Address(uint64(address)+offset), count)
	if err != nil {
		return nil, err
	}
	zeroOrigin := false
	for _, program := range programs {
		if program.Type == elf.PT_LOAD && program.Off == 0 && program.Vaddr == 0 && program.Filesz >= offset+count*56 {
			zeroOrigin = true
		}
	}
	if !zeroOrigin {
		return nil, fmt.Errorf("runtime ELF header/PHDR lacks zero-origin PT_LOAD coverage: %w", target.ErrUnsupported)
	}
	module, err := runtimeELFDescribe(memory, programs, uint64(address))
	if err != nil {
		return nil, err
	}
	if expectedDynamic != nil && module.Dynamic.Address != *expectedDynamic {
		return nil, fmt.Errorf("PT_DYNAMIC differs from link_map.l_ld: %w", target.ErrInvalidArgument)
	}
	module.Header = address
	return module, nil
}

func runtimeELFDescribe(memory *runtimeELFMemory, programs []elf.ProgHeader, bias uint64) (*runtimeELFModule, error) {
	module := &runtimeELFModule{LoadBias: bias, Programs: programs}
	for _, program := range programs {
		if program.Type != elf.PT_LOAD {
			continue
		}
		if program.Filesz > program.Memsz || program.Off > math.MaxUint64-program.Filesz || program.Vaddr > math.MaxUint64-bias || program.Memsz > math.MaxUint64-(bias+program.Vaddr) {
			return nil, fmt.Errorf("invalid runtime PT_LOAD extent: %w", target.ErrOverflow)
		}
		if program.Align > 1 && (program.Align&(program.Align-1) != 0 || program.Off%program.Align != program.Vaddr%program.Align) {
			return nil, fmt.Errorf("invalid runtime PT_LOAD alignment: %w", target.ErrInvalidArgument)
		}
		span := runtimeELFSpan{Address: target.Address(bias + program.Vaddr), Size: program.Memsz}
		if err := memory.covers(span.Address, span.Size, false); err != nil {
			return nil, err
		}
		module.Loads = append(module.Loads, span)
	}
	if len(module.Loads) == 0 {
		return nil, fmt.Errorf("runtime ELF has no PT_LOAD: %w", target.ErrInvalidArgument)
	}
	for _, program := range programs {
		if program.Type != elf.PT_DYNAMIC && program.Type != elf.PT_GNU_EH_FRAME {
			continue
		}
		if program.Filesz == 0 || program.Filesz > program.Memsz || program.Vaddr > math.MaxUint64-bias {
			return nil, fmt.Errorf("invalid runtime %s extent: %w", program.Type, target.ErrInvalidArgument)
		}
		span := runtimeELFSpan{Address: target.Address(bias + program.Vaddr), Size: program.Filesz}
		if !runtimeELFLoaded(module, span.Address, span.Size) {
			return nil, fmt.Errorf("runtime %s is outside PT_LOAD: %w", program.Type, target.ErrInvalidArgument)
		}
		if err := memory.covers(span.Address, span.Size, true); err != nil {
			return nil, err
		}
		destination := &module.Dynamic
		if program.Type == elf.PT_GNU_EH_FRAME {
			destination = &module.EHFrameHeader
		}
		if destination.Size != 0 {
			return nil, fmt.Errorf("duplicate runtime %s: %w", program.Type, target.ErrAmbiguous)
		}
		*destination = span
	}
	module.BuildID, module.BuildIDErr = runtimeELFBuildID(memory, module)
	if runtimeELFFatal(module.BuildIDErr) {
		return nil, module.BuildIDErr
	}
	return module, nil
}

func runtimeELFLoaded(module *runtimeELFModule, address target.Address, size uint64) bool {
	if size > math.MaxUint64-uint64(address) {
		return false
	}
	for _, load := range module.Loads {
		if address >= load.Address && uint64(address-load.Address) <= load.Size && size <= load.Size-uint64(address-load.Address) {
			return true
		}
	}
	return false
}

func runtimeELFBuildID(memory *runtimeELFMemory, module *runtimeELFModule) ([]byte, error) {
	var id []byte
	seen := make(map[runtimeELFSpan]bool)
	for _, program := range module.Programs {
		if program.Type != elf.PT_NOTE || program.Filesz == 0 {
			continue
		}
		if program.Vaddr > math.MaxUint64-module.LoadBias || program.Filesz > maxRuntimeELFNotes {
			return nil, target.ErrOverflow
		}
		span := runtimeELFSpan{target.Address(module.LoadBias + program.Vaddr), program.Filesz}
		if seen[span] {
			continue
		}
		seen[span] = true
		if !runtimeELFLoaded(module, span.Address, span.Size) {
			return nil, fmt.Errorf("runtime PT_NOTE is outside PT_LOAD: %w", target.ErrUnavailable)
		}
		data, err := memory.bytes(span.Address, span.Size)
		if err != nil {
			return nil, err
		}
		alignment := uint64(4)
		if program.Align == 8 {
			alignment = 8
		} else if program.Align > 1 && program.Align != 4 {
			return nil, fmt.Errorf("unsupported runtime note alignment: %w", target.ErrUnsupported)
		}
		for offset := uint64(0); offset < uint64(len(data)); {
			if uint64(len(data))-offset < 12 {
				return nil, fmt.Errorf("truncated runtime ELF note: %w", target.ErrInvalidArgument)
			}
			nameSize := uint64(binary.LittleEndian.Uint32(data[offset:]))
			descSize := uint64(binary.LittleEndian.Uint32(data[offset+4:]))
			kind := binary.LittleEndian.Uint32(data[offset+8:])
			nameStart := offset + 12
			if nameSize > uint64(len(data))-nameStart {
				return nil, target.ErrInvalidArgument
			}
			descStart := (nameStart + nameSize + alignment - 1) &^ (alignment - 1)
			if descStart > uint64(len(data)) || descSize > uint64(len(data))-descStart {
				return nil, target.ErrInvalidArgument
			}
			if kind == 3 && nameSize == 4 && string(data[nameStart:nameStart+nameSize]) == "GNU\x00" {
				if descSize == 0 {
					return nil, fmt.Errorf("empty runtime GNU build ID: %w", target.ErrInvalidArgument)
				}
				candidate := data[descStart : descStart+descSize]
				if id != nil && !bytes.Equal(id, candidate) {
					return nil, fmt.Errorf("conflicting runtime GNU build IDs: %w", target.ErrAmbiguous)
				}
				id = slices.Clone(candidate)
			}
			next := (descStart + descSize + alignment - 1) &^ (alignment - 1)
			if next > uint64(len(data)) {
				return nil, target.ErrInvalidArgument
			}
			offset = next
		}
	}
	if id == nil {
		return nil, fmt.Errorf("no runtime GNU build ID: %w", target.ErrUnavailable)
	}
	return id, nil
}

func runtimeELFDebugAddress(memory *runtimeELFMemory, span runtimeELFSpan) (target.Address, error) {
	address, err := runtimeELFDebugPointer(memory, span)
	if err != nil {
		return 0, err
	}
	if address == 0 {
		return 0, fmt.Errorf("runtime loader rendezvous is not published (DT_DEBUG): %w", target.ErrUnavailable)
	}
	return address, nil
}

func runtimeELFDebugPointer(memory *runtimeELFMemory, span runtimeELFSpan) (target.Address, error) {
	address, _, err := runtimeELFDebugEntry(memory, span)
	return address, err
}

func runtimeELFDebugEntry(memory *runtimeELFMemory, span runtimeELFSpan) (target.Address, bool, error) {
	if span.Size == 0 || span.Size%16 != 0 || span.Size > maxRuntimeELFNotes {
		return 0, false, fmt.Errorf("invalid runtime PT_DYNAMIC size: %w", target.ErrInvalidArgument)
	}
	data, err := memory.bytes(span.Address, span.Size)
	if err != nil {
		return 0, false, err
	}
	var address target.Address
	found, terminated := false, false
	for offset := 0; offset < len(data); offset += 16 {
		tag := elf.DynTag(binary.LittleEndian.Uint64(data[offset:]))
		if tag == elf.DT_NULL {
			terminated = true
			break
		}
		if tag != elf.DT_DEBUG {
			continue
		}
		if found {
			return 0, false, fmt.Errorf("duplicate runtime DT_DEBUG: %w", target.ErrAmbiguous)
		}
		found = true
		address = target.Address(binary.LittleEndian.Uint64(data[offset+8:]))
	}
	if !terminated {
		return 0, false, fmt.Errorf("runtime PT_DYNAMIC has no DT_NULL: %w", target.ErrInvalidArgument)
	}
	return address, found, nil
}

type runtimeLinkMap struct {
	namespace target.Address
	address   target.Address
	bias      uint64
	dynamic   target.Address
	name      string
}

type runtimeELFWitness struct {
	address target.Address
	data    []byte
}

func runtimeELFLinkMaps(memory *runtimeELFMemory, address target.Address) ([]runtimeLinkMap, error) {
	if memory == nil || address == 0 {
		return nil, target.ErrInvalidArgument
	}
	var links []runtimeLinkMap
	var witnesses []runtimeELFWitness
	namespaces := make(map[target.Address]bool)
	seenLinks := make(map[target.Address]bool)
	for address != 0 {
		if len(namespaces) == maxRuntimeELFNamespaces {
			return nil, fmt.Errorf("runtime loader namespace limit: %w", target.ErrOverflow)
		}
		if namespaces[address] {
			return nil, fmt.Errorf("cyclic runtime loader namespace list: %w", target.ErrInvalidArgument)
		}
		namespaces[address] = true
		debug, err := memory.bytes(address, 40)
		if err != nil {
			return nil, err
		}
		version := binary.LittleEndian.Uint32(debug)
		if version != 1 && version != 2 {
			return nil, fmt.Errorf("runtime rendezvous version %d: %w", version, target.ErrUnsupported)
		}
		if binary.LittleEndian.Uint32(debug[24:]) != 0 {
			return nil, fmt.Errorf("runtime loader list is not RT_CONSISTENT: %w", target.ErrUnavailable)
		}
		var nextNamespace target.Address
		if version == 2 {
			if uint64(address) > math.MaxUint64-40 {
				return nil, target.ErrOverflow
			}
			next, err := memory.bytes(address+40, 8)
			if err != nil {
				return nil, err
			}
			nextNamespace = target.Address(binary.LittleEndian.Uint64(next))
			debug = append(debug, next...)
		}
		witnesses = append(witnesses, runtimeELFWitness{address, debug})
		current := target.Address(binary.LittleEndian.Uint64(debug[8:]))
		var previous target.Address
		for current != 0 {
			if len(links) == maxRuntimeELFModules {
				return nil, fmt.Errorf("runtime loader module limit: %w", target.ErrOverflow)
			}
			if seenLinks[current] {
				return nil, fmt.Errorf("cyclic or shared runtime link_map node: %w", target.ErrInvalidArgument)
			}
			seenLinks[current] = true
			data, err := memory.bytes(current, 40)
			if err != nil {
				return nil, err
			}
			if target.Address(binary.LittleEndian.Uint64(data[32:])) != previous {
				return nil, fmt.Errorf("runtime link_map reverse link mismatch: %w", target.ErrInvalidArgument)
			}
			witnesses = append(witnesses, runtimeELFWitness{current, data})
			name, err := runtimeELFString(memory, target.Address(binary.LittleEndian.Uint64(data[8:])))
			if err != nil {
				return nil, err
			}
			links = append(links, runtimeLinkMap{
				namespace: address, address: current, bias: binary.LittleEndian.Uint64(data),
				dynamic: target.Address(binary.LittleEndian.Uint64(data[16:])), name: name,
			})
			previous, current = current, target.Address(binary.LittleEndian.Uint64(data[24:]))
		}
		address = nextNamespace
	}
	for _, witness := range witnesses {
		current, err := memory.bytes(witness.address, uint64(len(witness.data)))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(witness.data, current) {
			return nil, fmt.Errorf("runtime loader list changed while reading: %w", target.ErrStale)
		}
	}
	return links, nil
}

func runtimeELFString(memory *runtimeELFMemory, address target.Address) (string, error) {
	if address == 0 {
		return "", fmt.Errorf("null runtime loader name: %w", target.ErrInvalidArgument)
	}
	var value []byte
	for len(value) < maxRuntimeELFString {
		index := sort.Search(len(memory.mappings), func(index int) bool { return memory.mappings[index].End > address })
		if index == len(memory.mappings) || memory.mappings[index].Start > address || !memory.mappings[index].Read {
			return "", fmt.Errorf("runtime loader name is not readable: %w", target.ErrUnavailable)
		}
		size := min(uint64(256), uint64(maxRuntimeELFString-len(value)), uint64(memory.mappings[index].End-address))
		data, err := memory.bytes(address, size)
		if err != nil {
			return "", err
		}
		if end := bytes.IndexByte(data, 0); end >= 0 {
			return string(append(value, data[:end]...)), nil
		}
		value = append(value, data...)
		if size > math.MaxUint64-uint64(address) {
			return "", target.ErrOverflow
		}
		address += target.Address(size)
	}
	return "", fmt.Errorf("runtime loader name exceeds limit: %w", target.ErrOverflow)
}
