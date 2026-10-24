package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
)

const (
	maxUnwindSectionBytes = 16 << 20
	maxUnwindFileBytes    = 32 << 20
)

type unwindCommandSeed struct {
	snapshot    target.Snapshot
	thread      target.ThreadInfo
	registers   inspect.AMD64UnwindRegisters
	location    native.CodeLocation
	profile     inspect.AMD64UnwindProfile
	abiExplicit bool
	orc         bool
	symbols     []inspect.Symbol
	symbolKey   uiSymbolCacheKey
	symbolErr   error
	modules     []*runtimeELFModule
}

type unwindCFICache struct {
	index *inspect.CFIIndex
	err   error
}

type unwindCFIFinder struct {
	proc      *stoppedProc
	view      *runtimeELFView
	discovery error
	cache     map[*runtimeELFModule]unwindCFICache
	fileBytes uint64
}

func unwindCommandNumber(rawArgs string, fallback, minimum, maximum int, command string) (int, error) {
	text := strings.TrimSpace(rawArgs)
	if text == "" {
		return fallback, nil
	}
	for _, char := range text {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("%s requires a decimal integer between %d and %d: %w", command, minimum, maximum, target.ErrInvalidArgument)
		}
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || value < uint64(minimum) || value > uint64(maximum) {
		return 0, fmt.Errorf("%s requires a decimal integer between %d and %d: %w", command, minimum, maximum, target.ErrInvalidArgument)
	}
	return int(value), nil
}

func unwindCommandArguments(rawArgs string, fallback, minimum, maximum int, command string) (inspect.AMD64UnwindProfile, int, error) {
	profile := inspect.UnwindSysVAMD64
	first, rest := takeMemoryArgument(rawArgs)
	if first == "--abi" {
		name, remaining := takeMemoryArgument(rest)
		switch name {
		case "strict":
			profile = inspect.UnwindStrictCFI
		case "sysv":
			profile = inspect.UnwindSysVAMD64
		default:
			return profile, 0, fmt.Errorf("%s --abi requires strict or sysv: %w", command, target.ErrInvalidArgument)
		}
		rawArgs = remaining
	}
	value, err := unwindCommandNumber(rawArgs, fallback, minimum, maximum, command)
	return profile, value, err
}

func (c *Controller) readUnwindSeed(ctx context.Context) (unwindCommandSeed, error) {
	if err := contextReady(ctx); err != nil {
		return unwindCommandSeed{}, err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return unwindCommandSeed{}, err
	}
	if err := contextReady(ctx); err != nil {
		return unwindCommandSeed{}, err
	}
	registers, err := c.session.ReadThreadRegisters(thread.Token)
	if err != nil {
		return unwindCommandSeed{}, err
	}
	decoded, err := inspect.UnwindRegistersFromTarget(snapshot.Architecture, registers)
	if err != nil {
		return unwindCommandSeed{}, err
	}
	rawPC, err := contextRegisterValue(registers, abiFor(snapshot.Architecture).pc)
	if err != nil {
		return unwindCommandSeed{}, err
	}
	if err := contextReady(ctx); err != nil {
		return unwindCommandSeed{}, err
	}
	location, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil {
		return unwindCommandSeed{}, err
	}
	if location.RawPC != target.Address(rawPC) || location.Breakpoint != nil && *location.Breakpoint != location.InstructionPC ||
		location.Breakpoint == nil && location.RawPC != location.InstructionPC {
		return unwindCommandSeed{}, fmt.Errorf("unwind code location disagrees with actual registers or breakpoint state: %w", target.ErrStale)
	}
	if err := contextReady(ctx); err != nil {
		return unwindCommandSeed{}, err
	}
	return unwindCommandSeed{snapshot: snapshot, thread: thread, registers: decoded, location: location}, nil
}

func unwindConfirmedResult(result inspect.UnwindResult, walkErr, proofErr error) (inspect.UnwindResult, error) {
	if proofErr != nil || runtimeELFFatal(walkErr) {
		return inspect.UnwindResult{}, errors.Join(walkErr, proofErr)
	}
	return result, walkErr
}

func (c *Controller) collectUnwind(ctx context.Context, limit int, profile inspect.AMD64UnwindProfile) (unwindCommandSeed, inspect.UnwindResult, error) {
	seed, err := c.readUnwindSeed(ctx)
	if err != nil {
		return seed, inspect.UnwindResult{}, err
	}
	if _, ok := c.session.(*qemuSession); ok {
		return c.collectKernelUnwind(ctx, seed, limit, profile)
	}
	if seed.snapshot.Architecture == target.X86 && profile == inspect.UnwindSysVAMD64 {
		profile = inspect.UnwindSysVX86
	}
	seed.profile = profile
	var result inspect.UnwindResult
	var walkErr error
	proofErr := c.withStoppedProc(ctx, seed.snapshot, seed.thread, func(proc *stoppedProc) error {
		if source, ok := c.session.(addressWalkSymbolSource); ok {
			seed.symbols, seed.symbolErr = source.addressWalkSymbols(ctx, seed.snapshot, seed.thread)
			if runtimeELFFatal(seed.symbolErr) {
				walkErr = seed.symbolErr
				return nil
			}
			seed.symbols = slices.Clone(seed.symbols)
			seed.symbolKey = newUISymbolCacheKey(seed.snapshot, seed.thread)
		}
		view, discoveryErr := c.runtimeELFModules(ctx, seed.snapshot, proc)
		if runtimeELFFatal(discoveryErr) {
			if view != nil {
				view.Memory.close()
			}
			walkErr = discoveryErr
			return nil
		}
		if view == nil {
			if discoveryErr == nil {
				discoveryErr = target.ErrUnavailable
			}
			result, walkErr = inspect.Unwind(ctx, inspect.UnwindRequest{
				Registers: seed.registers, PC: seed.location.InstructionPC, MaxFrames: limit, Profile: profile,
				Find: func(context.Context, target.Address) (*inspect.CFIFrame, error) { return nil, discoveryErr },
			})
			return nil
		}
		defer view.Memory.close()
		seed.modules = slices.Clone(view.Modules)
		finder := unwindCFIFinder{proc: proc, view: view, discovery: discoveryErr, cache: make(map[*runtimeELFModule]unwindCFICache)}
		result, walkErr = inspect.Unwind(ctx, inspect.UnwindRequest{
			Registers: seed.registers, PC: seed.location.InstructionPC, MaxFrames: limit, Profile: profile,
			Find: finder.find, Read: view.Memory.Read,
		})
		return nil
	})
	result, err = unwindConfirmedResult(result, walkErr, proofErr)
	return seed, result, err
}

func unwindModuleContains(module *runtimeELFModule, address target.Address, size uint64, executable bool) (bool, error) {
	var flags elf.ProgFlag
	if executable {
		flags = elf.PF_X
	}
	return unwindModuleContainsFlags(module, address, size, flags)
}

func unwindModuleContainsFlags(module *runtimeELFModule, address target.Address, size uint64, flags elf.ProgFlag) (bool, error) {
	if module == nil || size == 0 || size-1 > math.MaxUint64-uint64(address) {
		return false, target.ErrInvalidArgument
	}
	last := address + target.Address(size-1)
	for _, program := range module.Programs {
		if program.Type != elf.PT_LOAD || program.Memsz == 0 || program.Flags&flags != flags {
			continue
		}
		if module.LoadBias > math.MaxUint64-program.Vaddr || program.Memsz-1 > math.MaxUint64-(module.LoadBias+program.Vaddr) {
			return false, target.ErrOverflow
		}
		start := target.Address(module.LoadBias + program.Vaddr)
		end := start + target.Address(program.Memsz-1)
		if address >= start && last <= end {
			return true, nil
		}
	}
	return false, nil
}

func (finder *unwindCFIFinder) metadataReader(module *runtimeELFModule) inspect.CFIReader {
	return func(ctx context.Context, address target.Address, data []byte) (int, error) {
		if err := contextReady(ctx); err != nil {
			return 0, err
		}
		if len(data) == 0 {
			return 0, nil
		}
		contains, err := unwindModuleContainsFlags(module, address, uint64(len(data)), elf.PF_R)
		if err != nil {
			return 0, err
		}
		if !contains {
			return 0, fmt.Errorf("CFI metadata read [%#x,+%d) is outside module %q readable PT_LOAD bounds: %w", address, len(data), module.ID, target.ErrUnavailable)
		}
		return finder.view.Memory.Read(ctx, address, data)
	}
}

func (finder *unwindCFIFinder) find(ctx context.Context, pc target.Address) (*inspect.CFIFrame, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	var selected *runtimeELFModule
	for _, module := range finder.view.Modules {
		contains, err := unwindModuleContains(module, pc, 1, true)
		if err != nil {
			return nil, err
		}
		if !contains {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("multiple proven runtime modules contain lookup PC %#x: %w", pc, target.ErrAmbiguous)
		}
		selected = module
	}
	if selected == nil {
		return nil, errors.Join(fmt.Errorf("no proven executable runtime module contains %#x: %w", pc, target.ErrUnavailable), finder.discovery)
	}
	cached, exists := finder.cache[selected]
	if !exists {
		cached.index, cached.err = finder.load(ctx, selected)
		finder.cache[selected] = cached
	}
	if cached.err != nil {
		return nil, cached.err
	}
	if cached.index == nil {
		return nil, fmt.Errorf("module %q has no CFI index: %w", selected.ID, target.ErrUnavailable)
	}
	frame, err := cached.index.Lookup(pc)
	if err != nil {
		return nil, err
	}
	start, end := frame.Range()
	if start >= end {
		return nil, target.ErrInvalidArgument
	}
	contains, err := unwindModuleContains(selected, start, uint64(end-start), true)
	if err != nil {
		return nil, err
	}
	if !contains {
		return nil, fmt.Errorf("FDE [%#x,%#x) is outside module %q executable PT_LOAD bounds: %w", start, end, selected.ID, target.ErrInvalidArgument)
	}
	return frame, nil
}

func (finder *unwindCFIFinder) load(ctx context.Context, module *runtimeELFModule) (index *inspect.CFIIndex, err error) {
	source := fmt.Sprintf("module=%q name=%q proof=%q", module.ID, module.Name, module.Proof)
	metadataRead := finder.metadataReader(module)
	if module.EHFrameHeader.Size != 0 {
		contains, err := unwindModuleContains(module, module.EHFrameHeader.Address, module.EHFrameHeader.Size, false)
		if err != nil || !contains {
			return nil, errors.Join(fmt.Errorf("EH frame header is outside module PT_LOAD bounds: %w", target.ErrInvalidArgument), err)
		}
		return inspect.ReadCFIHeader(ctx, module.EHFrameHeader.Address, module.EHFrameHeader.Size, source+" runtime .eh_frame_hdr", metadataRead, abiFor(module.Architecture).word)
	}
	file, err := openRuntimeMappedELF(finder.proc, module)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Source.Close())
		if err != nil {
			index = nil
		}
	}()
	if section := file.File.Section(".eh_frame"); section != nil && section.Size != 0 {
		if section.Flags&elf.SHF_ALLOC == 0 || section.Size > maxUnwindSectionBytes || module.LoadBias > math.MaxUint64-section.Addr {
			return nil, fmt.Errorf("runtime .eh_frame section flags, size or address: %w", target.ErrUnsupported)
		}
		address := target.Address(module.LoadBias + section.Addr)
		contains, err := unwindModuleContains(module, address, section.Size, false)
		if err != nil || !contains {
			return nil, errors.Join(fmt.Errorf(".eh_frame section is outside module PT_LOAD bounds: %w", target.ErrInvalidArgument), err)
		}
		data := make([]byte, int(section.Size))
		n, readErr := metadataRead(ctx, address, data)
		if readErr != nil || n != len(data) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			return nil, readErr
		}
		return inspect.ParseCFISection(ctx, inspect.CFISection{AddressSize: abiFor(module.Architecture).word, Kind: inspect.CFIEHFrame, Address: address, Data: data, Source: source + " runtime .eh_frame via " + file.Proof}, metadataRead)
	}
	section := file.File.Section(".debug_frame")
	if section == nil || section.Size == 0 {
		return nil, fmt.Errorf("module %q has no runtime EH frame header, .eh_frame or associated .debug_frame: %w", module.ID, target.ErrUnavailable)
	}
	if section.Size > maxUnwindSectionBytes {
		return nil, fmt.Errorf(".debug_frame exceeds %d bytes: %w", maxUnwindSectionBytes, target.ErrOverflow)
	}
	if err := finder.reserveFileMetadata(section.Size); err != nil {
		return nil, err
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != section.Size || len(data) > maxUnwindSectionBytes {
		return nil, fmt.Errorf(".debug_frame section size differs from confirmed data: %w", target.ErrInvalidArgument)
	}
	return inspect.ParseCFISection(ctx, inspect.CFISection{
		AddressSize: abiFor(module.Architecture).word, Kind: inspect.CFIDebugFrame, Address: target.Address(section.Addr), Data: data,
		LoadBias: module.LoadBias, Source: source + " file .debug_frame via " + file.Proof,
	}, metadataRead)
}

func (finder *unwindCFIFinder) reserveFileMetadata(size uint64) error {
	if finder.fileBytes > maxUnwindFileBytes || size > maxUnwindFileBytes-finder.fileBytes {
		return fmt.Errorf("unwind file metadata exceeds %d bytes: %w", maxUnwindFileBytes, target.ErrOverflow)
	}
	finder.fileBytes += size
	return nil
}

func (c *Controller) showBacktrace(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	profile, count, err := unwindCommandArguments(rawArgs, 32, 1, 256, "backtrace")
	if err != nil {
		return err
	}
	seed, result, walkErr := c.collectUnwind(ctx, count, profile)
	first, _ := takeMemoryArgument(rawArgs)
	seed.abiExplicit = first == "--abi"
	if len(result.Frames) == 0 {
		return walkErr
	}
	text := c.backtraceText(seed, result)
	return c.publishUnwind(ctx, text, walkErr)
}

func (c *Controller) showStackFrame(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	profile, index, err := unwindCommandArguments(rawArgs, 0, 0, 255, "stackframe")
	if err != nil {
		return err
	}
	seed, result, walkErr := c.collectUnwind(ctx, index+1, profile)
	first, _ := takeMemoryArgument(rawArgs)
	seed.abiExplicit = first == "--abi"
	if len(result.Frames) == 0 {
		return walkErr
	}
	if index >= len(result.Frames) {
		return c.publishUnwind(ctx, c.backtraceText(seed, result), errors.Join(walkErr, fmt.Errorf("frame %d is not confirmed: %w", index, target.ErrUnavailable)))
	}
	return c.publishUnwind(ctx, c.stackFrameText(seed, result.Frames[index], index), stackFrameUnwindError(result, index, walkErr))
}

func stackFrameUnwindError(result inspect.UnwindResult, index int, walkErr error) error {
	if limit, ok := walkErr.(*inspect.UnwindLimitError); ok && index >= 0 && index < len(result.Frames) && result.Limited && limit.Limit == index+1 {
		return nil
	}
	return walkErr
}

func (c *Controller) publishUnwind(ctx context.Context, text string, walkErr error) error {
	if err := contextReady(ctx); err != nil {
		return errors.Join(walkErr, err)
	}
	return errors.Join(walkErr, c.writef("%s", text))
}

type unwindUILabelKey struct {
	pc       target.Address
	lookup   target.Address
	returned bool
}

type unwindUIView struct {
	arch     target.Architecture
	renderer display.Renderer
	width    int
	symbols  []inspect.Symbol
	ends     []target.Address
	modules  []*runtimeELFModule
	labels   map[unwindUILabelKey]string
}

func (c *Controller) newUnwindUIView(seed unwindCommandSeed) unwindUIView {
	view := unwindUIView{arch: seed.snapshot.Architecture, renderer: c.renderer, width: display.OutputWidth(c.out), labels: make(map[unwindUILabelKey]string), modules: seed.modules}
	symbols := seed.symbols
	if seed.symbolKey != newUISymbolCacheKey(seed.snapshot, seed.thread) {
		symbols = nil
	}
	for _, symbol := range symbols {
		if symbol.AddressKnown && symbol.Type == elf.STT_FUNC && symbol.Section != elf.SHN_ABS && symbol.Name != "" && (symbol.Size == 0 || symbol.Size-1 <= math.MaxUint64-uint64(symbol.Address)) {
			view.symbols = append(view.symbols, symbol)
		}
	}
	slices.SortFunc(view.symbols, func(a, b inspect.Symbol) int {
		if a.Address < b.Address {
			return -1
		}
		if a.Address > b.Address {
			return 1
		}
		return strings.Compare(a.ModuleID+"\x00"+a.Name+"\x00"+a.Version, b.ModuleID+"\x00"+b.Name+"\x00"+b.Version)
	})
	var end target.Address
	for _, symbol := range view.symbols {
		last := symbol.Address
		if symbol.Size != 0 {
			last += target.Address(symbol.Size - 1)
		}
		end = max(end, last)
		view.ends = append(view.ends, end)
	}
	return view
}

func (view unwindUIView) line(output *strings.Builder, text string) {
	output.WriteString(display.Wrap(text+"\n", view.width, 4))
}

func (view unwindUIView) section(output *strings.Builder, name string) {
	view.line(output, view.renderer.Section(name, view.width))
}

func (view unwindUIView) address(address target.Address) string {
	text, _ := view.renderer.Address(abiFor(view.arch).arch, address, display.AddressUnknown)
	return text
}

func (view unwindUIView) symbol(frame inspect.UnwindFrame) string {
	key := unwindUILabelKey{frame.PC, frame.LookupPC, frame.ReturnPC}
	if label, exists := view.labels[key]; exists {
		return label
	}
	var best string
	var bestExact bool
	end := sort.Search(len(view.symbols), func(i int) bool { return view.symbols[i].Address > frame.LookupPC })
	for i := end - 1; i >= 0 && view.ends[i] >= frame.LookupPC; i-- {
		symbol := view.symbols[i]
		if frame.LookupPC != symbol.Address && uint64(frame.LookupPC-symbol.Address) >= symbol.Size || frame.PC < symbol.Address {
			continue
		}
		label := symbol.Name
		if offset := uint64(frame.PC - symbol.Address); offset != 0 {
			label += fmt.Sprintf("+0x%x", offset)
		}
		exact := frame.LookupPC == symbol.Address
		if best == "" || exact && !bestExact || exact == bestExact && uiCompareSymbolLabels(label, best) < 0 {
			best, bestExact = label, exact
		}
	}
	view.labels[key] = best
	return best
}

func (view unwindUIView) frameModule(frame inspect.UnwindFrame) (*runtimeELFModule, bool) {
	var selected *runtimeELFModule
	for _, module := range view.modules {
		contains, err := unwindModuleContains(module, frame.LookupPC, 1, true)
		if err != nil || !contains {
			continue
		}
		if selected != nil {
			return nil, true
		}
		selected = module
	}
	return selected, false
}

func (view unwindUIView) module(frame inspect.UnwindFrame) string {
	selected, ambiguous := view.frameModule(frame)
	if ambiguous {
		return "<ambiguous module>"
	}
	if selected == nil {
		return ""
	}
	if selected.Main {
		return "main"
	}
	if selected.Name != "" {
		return filepath.Base(selected.Name)
	}
	return selected.ID
}

func (view unwindUIView) moduleOffset(frame inspect.UnwindFrame) string {
	module, ambiguous := view.frameModule(frame)
	if module == nil || ambiguous {
		return ""
	}
	base := uint64(math.MaxUint64)
	for _, program := range module.Programs {
		if program.Type != elf.PT_LOAD || program.Memsz == 0 || program.Vaddr > math.MaxUint64-module.LoadBias {
			continue
		}
		base = min(base, program.Vaddr+module.LoadBias)
	}
	if uint64(frame.PC) < base {
		return ""
	}
	return fmt.Sprintf("module:%s+0x%x", view.module(frame), uint64(frame.PC)-base)
}

func unwindUIElide(text string, width int) string {
	if display.VisibleWidth(text) <= width {
		return text
	}
	if width < 3 {
		return strings.Repeat(".", max(0, width))
	}
	var result strings.Builder
	for _, char := range text {
		if display.VisibleWidth(result.String()+string(char)) > width-3 {
			break
		}
		result.WriteRune(char)
	}
	return result.String() + "..."
}

func (view unwindUIView) frame(output *strings.Builder, frame inspect.UnwindFrame, index int) {
	marker, style := fmt.Sprintf("[ #%d]", index), display.StyleMuted
	if index == 0 {
		marker, style = "[*#0]", display.StyleCurrent
	}
	line := view.renderer.Text(style, marker) + " " + view.renderer.Text(display.StylePurple, view.address(frame.PC))
	suffix := ""
	if frame.Signal {
		suffix = " [signal]"
	}
	if module := view.module(frame); module != "" {
		suffix += " [" + contextEscapedText(module) + "]"
	}

	label := view.symbol(frame)
	if label == "" {
		label = view.moduleOffset(frame)
	}
	if label != "" {
		available := view.width - display.VisibleWidth(line) - display.VisibleWidth(suffix) - 3
		if available >= 3 {
			label = unwindUIElide(contextEscapedText(label), available)
			line += " " + view.renderer.Text(display.StyleSymbol, "<"+label+">")
		}
	}
	view.line(output, line+view.renderer.Text(display.StyleMuted, suffix))
}

func (view unwindUIView) identity(output *strings.Builder, seed unwindCommandSeed) {
	thread := "Thread <unavailable>"
	if seed.thread.Ref.ID != 0 {
		thread = fmt.Sprintf("Thread %d", seed.thread.Ref.ID)
	}
	if seed.thread.TID > 0 {
		thread += fmt.Sprintf(" (tid %d)", seed.thread.TID)
	}
	if seed.abiExplicit && seed.orc {
		thread += " | Unwinder: ORC"
	} else if seed.abiExplicit {
		thread += " | ABI: " + unwindProfileName(seed.profile) + " (explicit)"
	}
	view.line(output, thread)
}

func (view unwindUIView) breakpointNote(output *strings.Builder, seed unwindCommandSeed) {
	if seed.location.Breakpoint != nil && seed.location.RawPC != seed.location.InstructionPC {
		view.line(output, view.renderer.Text(display.StyleMuted, "Raw "+strings.ToUpper(abiFor(seed.snapshot.Architecture).pc)+": "+view.address(seed.location.RawPC)+" (software breakpoint)."))
	}
}

func (c *Controller) backtraceText(seed unwindCommandSeed, result inspect.UnwindResult) string {
	var output strings.Builder
	view := c.newUnwindUIView(seed)
	view.section(&output, "trace")
	view.identity(&output, seed)
	for index, frame := range result.Frames {
		view.frame(&output, frame, index)
	}
	if seed.symbolErr != nil {
		view.line(&output, view.renderer.Text(display.StyleMuted, "Symbols incomplete: "+contextEscapedText(seed.symbolErr.Error())))
	}
	summary := "Unwind incomplete: caller information unavailable."
	if result.Complete {
		return output.String()
	} else if result.Limited {
		summary = fmt.Sprintf("Unwind partial: frame limit reached (%d).", len(result.Frames))
	}
	view.line(&output, view.renderer.Text(display.StyleMuted, summary))
	return output.String()
}

func unwindProfileName(profile inspect.AMD64UnwindProfile) string {
	switch profile {
	case inspect.UnwindStrictCFI:
		return "strict-cfi"
	case inspect.UnwindSysVX86:
		return "sysv-x86"
	case inspect.UnwindSysVAMD64:
		return "sysv-amd64"
	default:
		return "<unavailable>"
	}
}

func unwindRegisterLabel(number uint64, architectures ...target.Architecture) string {
	if len(architectures) > 0 && architectures[0] == target.X86 {
		names := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"}
		if number < uint64(len(names)) {
			return "$" + names[number]
		}
		return fmt.Sprintf("DWARF #%d", number)
	}
	names := [...]string{"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}
	if number < uint64(len(names)) {
		return "$" + names[number]
	}
	return fmt.Sprintf("DWARF #%d", number)
}

func unwindUIRule(saved inspect.UnwindSavedRegister, architectures ...target.Architecture) string {
	switch saved.Rule {
	case "offset":
		return fmt.Sprintf("memory CFA%+d", saved.Offset)
	case "val_offset":
		return fmt.Sprintf("value CFA%+d", saved.Offset)
	case "same_value":
		return "same value"
	case "register":
		return "register " + unwindRegisterLabel(saved.SourceRegister, architectures...)
	case "expression":
		return "memory expression"
	case "val_expression":
		return "value expression"
	case "":
		return "unavailable"
	default:
		return contextEscapedText(saved.Rule)
	}
}

func (c *Controller) stackFrameText(seed unwindCommandSeed, frame inspect.UnwindFrame, index int) string {
	var output strings.Builder
	view := c.newUnwindUIView(seed)
	view.section(&output, fmt.Sprintf("stackframe #%d", index))
	view.identity(&output, seed)
	view.frame(&output, frame, index)
	if seed.symbolErr != nil {
		view.line(&output, view.renderer.Text(display.StyleMuted, "Symbols incomplete: "+contextEscapedText(seed.symbolErr.Error())))
	}
	if index == 0 {
		view.breakpointNote(&output, seed)
	}
	if frame.CFAKnown {
		rule := "DWARF expression"
		if !frame.CFAExpression {
			rule = fmt.Sprintf("%s %+d", unwindRegisterLabel(frame.CFARegister, seed.snapshot.Architecture), frame.CFAOffset)
		}
		if frame.CFARule != "" {
			rule = frame.CFARule
		}
		view.line(&output, "CFA: "+view.address(frame.CFA)+" ("+rule+")")
	} else {
		view.line(&output, "CFA: <unavailable>")
	}
	if frame.Start < frame.End {
		kind := "CFI"
		if frame.MetadataKind != "" {
			kind = frame.MetadataKind
		}
		view.line(&output, fmt.Sprintf("%s record: %#x | code [%s, %s)", kind, frame.FDE, view.address(frame.Start), view.address(frame.End)))
	}
	view.section(&output, "frame registers")
	for number := 0; number < unwindRegisterCount(seed.snapshot.Architecture); number += 2 {
		var columns []string
		for register := number; register < min(number+2, unwindRegisterCount(seed.snapshot.Architecture)); register++ {
			value := "<unavailable>"
			if frame.Registers.Known&(1<<register) != 0 {
				value = fmt.Sprintf("0x%0*x", abiFor(seed.snapshot.Architecture).word*2, frame.Registers.Values[register])
			}
			name := view.renderer.Text(display.StyleRegister, unwindRegisterLabel(uint64(register), seed.snapshot.Architecture))
			columns = append(columns, display.Pad(name, 7)+value)
		}
		line := columns[0]
		if len(columns) == 2 {
			line = display.Pad(line, 31) + columns[1]
		}
		view.line(&output, line)
	}
	view.section(&output, "caller recovery")
	if len(frame.Saved) == 0 {
		view.line(&output, "Caller recovery information unavailable.")
		return output.String()
	}
	view.line(&output, display.Pad("Register", 9)+display.Pad("Rule", 20)+display.Pad("Saved at / source", 21)+display.Pad("Caller value", 21)+"Origin")
	for _, saved := range frame.Saved {
		location, value, origin := "-", "<unavailable>", "-"
		if saved.AddressKnown {
			location = view.address(saved.Address)
		} else if saved.Rule == "register" {
			location = unwindRegisterLabel(saved.SourceRegister, seed.snapshot.Architecture)
		}
		if saved.Available {
			value = fmt.Sprintf("0x%0*x", abiFor(seed.snapshot.Architecture).word*2, saved.Value)
		}
		switch saved.Provenance {
		case "cfi":
			origin = "CFI"
		case "abi:sysv-amd64", "abi:sysv-x86":
			origin = "SysV"
		}
		name := view.renderer.Text(display.StyleRegister, unwindRegisterLabel(saved.Register, seed.snapshot.Architecture))
		view.line(&output, display.Pad(name, 9)+display.Pad(unwindUIRule(saved, seed.snapshot.Architecture), 20)+display.Pad(location, 21)+display.Pad(value, 21)+origin)
	}
	return output.String()
}

func unwindRegisterCount(arch target.Architecture) int {
	if arch == target.X86 {
		return 9
	}
	return 17
}
