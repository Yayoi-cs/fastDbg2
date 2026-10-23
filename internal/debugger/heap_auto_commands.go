package debugger

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

type heapAutomaticArguments struct {
	all     bool
	arena   string
	verbose bool
	noPager bool
}

type heapAutomaticObservation struct {
	allocator *allocatorContext
	input     heapGraphInput
	arenas    []heapBinsObservation
	tcache    *heapTcacheObservation
	members   map[target.Address][]heapVisualMembership
}

func heapExplicitMode(rawArgs string) bool {
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return false
	}
	for _, argument := range args {
		switch argument {
		case "--layout", "--layout-file", "--module", "--debug-file", "--fast-link", "--tcache", "--words":
			return true
		}
	}
	return false
}

func parseAutomaticHeapArguments(rawArgs string, visual bool) (heapAutomaticArguments, error) {
	var result heapAutomaticArguments
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return result, fmt.Errorf("heap command arguments: %w: %w", err, target.ErrInvalidArgument)
	}
	seen := make(map[string]bool)
	for len(args) != 0 {
		name := args[0]
		args = args[1:]
		switch name {
		case "-a", "--arena", "--arena-addr":
			name = "arena"
			if len(args) == 0 || strings.TrimSpace(args[0]) == "" || strings.HasPrefix(args[0], "--") {
				return result, fmt.Errorf("--arena requires one address expression, quoted if it contains spaces: %w", target.ErrInvalidArgument)
			}
			result.arena, args = args[0], args[1:]
		case "--all":
			if visual {
				return result, fmt.Errorf("visual-heap accepts one arena, not --all: %w", target.ErrInvalidArgument)
			}
			result.all = true
		case "-v", "--verbose":
			if visual {
				return result, fmt.Errorf("--verbose applies to bins: %w", target.ErrInvalidArgument)
			}
			name, result.verbose = "verbose", true
		case "-n", "--no-pager":
			name, result.noPager = "no-pager", true
		default:
			return result, fmt.Errorf("unsupported heap argument %q: %w", name, target.ErrInvalidArgument)
		}
		if seen[name] {
			return result, fmt.Errorf("duplicate heap option %q: %w", name, target.ErrInvalidArgument)
		}
		seen[name] = true
	}
	if result.all && result.arena != "" {
		return result, fmt.Errorf("--all and --arena are mutually exclusive: %w", target.ErrInvalidArgument)
	}
	return result, nil
}

func (c *Controller) withAutomaticHeap(ctx context.Context, arguments heapAutomaticArguments, visit func(*allocatorContext, heapGraphInput) error) error {
	resolver := &lazyInspectionResolver{controller: c, ctx: ctx}
	if err := resolver.initialize(); err != nil {
		return err
	}
	var inspectionErr error
	proofErr := c.withAllocatorContext(ctx, resolver.snapshot, resolver.thread, func(allocator *allocatorContext) error {
		address := allocator.MainArena
		if arguments.arena != "" {
			value, err := inspect.EvalExpression(arguments.arena, resolver)
			if err != nil {
				return err
			}
			address = target.Address(value)
		}
		input := heapGraphInput{
			layout: allocator.Layout, address: address, proof: allocator.Proof,
			reader:    newHeapGraphReader(ctx, c.session, resolver.snapshot.Memory),
			alignment: allocator.Alignment,
		}
		if arguments.arena != "" {
			input.proof += fmt.Sprintf(" user-selected arena expression=%q", arguments.arena)
		}
		inspectionErr = visit(allocator, input)
		return nil
	})
	if proofErr != nil {
		return &heapGraphProofError{errors.Join(proofErr, inspectionErr)}
	}
	return inspectionErr
}

func heapPolicyForAllocator(allocator *allocatorContext) (heapBinPolicy, error) {
	if allocator == nil {
		return heapBinPolicy{}, target.ErrInvalidArgument
	}
	policy := heapBinPolicy{
		Alignment: allocator.Alignment, MinChunkSize: allocator.MinChunkSize,
		SmallBinCount: allocator.SmallBinCount, NormalBinCount: allocator.NormalBinCount,
		FastBinShift: allocator.FastBinShift, TcacheSmallBinCount: allocator.TcacheSmallBinCount,
		TcacheLargeBinCount: allocator.TcacheLargeBinCount,
	}
	if err := policy.validate(); err != nil {
		return heapBinPolicy{}, err
	}
	if allocator.ChunkHeaderSize != 16 || allocator.SizeFlags != 7 || allocator.Layout.Tcache == nil || allocator.Layout.TcacheEntry == nil {
		return heapBinPolicy{}, fmt.Errorf("allocator chunk or tcache ABI is not proven: %w", target.ErrUnsupported)
	}
	mode := allocator.Semantics.TcacheCounterMode
	if mode != "counts" && mode != "num_slots" {
		return heapBinPolicy{}, fmt.Errorf("allocator counter semantics %q are not proven: %w", mode, target.ErrUnsupported)
	}
	counter, counterKnown := allocator.Layout.Tcache.Fields[mode]
	if !counterKnown || counter.Count != policy.TcacheSmallBinCount+policy.TcacheLargeBinCount || allocator.Layout.Tcache.Fields["entries"].Count != counter.Count {
		return heapBinPolicy{}, fmt.Errorf("allocator tcache layout and source semantics differ: %w", target.ErrInvalidArgument)
	}
	fast, fastPresent := allocator.Layout.Arena.Fields["fastbinsY"]
	if fastPresent != (policy.FastBinShift != 0) || fastPresent && fast.Count == 0 {
		return heapBinPolicy{}, fmt.Errorf("allocator fastbin layout and source semantics differ: %w", target.ErrInvalidArgument)
	}
	return policy, nil
}

func validateAutomaticTcache(allocator *allocatorContext, input heapGraphInput, observation *heapTcacheObservation) error {
	policy, err := heapPolicyForAllocator(allocator)
	if err != nil {
		return err
	}
	var combined error
	for index := range observation.bins {
		bin := &observation.bins[index]
		bin.sizeMin, bin.sizeMax, _ = policy.tcacheRange(bin.index)
		if bin.counterKnown && bin.counterName == allocator.Semantics.TcacheCounterMode && bin.counter > allocator.Parameters.TcacheCount {
			bin.err = errors.Join(bin.err, fmt.Errorf("tcache[%d] %s=%d exceeds mp_.tcache_count=%d; observed inconsistency may be an in-progress allocator update: %w", bin.index, bin.counterName, bin.counter, allocator.Parameters.TcacheCount, target.ErrInvalidState))
		}
		var previous uint64
		for nodeIndex := range bin.nodes {
			if err := contextReady(input.reader.ctx); err != nil {
				return err
			}
			node := &bin.nodes[nodeIndex]
			if !node.linked {
				continue
			}
			if uint64(node.address)%allocator.Alignment != 0 || uint64(node.address) < allocator.ChunkHeaderSize {
				bin.err = errors.Join(bin.err, fmt.Errorf("tcache[%d] entry %#x violates the proven allocator alignment/header extent: %w", bin.index, node.address, target.ErrInvalidState))
				continue
			}
			address := node.address - target.Address(allocator.ChunkHeaderSize)
			data, err := input.reader.read(address, allocator.ChunkHeaderSize)
			if heapGraphFatal(err) {
				return err
			}
			bin.err = errors.Join(bin.err, err)
			if err != nil {
				if input.reader.exhausted {
					return errors.Join(combined, bin.err)
				}
				continue
			}
			raw, ok := heapGraphField(data, input.layout.Chunk.Fields["mchunk_size"], 0)
			if !ok {
				bin.err = errors.Join(bin.err, fmt.Errorf("tcache[%d] chunk header at %#x is incomplete: %w", bin.index, address, target.ErrPartial))
				continue
			}
			size := raw &^ allocator.SizeFlags
			node.chunkAddress, node.chunkSize, node.chunkKnown = address, size, true
			class, valid := policy.tcacheIndex(size)
			if !valid || class != bin.index || raw&2 != 0 {
				bin.err = errors.Join(bin.err, fmt.Errorf("tcache[%d] observed chunk %#x raw-size=%#x does not match its proven size class or non-mmapped requirement; allocator update may be in progress: %w", bin.index, address, raw, target.ErrInvalidState))
			}
			if bin.index >= policy.TcacheSmallBinCount && previous > size {
				bin.err = errors.Join(bin.err, fmt.Errorf("large tcache[%d] sizes decrease from %#x to %#x; observed ordering may be an in-progress allocator update: %w", bin.index, previous, size, target.ErrInvalidState))
			}
			previous = size
		}
		combined = errors.Join(combined, bin.err)
		if bin.err != nil {
			bin.complete = false
		}
	}
	return combined
}

func validateAutomaticBins(allocator *allocatorContext, input heapGraphInput, observation *heapBinsObservation) error {
	policy, err := heapPolicyForAllocator(allocator)
	if err != nil {
		return err
	}
	var combined error
	for index := range observation.bins {
		bin := &observation.bins[index]
		for _, node := range bin.nodes {
			if err := contextReady(input.reader.ctx); err != nil {
				return err
			}
			if !node.linked {
				continue
			}
			raw, ok := heapGraphField(node.data, input.layout.Chunk.Fields["mchunk_size"], 0)
			if !ok {
				bin.err = errors.Join(bin.err, fmt.Errorf("%s chunk size at %#x is unconfirmed: %w", bin.name, node.address, target.ErrPartial))
				continue
			}
			size := raw &^ allocator.SizeFlags
			valid := size >= allocator.MinChunkSize && size%allocator.Alignment == 0 && raw&2 == 0 && uint64(node.address)%allocator.Alignment == 0 && size <= math.MaxUint64-uint64(node.address)
			if bin.fast {
				index, classOK := policy.fastIndex(size, input.layout.Arena.Fields["fastbinsY"].Count)
				valid = valid && classOK && index == bin.index
			} else {
				switch policy.normalName(bin.index) {
				case "small":
					valid = valid && size == bin.index*allocator.Alignment
				case "large":
					valid = valid && size >= policy.SmallBinCount*policy.Alignment && policy.largeIndex(size) == bin.index
				case "reserved":
					valid = false
				}
			}
			if !valid {
				bin.err = errors.Join(bin.err, fmt.Errorf("%s observed node %#x raw-size=%#x violates its proven arena-bin class; allocator update may be in progress: %w", bin.name, node.address, raw, target.ErrInvalidState))
			}
		}
		if bin.err != nil {
			bin.complete = false
		}
		combined = errors.Join(combined, bin.err)
	}
	return combined
}

func collectAutomaticHeap(allocator *allocatorContext, input heapGraphInput, all bool) (heapAutomaticObservation, error) {
	policy, err := heapPolicyForAllocator(allocator)
	if err != nil {
		return heapAutomaticObservation{}, err
	}
	result := heapAutomaticObservation{allocator: allocator, input: input, members: make(map[target.Address][]heapVisualMembership)}
	var combined error
	if allocator.TcacheState == "active" && allocator.Tcache != 0 {
		tcache, err := walkHeapTcache(input, allocator.Tcache)
		if heapGraphFatal(err) {
			return heapAutomaticObservation{}, err
		}
		err = errors.Join(err, validateAutomaticTcache(allocator, input, &tcache))
		if heapGraphFatal(err) {
			return heapAutomaticObservation{}, err
		}
		for index := range tcache.bins {
			bin := &tcache.bins[index]
			bin.sizeMin, bin.sizeMax, _ = policy.tcacheRange(bin.index)
			for _, node := range bin.nodes {
				if !node.linked || !node.chunkKnown {
					continue
				}
				address := node.chunkAddress
				label := fmt.Sprintf("tcache[%d] thread=%d TID=%d", bin.index, allocator.ThreadRef.ID, allocator.TID)
				result.members[address] = append(result.members[address], heapVisualMembership{Label: label, Complete: bin.complete && bin.err == nil})
			}
		}
		result.tcache = &tcache
		combined = errors.Join(combined, err)
	}
	addresses := []target.Address{input.address}
	if all {
		arenas, err := walkHeapArenas(input, true)
		if heapGraphFatal(err) {
			return heapAutomaticObservation{}, err
		}
		combined = errors.Join(combined, err)
		addresses = nil
		for _, arena := range arenas {
			addresses = append(addresses, arena.address)
		}
	}
	for _, address := range addresses {
		if input.reader.exhausted {
			return result, errors.Join(combined, fmt.Errorf("heap traversal exhausted its global budget before arena %#x: %w", address, target.ErrUnavailable))
		}
		arenaInput := input
		arenaInput.address = address
		data, readErr := input.reader.read(address, input.layout.Arena.Size)
		if heapGraphFatal(readErr) {
			return heapAutomaticObservation{}, readErr
		}
		top, topKnown := heapGraphField(data, input.layout.Arena.Fields["top"], 0)
		if readErr == nil && topKnown && top == 0 {
			if err := input.reader.takeNode(); err != nil {
				return result, errors.Join(combined, err)
			}
			result.arenas = append(result.arenas, heapBinsObservation{arena: heapArenaObservation{address: address, data: data}})
			continue
		}
		observation, err := walkHeapBins(arenaInput)
		if heapGraphFatal(err) {
			return heapAutomaticObservation{}, err
		}
		err = errors.Join(err, validateAutomaticBins(allocator, arenaInput, &observation))
		if heapGraphFatal(err) {
			return heapAutomaticObservation{}, err
		}
		for _, bin := range observation.bins {
			for _, node := range bin.nodes {
				if !node.linked {
					continue
				}
				label := fmt.Sprintf("%s[%d] arena=0x%x", policy.normalName(bin.index), bin.index, address)
				if bin.fast {
					label = fmt.Sprintf("fastbin[%d] arena=0x%x", bin.index, address)
				}
				result.members[node.address] = append(result.members[node.address], heapVisualMembership{Label: label, Complete: bin.complete})
			}
		}
		result.arenas = append(result.arenas, observation)
		combined = errors.Join(combined, readErr, err)
	}
	return result, combined
}

func formatAutomaticBins(ctx context.Context, observation heapAutomaticObservation, renderer display.Renderer, verbose bool) (string, error) {
	policy, err := heapPolicyForAllocator(observation.allocator)
	if err != nil {
		return "", err
	}
	var output strings.Builder
	allocator, input := observation.allocator, observation.input
	fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleHeading, "[glibc bins]"))
	fmt.Fprintf(&output, "selected thread=%d TID=%d; tcache is thread-local and is displayed separately from arenas.\n", allocator.ThreadRef.ID, allocator.TID)
	if observation.tcache != nil {
		text, err := formatHeapTcache(ctx, input, *observation.tcache, renderer, verbose)
		if err != nil {
			return "", err
		}
		output.WriteString(text)
	} else {
		fmt.Fprintf(&output, "%s\ntcache=0x%016x state=%s\n", renderer.Text(display.StyleHeading, "[tcache]"), allocator.Tcache, strconv.Quote(allocator.TcacheState))
	}
	for _, arena := range observation.arenas {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		kind := "arena"
		if arena.arena.address == allocator.MainArena {
			kind = "main_arena"
		}
		address, _ := renderer.Address(target.AMD64, arena.arena.address, display.AddressHeap)
		fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleHeading, fmt.Sprintf("[%s %s]", kind, address)))
		top, topKnown := heapGraphField(arena.arena.data, input.layout.Arena.Fields["top"], 0)
		if topKnown {
			fmt.Fprintf(&output, "top=0x%016x\n", top)
		}
		if topKnown && top == 0 && len(arena.bins) == 0 {
			output.WriteString("Arena initialization is not complete; no bin-chain emptiness is inferred.\n")
			continue
		}
		for _, group := range []string{"fast", "unsorted", "small", "large", "reserved"} {
			if group == "reserved" && !verbose {
				present := false
				for _, bin := range arena.bins {
					present = present || !bin.fast && policy.normalName(bin.index) == group && (!bin.complete || len(bin.nodes) != 0)
				}
				if !present {
					continue
				}
			}
			fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleHeading, "["+group+" bins]"))
			if group == "fast" {
				if _, exists := input.layout.Arena.Fields["fastbinsY"]; !exists {
					output.WriteString("  (not present in this allocator build)\n")
					continue
				}
			}
			shown, total := 0, 0
			for _, bin := range arena.bins {
				if err := contextReady(ctx); err != nil {
					return "", err
				}
				belongs := bin.fast && group == "fast" || !bin.fast && policy.normalName(bin.index) == group
				if !belongs {
					continue
				}
				total++
				if !verbose && bin.complete && len(bin.nodes) == 0 {
					continue
				}
				shown++
				index := bin.index
				if !bin.fast && index != 0 {
					index--
				}
				fmt.Fprintf(&output, "  %s[idx=%d", group, index)
				if !bin.fast {
					fmt.Fprintf(&output, " bin=%d", bin.index)
				}
				if group == "small" {
					fmt.Fprintf(&output, " size=0x%x", bin.index*allocator.Alignment)
				} else if group == "fast" {
					if size, ok := policy.fastRange(bin.index, input.layout.Arena.Fields["fastbinsY"].Count); ok {
						fmt.Fprintf(&output, " size=0x%x", size)
					}
				} else if group == "large" {
					if minimum, maximum, ok := policy.largeRange(bin.index); ok {
						fmt.Fprintf(&output, " size=0x%x-0x%x", minimum, maximum)
					}
				}
				fmt.Fprintf(&output, "] head=0x%016x observed=%d complete=%t\n", bin.head, len(bin.nodes), bin.complete)
				for _, node := range bin.nodes {
					address, _ := renderer.Address(target.AMD64, node.address, display.AddressHeap)
					fmt.Fprintf(&output, "    -> %s", address)
					if value, ok := heapGraphField(node.data, input.layout.Chunk.Fields["mchunk_size"], 0); ok {
						fmt.Fprintf(&output, " size=0x%x", value&^allocator.SizeFlags)
					}
					if node.linked {
						if bin.fast {
							fmt.Fprintf(&output, " fd.stored=0x%016x next=0x%016x", node.stored, node.next)
						} else {
							fmt.Fprintf(&output, " fd=0x%016x bk=0x%016x", node.next, node.back)
						}
					} else {
						fmt.Fprintf(&output, " <incomplete: %d confirmed bytes>", len(node.data))
					}
					output.WriteByte('\n')
				}
				if bin.err != nil {
					fmt.Fprintf(&output, "    <incomplete: %q>\n", bin.err.Error())
				}
			}
			if shown == 0 {
				if total == 0 {
					output.WriteString("  (not examined)\n")
				} else {
					fmt.Fprintf(&output, "  (%d observed empty lists)\n", total)
				}
			}
		}
	}
	return output.String(), contextReady(ctx)
}

func (c *Controller) publishAutomaticHeap(ctx context.Context, text string, inspectionErr error, noPager bool) error {
	if heapGraphFatal(inspectionErr) || contextReady(ctx) != nil {
		return errors.Join(inspectionErr, contextReady(ctx))
	}
	if text == "" {
		return inspectionErr
	}
	if noPager {
		return errors.Join(inspectionErr, c.heapGraphWritef(ctx, "%s", text))
	}
	return errors.Join(inspectionErr, c.publishPaged(ctx, text), contextReady(ctx))
}

func (c *Controller) showAutomaticBins(ctx context.Context, rawArgs string) error {
	arguments, err := parseAutomaticHeapArguments(rawArgs, false)
	if err != nil {
		return err
	}
	var observation heapAutomaticObservation
	err = c.withAutomaticHeap(ctx, arguments, func(allocator *allocatorContext, input heapGraphInput) error {
		var err error
		observation, err = collectAutomaticHeap(allocator, input, arguments.all)
		return err
	})
	if heapGraphFatal(err) || observation.allocator == nil {
		return err
	}
	text, formatErr := formatAutomaticBins(ctx, observation, c.renderer, arguments.verbose)
	return c.publishAutomaticHeap(ctx, text, errors.Join(err, formatErr), arguments.noPager)
}

func (c *Controller) showAutomaticArenas(ctx context.Context, rawArgs string) error {
	arguments, err := parseAutomaticHeapArguments(rawArgs, false)
	if err != nil {
		return err
	}
	if arguments.verbose {
		return fmt.Errorf("arena supports --all, --arena ADDRESS and --no-pager: %w", target.ErrInvalidArgument)
	}
	var allocator *allocatorContext
	var input heapGraphInput
	var arenas []heapArenaObservation
	err = c.withAutomaticHeap(ctx, arguments, func(value *allocatorContext, graph heapGraphInput) error {
		allocator, input = value, graph
		var err error
		arenas, err = walkHeapArenas(graph, arguments.all || arguments.arena == "")
		return err
	})
	if heapGraphFatal(err) || allocator == nil || len(arenas) == 0 {
		return err
	}
	var output strings.Builder
	fmt.Fprintf(&output, "%s\n", c.renderer.Text(display.StyleHeading, "[arenas]"))
	fmt.Fprintf(&output, "selected thread=%d TID=%d; * marks its thread_arena TLS value, attached is a raw allocator counter.\n", allocator.ThreadRef.ID, allocator.TID)
	output.WriteString("  Kind        Arena              Top                System memory      Attached  Next\n")
	for _, arena := range arenas {
		if err := contextReady(ctx); err != nil {
			return err
		}
		marker, kind := " ", "arena"
		if arena.address == allocator.ThreadArena {
			marker = "*"
		}
		if arena.address == allocator.MainArena {
			kind = "main_arena"
		}
		values := make([]string, 4)
		for index, name := range []string{"top", "system_mem", "attached_threads", "next"} {
			values[index] = "<unconfirmed>"
			if field, ok := input.layout.Arena.Fields[name]; ok {
				if value, confirmed := heapGraphField(arena.data, field, 0); confirmed {
					if name == "attached_threads" {
						values[index] = strconv.FormatUint(value, 10)
					} else {
						values[index] = fmt.Sprintf("0x%016x", value)
					}
				}
			}
		}
		address, _ := c.renderer.Address(target.AMD64, arena.address, display.AddressHeap)
		fmt.Fprintf(&output, "%s %-11s %s %s %s %-9s %s\n", marker, kind, address, values[0], values[1], values[2], values[3])
	}
	fmt.Fprintf(&output, "observed-arenas=%d\n", len(arenas))
	return c.publishAutomaticHeap(ctx, output.String(), err, arguments.noPager)
}

func (c *Controller) showAutomaticVisualHeap(ctx context.Context, rawArgs string) error {
	arguments, err := parseAutomaticHeapArguments(rawArgs, true)
	if err != nil {
		return err
	}
	var observation heapVisualObservation
	var empty string
	err = c.withAutomaticHeap(ctx, arguments, func(allocator *allocatorContext, input heapGraphInput) error {
		extents, err := allocator.HeapExtents(input.address)
		if err != nil {
			return err
		}
		if len(extents) == 0 {
			empty = "[visual-heap]\nNo initialized heap extent was observed for this arena.\n"
			return nil
		}
		bins, binErr := collectAutomaticHeap(allocator, input, false)
		if heapGraphFatal(binErr) {
			return binErr
		}
		regions := make([]heapVisualExtent, len(extents))
		for index, extent := range extents {
			regions[index] = heapVisualExtent{Base: extent.Base, Start: extent.Start, End: extent.End, Top: extent.Top, Arena: extent.Arena, Label: extent.Label, TerminalFencepost: extent.TerminalFencepost}
		}
		observation, err = collectHeapVisual(input, regions, bins.members)
		return errors.Join(binErr, err)
	})
	if heapGraphFatal(err) {
		return err
	}
	if empty != "" {
		return c.publishAutomaticHeap(ctx, empty, err, arguments.noPager)
	}
	text, formatErr := renderHeapVisual(ctx, observation, c.renderer)
	return c.publishAutomaticHeap(ctx, text, errors.Join(err, formatErr), arguments.noPager)
}
