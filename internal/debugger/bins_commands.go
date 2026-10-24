package debugger

import (
	"context"
	"errors"
	"fmt"
	"math"

	"fastdbg2/target"
)

type heapBinNode struct {
	address      target.Address
	data         []byte
	stored       uint64
	next         target.Address
	back         target.Address
	linked       bool
	chunkAddress target.Address
	chunkSize    uint64
	chunkKnown   bool
}

type heapBinObservation struct {
	index    uint64
	name     string
	fast     bool
	head     target.Address
	tail     target.Address
	sentinel target.Address
	nodes    []heapBinNode
	complete bool
	err      error
}

type heapBinsObservation struct {
	arena heapArenaObservation
	bins  []heapBinObservation
}

func heapChunkReadSize(input heapGraphInput, fast bool) uint64 {
	var size uint64
	for _, name := range []string{"mchunk_prev_size", "mchunk_size", "fd", "bk"} {
		if fast && name == "bk" {
			continue
		}
		if field, exists := input.layout.Chunk.Fields[name]; exists {
			size = max(size, field.Offset+field.Width)
		}
	}
	return size
}

func walkHeapBin(input heapGraphInput, bin heapBinObservation, owners map[target.Address]string) heapBinObservation {
	address := bin.head
	previous := bin.sentinel
	for {
		if !bin.fast && address == bin.sentinel {
			if previous != bin.tail {
				bin.err = fmt.Errorf("%s tail %#x differs from the observed predecessor %#x; observed inconsistency may be an in-progress allocator update: %w", bin.name, bin.tail, previous, target.ErrInvalidState)
			} else {
				bin.complete = true
			}
			return bin
		}
		if address == 0 {
			if bin.fast {
				bin.complete = true
			} else {
				bin.err = fmt.Errorf("%s reaches NULL before its sentinel; observed inconsistency may be an in-progress allocator update: %w", bin.name, target.ErrInvalidState)
			}
			return bin
		}
		if owner, exists := owners[address]; exists {
			bin.err = fmt.Errorf("%s repeats link target %#x already observed in %s; observed inconsistency may be an in-progress allocator update: %w", bin.name, address, owner, target.ErrInvalidState)
			return bin
		}
		if err := input.reader.takeNode(); err != nil {
			bin.err = err
			return bin
		}
		owners[address] = bin.name
		data, err := input.reader.read(address, heapChunkReadSize(input, bin.fast))
		node := heapBinNode{address: address, data: data}
		if err != nil {
			bin.nodes, bin.err = append(bin.nodes, node), err
			return bin
		}
		stored, forwardOK := heapGraphField(data, input.layout.Chunk.Fields["fd"], 0)
		var back uint64
		backOK := true
		if !bin.fast {
			back, backOK = heapGraphField(data, input.layout.Chunk.Fields["bk"], 0)
		}
		if !forwardOK || !backOK {
			bin.nodes = append(bin.nodes, node)
			bin.err = fmt.Errorf("%s link fields are unconfirmed at %#x: %w", bin.name, address, target.ErrPartial)
			return bin
		}
		forward := stored
		if bin.fast && input.layout.FastLink == "safe-link-12" {
			fieldOffset := input.layout.Chunk.Fields["fd"].Offset
			if fieldOffset > math.MaxUint64-uint64(address) {
				bin.nodes = append(bin.nodes, node)
				bin.err = fmt.Errorf("safe-link field address overflows at %#x: %w", address, target.ErrOverflow)
				return bin
			}
			forward ^= (uint64(address) + fieldOffset) >> 12
		}
		node.stored, node.next, node.back, node.linked = stored, target.Address(forward), target.Address(back), true
		bin.nodes = append(bin.nodes, node)
		if !bin.fast && node.back != previous {
			bin.err = fmt.Errorf("%s bk at %#x is %#x, not predecessor %#x; observed inconsistency may be an in-progress allocator update: %w", bin.name, address, node.back, previous, target.ErrInvalidState)
			return bin
		}
		previous, address = address, node.next
	}
}

func walkHeapBins(input heapGraphInput) (heapBinsObservation, error) {
	var result heapBinsObservation
	if err := input.reader.takeNode(); err != nil {
		return result, err
	}
	data, err := input.reader.read(input.address, input.layout.Arena.Size)
	result.arena = heapArenaObservation{input.address, data, err}
	if err != nil {
		return result, err
	}
	owners := make(map[target.Address]string)
	var combined error
	fast := input.layout.Arena.Fields["fastbinsY"]
	for index := uint64(0); index < fast.Count; index++ {
		value, ok := heapGraphField(data, fast, index)
		if !ok {
			return result, errors.Join(combined, fmt.Errorf("fastbinsY[%d] is unconfirmed: %w", index, target.ErrPartial))
		}
		bin := walkHeapBin(input, heapBinObservation{index: index, name: fmt.Sprintf("fastbinsY[%d]", index), fast: true, head: target.Address(value)}, owners)
		if heapGraphFatal(bin.err) {
			return heapBinsObservation{}, bin.err
		}
		result.bins = append(result.bins, bin)
		combined = errors.Join(combined, bin.err)
		if input.reader.exhausted {
			return result, errors.Join(combined, fmt.Errorf("bin traversal reached the global inspection budget: %w", target.ErrUnavailable))
		}
	}
	normal := input.layout.Arena.Fields["bins"]
	for index := uint64(0); index < normal.Count/2; index++ {
		head, headOK := heapGraphField(data, normal, index*2)
		tail, tailOK := heapGraphField(data, normal, index*2+1)
		if !headOK || !tailOK {
			return result, errors.Join(combined, fmt.Errorf("bins pair %d is unconfirmed: %w", index+1, target.ErrPartial))
		}
		offset := normal.Offset + index*2*normal.Stride
		fdOffset := input.layout.Chunk.Fields["fd"].Offset
		if offset > math.MaxUint64-uint64(input.address) || uint64(input.address)+offset < fdOffset {
			return result, errors.Join(combined, fmt.Errorf("normal bin %d sentinel address overflows: %w", index+1, target.ErrOverflow))
		}
		sentinel := target.Address(uint64(input.address) + offset - fdOffset)
		bin := walkHeapBin(input, heapBinObservation{index: index + 1, name: fmt.Sprintf("normal-bin[%d]", index+1), head: target.Address(head), tail: target.Address(tail), sentinel: sentinel}, owners)
		if heapGraphFatal(bin.err) {
			return heapBinsObservation{}, bin.err
		}
		result.bins = append(result.bins, bin)
		combined = errors.Join(combined, bin.err)
		if input.reader.exhausted {
			return result, errors.Join(combined, fmt.Errorf("bin traversal reached the global inspection budget: %w", target.ErrUnavailable))
		}
	}
	return result, combined
}

func (c *Controller) showBins(ctx context.Context, rawArgs string) error {
	if !heapExplicitMode(rawArgs) {
		return c.showAutomaticBins(ctx, rawArgs)
	}
	arguments, err := parseHeapGraphArguments(rawArgs, false)
	if err != nil {
		return err
	}
	var input heapGraphInput
	var observation heapBinsObservation
	var tcache *heapTcacheObservation
	err = c.withHeapGraphInput(ctx, arguments, func(value heapGraphInput) error {
		input = value
		var err error
		observation, err = walkHeapBins(value)
		if value.tcacheAddress != nil && !heapGraphFatal(err) && !value.reader.exhausted {
			result, tcacheErr := walkHeapTcache(value, *value.tcacheAddress)
			tcache = &result
			err = errors.Join(err, tcacheErr)
		}
		return err
	})
	if heapGraphFatal(err) || input.reader == nil {
		return err
	}
	if outputErr := c.heapGraphHeading(ctx, "bins", input); outputErr != nil {
		return errors.Join(err, outputErr)
	}
	if outputErr := c.heapGraphWritef(ctx, "arena=0x%0*x (%d/%d confirmed bytes).\n", c.abi().word*2, input.address, len(observation.arena.data), input.layout.Arena.Size); outputErr != nil {
		return errors.Join(err, outputErr)
	}
	if input.tcacheAddress == nil {
		if outputErr := c.heapGraphWritef(ctx, "tcache is not inspected (not-requested).\n"); outputErr != nil {
			return errors.Join(err, outputErr)
		}
	} else if tcache != nil {
		text, formatErr := formatHeapTcache(ctx, input, *tcache, c.renderer, true)
		if formatErr != nil {
			return errors.Join(err, formatErr)
		}
		if outputErr := c.heapGraphWritef(ctx, "%s", text); outputErr != nil {
			return errors.Join(err, outputErr)
		}
	} else if outputErr := c.heapGraphWritef(ctx, "tcache=0x%0*x was not inspected after the global budget was exhausted.\n", c.abi().word*2, *input.tcacheAddress); outputErr != nil {
		return errors.Join(err, outputErr)
	}
	for _, bin := range observation.bins {
		if outputErr := c.heapGraphWritef(ctx, "%s head=0x%0*x", bin.name, c.abi().word*2, bin.head); outputErr != nil {
			return errors.Join(err, outputErr)
		}
		if !bin.fast {
			if outputErr := c.heapGraphWritef(ctx, " tail=0x%0*x sentinel=0x%0*x", c.abi().word*2, bin.tail, c.abi().word*2, bin.sentinel); outputErr != nil {
				return errors.Join(err, outputErr)
			}
		}
		if outputErr := c.heapGraphWritef(ctx, " nodes=%d complete=%t\n", len(bin.nodes), bin.complete); outputErr != nil {
			return errors.Join(err, outputErr)
		}
		for _, node := range bin.nodes {
			if outputErr := c.heapGraphWritef(ctx, "  0x%0*x", c.abi().word*2, node.address); outputErr != nil {
				return errors.Join(err, outputErr)
			}
			if node.linked {
				if outputErr := c.heapGraphWritef(ctx, " fd.stored=0x%0*x next=0x%0*x", input.layout.Pointer*2, node.stored, c.abi().word*2, node.next); outputErr != nil {
					return errors.Join(err, outputErr)
				}
				if !bin.fast {
					if outputErr := c.heapGraphWritef(ctx, " bk=0x%0*x", c.abi().word*2, node.back); outputErr != nil {
						return errors.Join(err, outputErr)
					}
				}
			} else if outputErr := c.heapGraphWritef(ctx, " <incomplete node: %d confirmed bytes>", len(node.data)); outputErr != nil {
				return errors.Join(err, outputErr)
			}
			if field, exists := input.layout.Chunk.Fields["mchunk_size"]; exists {
				if value, ok := heapGraphField(node.data, field, 0); ok {
					if outputErr := c.heapGraphWritef(ctx, " mchunk_size.raw=0x%x", value); outputErr != nil {
						return errors.Join(err, outputErr)
					}
				}
			}
			if outputErr := c.heapGraphWritef(ctx, "\n"); outputErr != nil {
				return errors.Join(err, outputErr)
			}
		}
		if bin.err != nil {
			if outputErr := c.heapGraphWritef(ctx, "  <incomplete: %q>\n", bin.err.Error()); outputErr != nil {
				return errors.Join(err, outputErr)
			}
		}
	}
	if outputErr := c.heapGraphWritef(ctx, "observed-nodes=%d requested-bytes=%d\n", input.reader.nodes, input.reader.bytes); outputErr != nil {
		return errors.Join(err, outputErr)
	}
	return err
}
