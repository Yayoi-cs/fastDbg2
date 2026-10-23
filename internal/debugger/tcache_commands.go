package debugger

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"fastdbg2/display"
	"fastdbg2/target"
)

type heapTcacheBin struct {
	index        uint64
	head         target.Address
	headKnown    bool
	counter      uint64
	counterName  string
	counterKnown bool
	nodes        []heapBinNode
	complete     bool
	err          error
	sizeMin      uint64
	sizeMax      uint64
}

type heapTcacheObservation struct {
	address target.Address
	data    []byte
	bins    []heapTcacheBin
	err     error
}

func heapTcacheReadSize(input heapGraphInput) uint64 {
	var size uint64
	for _, name := range []string{"next", "key"} {
		if field, ok := input.layout.TcacheEntry.Fields[name]; ok {
			size = max(size, field.Offset+field.Width)
		}
	}
	return size
}

func walkHeapTcacheBin(input heapGraphInput, bin heapTcacheBin, owners map[target.Address]uint64) heapTcacheBin {
	address := bin.head
	for address != 0 {
		if input.alignment != 0 && uint64(address)%input.alignment != 0 {
			bin.err = fmt.Errorf("tcache[%d] entry %#x violates proven alignment %d; observed inconsistency may be an in-progress allocator update: %w", bin.index, address, input.alignment, target.ErrInvalidState)
			return bin
		}
		if previous, exists := owners[address]; exists {
			bin.err = fmt.Errorf("tcache[%d] repeats entry %#x already observed in tcache[%d]; observed inconsistency may be an in-progress allocator update: %w", bin.index, address, previous, target.ErrInvalidState)
			return bin
		}
		if err := input.reader.takeNode(); err != nil {
			bin.err = err
			return bin
		}
		owners[address] = bin.index
		data, err := input.reader.read(address, heapTcacheReadSize(input))
		node := heapBinNode{address: address, data: data}
		if err != nil {
			bin.nodes, bin.err = append(bin.nodes, node), err
			return bin
		}
		field := input.layout.TcacheEntry.Fields["next"]
		stored, ok := heapGraphField(data, field, 0)
		if !ok {
			bin.nodes = append(bin.nodes, node)
			bin.err = fmt.Errorf("tcache[%d] next field at %#x is unconfirmed: %w", bin.index, address, target.ErrPartial)
			return bin
		}
		next := stored
		if input.layout.TcacheLink == "safe-link-12" {
			if field.Offset > math.MaxUint64-uint64(address) {
				bin.nodes = append(bin.nodes, node)
				bin.err = fmt.Errorf("tcache next field address overflows at %#x: %w", address, target.ErrOverflow)
				return bin
			}
			next ^= (uint64(address) + field.Offset) >> 12
		}
		node.stored, node.next, node.linked = stored, target.Address(next), true
		bin.nodes = append(bin.nodes, node)
		address = node.next
	}
	bin.complete = true
	return bin
}

func walkHeapTcache(input heapGraphInput, address target.Address) (heapTcacheObservation, error) {
	result := heapTcacheObservation{address: address}
	if input.layout.Tcache == nil || input.layout.TcacheEntry == nil {
		return result, fmt.Errorf("tcache layout is unavailable: %w", target.ErrUnavailable)
	}
	if err := input.reader.takeNode(); err != nil {
		return result, err
	}
	data, rootErr := input.reader.read(address, input.layout.Tcache.Size)
	if heapGraphFatal(rootErr) {
		return heapTcacheObservation{}, rootErr
	}
	result.data, result.err = data, rootErr
	entries := input.layout.Tcache.Fields["entries"]
	counterName := ""
	for _, name := range []string{"counts", "num_slots"} {
		if _, ok := input.layout.Tcache.Fields[name]; ok {
			counterName = name
		}
	}
	owners := make(map[target.Address]uint64)
	combined := rootErr
	for index := uint64(0); index < entries.Count; index++ {
		if err := contextReady(input.reader.ctx); err != nil {
			return heapTcacheObservation{}, errors.Join(combined, err)
		}
		head, headKnown := heapGraphField(data, entries, index)
		bin := heapTcacheBin{index: index, head: target.Address(head), headKnown: headKnown, counterName: counterName}
		if counterName != "" {
			bin.counter, bin.counterKnown = heapGraphField(data, input.layout.Tcache.Fields[counterName], index)
		}
		if rootErr == nil && headKnown {
			bin = walkHeapTcacheBin(input, bin, owners)
			if heapGraphFatal(bin.err) {
				return heapTcacheObservation{}, bin.err
			}
			combined = errors.Join(combined, bin.err)
		}
		result.bins = append(result.bins, bin)
		if input.reader.exhausted {
			break
		}
	}
	return result, combined
}

func formatHeapTcache(ctx context.Context, input heapGraphInput, observation heapTcacheObservation, renderer display.Renderer, verbose bool) (string, error) {
	var output strings.Builder
	if err := contextReady(ctx); err != nil {
		return "", err
	}
	fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleHeading, "[tcache]"))
	fmt.Fprintf(&output, "tcache_perthread_struct=0x%016x encoding=%s (%d/%d confirmed bytes)\n", observation.address, input.layout.TcacheLink, len(observation.data), input.layout.Tcache.Size)
	var nodes, empty int
	for _, bin := range observation.bins {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		if bin.complete && bin.head == 0 {
			empty++
			if !verbose {
				continue
			}
		}
		head := "<unconfirmed>"
		if bin.headKnown {
			head, _ = renderer.Address(target.AMD64, bin.head, display.AddressHeap)
		}
		fmt.Fprintf(&output, "tcache[idx=%d", bin.index)
		if bin.sizeMin != 0 {
			fmt.Fprintf(&output, " size=0x%x", bin.sizeMin)
			if bin.sizeMax != bin.sizeMin {
				fmt.Fprintf(&output, "-0x%x", bin.sizeMax)
			}
		}
		fmt.Fprintf(&output, "] head=%s", head)
		if bin.counterName != "" {
			value := "<unconfirmed>"
			if bin.counterKnown {
				value = fmt.Sprintf("%d", bin.counter)
			}
			fmt.Fprintf(&output, " %s.raw=%s", bin.counterName, value)
		}
		fmt.Fprintf(&output, " observed=%d complete=%t\n", len(bin.nodes), bin.complete)
		for _, node := range bin.nodes {
			if err := contextReady(ctx); err != nil {
				return "", err
			}
			nodes++
			address, _ := renderer.Address(target.AMD64, node.address, display.AddressHeap)
			fmt.Fprintf(&output, "  -> %s", address)
			if node.chunkKnown {
				chunk, _ := renderer.Address(target.AMD64, node.chunkAddress, display.AddressHeap)
				fmt.Fprintf(&output, " chunk=%s size=0x%x", chunk, node.chunkSize)
			}
			if node.linked {
				next, _ := renderer.Address(target.AMD64, node.next, display.AddressHeap)
				fmt.Fprintf(&output, " next.stored=0x%016x next=%s", node.stored, next)
			} else {
				fmt.Fprintf(&output, " <incomplete entry: %d confirmed bytes>", len(node.data))
			}
			if key, ok := input.layout.TcacheEntry.Fields["key"]; ok {
				if value, confirmed := heapGraphField(node.data, key, 0); confirmed {
					fmt.Fprintf(&output, " key.raw=0x%016x", value)
				}
			}
			output.WriteByte('\n')
		}
		if bin.err != nil {
			fmt.Fprintf(&output, "  <incomplete: %q>\n", bin.err.Error())
		}
	}
	if observation.err != nil {
		fmt.Fprintf(&output, "<tcache root incomplete: %q>\n", observation.err.Error())
	}
	fmt.Fprintf(&output, "observed-tcache-entries=%d empty-lists=%d; counters are raw, not an allocation-state or ownership proof.\n", nodes, empty)
	return output.String(), contextReady(ctx)
}
