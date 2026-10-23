package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

const (
	heapVisualHeaderSize = 16
	heapVisualAlignment  = 16
	heapVisualMinChunk   = 32
)

type heapVisualExtent struct {
	Base, Start, End, Top, Arena target.Address
	TerminalFencepost            target.Address
	Label                        string
}

type heapVisualMembership struct {
	Label    string
	Complete bool
}

type heapVisualObservation struct {
	proof   string
	extents []heapVisualExtentObservation
	err     error
}

type heapVisualExtentObservation struct {
	extent   heapVisualExtent
	chunks   []heapVisualChunkObservation
	end      target.Address
	complete bool
}

type heapVisualChunkObservation struct {
	address          target.Address
	ordinal          int
	header, payload  []byte
	size, rawSize    uint64
	requestedPayload uint64
	decoded          bool
	top, fencepost   bool
	terminal         bool
	validatedTail    bool
	nextInUse        int8
	members          []heapVisualMembership
	err              error
}

func validateHeapVisual(input heapGraphInput, extents []heapVisualExtent) error {
	if input.reader == nil || input.reader.ctx == nil || input.reader.session == nil {
		return fmt.Errorf("visual-heap requires a stopped memory reader: %w", target.ErrInvalidArgument)
	}
	if err := contextReady(input.reader.ctx); err != nil {
		return err
	}
	if err := input.layout.Validate(); err != nil {
		return err
	}
	for index, name := range []string{"mchunk_prev_size", "mchunk_size"} {
		if input.layout.Chunk.Fields[name] != (inspect.HeapField{Offset: uint64(index * 8), Width: 8, Count: 1, Stride: 8}) {
			return fmt.Errorf("visual-heap requires the proven amd64 16-byte chunk header; %s layout differs: %w", name, target.ErrUnsupported)
		}
	}
	if len(extents) == 0 || len(extents) > heapGraphMaxArenas {
		return fmt.Errorf("visual-heap requires 1..%d proven extents: %w", heapGraphMaxArenas, target.ErrInvalidArgument)
	}
	ordered := slices.Clone(extents)
	for _, extent := range ordered {
		if err := contextReady(input.reader.ctx); err != nil {
			return err
		}
		if extent.Base > extent.Start || extent.Start >= extent.End || uint64(extent.Start)%heapVisualAlignment != 0 || uint64(extent.End)%heapVisualAlignment != 0 {
			return fmt.Errorf("visual-heap needs Base <= Start < End and aligned chunk endpoints: %w", target.ErrInvalidArgument)
		}
		if extent.Top != 0 && (extent.Top < extent.Start || extent.Top >= extent.End || uint64(extent.Top)%heapVisualAlignment != 0) {
			return fmt.Errorf("visual-heap TOP must be an aligned header within its proven extent: %w", target.ErrInvalidArgument)
		}
		if extent.TerminalFencepost != 0 && (extent.Top != 0 || extent.Arena == 0 || extent.End-extent.Start < 32 || extent.TerminalFencepost != extent.End-16) {
			return fmt.Errorf("visual-heap terminal fencepost requires an older proven heap_info extent with a final 16-byte header: %w", target.ErrInvalidArgument)
		}
	}
	var followingTop bool
	for index := len(extents) - 1; index >= 0; index-- {
		if index == len(extents)-1 || extents[index+1].Arena != extents[index].Arena {
			followingTop = false
		}
		if extents[index].Top != 0 {
			followingTop = true
		}
		if extents[index].TerminalFencepost != 0 && !followingTop {
			return fmt.Errorf("visual-heap retired heap_info extent has no supplied continuation to the arena's current TOP: %w", target.ErrInvalidArgument)
		}
	}
	slices.SortFunc(ordered, func(a, b heapVisualExtent) int {
		if a.Start < b.Start {
			return -1
		}
		if a.Start > b.Start {
			return 1
		}
		return 0
	})
	for index := 1; index < len(ordered); index++ {
		if ordered[index].Start < ordered[index-1].End {
			return fmt.Errorf("visual-heap extents overlap; chunk identities would be duplicated: %w", target.ErrInvalidArgument)
		}
	}
	return nil
}

func collectHeapVisual(input heapGraphInput, extents []heapVisualExtent, members map[target.Address][]heapVisualMembership) (heapVisualObservation, error) {
	var result heapVisualObservation
	if err := validateHeapVisual(input, extents); err != nil {
		return result, err
	}
	result.proof = input.proof
	result.extents = make([]heapVisualExtentObservation, len(extents))
	for index, extent := range extents {
		result.extents[index] = heapVisualExtentObservation{extent: extent, end: extent.Start}
	}
	finish := func(err error) (heapVisualObservation, error) {
		if heapGraphFatal(err) {
			return heapVisualObservation{}, err
		}
		result.err = err
		return result, err
	}
	ordinal := 0
	for index, extent := range extents {
		view := &result.extents[index]
		for address := extent.Start; address < extent.End; {
			if err := input.reader.takeNode(); err != nil {
				return finish(err)
			}
			data, err := input.reader.read(address, heapVisualHeaderSize)
			if heapGraphFatal(err) {
				return finish(err)
			}
			view.chunks = append(view.chunks, heapVisualChunkObservation{
				address: address, ordinal: -1, header: data, nextInUse: -1,
				top: extent.Top != 0 && address == extent.Top, members: slices.Clone(members[address]), err: err,
			})
			chunk := &view.chunks[len(view.chunks)-1]
			if err != nil || len(data) != heapVisualHeaderSize {
				if err == nil {
					err = fmt.Errorf("visual-heap header at %#x is incomplete: %w", address, target.ErrPartial)
					chunk.err = err
				}
				return finish(err)
			}
			chunk.decoded = true
			chunk.ordinal = ordinal
			ordinal++
			chunk.rawSize = binary.LittleEndian.Uint64(data[8:])
			chunk.size = chunk.rawSize &^ 7
			if len(view.chunks) > 1 {
				view.chunks[len(view.chunks)-2].nextInUse = int8(chunk.rawSize & 1)
			}
			if extent.TerminalFencepost != 0 && address == extent.TerminalFencepost {
				chunk.terminal = true
				valid := false
				if len(view.chunks) > 1 {
					previous := &view.chunks[len(view.chunks)-2]
					footer := binary.LittleEndian.Uint64(data[:8])
					valid = chunk.rawSize == 1 && (footer == 16 || footer == 32) && previous.size == footer && previous.rawSize&^1 == footer && address-previous.address == target.Address(footer)
					if valid {
						previous.fencepost, previous.validatedTail = true, true
					}
				}
				if !valid {
					chunk.err = fmt.Errorf("heap_info terminal fencepost at %#x does not match its source-defined predecessor and footer; observation may intersect an allocator update: %w", address, target.ErrInvalidState)
					return finish(chunk.err)
				}
				chunk.validatedTail = true
				view.end, view.complete = extent.End, true
				break
			}
			if !chunk.top && chunk.rawSize&^1 == heapVisualHeaderSize {
				chunk.fencepost = true
				if extent.TerminalFencepost != 0 && address+heapVisualHeaderSize == extent.TerminalFencepost {
					address += heapVisualHeaderSize
					view.end = address
					continue
				}
				chunk.err = fmt.Errorf("fencepost-sized boundary at %#x; the remaining extent is not proven and may contain a foreign sbrk gap; traversal stops here: %w", address, target.ErrUnavailable)
				return finish(chunk.err)
			}
			if chunk.size < heapVisualMinChunk || chunk.size%heapVisualAlignment != 0 || chunk.rawSize&2 != 0 {
				chunk.err = fmt.Errorf("inconsistent arena chunk header at %#x: size=%#x IS_MMAPPED=%d; observation may intersect an allocator update: %w", address, chunk.size, chunk.rawSize>>1&1, target.ErrInvalidState)
				return finish(chunk.err)
			}
			if chunk.size > math.MaxUint64-uint64(address) {
				chunk.err = fmt.Errorf("chunk at %#x exceeds the address space: %w", address, target.ErrOverflow)
				return finish(chunk.err)
			}
			next := address + target.Address(chunk.size)
			if next > extent.End || !chunk.top && extent.Top != 0 && next > extent.Top || extent.TerminalFencepost != 0 && next > extent.TerminalFencepost {
				chunk.err = fmt.Errorf("chunk at %#x ends at %#x beyond its proven boundary; observation may intersect an allocator update: %w", address, next, target.ErrInvalidState)
				return finish(chunk.err)
			}
			chunk.requestedPayload = chunk.size - heapVisualHeaderSize
			payloadSize := chunk.requestedPayload
			if _, cached := input.reader.cache[heapGraphReadKey{address + heapVisualHeaderSize, payloadSize}]; !cached {
				payloadSize = min(payloadSize, heapGraphMaxBytes-input.reader.bytes)
			}
			if payloadSize != 0 {
				chunk.payload, chunk.err = input.reader.read(address+heapVisualHeaderSize, payloadSize)
			}
			if payloadSize < chunk.requestedPayload {
				input.reader.exhausted = true
				chunk.err = errors.Join(chunk.err, fmt.Errorf("visual-heap payload at %#x exceeds the remaining global %d-byte read budget: %w", address+heapVisualHeaderSize, heapGraphMaxBytes, target.ErrUnavailable))
			}
			if chunk.err != nil {
				return finish(chunk.err)
			}
			view.end = next
			if chunk.top {
				view.complete = true
				break
			}
			address = next
			if address == extent.End {
				view.complete = true
			}
		}
	}
	if err := contextReady(input.reader.ctx); err != nil {
		return finish(err)
	}
	return result, nil
}

func renderHeapVisual(ctx context.Context, observation heapVisualObservation, renderer display.Renderer) (string, error) {
	if err := contextReady(ctx); err != nil {
		return "", err
	}
	if heapGraphFatal(observation.err) {
		return "", observation.err
	}
	if len(observation.extents) == 0 {
		return "", nil
	}
	var output strings.Builder
	fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleHeading, "[visual-heap]"))
	for index, view := range observation.extents {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		extent := view.extent
		fmt.Fprintf(&output, "heap[%d] arena=0x%016x range=[0x%016x, 0x%016x) TOP=0x%016x\n", index, extent.Arena, extent.Start, extent.End, extent.Top)
		output.WriteString("Address            | +Chunk  | +Heap   : Word[0]            Word[1]            | ASCII            | Facts\n")
		for _, chunk := range view.chunks {
			if err := contextReady(ctx); err != nil {
				return "", err
			}
			label := heapVisualChunkLabel(chunk)
			style := heapVisualChunkStyle(chunk.ordinal)
			if err := renderHeapVisualRows(ctx, &output, renderer, extent, chunk.address, 0, chunk.header, label, false, style); err != nil {
				return "", err
			}
			if len(chunk.payload) > 0 {
				if err := renderHeapVisualRows(ctx, &output, renderer, extent, chunk.address, heapVisualHeaderSize, chunk.payload, "", true, style); err != nil {
					return "", err
				}
			}
			if chunk.requestedPayload != 0 {
				if uint64(len(chunk.payload)) < chunk.requestedPayload {
					fmt.Fprintf(&output, "    <partial payload: %d/%d requested bytes confirmed>\n", len(chunk.payload), chunk.requestedPayload)
				}
			}
			if chunk.err != nil {
				fmt.Fprintf(&output, "    %s\n", renderer.Text(display.StyleError, "<incomplete: "+strconv.QuoteToGraphic(chunk.err.Error())+">"))
			}
		}
		fmt.Fprintf(&output, "heap[%d] headers=%d complete=%t\n", index, len(view.chunks), view.complete)
		if view.end < extent.End {
			if view.complete {
				fmt.Fprintf(&output, "    <range [0x%016x, 0x%016x) is not traversed after declared TOP>\n", view.end, extent.End)
			} else {
				fmt.Fprintf(&output, "    <range [0x%016x, 0x%016x) is not fully inspected>\n", view.end, extent.End)
			}
		}
	}
	for index, view := range observation.extents {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		fmt.Fprintf(&output, "heap[%d] base=0x%016x %s\n", index, view.extent.Base, strconv.QuoteToGraphic(view.extent.Label))
	}
	fmt.Fprintf(&output, "provenance=%s\n", strconv.QuoteToGraphic(observation.proof))
	fmt.Fprintf(&output, "header=%d payload-policy=full including TOP; global read budget=%d bytes\n", heapVisualHeaderSize, heapGraphMaxBytes)
	output.WriteString("Membership labels identify observed list links; unlisted chunks are not classified as allocated.\n")
	if observation.err != nil {
		fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleError, "<visual-heap incomplete: "+strconv.QuoteToGraphic(observation.err.Error())+">"))
	}
	if err := contextReady(ctx); err != nil {
		return "", err
	}
	return output.String(), nil
}

func heapVisualChunkLabel(chunk heapVisualChunkObservation) string {
	if !chunk.decoded {
		return fmt.Sprintf("<partial header: %d/%d bytes confirmed; not decoded>", len(chunk.header), heapVisualHeaderSize)
	}
	name := "chunk"
	if chunk.top {
		name = "TOP"
	} else if chunk.terminal && chunk.validatedTail {
		name = "validated heap_info terminal fencepost"
	} else if chunk.terminal {
		name = "unconfirmed heap_info terminal fencepost"
	} else if chunk.fencepost && chunk.validatedTail {
		name = "validated heap_info fencepost"
	} else if chunk.fencepost {
		name = "fencepost-sized boundary"
	}
	var labels []string
	if name != "chunk" || len(chunk.members) == 0 {
		labels = append(labels, name)
	}
	for _, member := range chunk.members {
		quoted := strconv.QuoteToGraphic(member.Label)
		label := quoted[1 : len(quoted)-1]
		if !member.Complete {
			label += " (incomplete list)"
		}
		labels = append(labels, label)
	}
	label := fmt.Sprintf("%s size=0x%x P=%d M=%d A=%d", strings.Join(labels, "; "), chunk.size, chunk.rawSize&1, chunk.rawSize>>1&1, chunk.rawSize>>2&1)
	if !chunk.top && !chunk.fencepost && !chunk.terminal && len(chunk.members) == 0 {
		switch chunk.nextInUse {
		case 0:
			label += "; in-use bit clear (next.PREV_INUSE)"
		case 1:
			label += "; in-use bit set (next.PREV_INUSE)"
		default:
			label += "; in-use bit unavailable (next header not confirmed)"
		}
	}
	return label
}

func heapVisualChunkStyle(ordinal int) display.Style {
	if ordinal < 0 {
		return display.StyleMuted
	}
	return [...]display.Style{display.StyleChanged, display.StyleCurrent, display.StyleRegister, display.StyleString}[ordinal%4]
}

func renderHeapVisualRows(ctx context.Context, output *strings.Builder, renderer display.Renderer, extent heapVisualExtent, header target.Address, start uint64, data []byte, label string, compress bool, style display.Style) error {
	for offset := 0; offset < len(data) || offset == 0 && len(data) == 0; offset += 16 {
		if err := contextReady(ctx); err != nil {
			return err
		}
		row := data[offset:min(offset+16, len(data))]
		address := header + target.Address(start) + target.Address(offset)
		addressText, err := renderer.Address(target.AMD64, address, display.AddressUnknown)
		if err != nil {
			return err
		}
		words := [2]string{}
		for word := range words {
			bytes := row[min(word*8, len(row)):min((word+1)*8, len(row))]
			switch len(bytes) {
			case 0:
				words[word] = "<unavailable>"
			case 8:
				words[word] = fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(bytes))
			default:
				words[word] = "bytes[" + fmt.Sprintf("%x", bytes) + "]"
			}
		}
		var ascii strings.Builder
		for _, value := range row {
			if value >= 0x20 && value < 0x7f {
				ascii.WriteByte(value)
			} else {
				ascii.WriteByte('.')
			}
		}
		line := fmt.Sprintf("%s | +0x%04x | +0x%04x : %-18s %-18s | %-16s | %s", addressText, start+uint64(offset), uint64(address-extent.Base), words[0], words[1], ascii.String(), label)
		output.WriteString(renderer.Text(style, line) + "\n")
		label = ""
		if compress && len(row) == 16 {
			end := offset + 16
			for end+16 <= len(data) && bytes.Equal(row, data[end:end+16]) {
				if err := contextReady(ctx); err != nil {
					return err
				}
				end += 16
			}
			if end > offset+16 {
				line := fmt.Sprintf("    * %d lines, 0x%x bytes", (end-offset)/16-1, end-offset-16)
				output.WriteString(renderer.Text(style, line) + "\n")
				offset = end - 16
			}
		}
	}
	return nil
}
