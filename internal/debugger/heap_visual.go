package debugger

import (
	"bytes"
	"context"
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
	word    uint64
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
		if input.layout.Chunk.Fields[name] != (inspect.HeapField{Offset: uint64(index) * input.layout.Pointer, Width: input.layout.Pointer, Count: 1, Stride: input.layout.Pointer}) {
			return fmt.Errorf("visual-heap requires a %d-byte chunk header; %s layout differs: %w", 2*input.layout.Pointer, name, target.ErrUnsupported)
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
		if extent.Base > extent.Start || extent.Start >= extent.End || (uint64(extent.Start)+2*input.layout.Pointer)%heapVisualAlignment != 0 || uint64(extent.End)%heapVisualAlignment != 0 {
			return fmt.Errorf("visual-heap needs Base <= Start < End and aligned chunk endpoints: %w", target.ErrInvalidArgument)
		}
		if extent.Top != 0 && (extent.Top < extent.Start || extent.Top >= extent.End || (uint64(extent.Top)+2*input.layout.Pointer)%heapVisualAlignment != 0) {
			return fmt.Errorf("visual-heap TOP must be an aligned header within its proven extent: %w", target.ErrInvalidArgument)
		}
		if extent.TerminalFencepost != 0 && (extent.Top != 0 || extent.Arena == 0 || uint64(extent.End-extent.Start) < 4*input.layout.Pointer || extent.TerminalFencepost != extent.End-target.Address(2*input.layout.Pointer)) {
			return fmt.Errorf("visual-heap terminal fencepost requires an older proven heap_info extent with a final %d-byte header: %w", 2*input.layout.Pointer, target.ErrInvalidArgument)
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
	word := input.layout.Pointer
	headerSize := word * 2
	var result heapVisualObservation
	if err := validateHeapVisual(input, extents); err != nil {
		return result, err
	}
	result.word = word
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
			data, err := input.reader.read(address, headerSize)
			if heapGraphFatal(err) {
				return finish(err)
			}
			view.chunks = append(view.chunks, heapVisualChunkObservation{
				address: address, ordinal: -1, header: data, nextInUse: -1,
				top: extent.Top != 0 && address == extent.Top, members: slices.Clone(members[address]), err: err,
			})
			chunk := &view.chunks[len(view.chunks)-1]
			if err != nil || uint64(len(data)) != headerSize {
				if err == nil {
					err = fmt.Errorf("visual-heap header at %#x is incomplete: %w", address, target.ErrPartial)
					chunk.err = err
				}
				return finish(err)
			}
			chunk.decoded = true
			chunk.ordinal = ordinal
			ordinal++
			chunk.rawSize = inspectionWord(data[word:])
			chunk.size = chunk.rawSize &^ 7
			if len(view.chunks) > 1 {
				view.chunks[len(view.chunks)-2].nextInUse = int8(chunk.rawSize & 1)
			}
			if extent.TerminalFencepost != 0 && address == extent.TerminalFencepost {
				chunk.terminal = true
				valid := false
				if len(view.chunks) > 1 {
					previous := &view.chunks[len(view.chunks)-2]
					footer := inspectionWord(data[:word])
					valid = chunk.rawSize == 1 && (footer == headerSize || footer == 4*word) && previous.size == footer && previous.rawSize&^1 == footer && address-previous.address == target.Address(footer)
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
			if !chunk.top && chunk.rawSize&^1 == headerSize {
				chunk.fencepost = true
				if extent.TerminalFencepost != 0 && address+target.Address(headerSize) == extent.TerminalFencepost {
					address += target.Address(headerSize)
					view.end = address
					continue
				}
				chunk.err = fmt.Errorf("fencepost-sized boundary at %#x; the remaining extent is not proven and may contain a foreign sbrk gap; traversal stops here: %w", address, target.ErrUnavailable)
				return finish(chunk.err)
			}
			if chunk.size < 4*word || (!chunk.top && chunk.size%heapVisualAlignment != 0 || chunk.top && (chunk.size+headerSize)%heapVisualAlignment != 0) || chunk.rawSize&2 != 0 {
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
			chunk.requestedPayload = chunk.size - headerSize
			payloadSize := chunk.requestedPayload
			if _, cached := input.reader.cache[heapGraphReadKey{address + target.Address(headerSize), payloadSize}]; !cached {
				payloadSize = min(payloadSize, heapGraphMaxBytes-input.reader.bytes)
			}
			if payloadSize != 0 {
				chunk.payload, chunk.err = input.reader.read(address+target.Address(headerSize), payloadSize)
			}
			if payloadSize < chunk.requestedPayload {
				input.reader.exhausted = true
				chunk.err = errors.Join(chunk.err, fmt.Errorf("visual-heap payload at %#x exceeds the remaining global %d-byte read budget: %w", address+target.Address(headerSize), heapGraphMaxBytes, target.ErrUnavailable))
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
	word := observation.word
	if word == 0 {
		word = 8
	}
	var output strings.Builder
	for _, view := range observation.extents {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		extent := view.extent
		for _, chunk := range view.chunks {
			if err := contextReady(ctx); err != nil {
				return "", err
			}
			label := heapVisualChunkLabel(chunk, word)
			style := heapVisualChunkStyle(chunk.ordinal)
			headerLabel := label
			if len(chunk.payload) != 0 {
				headerLabel = ""
			}
			if err := renderHeapVisualRows(ctx, &output, renderer, extent, chunk.address, 0, chunk.header, headerLabel, false, style, int(word)); err != nil {
				return "", err
			}
			if len(chunk.payload) > 0 {
				if err := renderHeapVisualRows(ctx, &output, renderer, extent, chunk.address, word*2, chunk.payload, label, true, style, int(word)); err != nil {
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
		if !view.complete && view.end < extent.End {
			fmt.Fprintf(&output, "    <range [0x%0*x, 0x%0*x) is not fully inspected>\n", word*2, view.end, word*2, extent.End)
		}
	}
	if observation.err != nil {
		fmt.Fprintf(&output, "%s\n", renderer.Text(display.StyleError, "<visual-heap incomplete: "+strconv.QuoteToGraphic(observation.err.Error())+">"))
	}
	if err := contextReady(ctx); err != nil {
		return "", err
	}
	return output.String(), nil
}

func heapVisualChunkLabel(chunk heapVisualChunkObservation, words ...uint64) string {
	header := uint64(heapVisualHeaderSize)
	if len(words) > 0 {
		header = 2 * words[0]
	}
	if !chunk.decoded {
		return fmt.Sprintf("<partial header: %d/%d bytes confirmed; not decoded>", len(chunk.header), header)
	}
	var labels []string
	if chunk.top {
		labels = append(labels, "top")
	} else if chunk.validatedTail {
		labels = append(labels, "fencepost")
	} else if chunk.fencepost || chunk.terminal {
		labels = append(labels, "boundary")
	}
	for _, member := range chunk.members {
		label := contextEscapedText(member.Label)
		if !member.Complete {
			label += " (incomplete list)"
		}
		labels = append(labels, label)
	}
	return strings.Join(labels, ", ")
}

func heapVisualChunkStyle(ordinal int) display.Style {
	if ordinal < 0 {
		return display.StyleMuted
	}
	return [...]display.Style{display.StyleRed, display.StyleGreen, display.StyleYellow, display.StyleBlue, display.StylePurple, display.StyleCyan}[ordinal%6]
}

func renderHeapVisualRows(ctx context.Context, output *strings.Builder, renderer display.Renderer, extent heapVisualExtent, header target.Address, start uint64, data []byte, label string, compress bool, style display.Style, widths ...int) error {
	size := 8
	if len(widths) > 0 {
		size = widths[0]
	}
	stride := size * 2
	arch := target.AMD64
	if size == 4 {
		arch = target.X86
	}
	for offset := 0; offset < len(data) || offset == 0 && len(data) == 0; offset += stride {
		if err := contextReady(ctx); err != nil {
			return err
		}
		row := data[offset:min(offset+stride, len(data))]
		address := header + target.Address(start) + target.Address(offset)
		addressText, err := renderer.Address(arch, address, display.AddressUnknown)
		if err != nil {
			return err
		}
		words := [2]string{}
		for word := range words {
			bytes := row[min(word*size, len(row)):min((word+1)*size, len(row))]
			switch len(bytes) {
			case 0:
				words[word] = "<unavailable>"
			case 4, 8:
				words[word] = fmt.Sprintf("0x%0*x", size*2, inspectionWord(bytes))
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
		line := fmt.Sprintf("%s|+0x%05x|+0x%05x: %-*s %-*s | %-*s |", addressText, start+uint64(offset), uint64(address-extent.Base), size*2+2, words[0], size*2+2, words[1], stride, ascii.String())
		if label != "" {
			line += " <- " + label
		}
		output.WriteString(renderer.Text(style, line) + "\n")
		label = ""
		if compress && len(row) == stride {
			end := offset + stride
			for end+stride <= len(data) && bytes.Equal(row, data[end:end+stride]) {
				if err := contextReady(ctx); err != nil {
					return err
				}
				end += stride
			}
			if end > offset+stride {
				line := fmt.Sprintf("    * %d lines, 0x%x bytes", (end-offset)/stride-1, end-offset-stride)
				output.WriteString(renderer.Text(style, line) + "\n")
				offset = end - stride
			}
		}
	}
	return nil
}
