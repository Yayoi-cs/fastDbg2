package debugger

import (
	"context"
	"encoding/binary"
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

const (
	heapLayoutName       = "glibc-amd64"
	heapLayoutHeaderSize = 16
	heapLayoutMinSize    = 32
	heapLayoutAlignment  = 16
	heapLayoutMaxWords   = 4
	heapLayoutMaxBytes   = 1 << 20
	heapLayoutMaxChunks  = 4096
)

type heapLayoutArguments struct {
	expressions []string
	words       int
}

type heapLayoutHeader struct {
	previous uint64
	rawSize  uint64
}

func parseHeapLayoutArguments(rawArgs string, visual bool) (heapLayoutArguments, error) {
	var result heapLayoutArguments
	var hasLayout, hasWords bool
	rest := strings.TrimSpace(rawArgs)
	for strings.HasPrefix(rest, "--") {
		option, remaining := takeMemoryArgument(rest)
		if option == "--" {
			rest = remaining
			break
		}
		value, remaining := takeMemoryArgument(remaining)
		switch option {
		case "--layout":
			if hasLayout || value == "" {
				return result, fmt.Errorf("specify --layout exactly once with a layout name: %w", target.ErrInvalidArgument)
			}
			if value != heapLayoutName {
				return result, fmt.Errorf("heap layout %q; supported explicit layout is %s: %w", value, heapLayoutName, target.ErrUnsupported)
			}
			hasLayout = true
		case "--words":
			if visual || hasWords || value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return result, fmt.Errorf("chunk --words accepts one count from 0 to %d: %w", heapLayoutMaxWords, target.ErrInvalidArgument)
			}
			count, err := strconv.ParseUint(value, 10, 8)
			if err != nil || count > heapLayoutMaxWords {
				return result, fmt.Errorf("chunk --words must be between 0 and %d: %w", heapLayoutMaxWords, target.ErrInvalidArgument)
			}
			result.words, hasWords = int(count), true
		default:
			return result, fmt.Errorf("unknown heap layout option %q: %w", option, target.ErrInvalidArgument)
		}
		rest = remaining
	}
	if !hasLayout {
		return result, fmt.Errorf("an explicit --layout %s is required; allocator layouts are not detected automatically: %w", heapLayoutName, target.ErrUnsupported)
	}
	if !visual {
		if rest == "" {
			return result, fmt.Errorf("usage: chunk --layout %s [--words N] EXPR: %w", heapLayoutName, target.ErrInvalidArgument)
		}
		result.expressions = []string{rest}
		return result, nil
	}
	arguments, err := cli.ParseArgs(rest)
	if err != nil {
		return result, fmt.Errorf("heap range arguments: %w: %w", err, target.ErrInvalidArgument)
	}
	if len(arguments) != 2 || strings.TrimSpace(arguments[0]) == "" || strings.TrimSpace(arguments[1]) == "" {
		return result, fmt.Errorf("usage: visual-heap --layout %s START END; END is exclusive, quote expressions containing spaces: %w", heapLayoutName, target.ErrInvalidArgument)
	}
	result.expressions = arguments
	return result, nil
}

func (c *Controller) heapLayoutAddresses(ctx context.Context, expressions []string) (target.MemoryToken, []target.Address, error) {
	resolver := &lazyInspectionResolver{controller: c, ctx: ctx}
	if err := resolver.initialize(); err != nil {
		return target.MemoryToken{}, nil, err
	}
	addresses := make([]target.Address, len(expressions))
	for i, expression := range expressions {
		value, err := inspect.EvalExpression(expression, resolver)
		if err != nil {
			return target.MemoryToken{}, nil, err
		}
		addresses[i] = target.Address(value)
	}
	if err := contextReady(ctx); err != nil {
		return target.MemoryToken{}, nil, err
	}
	return resolver.snapshot.Memory, addresses, nil
}

func decodeHeapLayoutHeader(data []byte) heapLayoutHeader {
	return heapLayoutHeader{previous: binary.LittleEndian.Uint64(data[:8]), rawSize: binary.LittleEndian.Uint64(data[8:16])}
}

func (header heapLayoutHeader) size() uint64 { return header.rawSize &^ 7 }

func (header heapLayoutHeader) validate(address target.Address) error {
	if uint64(address)%heapLayoutAlignment != 0 || header.size() < heapLayoutMinSize || header.size()%heapLayoutAlignment != 0 {
		return fmt.Errorf("structurally invalid %s header at %#x: address and size must be aligned to %d and size must be at least %#x: %w", heapLayoutName, address, heapLayoutAlignment, heapLayoutMinSize, target.ErrInvalidArgument)
	}
	if header.size() > math.MaxUint64-uint64(address) {
		return fmt.Errorf("structurally invalid %s header at %#x: chunk size overflows the address space: %w", heapLayoutName, address, target.ErrOverflow)
	}
	return nil
}

func (c *Controller) heapLayoutTitle(name string) error {
	view := c.metadataView()
	view.heading(name)
	view.field("Layout", heapLayoutName+" (user-selected)", metadataPlain)
	view.note("Raw fields only; allocation ownership and state are not determined.", metadataUnknown)
	return c.writef("%s", view.output.String())
}

func (c *Controller) showHeapChunk(ctx context.Context, rawArgs string) error {
	width := display.OutputWidth(c.out)
	writef := func(format string, values ...any) error {
		return c.writef("%s", display.Wrap(fmt.Sprintf(format, values...), width, 4))
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	arguments, err := parseHeapLayoutArguments(rawArgs, false)
	if err != nil {
		return err
	}
	token, addresses, err := c.heapLayoutAddresses(ctx, arguments.expressions)
	if err != nil {
		return err
	}
	address := addresses[0]
	count := heapLayoutHeaderSize + arguments.words*8
	if err := inspectionRange(address, count); err != nil {
		return err
	}
	data := make([]byte, count)
	n, readErr := c.session.ReadSpaceMemory(token, address, data)
	data, readErr = inspectionConfirmedBytes(data, n, readErr)
	if err := contextReady(ctx); err != nil {
		return errors.Join(readErr, err)
	}
	if errors.Is(readErr, target.ErrStale) {
		return readErr
	}
	var structuralErr error
	if len(data) >= heapLayoutHeaderSize {
		structuralErr = decodeHeapLayoutHeader(data).validate(address)
	}
	if err := c.heapLayoutTitle("chunk"); err != nil {
		return errors.Join(readErr, structuralErr, err)
	}
	addressText, err := c.renderer.Address(target.AMD64, address, display.AddressUnknown)
	if err != nil {
		return errors.Join(readErr, structuralErr, err)
	}
	if err := writef("header=%s\n", addressText); err != nil {
		return errors.Join(readErr, structuralErr, err)
	}
	if arguments.words != 0 {
		if err := writef("Extra words are explicit raw reads at header+offset; no ownership within this chunk is asserted.\n"); err != nil {
			return errors.Join(readErr, structuralErr, err)
		}
	}
	for offset := 0; offset < len(data); offset += 8 {
		name := "prev_size"
		if offset == 8 {
			name = "raw_size"
		} else if offset >= heapLayoutHeaderSize {
			name = fmt.Sprintf("stored_word[%d]", (offset-heapLayoutHeaderSize)/8)
		}
		word := data[offset:min(offset+8, len(data))]
		value := fmt.Sprintf("<partial bytes: %s>", display.FormatBytes(word))
		if len(word) == 8 {
			value = fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(word))
		}
		if err := writef("  +0x%02x %s = %s\n", offset, c.renderer.Text(display.StyleSymbol, fmt.Sprintf("%-14s", name)), value); err != nil {
			return errors.Join(readErr, structuralErr, err)
		}
	}
	if len(data) >= heapLayoutHeaderSize {
		header := decodeHeapLayoutHeader(data)
		if err := writef("  size=0x%x PREV_INUSE=%d IS_MMAPPED=%d NON_MAIN_ARENA=%d (raw bits)\n", header.size(), header.rawSize&1, header.rawSize>>1&1, header.rawSize>>2&1); err != nil {
			return errors.Join(readErr, structuralErr, err)
		}
	}
	if structuralErr != nil {
		return errors.Join(readErr, structuralErr, writef("  <structurally invalid layout>\n"))
	}
	return readErr
}

func (c *Controller) showVisualHeap(ctx context.Context, rawArgs string) error {
	if !heapExplicitMode(rawArgs) && (strings.TrimSpace(rawArgs) == "" || strings.HasPrefix(strings.TrimSpace(rawArgs), "-")) {
		return c.showAutomaticVisualHeap(ctx, rawArgs)
	}
	width := display.OutputWidth(c.out)
	writef := func(format string, values ...any) error {
		return c.writef("%s", display.Wrap(fmt.Sprintf(format, values...), width, 4))
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	arguments, err := parseHeapLayoutArguments(rawArgs, true)
	if err != nil {
		return err
	}
	token, addresses, err := c.heapLayoutAddresses(ctx, arguments.expressions)
	if err != nil {
		return err
	}
	start, end := addresses[0], addresses[1]
	if start >= end || uint64(start)%heapLayoutAlignment != 0 || uint64(end)%heapLayoutAlignment != 0 {
		return fmt.Errorf("visual-heap needs START < END and %d-byte aligned endpoints: %w", heapLayoutAlignment, target.ErrInvalidArgument)
	}
	if end-start > heapLayoutMaxBytes {
		return fmt.Errorf("visual-heap range exceeds %d bytes: %w", heapLayoutMaxBytes, target.ErrInvalidArgument)
	}
	if err := c.heapLayoutTitle("visual-heap"); err != nil {
		return err
	}
	if err := writef("range=[0x%016x, 0x%016x) max-headers=%d max-bytes=%d\n", start, end, heapLayoutMaxChunks, heapLayoutMaxBytes); err != nil {
		return err
	}
	count := 0
	for address := start; address < end; count++ {
		if err := contextReady(ctx); err != nil {
			return err
		}
		if count == heapLayoutMaxChunks {
			return fmt.Errorf("visual-heap reached %d headers before END: %w", heapLayoutMaxChunks, target.ErrUnavailable)
		}
		var data [heapLayoutHeaderSize]byte
		n, readErr := c.session.ReadSpaceMemory(token, address, data[:])
		prefix, readErr := inspectionConfirmedBytes(data[:], n, readErr)
		if err := contextReady(ctx); err != nil {
			return errors.Join(readErr, err)
		}
		if errors.Is(readErr, target.ErrStale) {
			return readErr
		}
		addressText, err := c.renderer.Address(target.AMD64, address, display.AddressUnknown)
		if err != nil {
			return errors.Join(readErr, err)
		}
		if len(prefix) != heapLayoutHeaderSize {
			return errors.Join(readErr, writef("%s <partial header bytes: %s>\n", addressText, display.FormatBytes(prefix)))
		}
		header := decodeHeapLayoutHeader(prefix)
		structuralErr := header.validate(address)
		if structuralErr == nil && header.size() > uint64(end-address) {
			structuralErr = fmt.Errorf("chunk size at %#x extends past exclusive END %#x: %w", address, end, target.ErrInvalidArgument)
		}
		status := ""
		if structuralErr != nil {
			status = " <structurally invalid range/layout>"
		}
		if err := writef("%s prev_size=0x%016x raw_size=0x%016x size=0x%x P=%d M=%d A=%d%s\n", addressText, header.previous, header.rawSize, header.size(), header.rawSize&1, header.rawSize>>1&1, header.rawSize>>2&1, status); err != nil {
			return errors.Join(readErr, structuralErr, err)
		}
		if readErr != nil || structuralErr != nil {
			return errors.Join(readErr, structuralErr)
		}
		address += target.Address(header.size())
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	return writef("headers=%d covered=0x%x; P=PREV_INUSE M=IS_MMAPPED A=NON_MAIN_ARENA are raw bits.\n", count, end-start)
}
