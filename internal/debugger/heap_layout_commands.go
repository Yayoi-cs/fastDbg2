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
	arch        target.Architecture
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
			if value != heapLayoutName && value != "glibc-x86" {
				return result, fmt.Errorf("heap layout %q; supported explicit layouts are %s and glibc-x86: %w", value, heapLayoutName, target.ErrUnsupported)
			}
			if value == "glibc-x86" {
				result.arch = target.X86
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
		return result, fmt.Errorf("an explicit --layout %s|glibc-x86 is required; allocator layouts are not detected automatically: %w", heapLayoutName, target.ErrUnsupported)
	}
	if !visual {
		if rest == "" {
			return result, fmt.Errorf("usage: chunk --layout %s|glibc-x86 [--words N] EXPR: %w", heapLayoutName, target.ErrInvalidArgument)
		}
		result.expressions = []string{rest}
		return result, nil
	}
	arguments, err := cli.ParseArgs(rest)
	if err != nil {
		return result, fmt.Errorf("heap range arguments: %w: %w", err, target.ErrInvalidArgument)
	}
	if len(arguments) != 2 || strings.TrimSpace(arguments[0]) == "" || strings.TrimSpace(arguments[1]) == "" {
		return result, fmt.Errorf("usage: visual-heap --layout %s|glibc-x86 START END; END is exclusive, quote expressions containing spaces: %w", heapLayoutName, target.ErrInvalidArgument)
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
		if value > abiFor(resolver.snapshot.Architecture).maximum {
			return target.MemoryToken{}, nil, target.ErrOverflow
		}
		addresses[i] = target.Address(value)
	}
	if err := contextReady(ctx); err != nil {
		return target.MemoryToken{}, nil, err
	}
	return resolver.snapshot.Memory, addresses, nil
}

func decodeHeapLayoutHeader(data []byte, widths ...int) heapLayoutHeader {
	word := 8
	if len(widths) > 0 {
		word = widths[0]
	}
	return heapLayoutHeader{previous: inspectionWord(data[:word]), rawSize: inspectionWord(data[word : 2*word])}
}

func (header heapLayoutHeader) size() uint64 { return header.rawSize &^ 7 }

func (header heapLayoutHeader) validate(address target.Address, widths ...int) error {
	word := 8
	if len(widths) > 0 {
		word = widths[0]
	}
	name := heapLayoutName
	if word == 4 {
		name = "glibc-x86"
	}
	if (uint64(address)+uint64(2*word))%heapLayoutAlignment != 0 || header.size() < uint64(4*word) || header.size()%uint64(2*word) != 0 {
		return fmt.Errorf("structurally invalid %s header at %#x: address and size must be aligned to %d and size must be at least %#x: %w", name, address, heapLayoutAlignment, 4*word, target.ErrInvalidArgument)
	}
	if header.size() > math.MaxUint64-uint64(address) {
		return fmt.Errorf("structurally invalid %s header at %#x: chunk size overflows the address space: %w", name, address, target.ErrOverflow)
	}
	return nil
}

func (c *Controller) heapLayoutTitle(name string) error {
	view := c.metadataView()
	view.heading(name)
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
	word := abiFor(arguments.arch).word
	headerSize := 2 * word
	token, addresses, err := c.heapLayoutAddresses(ctx, arguments.expressions)
	if err != nil {
		return err
	}
	address := addresses[0]
	count := headerSize + arguments.words*word
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
	if len(data) >= headerSize {
		structuralErr = decodeHeapLayoutHeader(data, word).validate(address, word)
	}
	if err := c.heapLayoutTitle("chunk"); err != nil {
		return errors.Join(readErr, structuralErr, err)
	}
	addressText, err := c.renderer.Address(abiFor(arguments.arch).arch, address, display.AddressUnknown)
	if err != nil {
		return errors.Join(readErr, structuralErr, err)
	}
	if err := writef("header=%s\n", addressText); err != nil {
		return errors.Join(readErr, structuralErr, err)
	}
	for offset := 0; offset < len(data); offset += word {
		name := "prev_size"
		if offset == word {
			name = "raw_size"
		} else if offset >= headerSize {
			name = fmt.Sprintf("stored_word[%d]", (offset-headerSize)/word)
		}
		piece := data[offset:min(offset+word, len(data))]
		value := fmt.Sprintf("<partial bytes: %s>", display.FormatBytes(piece))
		if len(piece) == word {
			value = fmt.Sprintf("0x%0*x", word*2, inspectionWord(piece))
		}
		if err := writef("  +0x%02x %s = %s\n", offset, c.renderer.Text(display.StyleSymbol, fmt.Sprintf("%-14s", name)), value); err != nil {
			return errors.Join(readErr, structuralErr, err)
		}
	}
	if len(data) >= headerSize {
		header := decodeHeapLayoutHeader(data, word)
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
	word := abiFor(arguments.arch).word
	headerSize := 2 * word
	token, addresses, err := c.heapLayoutAddresses(ctx, arguments.expressions)
	if err != nil {
		return err
	}
	start, end := addresses[0], addresses[1]
	if start >= end || (uint64(start)+uint64(headerSize))%heapLayoutAlignment != 0 || uint64(end)%heapLayoutAlignment != 0 && (uint64(end)+uint64(headerSize))%heapLayoutAlignment != 0 {
		return fmt.Errorf("visual-heap needs START < END and endpoints consistent with %d-byte payload alignment: %w", heapLayoutAlignment, target.ErrInvalidArgument)
	}
	if end-start > heapLayoutMaxBytes {
		return fmt.Errorf("visual-heap range exceeds %d bytes: %w", heapLayoutMaxBytes, target.ErrInvalidArgument)
	}
	if err := c.heapLayoutTitle("visual-heap"); err != nil {
		return err
	}
	if err := writef("range=[0x%0*x, 0x%0*x) max-headers=%d max-bytes=%d\n", word*2, start, word*2, end, heapLayoutMaxChunks, heapLayoutMaxBytes); err != nil {
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
		data := make([]byte, headerSize)
		n, readErr := c.session.ReadSpaceMemory(token, address, data[:])
		prefix, readErr := inspectionConfirmedBytes(data[:], n, readErr)
		if err := contextReady(ctx); err != nil {
			return errors.Join(readErr, err)
		}
		if errors.Is(readErr, target.ErrStale) {
			return readErr
		}
		addressText, err := c.renderer.Address(abiFor(arguments.arch).arch, address, display.AddressUnknown)
		if err != nil {
			return errors.Join(readErr, err)
		}
		if len(prefix) != headerSize {
			return errors.Join(readErr, writef("%s <partial header bytes: %s>\n", addressText, display.FormatBytes(prefix)))
		}
		header := decodeHeapLayoutHeader(prefix, word)
		structuralErr := header.validate(address, word)
		if structuralErr == nil && header.size() > uint64(end-address) {
			structuralErr = fmt.Errorf("chunk size at %#x extends past exclusive END %#x: %w", address, end, target.ErrInvalidArgument)
		}
		status := ""
		if structuralErr != nil {
			status = " <structurally invalid range/layout>"
		}
		if err := writef("%s prev_size=0x%0*x raw_size=0x%0*x size=0x%x P=%d M=%d A=%d%s\n", addressText, word*2, header.previous, word*2, header.rawSize, header.size(), header.rawSize&1, header.rawSize>>1&1, header.rawSize>>2&1, status); err != nil {
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
