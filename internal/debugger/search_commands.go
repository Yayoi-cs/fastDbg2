package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

const (
	searchChunkBytes     = 64 << 10
	searchMaxPattern     = 64 << 10
	searchDefaultBytes   = 256 << 20
	searchMaximumBytes   = 1 << 30
	searchDefaultMatches = 4096
	searchMaximumMatches = 65536
	searchCancelStride   = 4096
)

type searchArguments struct {
	value      string
	bounds     []string
	width      int
	bigEndian  bool
	maxBytes   uint64
	maxMatches int
}

type searchSpan struct {
	start target.Address
	end   target.Address
}

type searchResult struct {
	addresses []target.Address
	bytesRead uint64
}

type searchMemoryReader struct {
	session session
	token   target.MemoryToken
	code    bool
}

func (reader searchMemoryReader) ReadMemory(address target.Address, data []byte) (int, error) {
	if reader.code {
		return reader.session.ReadCodeMemory(reader.token, address, data)
	}
	return reader.session.ReadSpaceMemory(reader.token, address, data)
}

type searchFileReader struct{ file *os.File }

func (reader searchFileReader) ReadMemory(address target.Address, data []byte) (int, error) {
	if uint64(address) > math.MaxInt64 {
		return 0, target.ErrOverflow
	}
	return reader.file.ReadAt(data, int64(address))
}

func parseSearchArguments(kind, rawArgs string) (searchArguments, error) {
	options := searchArguments{maxBytes: searchDefaultBytes, maxMatches: searchDefaultMatches}
	if len(rawArgs) > 4*searchMaxPattern+1024 {
		return options, fmt.Errorf("search arguments are too long: %w", target.ErrInvalidArgument)
	}
	if kind != "search-string" && kind != "search-value" && kind != "findruction" {
		return options, target.ErrInvalidArgument
	}
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return options, fmt.Errorf("%s arguments: %w: %v", kind, target.ErrInvalidArgument, err)
	}
	seen := make(map[string]bool)
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		name := args[0]
		args = args[1:]
		if name == "--" {
			break
		}
		if seen[name] || len(args) == 0 {
			return options, fmt.Errorf("%s needs one value and may appear once: %w", name, target.ErrInvalidArgument)
		}
		seen[name] = true
		value := args[0]
		args = args[1:]
		if name == "--endian" && kind == "search-value" {
			if value != "little" && value != "big" {
				return options, fmt.Errorf("--endian must be little or big: %w", target.ErrInvalidArgument)
			}
			options.bigEndian = value == "big"
			continue
		}
		number, err := strconv.ParseUint(value, 0, 64)
		if err != nil || number == 0 {
			return options, fmt.Errorf("%s needs a positive integer: %w", name, target.ErrInvalidArgument)
		}
		switch {
		case name == "--size" && kind == "search-value" && number <= 8:
			options.width = int(number)
		case name == "--max-bytes" && number <= searchMaximumBytes:
			options.maxBytes = number
		case name == "--max-matches" && number <= searchMaximumMatches:
			options.maxMatches = int(number)
		default:
			return options, fmt.Errorf("unsupported option or out-of-range value %s %q: %w", name, value, target.ErrInvalidArgument)
		}
	}
	if len(args) < 1 || len(args) > 3 || args[0] == "" {
		return options, fmt.Errorf("usage: %s [OPTIONS] PATTERN [START [END]]: %w", kind, target.ErrInvalidArgument)
	}
	options.value, options.bounds = args[0], args[1:]
	return options, nil
}

func searchValueBytes(value uint64, width int, bigEndian bool) ([]byte, error) {
	if width < 0 || width > 8 {
		return nil, target.ErrInvalidArgument
	}
	if width == 0 {
		width = 1
		for remaining := value >> 8; remaining != 0; remaining >>= 8 {
			width++
		}
	}
	if width < 8 && value>>(width*8) != 0 {
		return nil, fmt.Errorf("value %#x does not fit in %d bytes: %w", value, width, target.ErrOverflow)
	}
	data := make([]byte, width)
	for i := range data {
		index := i
		if bigEndian {
			index = len(data) - 1 - i
		}
		data[index] = byte(value >> (i * 8))
	}
	return data, nil
}

func searchMapSpans(maps []procMap, bounds []target.Address, executable bool) ([]searchSpan, string, error) {
	if len(bounds) > 2 {
		return nil, "", target.ErrInvalidArgument
	}
	var start, end target.Address
	if len(bounds) != 0 {
		start = bounds[0]
		if len(bounds) == 2 {
			end = bounds[1]
		} else {
			for _, mapping := range maps {
				if start >= mapping.Start && start < mapping.End && (mapping.Read && !executable || mapping.Execute && executable) {
					end = mapping.End
					break
				}
			}
			if end == 0 {
				return nil, "", fmt.Errorf("start %#x has no containing eligible mapping: %w", start, target.ErrNotFound)
			}
		}
		if start >= end {
			return nil, "", fmt.Errorf("search requires START < END: %w", target.ErrInvalidArgument)
		}
	}
	scope := "readable mappings"
	if executable {
		scope = "executable mappings"
	}
	if len(bounds) != 0 {
		scope += fmt.Sprintf(" intersect [0x%x, 0x%x)", start, end)
	}
	var spans []searchSpan
	for i, mapping := range maps {
		if mapping.Start >= mapping.End || i > 0 && maps[i-1].End > mapping.Start {
			return nil, "", fmt.Errorf("unordered or invalid mapping: %w", target.ErrInvalidArgument)
		}
		if executable && !mapping.Execute || !executable && !mapping.Read {
			continue
		}
		span := searchSpan{start: mapping.Start, end: mapping.End}
		if len(bounds) != 0 {
			span.start = max(span.start, start)
			span.end = min(span.end, end)
		}
		if span.start < span.end {
			spans = append(spans, span)
		}
	}
	if len(spans) == 0 {
		return nil, "", fmt.Errorf("no eligible mappings in search scope: %w", target.ErrNotFound)
	}
	return spans, scope, nil
}

func scanSearch(ctx context.Context, reader inspect.MemoryReader, spans []searchSpan, pattern []byte, maxBytes uint64, maxMatches int) (searchResult, error) {
	var result searchResult
	if err := contextReady(ctx); err != nil {
		return result, err
	}
	if reader == nil || len(pattern) == 0 || len(pattern) > searchMaxPattern || maxBytes == 0 || maxBytes > searchMaximumBytes || maxMatches < 1 || maxMatches > searchMaximumMatches {
		return result, target.ErrInvalidArgument
	}
	for i, span := range spans {
		if span.start >= span.end || i > 0 && spans[i-1].end > span.start {
			return result, target.ErrInvalidArgument
		}
	}
	pattern = bytes.Clone(pattern)
	prefix, err := searchPatternPrefix(ctx, pattern)
	if err != nil {
		return result, err
	}
	buffer := make([]byte, searchChunkBytes)
	matched := 0
	var priorEnd target.Address
	var planned uint64
	var failures []error
	for _, span := range spans {
		if span.start != priorEnd {
			matched = 0
		}
		length := uint64(span.end - span.start)
		allowed := min(length, maxBytes-planned)
		planned += allowed
		for offset := uint64(0); offset < allowed; {
			if err := ctx.Err(); err != nil {
				return searchResult{}, errors.Join(errors.Join(failures...), err)
			}
			want := int(min(uint64(searchChunkBytes), allowed-offset))
			data := buffer[:want]
			address := span.start + target.Address(offset)
			n, readErr := reader.ReadMemory(address, data)
			if n < 0 || n > want {
				return searchResult{}, errors.Join(readErr, fmt.Errorf("search reader returned %d bytes for %d: %w", n, want, target.ErrInvalidArgument))
			}
			if errors.Is(readErr, target.ErrStale) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) || ctx.Err() != nil {
				return searchResult{}, errors.Join(errors.Join(failures...), readErr, ctx.Err())
			}
			if n < want && readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			data = data[:n]
			result.bytesRead += uint64(n)
			for i, value := range data {
				if i%searchCancelStride == 0 {
					if err := ctx.Err(); err != nil {
						return searchResult{}, errors.Join(errors.Join(failures...), readErr, err)
					}
				}
				for matched > 0 && value != pattern[matched] {
					matched = prefix[matched-1]
				}
				if value == pattern[matched] {
					matched++
				}
				if matched == len(pattern) {
					if len(result.addresses) == maxMatches {
						return result, errors.Join(errors.Join(failures...), readErr, searchLimitError("matches", uint64(maxMatches)))
					}
					result.addresses = append(result.addresses, address+target.Address(i+1)-target.Address(len(pattern)))
					matched = prefix[matched-1]
				}
			}
			if readErr != nil {
				failures = append(failures, &target.PartialError{Op: fmt.Sprintf("search mapping [0x%x, 0x%x) at 0x%x", span.start, span.end, address), Completed: n, Total: want, Err: readErr})
				matched = 0
				break
			}
			offset += uint64(n)
		}
		priorEnd = span.end
		if allowed < length {
			return result, errors.Join(errors.Join(failures...), searchLimitError("bytes", maxBytes))
		}
	}
	if err := ctx.Err(); err != nil {
		return searchResult{}, errors.Join(errors.Join(failures...), err)
	}
	return result, errors.Join(failures...)
}

func searchPatternPrefix(ctx context.Context, pattern []byte) ([]int, error) {
	prefix := make([]int, len(pattern))
	for i, matched := 1, 0; i < len(pattern); i++ {
		if i%searchCancelStride == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		for matched > 0 && pattern[i] != pattern[matched] {
			matched = prefix[matched-1]
		}
		if pattern[i] == pattern[matched] {
			matched++
		}
		prefix[i] = matched
	}
	return prefix, nil
}

func searchLimitError(unit string, limit uint64) error {
	return fmt.Errorf("search incomplete: maximum %s %d reached: %w", unit, limit, errors.Join(target.ErrPartial, target.ErrOverflow))
}

func (c *Controller) commandSearch(ctx context.Context, kind, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	options, err := parseSearchArguments(kind, rawArgs)
	if err != nil {
		return err
	}
	pattern := []byte(options.value)
	if kind == "findruction" {
		pattern, err = assembleAMD64(ctx, options.value)
		if err != nil {
			return err
		}
	}
	if kind != "search-value" && (len(pattern) == 0 || len(pattern) > searchMaxPattern) {
		return fmt.Errorf("pattern must have 1..%d bytes: %w", searchMaxPattern, target.ErrInvalidArgument)
	}
	if c.session == nil && kind == "findruction" && len(options.bounds) == 0 {
		return c.searchConfiguredELF(ctx, pattern, options)
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if kind == "search-value" {
		value, err := c.evaluate(ctx, options.value, snapshot, thread)
		if err != nil {
			return err
		}
		pattern, err = searchValueBytes(uint64(value), options.width, options.bigEndian)
		if err != nil {
			return err
		}
	}
	bounds := make([]target.Address, len(options.bounds))
	for i, expression := range options.bounds {
		bounds[i], err = c.evaluate(ctx, expression, snapshot, thread)
		if err != nil {
			return err
		}
	}
	maps, err := c.readProcessMaps(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	spans, scope, err := searchMapSpans(maps, bounds, kind == "findruction")
	if err != nil {
		return err
	}
	reader := searchMemoryReader{session: c.session, token: snapshot.Memory, code: kind == "findruction"}
	result, searchErr := scanSearch(ctx, reader, spans, pattern, options.maxBytes, options.maxMatches)
	if errors.Is(searchErr, target.ErrStale) || errors.Is(searchErr, context.Canceled) || errors.Is(searchErr, context.DeadlineExceeded) || ctx.Err() != nil {
		return errors.Join(searchErr, ctx.Err())
	}
	if err := c.verifyProcSnapshot(snapshot, thread); err != nil {
		return errors.Join(searchErr, err)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(searchErr, err)
	}
	source, addressKind := "live-raw", display.AddressUnknown
	if reader.code {
		source, addressKind = "live-logical", display.AddressCode
	}
	if err := c.searchHeading(source, scope, pattern, result, searchErr); err != nil {
		return errors.Join(searchErr, err)
	}
	for _, address := range result.addresses {
		if err := ctx.Err(); err != nil {
			return errors.Join(searchErr, err)
		}
		text, err := c.renderer.Address(target.AMD64, address, addressKind)
		if err != nil {
			return errors.Join(searchErr, err)
		}
		if err := c.writef("  %s\n", text); err != nil {
			return errors.Join(searchErr, err)
		}
	}
	return searchErr
}

func (c *Controller) searchHeading(source, scope string, pattern []byte, result searchResult, searchErr error) error {
	status := "complete"
	state := metadataPresent
	if searchErr != nil {
		status = "partial"
		state = metadataPartial
	}
	view := c.metadataView()
	view.heading("search")
	view.field("Source", source, metadataPlain)
	view.field("Scope", scope, metadataPlain)
	view.field("Pattern", fmt.Sprintf("%x (%d bytes)", pattern, len(pattern)), metadataPlain)
	view.field("Matches", fmt.Sprintf("%d confirmed byte match(es)", len(result.addresses)), metadataPlain)
	view.field("Bytes read", fmt.Sprint(result.bytesRead), metadataPlain)
	view.field("Status", status, state)
	return c.writef("%s", view.output.String())
}

func (c *Controller) searchConfiguredELF(ctx context.Context, pattern []byte, options searchArguments) (err error) {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if len(pattern) == 0 || len(pattern) > searchMaxPattern || options.maxBytes == 0 || options.maxBytes > searchMaximumBytes || options.maxMatches < 1 || options.maxMatches > searchMaximumMatches {
		return target.ErrInvalidArgument
	}
	if c.path == "" {
		return fmt.Errorf("configure an AMD64 executable before file search: %w", target.ErrInvalidState)
	}
	file, err := openRegularELFSource(ctx, c.path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return fmt.Errorf("ELF search requires a regular file: %w", target.ErrInvalidArgument)
	}
	image, err := elf.NewFile(file)
	if err != nil {
		return err
	}
	if err := validateAMD64ELF(image); err != nil {
		return err
	}
	var segments []*elf.Prog
	for _, segment := range image.Progs {
		if segment.Type != elf.PT_LOAD || segment.Flags&elf.PF_X == 0 || segment.Filesz == 0 {
			continue
		}
		if segment.Off > uint64(info.Size()) || segment.Filesz > uint64(info.Size())-segment.Off || segment.Filesz-1 > math.MaxUint64-segment.Vaddr || segment.Filesz > segment.Memsz {
			return fmt.Errorf("invalid executable ELF segment: %w", target.ErrInvalidArgument)
		}
		segments = append(segments, segment)
	}
	if len(segments) == 0 {
		return fmt.Errorf("ELF has no nonempty executable PT_LOAD: %w", target.ErrNotFound)
	}
	var result searchResult
	var offsets []target.Address
	var failures []error
	var planned uint64
	for _, segment := range segments {
		if planned == options.maxBytes {
			failures = append(failures, searchLimitError("bytes", options.maxBytes))
			break
		}
		if len(result.addresses) == options.maxMatches {
			failures = append(failures, searchLimitError("matches", uint64(options.maxMatches)))
			break
		}
		span := searchSpan{start: target.Address(segment.Off), end: target.Address(segment.Off + segment.Filesz)}
		part, readErr := scanSearch(ctx, searchFileReader{file}, []searchSpan{span}, pattern, options.maxBytes-planned, options.maxMatches-len(result.addresses))
		if ctx.Err() != nil || errors.Is(readErr, target.ErrStale) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
			return errors.Join(readErr, ctx.Err())
		}
		planned += min(segment.Filesz, options.maxBytes-planned)
		result.bytesRead += part.bytesRead
		for _, offset := range part.addresses {
			offsets = append(offsets, offset)
			result.addresses = append(result.addresses, target.Address(segment.Vaddr)+(offset-target.Address(segment.Off)))
		}
		if readErr != nil {
			failures = append(failures, readErr)
			if errors.Is(readErr, target.ErrOverflow) {
				break
			}
		}
	}
	searchErr := errors.Join(failures...)
	after, err := file.Stat()
	if err != nil {
		return errors.Join(searchErr, err)
	}
	if info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return errors.Join(searchErr, fmt.Errorf("ELF file changed during search: %w", target.ErrStale))
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(searchErr, err)
	}
	scope := fmt.Sprintf("ELF executable PT_LOAD file=%q", c.path)
	if err := c.searchHeading("file-unrelocated", scope, pattern, result, searchErr); err != nil {
		return errors.Join(searchErr, err)
	}
	for i, address := range result.addresses {
		if err := ctx.Err(); err != nil {
			return errors.Join(searchErr, err)
		}
		if err := c.writef("  elf-vaddr=0x%016x file-offset=0x%x\n", address, offsets[i]); err != nil {
			return errors.Join(searchErr, err)
		}
	}
	return searchErr
}
