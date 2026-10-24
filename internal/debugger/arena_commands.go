package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"fastdbg2/inspect"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

const (
	heapGraphMaxNodes  = 4096
	heapGraphMaxArenas = 256
	heapGraphMaxBytes  = 1 << 20
	heapGraphMaxJSON   = 64 << 10
)

type heapGraphArguments struct {
	layoutFile string
	module     string
	debugFile  string
	fastLink   string
	expression string
	tcache     string
	all        bool
}

type heapGraphReadKey struct {
	address target.Address
	size    uint64
}

type heapGraphRead struct {
	data []byte
	err  error
}

type heapGraphReader struct {
	ctx       context.Context
	session   session
	token     target.MemoryToken
	cache     map[heapGraphReadKey]heapGraphRead
	bytes     uint64
	nodes     int
	exhausted bool
}

type heapArenaObservation struct {
	address target.Address
	data    []byte
	err     error
}

type heapGraphInput struct {
	layout        inspect.HeapLayout
	address       target.Address
	proof         string
	reader        *heapGraphReader
	tcacheAddress *target.Address
	alignment     uint64
}

type heapGraphProofError struct {
	err error
}

func (err *heapGraphProofError) Error() string {
	return fmt.Sprintf("heap metadata provenance could not be confirmed: %v", err.err)
}

func (err *heapGraphProofError) Unwrap() error { return err.err }

func parseHeapGraphArguments(rawArgs string, arena bool) (heapGraphArguments, error) {
	var result heapGraphArguments
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return result, fmt.Errorf("heap arguments: %w: %w", err, target.ErrInvalidArgument)
	}
	seen := make(map[string]bool)
	for len(args) != 0 && strings.HasPrefix(args[0], "--") {
		name := args[0]
		args = args[1:]
		if name == "--" {
			break
		}
		if seen[name] {
			return result, fmt.Errorf("duplicate heap option %q: %w", name, target.ErrInvalidArgument)
		}
		seen[name] = true
		if name == "--all" {
			if !arena {
				return result, fmt.Errorf("--all is only supported by arena: %w", target.ErrInvalidArgument)
			}
			result.all = true
			continue
		}
		if name != "--layout-file" && name != "--module" && name != "--debug-file" && name != "--fast-link" && name != "--tcache" {
			return result, fmt.Errorf("unknown heap option %q: %w", name, target.ErrInvalidArgument)
		}
		if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "--") {
			return result, fmt.Errorf("heap option %s requires a value: %w", name, target.ErrInvalidArgument)
		}
		value := args[0]
		args = args[1:]
		switch name {
		case "--layout-file":
			result.layoutFile = value
		case "--module":
			result.module = value
		case "--debug-file":
			result.debugFile = value
		case "--fast-link":
			result.fastLink = value
		case "--tcache":
			if arena {
				return result, fmt.Errorf("--tcache is only supported by bins: %w", target.ErrInvalidArgument)
			}
			result.tcache = value
		}
	}
	if len(args) > 1 || len(args) == 1 && strings.TrimSpace(args[0]) == "" {
		return result, fmt.Errorf("heap commands accept at most one address expression; quote expressions containing spaces: %w", target.ErrInvalidArgument)
	}
	if len(args) == 1 {
		result.expression = args[0]
	}
	if result.layoutFile != "" {
		if result.module != "" || result.debugFile != "" || result.fastLink != "" || result.expression == "" {
			return result, fmt.Errorf("--layout-file requires an explicit address and cannot be combined with --module, --debug-file or --fast-link: %w", target.ErrInvalidArgument)
		}
		return result, nil
	}
	if result.module == "" {
		return result, fmt.Errorf("specify --layout-file FILE ADDRESS or --module ID --fast-link plain|safe-link-12; no allocator discovery is performed: %w", target.ErrInvalidArgument)
	}
	if result.tcache != "" {
		return result, fmt.Errorf("explicit --tcache requires --layout-file: %w", target.ErrInvalidArgument)
	}
	if result.fastLink != "plain" && result.fastLink != "safe-link-12" {
		return result, fmt.Errorf("DWARF heap layout requires explicit --fast-link plain|safe-link-12: %w", target.ErrInvalidArgument)
	}
	return result, nil
}

func readHeapGraphLayout(ctx context.Context, path string) (layout inspect.HeapLayout, err error) {
	file, err := openRegularELFSource(ctx, path)
	if err != nil {
		return layout, fmt.Errorf("heap layout file: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, heapGraphMaxJSON+1))
	if err != nil {
		return layout, err
	}
	if err := contextReady(ctx); err != nil {
		return layout, err
	}
	if len(data) > heapGraphMaxJSON {
		return layout, fmt.Errorf("heap layout file exceeds %d bytes: %w", heapGraphMaxJSON, target.ErrInvalidArgument)
	}
	return inspect.ParseHeapLayout(data)
}

func newHeapGraphReader(ctx context.Context, session session, token target.MemoryToken) *heapGraphReader {
	return &heapGraphReader{ctx: ctx, session: session, token: token, cache: make(map[heapGraphReadKey]heapGraphRead)}
}

func (reader *heapGraphReader) read(address target.Address, size uint64) ([]byte, error) {
	if err := contextReady(reader.ctx); err != nil {
		return nil, err
	}
	key := heapGraphReadKey{address, size}
	if value, ok := reader.cache[key]; ok {
		return value.data, value.err
	}
	if size == 0 || size > heapGraphMaxBytes || size-1 > math.MaxUint64-uint64(address) {
		return nil, fmt.Errorf("heap read range at %#x size %#x: %w", address, size, target.ErrOverflow)
	}
	if size > heapGraphMaxBytes-reader.bytes {
		reader.exhausted = true
		return nil, fmt.Errorf("heap inspection reached the global %d-byte read budget: %w", heapGraphMaxBytes, target.ErrUnavailable)
	}
	reader.bytes += size
	data := make([]byte, int(size))
	n, err := reader.session.ReadSpaceMemory(reader.token, address, data)
	data, err = inspectionConfirmedBytes(data, n, err)
	if contextErr := contextReady(reader.ctx); contextErr != nil {
		return nil, errors.Join(err, contextErr)
	}
	if errors.Is(err, target.ErrStale) {
		return nil, err
	}
	reader.cache[key] = heapGraphRead{data, err}
	return data, err
}

func (reader *heapGraphReader) takeNode() error {
	if err := contextReady(reader.ctx); err != nil {
		return err
	}
	if reader.nodes == heapGraphMaxNodes {
		reader.exhausted = true
		return fmt.Errorf("heap inspection reached the global %d-node budget: %w", heapGraphMaxNodes, target.ErrUnavailable)
	}
	reader.nodes++
	return nil
}

func heapGraphField(data []byte, field inspect.HeapField, index uint64) (uint64, bool) {
	if index >= field.Count || field.Stride != 0 && index > (math.MaxUint64-field.Offset)/field.Stride {
		return 0, false
	}
	offset := field.Offset + index*field.Stride
	if offset > uint64(len(data)) || field.Width > uint64(len(data))-offset {
		return 0, false
	}
	value := data[offset : offset+field.Width]
	switch field.Width {
	case 1:
		return uint64(value[0]), true
	case 2:
		return uint64(binary.LittleEndian.Uint16(value)), true
	case 4:
		return uint64(binary.LittleEndian.Uint32(value)), true
	case 8:
		return binary.LittleEndian.Uint64(value), true
	default:
		return 0, false
	}
}

func heapGraphFatal(err error) bool {
	var proofErr *heapGraphProofError
	return errors.As(err, &proofErr) || errors.Is(err, target.ErrStale) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (c *Controller) withHeapGraphInput(ctx context.Context, arguments heapGraphArguments, visit func(heapGraphInput) error) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if arguments.layoutFile == "" {
		return c.withHeapDWARFInput(ctx, arguments, visit)
	}
	layout, err := readHeapGraphLayout(ctx, arguments.layoutFile)
	if err != nil {
		return err
	}
	if arguments.tcache != "" && (layout.Tcache == nil || layout.TcacheEntry == nil) {
		return fmt.Errorf("--tcache requires tcache, tcache_entry and tcache_link in the explicit layout: %w", target.ErrInvalidArgument)
	}
	resolver := &lazyInspectionResolver{controller: c, ctx: ctx}
	if err := resolver.initialize(); err != nil {
		return err
	}
	address, err := inspect.EvalExpression(arguments.expression, resolver)
	if err != nil {
		return err
	}
	input := heapGraphInput{
		layout: layout, address: target.Address(address),
		proof:  fmt.Sprintf("user-selected layout=%q address-expression=%q", arguments.layoutFile, arguments.expression),
		reader: newHeapGraphReader(ctx, c.session, resolver.snapshot.Memory),
	}
	if arguments.tcache != "" {
		value, err := inspect.EvalExpression(arguments.tcache, resolver)
		if err != nil {
			return err
		}
		address := target.Address(value)
		input.tcacheAddress = &address
		input.proof += fmt.Sprintf(" tcache-address-expression=%q", arguments.tcache)
	}
	return visit(input)
}

func walkHeapArenas(input heapGraphInput, all bool) ([]heapArenaObservation, error) {
	var result []heapArenaObservation
	visited := make(map[target.Address]struct{})
	address := input.address
	for {
		if len(result) == heapGraphMaxArenas {
			return result, fmt.Errorf("arena traversal reached %d arenas before its starting address: %w", heapGraphMaxArenas, target.ErrUnavailable)
		}
		if _, exists := visited[address]; exists {
			return result, fmt.Errorf("arena next link repeats %#x without returning to the starting address; observed inconsistency may be an in-progress allocator update: %w", address, target.ErrInvalidState)
		}
		visited[address] = struct{}{}
		if err := input.reader.takeNode(); err != nil {
			return result, err
		}
		data, err := input.reader.read(address, input.layout.Arena.Size)
		if heapGraphFatal(err) {
			return nil, err
		}
		result = append(result, heapArenaObservation{address, data, err})
		if err != nil || !all {
			return result, err
		}
		next, ok := heapGraphField(data, input.layout.Arena.Fields["next"], 0)
		if !ok {
			return result, fmt.Errorf("arena next field is incomplete: %w", target.ErrPartial)
		}
		if target.Address(next) == input.address {
			return result, nil
		}
		if next == 0 {
			return result, fmt.Errorf("arena next link is NULL before returning to the starting address; observed inconsistency may be an in-progress allocator update: %w", target.ErrInvalidState)
		}
		address = target.Address(next)
	}
}

func (c *Controller) heapGraphHeading(ctx context.Context, name string, input heapGraphInput) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if err := (contextOutput{writef: c.writef, renderer: c.renderer}).heading(name); err != nil {
		return err
	}
	return nil
}

func (c *Controller) heapGraphWritef(ctx context.Context, format string, args ...any) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	return errors.Join(c.writef(format, args...), contextReady(ctx))
}

func (c *Controller) showArenas(ctx context.Context, rawArgs string) error {
	if !heapExplicitMode(rawArgs) {
		return c.showAutomaticArenas(ctx, rawArgs)
	}
	arguments, err := parseHeapGraphArguments(rawArgs, true)
	if err != nil {
		return err
	}
	var input heapGraphInput
	var arenas []heapArenaObservation
	err = c.withHeapGraphInput(ctx, arguments, func(value heapGraphInput) error {
		input = value
		var err error
		arenas, err = walkHeapArenas(value, arguments.all)
		return err
	})
	if heapGraphFatal(err) || input.reader == nil || len(arenas) == 0 {
		return err
	}
	if outputErr := c.heapGraphHeading(ctx, "arena", input); outputErr != nil {
		return errors.Join(err, outputErr)
	}
	var names []string
	for name := range input.layout.Arena.Fields {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		left, right := input.layout.Arena.Fields[a].Offset, input.layout.Arena.Fields[b].Offset
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
		return strings.Compare(a, b)
	})
	for index, arena := range arenas {
		if outputErr := c.heapGraphWritef(ctx, "arena[%d] 0x%0*x (%d/%d confirmed bytes)\n", index, c.abi().word*2, arena.address, len(arena.data), input.layout.Arena.Size); outputErr != nil {
			return errors.Join(err, outputErr)
		}
		for _, name := range names {
			field := input.layout.Arena.Fields[name]
			if field.Count != 1 {
				if outputErr := c.heapGraphWritef(ctx, "  +0x%x %-18s count=%d width=%d stride=%d\n", field.Offset, name, field.Count, field.Width, field.Stride); outputErr != nil {
					return errors.Join(err, outputErr)
				}
				continue
			}
			value, ok := heapGraphField(arena.data, field, 0)
			text := "<unconfirmed>"
			if ok {
				text = fmt.Sprintf("0x%0*x", int(field.Width)*2, value)
			}
			if outputErr := c.heapGraphWritef(ctx, "  +0x%x %-18s %s\n", field.Offset, name, text); outputErr != nil {
				return errors.Join(err, outputErr)
			}
		}
	}
	if outputErr := c.heapGraphWritef(ctx, "observed-arenas=%d requested-bytes=%d\n", len(arenas), input.reader.bytes); outputErr != nil {
		return errors.Join(err, outputErr)
	}
	return err
}
