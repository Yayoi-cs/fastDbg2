package debugger

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

const (
	defaultAddressWalkDepth = 4
	maxAddressWalkDepth     = 16
	maxAddressWalkReads     = 4096
)

type addressWalkReader interface {
	ReadSpaceMemory(target.MemoryToken, target.Address, []byte) (int, error)
}

type addressWalkMapSource interface {
	addressWalkMaps(context.Context, target.Snapshot, target.ThreadInfo) ([]procMap, error)
}

type addressWalkWord struct {
	data     [8]byte
	n        int
	value    uint64
	terminal string
	err      error
}

type addressWalker struct {
	arch        target.Architecture
	reader      addressWalkReader
	memory      target.MemoryToken
	maps        []procMap
	mapErr      error
	mapNotice   bool
	renderer    display.Renderer
	rowStyle    display.Style
	labels      map[target.Address][]string
	cache       map[target.Address]addressWalkWord
	reads       int
	fatal       error
	symbol      func(target.Address) string
	symbolCache map[target.Address]string
	textCache   map[target.Address]string
	textBytes   map[target.Address]byte
	textFailed  map[target.Address]bool
	textRead    int
	textCalls   int
}

func newAddressWalker(reader addressWalkReader, memory target.MemoryToken, mappings []procMap, registers []target.Register, renderer display.Renderer, architectures ...target.Architecture) (*addressWalker, error) {
	if reader == nil || memory.Space.ID == 0 || memory.Space.Session == 0 || memory.Revision == 0 {
		return nil, target.ErrInvalidArgument
	}
	for index, mapping := range mappings {
		if mapping.Start >= mapping.End || index != 0 && mappings[index-1].End > mapping.Start {
			return nil, fmt.Errorf("address view requires ordered, non-overlapping mappings: %w", target.ErrInvalidArgument)
		}
	}
	walker := &addressWalker{
		reader: reader, memory: memory, maps: slices.Clone(mappings), renderer: renderer,
		labels: make(map[target.Address][]string), cache: make(map[target.Address]addressWalkWord), symbolCache: make(map[target.Address]string),
		textCache: make(map[target.Address]string), textBytes: make(map[target.Address]byte), textFailed: make(map[target.Address]bool),
	}
	if len(architectures) > 0 {
		walker.arch = architectures[0]
	}
	seen := make(map[string]bool)
	for _, register := range registers {
		if register.Name != walker.abi().sp && register.Name != walker.abi().bp {
			continue
		}
		if seen[register.Name] {
			return nil, fmt.Errorf("duplicate address label register %q: %w", register.Name, target.ErrAmbiguous)
		}
		seen[register.Name] = true
		if !register.Available || register.Bits != walker.abi().bits {
			continue
		}
		value, err := contextScalar(register)
		if err != nil {
			continue
		}
		address := target.Address(value)
		label := "$" + register.Name + ">"
		if !slices.Contains(walker.labels[address], label) {
			walker.labels[address] = append(walker.labels[address], label)
		}
	}
	return walker, nil
}

func (c *Controller) newAddressView(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, registers []target.Register) (*addressWalker, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	source, ok := c.session.(addressWalkMapSource)
	if !ok {
		return nil, nil
	}
	mappings, mapErr := source.addressWalkMaps(ctx, snapshot, thread)
	if addressWalkFatal(mapErr) || contextReady(ctx) != nil {
		return nil, errors.Join(mapErr, ctx.Err())
	}
	if mapErr != nil {
		mappings = nil
	}
	walker, err := newAddressWalker(c.session, snapshot.Memory, mappings, registers, c.renderer, snapshot.Architecture)
	if err != nil {
		mapErr = errors.Join(mapErr, err)
		walker, err = newAddressWalker(c.session, snapshot.Memory, nil, registers, c.renderer, snapshot.Architecture)
		if err != nil {
			return nil, errors.Join(mapErr, err)
		}
	}
	walker.mapErr = mapErr
	if symbolErr := c.addAddressSymbols(ctx, snapshot, thread, walker); addressWalkFatal(symbolErr) {
		return nil, errors.Join(mapErr, symbolErr)
	}
	if err := contextReady(ctx); err != nil {
		return nil, errors.Join(mapErr, err)
	}
	return walker, mapErr
}

func addressWalkFatal(err error) bool {
	return errors.Is(err, target.ErrStale) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (walker *addressWalker) ready(ctx context.Context) error {
	if walker.fatal != nil {
		return walker.fatal
	}
	if err := contextReady(ctx); err != nil {
		walker.fatal = err
	}
	return walker.fatal
}

func (walker *addressWalker) mapIndex(address target.Address) int {
	index := sort.Search(len(walker.maps), func(index int) bool { return walker.maps[index].End > address })
	if index == len(walker.maps) || walker.maps[index].Start > address {
		return -1
	}
	return index
}

func (walker *addressWalker) terminal(address target.Address) string {
	index := walker.mapIndex(address)
	if index < 0 {
		return "unmapped"
	}
	if !walker.maps[index].Read {
		return "unreadable"
	}
	if uint64(address) > walker.abi().maximum-uint64(walker.abi().word-1) {
		return "boundary"
	}
	last := address + target.Address(walker.abi().word-1)
	cursor := address
	for ; index < len(walker.maps); index++ {
		mapping := walker.maps[index]
		if mapping.Start > cursor {
			return "boundary"
		}
		if !mapping.Read {
			return "unreadable"
		}
		if last < mapping.End {
			return ""
		}
		cursor = mapping.End
	}
	return "boundary"
}

func (walker *addressWalker) Address(address target.Address) (string, error) {
	index := walker.mapIndex(address)
	if walker.mapErr != nil || index < 0 {
		return walker.renderer.Address(walker.abi().arch, address, display.AddressUnknown)
	}
	mapping := walker.maps[index]
	return walker.renderer.AddressPermissions(walker.abi().arch, address, mapping.Read, mapping.Write, mapping.Execute)
}

func (walker *addressWalker) Labels(address target.Address) string {
	labels := walker.labels[address]
	rsp, rbp := slices.Contains(labels, "$"+walker.abi().sp+">"), slices.Contains(labels, "$"+walker.abi().bp+">")
	if rsp && rbp {
		return "$" + walker.abi().sp + "/" + walker.abi().bp + ">"
	}
	if rsp {
		return "$" + walker.abi().sp + ">"
	}
	if rbp {
		return "$" + walker.abi().bp + ">"
	}
	return ""
}

func (walker *addressWalker) valueText(value uint64) (string, error) {
	address := target.Address(value)
	text, err := walker.Address(address)
	if err != nil {
		return "", err
	}
	if walker.symbol != nil {
		label, exists := walker.symbolCache[address]
		if !exists {
			label = walker.symbol(address)
			walker.symbolCache[address] = label
		}
		if label != "" {
			text += " <" + contextEscapedText(label) + ">"
		}
	}
	return text, nil
}

func (walker *addressWalker) word(ctx context.Context, address target.Address, mapped bool) addressWalkWord {
	if err := walker.ready(ctx); err != nil {
		return addressWalkWord{err: err}
	}
	if mapped {
		if terminal := walker.terminal(address); terminal != "" {
			return addressWalkWord{terminal: terminal}
		}
	}
	if cached, ok := walker.cache[address]; ok {
		return cached
	}
	if word, ok := walker.textWord(address); ok {
		walker.cache[address] = word
		return word
	}
	if walker.reads == maxAddressWalkReads {
		return addressWalkWord{terminal: "budget", err: fmt.Errorf("address walk reached %d qword reads: %w", maxAddressWalkReads, target.ErrPartial)}
	}
	word := addressWalkWord{}
	walker.reads++
	n, err := walker.reader.ReadSpaceMemory(walker.memory, address, word.data[:walker.abi().word])
	data, err := inspectionConfirmedBytes(word.data[:walker.abi().word], n, err)
	word.n, word.err = len(data), err
	if err := contextReady(ctx); err != nil {
		word.err = errors.Join(word.err, err)
	}
	if addressWalkFatal(word.err) {
		walker.fatal = word.err
		return addressWalkWord{err: word.err}
	}
	if word.n == walker.abi().word {
		word.value = inspectionWord(word.data[:walker.abi().word])
	}
	walker.cache[address] = word
	if word.err == nil && word.n == walker.abi().word {
		walker.rememberTextBytes(address, word.data[:walker.abi().word])
	}
	return word
}

func (walker *addressWalker) state(text string) string {
	return walker.renderer.Text(display.StyleMuted, "["+text+"]")
}

func (walker *addressWalker) unavailable(word addressWalkWord) string {
	if word.n == 0 {
		return walker.renderer.Text(display.StyleError, "[unavailable]")
	}
	return walker.renderer.Text(display.StyleError, fmt.Sprintf("<partial %d/%d: %s>", word.n, walker.abi().word, display.FormatBytes(word.data[:word.n])))
}

func (walker *addressWalker) walk(ctx context.Context, value uint64, depth int, visited map[target.Address]bool, source addressTextSource) (string, error) {
	if err := walker.ready(ctx); err != nil {
		return "", err
	}
	if depth < 0 || depth > maxAddressWalkDepth {
		return "", target.ErrInvalidArgument
	}
	text, err := walker.valueText(value)
	if err != nil {
		return "", err
	}
	if err := walker.ready(ctx); err != nil {
		return "", err
	}
	if walker.mapErr != nil {
		if !walker.mapNotice {
			walker.mapNotice = true
			text += " " + walker.state("maps unavailable")
		}
		return text, nil
	}
	for followed := 0; ; followed++ {
		if err := walker.ready(ctx); err != nil {
			return "", err
		}
		address := target.Address(value)
		if visited[address] {
			return text + " -> " + walker.state("loop detected"), nil
		}
		if terminal := walker.terminal(address); terminal != "" {
			annotation, err := walker.leafText(ctx, address, source)
			if err != nil {
				return "", err
			}
			return text + annotation, nil
		}
		if followed == depth {
			return text + " -> ...", nil
		}
		visited[address] = true
		word := walker.word(ctx, address, true)
		if addressWalkFatal(word.err) {
			return "", word.err
		}
		if word.terminal != "" {
			return text + " " + walker.state(word.terminal), word.err
		}
		if word.n != walker.abi().word {
			return text + " -> " + walker.unavailable(word), word.err
		}
		value = word.value
		if visited[target.Address(value)] && word.err == nil {
			return text + " -> " + walker.state("loop detected"), nil
		}
		next, err := walker.valueText(value)
		if err != nil {
			return text, err
		}
		if err := walker.ready(ctx); err != nil {
			return "", err
		}
		text += " -> " + next
		if word.err != nil {
			return text + " " + walker.renderer.Text(display.StyleError, "[unavailable]"), word.err
		}
		source = addressTextSource{address: address, known: true}
	}
}

func (walker *addressWalker) Value(ctx context.Context, value uint64, depth int) (string, error) {
	return walker.walk(ctx, value, depth, make(map[target.Address]bool), addressTextSource{})
}

func (walker *addressWalker) Rows(ctx context.Context, address target.Address, count, depth int) (string, error) {
	if err := walker.ready(ctx); err != nil {
		return "", err
	}
	if count < 1 || count > maxMemoryBytes/walker.abi().word || depth < 0 || depth > maxAddressWalkDepth {
		return "", target.ErrInvalidArgument
	}
	if err := inspectionRange(address, count*walker.abi().word); err != nil {
		return "", err
	}
	var output strings.Builder
	for index := 0; index < count; index++ {
		current := address + target.Address(index*walker.abi().word)
		word := walker.word(ctx, current, false)
		if addressWalkFatal(word.err) {
			return "", word.err
		}
		addressText, err := walker.Address(current)
		if walker.rowStyle != display.StylePlain {
			addressText = walker.renderer.Text(walker.rowStyle, fmt.Sprintf("0x%0*x", walker.abi().word*2, current))
		}
		if err != nil {
			return "", err
		}
		var valueText string
		readErr := word.err
		switch {
		case word.terminal != "":
			valueText = walker.state(word.terminal)
		case word.n != walker.abi().word:
			valueText = walker.unavailable(word)
		case word.err != nil:
			valueText, err = walker.valueText(word.value)
			valueText += " " + walker.renderer.Text(display.StyleError, "[unavailable]")
		default:
			valueText, readErr = walker.walk(ctx, word.value, depth, map[target.Address]bool{current: true}, addressTextSource{address: current, known: true})
		}
		if err != nil {
			return "", err
		}
		if err := walker.ready(ctx); err != nil {
			return "", err
		}
		if addressWalkFatal(readErr) {
			return "", readErr
		}
		fmt.Fprintf(&output, "%-9s %s|+0x%04x|+%03d: %s\n", walker.Labels(current), addressText, index*walker.abi().word, index, valueText)
		if readErr != nil {
			return output.String(), readErr
		}
	}
	if err := walker.ready(ctx); err != nil {
		return "", err
	}
	return output.String(), nil
}

func (c *Controller) addressWalkExpression(ctx context.Context, expression string, snapshot target.Snapshot, thread target.ThreadInfo) (target.Address, []target.Register, error) {
	if err := contextReady(ctx); err != nil {
		return 0, nil, err
	}
	if err := validateImageSnapshot(snapshot, thread); err != nil {
		return 0, nil, err
	}
	registers, err := c.session.ReadThreadRegisters(thread.Token)
	if err != nil {
		return 0, nil, err
	}
	resolver := &lazyInspectionResolver{controller: c, ctx: ctx, snapshot: snapshot, thread: thread, ready: true, registers: registers, readRegs: true}
	value, err := inspect.EvalExpression(expression, resolver)
	if err == nil && value > abiFor(snapshot.Architecture).maximum {
		return 0, nil, target.ErrOverflow
	}
	return target.Address(value), registers, errors.Join(err, contextReady(ctx))
}

func (c *Controller) publishAddressWalk(ctx context.Context, heading, body string, readErr error) error {
	if addressWalkFatal(readErr) || contextReady(ctx) != nil {
		return errors.Join(readErr, contextReady(ctx))
	}
	width := display.OutputWidth(c.out)
	text := c.renderer.Section(heading, width) + "\n" + display.Wrap(body, width, 10)
	if err := contextReady(ctx); err != nil {
		return errors.Join(readErr, err)
	}
	return errors.Join(readErr, c.writef("%s", text))
}
