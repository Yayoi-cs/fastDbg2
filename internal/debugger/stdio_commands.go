package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

type stdioObject struct {
	name    string
	module  *mappedELF
	address target.Address
	size    uint64
}

type stdioBlock struct {
	address target.Address
	data    []byte
	state   string
}

type stdioStream struct {
	object stdioObject
	layout stdioLayout
	blocks [4]stdioBlock
}

func stdioValue(data []byte, field stdioField) (uint64, bool) {
	if field.offset < 0 || field.size < 1 || field.size > 8 || field.offset > len(data) || field.size > len(data)-field.offset {
		return 0, false
	}
	var value uint64
	for i := 0; i < field.size; i++ {
		value |= uint64(data[field.offset+i]) << (8 * i)
	}
	if field.bits > 0 {
		value >>= field.bit
		if field.bits < 64 {
			value &= (uint64(1) << field.bits) - 1
		}
	}
	return value, true
}

func stdioPointer(block stdioBlock, record stdioRecord, name string) (target.Address, bool) {
	for _, field := range record.fields {
		if field.name == name && field.pointer {
			v, ok := stdioValue(block.data, field)
			return target.Address(v), ok
		}
	}
	return 0, false
}

func readStdioStreams(ctx context.Context, reader addressWalkReader, token target.MemoryToken, streams []stdioStream) error {
	type key struct {
		address target.Address
		size    int
	}
	cache := make(map[key]stdioBlock)
	var readErrors error
	read := func(address target.Address, size int) (stdioBlock, error) {
		if err := contextReady(ctx); err != nil {
			return stdioBlock{}, err
		}
		if address == 0 {
			return stdioBlock{state: "NULL"}, nil
		}
		k := key{address, size}
		if b, ok := cache[k]; ok {
			return b, nil
		}
		b := stdioBlock{address: address}
		if size <= 0 || size > maxMemoryBytes || uint64(size-1) > math.MaxUint64-uint64(address) {
			return b, target.ErrOverflow
		}
		b.data = make([]byte, size)
		n, err := reader.ReadSpaceMemory(token, address, b.data)
		b.data, err = inspectionConfirmedBytes(b.data, n, err)
		if uiDisplayFatal(err) {
			return b, err
		}
		if err != nil {
			readErrors = errors.Join(readErrors, fmt.Errorf("stdio read at %#x: %w", address, err))
		}
		cache[k] = b
		return b, nil
	}
	for i := range streams {
		s := &streams[i]
		var err error
		s.blocks[0], err = read(s.object.address, s.layout.file.size)
		if err != nil {
			return err
		}
		for _, step := range []struct {
			from, to int
			record   stdioRecord
			name     string
			size     int
		}{
			{0, 1, s.layout.file, "vtable", s.layout.jump.size},
			{0, 2, s.layout.file, "_wide_data", s.layout.wide.size},
			{2, 3, s.layout.wide, "_wide_vtable", s.layout.jump.size},
		} {
			pointer, ok := stdioPointer(s.blocks[step.from], step.record, step.name)
			if !ok {
				s.blocks[step.to].state = "unavailable"
				if s.blocks[step.from].state == "NULL" {
					s.blocks[step.to].state = "NULL"
				}
				continue
			}
			s.blocks[step.to], err = read(pointer, step.size)
			if err != nil {
				return err
			}
		}
	}
	return readErrors
}

func stdioCell(view *metadataView, block stdioBlock, field stdioField, mappings []procMap, labels map[target.Address]string) string {
	if block.state != "" {
		return block.state
	}
	if field.offset > len(block.data) || field.size > len(block.data)-field.offset {
		return view.renderer.Text(display.StyleError, "unavailable")
	}
	if field.aggregate {
		return "..."
	}
	value, ok := stdioValue(block.data, field)
	if !ok {
		return view.renderer.Text(display.StyleError, "unavailable")
	}
	width := field.size * 2
	if field.bits > 0 {
		width = (field.bits + 3) / 4
	}
	text := fmt.Sprintf("0x%0*x", width, value)
	if field.pointer && value != 0 {
		text = view.address(target.Address(value), mappings)
		if name := labels[target.Address(value)]; name != "" {
			text += " <" + contextEscapedText(name) + ">"
		}
	}
	return text
}

func renderStdio(view *metadataView, streams []stdioStream, mappings []procMap, labels map[target.Address]string) string {
	var output strings.Builder
	widths := make([]int, len(streams))
	names := []string{"FILE", "FILE->vtable", "FILE->_wide_data", "FILE->_wide_data->_wide_vtable"}
	rows := make([][][]string, 4)
	fieldSets := []stdioRecord{streams[0].layout.file, streams[0].layout.jump, streams[0].layout.wide, streams[0].layout.jump}
	memberWidth := 15
	for section, record := range fieldSets {
		for _, field := range record.fields {
			memberWidth = max(memberWidth, display.VisibleWidth(contextEscapedText(field.name)))
			cells := make([]string, len(streams))
			for i, s := range streams {
				cells[i] = stdioCell(view, s.blocks[section], field, mappings, labels)
				widths[i] = max(44, widths[i], display.VisibleWidth(cells[i])+2)
			}
			rows[section] = append(rows[section], cells)
		}
	}
	headers := make([]string, len(streams))
	for i, s := range streams {
		headers[i] = view.renderer.Text(display.StyleGreen, fmt.Sprintf("0x%0*x", abiFor(view.arch).word*2, s.object.address)) + " <" + s.object.name + ">"
		widths[i] = max(widths[i], display.VisibleWidth(headers[i])+2)
	}
	writeCells := func(cells []string) {
		for i, cell := range cells {
			if i == len(cells)-1 {
				output.WriteString(cell)
			} else {
				output.WriteString(display.Pad(cell, widths[i]))
			}
		}
		output.WriteByte('\n')
	}
	fmt.Fprintf(&output, "  off | %-*s : ", memberWidth, "member")
	writeCells(headers)
	for section, record := range fieldSets {
		output.WriteString(view.renderer.Section(names[section], view.width) + "\n")
		for i, field := range record.fields {
			fmt.Fprintf(&output, "+0x%02x | %s : ", field.offset, display.Pad(contextEscapedText(field.name), memberWidth))
			writeCells(rows[section][i])
		}
	}
	return output.String()
}

func (c *Controller) showStdio(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	arguments, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return err
	}
	selection := elfModuleSelection{All: true}
	if len(arguments) != 0 {
		if len(arguments) != 2 || arguments[0] != "--module" {
			return fmt.Errorf("usage: stdio [--module EXACT]: %w", target.ErrInvalidArgument)
		}
		selection, _, err = parseELFModuleArguments(arguments, false)
		if err != nil {
			return err
		}
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	labels := make(map[target.Address]string)
	var streams []stdioStream
	var readErrors error
	err = c.withELFModules(ctx, snapshot, thread, selection, func(modules []*mappedELF) error {
		var objects []stdioObject
		for _, name := range []string{"_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"} {
			var matches []stdioObject
			for _, module := range modules {
				address, size, err := elfStdioObject(module, name)
				if errors.Is(err, target.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				matches = append(matches, stdioObject{name, module, address, size})
			}
			if len(matches) == 0 {
				return fmt.Errorf("stdio symbol %q: %w", name, target.ErrNotFound)
			}
			if len(matches) != 1 {
				return fmt.Errorf("stdio symbol %q occurs in %d mapped ELF images; use --module EXACT: %w", name, len(matches), target.ErrAmbiguous)
			}
			objects = append(objects, matches[0])
		}
		for _, module := range modules {
			var selected []stdioObject
			for _, object := range objects {
				if object.module == module {
					selected = append(selected, object)
				}
			}
			if len(selected) == 0 {
				continue
			}
			layouts, err := stdioModuleLayouts(ctx, module, selected, labels)
			if err != nil {
				return fmt.Errorf("stdio FILE layout in %q (matching libc debug information required): %w", module.ID, err)
			}
			for i, object := range selected {
				streams = append(streams, stdioStream{object: object, layout: layouts[i]})
			}
		}
		sort.SliceStable(streams, func(i, j int) bool {
			order := map[string]int{"_IO_2_1_stdin_": 0, "_IO_2_1_stdout_": 1, "_IO_2_1_stderr_": 2}
			return order[streams[i].object.name] < order[streams[j].object.name]
		})
		for i := range streams {
			if !reflect.DeepEqual(streams[0].layout, streams[i].layout) {
				return fmt.Errorf("stdio incompatible stream layouts: %w", target.ErrAmbiguous)
			}
		}
		readErrors = readStdioStreams(ctx, c.session, snapshot.Memory, streams)
		if uiDisplayFatal(readErrors) {
			return readErrors
		}
		return nil
	})
	if err != nil {
		return err
	}
	mappings, err := c.readProcessMaps(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	if source, ok := c.session.(addressWalkSymbolSource); ok {
		symbols, symbolErr := source.addressWalkSymbols(ctx, snapshot, thread)
		if uiDisplayFatal(symbolErr) {
			return symbolErr
		}
		for _, s := range symbols {
			if s.AddressKnown && s.Name != "" && s.Section != elf.SHN_ABS {
				old := labels[s.Address]
				if old == "" || uiCompareSymbolLabels(s.Name, old) < 0 {
					labels[s.Address] = s.Name
				}
			}
		}
	}
	for _, s := range streams {
		labels[s.object.address] = s.object.name
	}
	if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
		return err
	}
	return errors.Join(readErrors, c.publishPaged(ctx, renderStdio(c.metadataView(), streams, mappings, labels)))
}
