package debugger

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestStdioRecordBitfields(t *testing.T) {
	integer := &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 4}}}
	record := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 8}, Kind: "struct", Field: []*dwarf.StructField{
		{Name: "_flags", Type: integer},
		{Name: "_flags2", Type: integer, DataBitOffset: 32, BitSize: 24},
		{Name: "next", Type: integer, DataBitOffset: 56, BitSize: 8},
	}}
	layout, err := stdioRecordType(record)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0x88, 0x20, 0xad, 0xfb, 0x12, 0x34, 0x56, 0xab}
	for i, want := range []uint64{0xfbad2088, 0x563412, 0xab} {
		value, ok := stdioValue(data, layout.fields[i])
		if !ok || value != want {
			t.Fatalf("%d: %#x %t", i, value, ok)
		}
	}
	legacy := *record.Field[1]
	legacy.DataBitOffset = 0
	legacy.ByteOffset = 4
	legacy.BitOffset = 8
	record.Field[1] = &legacy
	old, err := stdioRecordType(record)
	if err != nil || !reflect.DeepEqual(old, layout) {
		t.Fatalf("DWARF 3/4 bitfields differ: %+v %v", old, err)
	}
	record.Field[2].DataBitOffset = 48
	if _, err := stdioRecordType(record); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("overlapping fields: %v", err)
	}
}

func TestStdioVariableReferences(t *testing.T) {
	declaration := &dwarf.Entry{Offset: 1, Tag: dwarf.TagVariable, Field: []dwarf.Field{{Attr: dwarf.AttrName, Val: "_IO_2_1_stdin_"}, {Attr: dwarf.AttrType, Val: dwarf.Offset(3)}}}
	definition := &dwarf.Entry{Offset: 2, Tag: dwarf.TagVariable, Field: []dwarf.Field{{Attr: dwarf.AttrSpecification, Val: dwarf.Offset(1)}}}
	entries := map[dwarf.Offset]*dwarf.Entry{1: declaration, 2: definition}
	name, err := stdioVariableAttr(definition, entries, dwarf.AttrName)
	if err != nil || name != "_IO_2_1_stdin_" {
		t.Fatalf("%v %v", name, err)
	}
	declaration.Field = []dwarf.Field{{Attr: dwarf.AttrAbstractOrigin, Val: dwarf.Offset(2)}}
	if _, err := stdioVariableAttr(definition, entries, dwarf.AttrType); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("cycle: %v", err)
	}
}

type stdioTestReader struct {
	data  map[target.Address][]byte
	calls map[target.Address]int
	fail  error
}

func (r *stdioTestReader) ReadSpaceMemory(_ target.MemoryToken, address target.Address, output []byte) (int, error) {
	r.calls[address]++
	n := copy(output, r.data[address])
	if r.fail != nil {
		return n, r.fail
	}
	if n < len(output) {
		return n, fmt.Errorf("short: %w", target.ErrPartial)
	}
	return n, nil
}

func TestStdioFollowReadsAndPartial(t *testing.T) {
	layout := stdioLayout{
		file: stdioRecord{size: 16, fields: []stdioField{{name: "vtable", size: 8, pointer: true}, {name: "_wide_data", offset: 8, size: 8, pointer: true}}},
		jump: stdioRecord{size: 8, fields: []stdioField{{name: "__finish", size: 8, pointer: true}}},
		wide: stdioRecord{size: 8, fields: []stdioField{{name: "_wide_vtable", size: 8, pointer: true}}},
	}
	bytes := func(values ...uint64) []byte {
		result := make([]byte, len(values)*8)
		for i, v := range values {
			binary.LittleEndian.PutUint64(result[i*8:], v)
		}
		return result
	}
	reader := &stdioTestReader{data: map[target.Address][]byte{0x100: bytes(0x400, 0x500), 0x200: bytes(0x400, 0), 0x300: bytes(0x400, 0x600), 0x400: bytes(0x700), 0x500: bytes(0x400), 0x600: {1, 2}}, calls: make(map[target.Address]int)}
	streams := []stdioStream{{object: stdioObject{address: 0x100}, layout: layout}, {object: stdioObject{address: 0x200}, layout: layout}, {object: stdioObject{address: 0x300}, layout: layout}}
	err := readStdioStreams(context.Background(), reader, target.MemoryToken{}, streams)
	if !errors.Is(err, target.ErrPartial) {
		t.Fatal(err)
	}
	if reader.calls[0x400] != 1 || len(reader.calls) != 6 {
		t.Fatalf("shared tables not reused: %v", reader.calls)
	}
	if streams[1].blocks[2].state != "NULL" || streams[1].blocks[3].state != "NULL" || streams[2].blocks[3].state != "unavailable" {
		t.Fatalf("null/short pointers: %+v", streams)
	}
	view := &metadataView{renderer: display.Renderer{}}
	if got := stdioCell(view, streams[2].blocks[2], layout.wide.fields[0], nil, nil); got != "unavailable" {
		t.Fatal(got)
	}
	reader.fail = target.ErrStale
	if err := readStdioStreams(context.Background(), reader, target.MemoryToken{}, streams); !errors.Is(err, target.ErrStale) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader.calls = make(map[target.Address]int)
	if err := readStdioStreams(ctx, reader, target.MemoryToken{}, streams); !errors.Is(err, context.Canceled) || len(reader.calls) != 0 {
		t.Fatalf("cancel: %v %v", err, reader.calls)
	}
}

func TestStdioMatchingLibcLayouts(t *testing.T) {
	for minor := 35; minor <= 44; minor++ {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			path := filepath.Join("..", "..", ".libc", fmt.Sprintf("2.%d", minor), "lib", "libc.so.6")
			file, err := elf.Open(path)
			if os.IsNotExist(err) {
				t.Skip("local libc collection unavailable")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			module := &mappedELF{File: file, ID: path}
			var objects []stdioObject
			for _, name := range []string{"_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"} {
				address, size, err := elfStdioObject(module, name)
				if err != nil {
					t.Fatal(err)
				}
				objects = append(objects, stdioObject{name, module, address, size})
			}
			layouts, err := stdioModuleLayouts(context.Background(), module, objects, make(map[target.Address]string))
			if err != nil {
				t.Fatal(err)
			}
			for _, layout := range layouts {
				if layout.file.size != 224 || layout.jump.size != 168 || layout.wide.size != 232 {
					t.Fatalf("incorrect layout %+v", layout)
				}
				names := make(map[string]stdioField)
				for _, field := range layout.file.fields {
					names[field.name] = field
				}
				if names["vtable"].offset != 216 || names["_wide_data"].offset != 160 {
					t.Fatalf("bad pointer fields: %+v", names)
				}
				if minor >= 42 {
					if names["_total_written"].offset != 200 {
						t.Fatalf("new FILE tail missing: %+v", names)
					}
				}
			}
			if !reflect.DeepEqual(layouts[0], layouts[1]) || !reflect.DeepEqual(layouts[1], layouts[2]) {
				t.Fatal("stream layouts differ")
			}
			objects[0].address++
			if _, err := stdioModuleLayouts(context.Background(), module, objects, make(map[target.Address]string)); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("ELF/DWARF mismatch: %v", err)
			}
		})
	}
}

func assertStdioNativeFields(t *testing.T, f *expansionIntegration, output string) {
	t.Helper()
	lines := strings.Split(output, "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "  off | member") {
		t.Fatalf("stdio header missing: %s", output)
	}
	headers := strings.Fields(strings.SplitN(lines[0], ":", 2)[1])
	if len(headers) != 6 {
		t.Fatalf("stdio columns: %v", headers)
	}
	for i, name := range []string{"_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"} {
		if headers[i*2+1] != "<"+name+">" {
			t.Fatalf("column order: %v", headers)
		}
		data := f.read(t, headers[i*2], 224)
		for _, check := range []struct {
			name         string
			offset, size int
		}{{"_flags", 0, 4}, {"_IO_read_ptr", 8, 8}, {"_fileno", 112, 4}, {"vtable", 216, 8}} {
			found := false
			for _, line := range lines {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) != 2 || !strings.Contains(parts[0], "| "+check.name+" ") {
					continue
				}
				cells := strings.Fields(parts[1])
				var values []string
				for _, cell := range cells {
					if strings.HasPrefix(cell, "0x") {
						values = append(values, cell)
					}
				}
				if len(values) != 3 {
					t.Fatalf("field %s: %s", check.name, line)
				}
				v, _ := stdioValue(data, stdioField{offset: check.offset, size: check.size})
				want := fmt.Sprintf("0x%0*x", check.size*2, v)
				if values[i] != want {
					t.Fatalf("%s %s got %s want %s", name, check.name, values[i], want)
				}
				found = true
				break
			}
			if !found {
				t.Fatalf("missing field %s", check.name)
			}
		}
	}
	for _, section := range []string{"[FILE]", "[FILE->vtable]", "[FILE->_wide_data]", "[FILE->_wide_data->_wide_vtable]"} {
		if strings.Count(output, section) != 1 {
			t.Fatalf("missing/duplicate section %s", section)
		}
	}
}

func TestStdioNativeMissingTypes(t *testing.T) {
	f, _ := newLegacyFixture(t, false, true, legacyStaticMetadataFixture, "legacy_static_point", false)
	output, err := f.execute("stdio-dump --module main")
	if !errors.Is(err, target.ErrUnavailable) || output != "" {
		t.Fatalf("untyped libc decoded: %v\n%s", err, output)
	}
}

func TestStdioNativeNestedFields(t *testing.T) {
	f := newExpansionIntegration(t, false)
	f.breakpoint(t)
	output := f.command(t, "stdio-dump")
	assertStdioNativeFields(t, f, output)
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	err = f.controller.withELFModules(context.Background(), snapshot, thread, elfModuleSelection{All: true}, func(modules []*mappedELF) error {
		for _, module := range modules {
			address, size, err := elfStdioObject(module, "_IO_2_1_stdin_")
			if errors.Is(err, target.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			object := stdioObject{"_IO_2_1_stdin_", module, address, size}
			layouts, err := stdioModuleLayouts(context.Background(), module, []stdioObject{object}, make(map[target.Address]string))
			if err != nil {
				return err
			}
			streams := []stdioStream{{object: object, layout: layouts[0]}}
			if err := readStdioStreams(context.Background(), f.controller.session, snapshot.Memory, streams); err != nil {
				return err
			}
			for section, record := range []stdioRecord{layouts[0].file, layouts[0].jump, layouts[0].wide, layouts[0].jump} {
				data := f.read(t, fmt.Sprintf("%#x", streams[0].blocks[section].address), record.size)
				if !reflect.DeepEqual(data, streams[0].blocks[section].data) {
					t.Fatalf("section %d differs from native memory", section)
				}
			}
			return nil
		}
		return target.ErrNotFound
	})
	if err != nil {
		t.Fatal(err)
	}
}
