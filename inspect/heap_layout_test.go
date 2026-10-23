package inspect_test

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func heapTestLayout() inspect.HeapLayout {
	return inspect.HeapLayout{
		Schema: 1, Allocator: "glibc", Arch: "amd64", Endian: "little", Pointer: 8, FastLink: "plain",
		Arena: inspect.HeapRecord{Size: 2200, Fields: map[string]inspect.HeapField{
			"mutex":            {Offset: 0, Width: 4, Count: 1, Stride: 4},
			"flags":            {Offset: 4, Width: 4, Count: 1, Stride: 4},
			"have_fastchunks":  {Offset: 8, Width: 4, Count: 1, Stride: 4},
			"fastbinsY":        {Offset: 16, Width: 8, Count: 10, Stride: 8},
			"top":              {Offset: 96, Width: 8, Count: 1, Stride: 8},
			"last_remainder":   {Offset: 104, Width: 8, Count: 1, Stride: 8},
			"bins":             {Offset: 112, Width: 8, Count: 254, Stride: 8},
			"binmap":           {Offset: 2144, Width: 4, Count: 4, Stride: 4},
			"next":             {Offset: 2160, Width: 8, Count: 1, Stride: 8},
			"next_free":        {Offset: 2168, Width: 8, Count: 1, Stride: 8},
			"attached_threads": {Offset: 2176, Width: 8, Count: 1, Stride: 8},
			"system_mem":       {Offset: 2184, Width: 8, Count: 1, Stride: 8},
			"max_system_mem":   {Offset: 2192, Width: 8, Count: 1, Stride: 8},
		}},
		Chunk: inspect.HeapRecord{Size: 48, Fields: map[string]inspect.HeapField{
			"mchunk_prev_size": {Offset: 0, Width: 8, Count: 1, Stride: 8},
			"mchunk_size":      {Offset: 8, Width: 8, Count: 1, Stride: 8},
			"fd":               {Offset: 16, Width: 8, Count: 1, Stride: 8},
			"bk":               {Offset: 24, Width: 8, Count: 1, Stride: 8},
			"fd_nextsize":      {Offset: 32, Width: 8, Count: 1, Stride: 8},
			"bk_nextsize":      {Offset: 40, Width: 8, Count: 1, Stride: 8},
		}},
	}
}

func heapTestJSON(t *testing.T, layout inspect.HeapLayout) []byte {
	t.Helper()
	data, err := json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHeapLayoutJSONRoundTrip(t *testing.T) {
	for _, encoding := range []string{"plain", "safe-link-12"} {
		layout := heapTestLayout()
		layout.FastLink = encoding
		data := heapTestJSON(t, layout)
		var indented bytes.Buffer
		if err := json.Indent(&indented, data, "", "  "); err != nil {
			t.Fatal(err)
		}
		if parsed, err := inspect.ParseHeapLayout(indented.Bytes()); err != nil || !reflect.DeepEqual(parsed, layout) {
			t.Fatalf("indented layout=%+v err=%v", parsed, err)
		}
		parsed, err := inspect.ParseHeapLayout(data)
		if err != nil || !reflect.DeepEqual(parsed, layout) {
			t.Fatalf("parsed=%+v err=%v", parsed, err)
		}
		for index := range data {
			data[index] = 0
		}
		if !reflect.DeepEqual(parsed, layout) {
			t.Fatal("layout aliases JSON input")
		}
	}
}

func TestHeapLayoutJSONStrictKeysAndValues(t *testing.T) {
	valid := string(heapTestJSON(t, heapTestLayout()))
	replace := func(old, value string) string {
		return strings.Replace(valid, old, value, 1)
	}
	for _, test := range []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"null", "null"},
		{"array", "[]"},
		{"truncated", valid[:len(valid)-1]},
		{"trailing-object", valid + "{}"},
		{"trailing-garbage", valid + "n"},
		{"trailing-null", valid + "null"},
		{"unknown-root", replace(`"schema":1`, `"schema":1,"version":1`)},
		{"duplicate-root", replace(`"schema":1`, `"schema":1,"schema":1`)},
		{"duplicate-escaped-root", replace(`"schema":1`, `"schema":1,"sch\u0065ma":1`)},
		{"case-root", replace(`"schema":1`, `"Schema":1`)},
		{"missing-schema", replace(`"schema":1,`, "")},
		{"null-schema", replace(`"schema":1`, `"schema":null`)},
		{"bool-schema", replace(`"schema":1`, `"schema":true`)},
		{"float-schema", replace(`"schema":1`, `"schema":1.0`)},
		{"exponent-schema", replace(`"schema":1`, `"schema":1e0`)},
		{"negative-schema", replace(`"schema":1`, `"schema":-1`)},
		{"overflow-schema", replace(`"schema":1`, `"schema":18446744073709551616`)},
		{"null-string", replace(`"arch":"amd64"`, `"arch":null`)},
		{"integer-string", replace(`"arch":"amd64"`, `"arch":64`)},
		{"missing-encoding", replace(`,"fast_link":"plain"`, "")},
		{"null-record", replace(`"arena":{"size":2200`, `"arena":null,"x":{"size":2200`)},
		{"unknown-record", replace(`"size":2200`, `"size":2200,"pad":0`)},
		{"duplicate-record", replace(`"size":2200`, `"size":2200,"size":2200`)},
		{"unknown-field", replace(`"mutex":`, `"unknown":`)},
		{"duplicate-field", replace(`"fields":{`, `"fields":{"next":{"offset":0,"width":8,"count":1,"stride":8},`)},
		{"unknown-property", replace(`"offset":`, `"off":`)},
		{"duplicate-property", replace(`"width":8`, `"width":8,"width":8`)},
		{"case-property", replace(`"width":8`, `"Width":8`)},
		{"missing-property", replace(`"width":8,`, "")},
		{"null-property", replace(`"width":8`, `"width":null`)},
		{"string-property", replace(`"width":8`, `"width":"8"`)},
		{"float-property", replace(`"width":8`, `"width":8.0`)},
		{"exponent-property", replace(`"width":8`, `"width":8e0`)},
		{"overflow-property", replace(`"width":8`, `"width":18446744073709551616`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout, err := inspect.ParseHeapLayout([]byte(test.data))
			if !errors.Is(err, target.ErrInvalidArgument) || !reflect.DeepEqual(layout, inspect.HeapLayout{}) {
				t.Fatalf("layout=%+v err=%v", layout, err)
			}
		})
	}
}

func TestHeapLayoutJSONSizeBound(t *testing.T) {
	data := heapTestJSON(t, heapTestLayout())
	data = append(data, bytes.Repeat([]byte{' '}, 65536-len(data))...)
	if _, err := inspect.ParseHeapLayout(data); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.ParseHeapLayout(append(data, ' ')); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestHeapLayoutValidationRejectsInvalidRecords(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*inspect.HeapLayout)
	}{
		{"schema", func(l *inspect.HeapLayout) { l.Schema = 2 }},
		{"allocator", func(l *inspect.HeapLayout) { l.Allocator = "other" }},
		{"architecture", func(l *inspect.HeapLayout) { l.Arch = "arm64" }},
		{"endian", func(l *inspect.HeapLayout) { l.Endian = "big" }},
		{"pointer", func(l *inspect.HeapLayout) { l.Pointer = 4 }},
		{"encoding-missing", func(l *inspect.HeapLayout) { l.FastLink = "" }},
		{"encoding-inferred", func(l *inspect.HeapLayout) { l.FastLink = "auto" }},
		{"arena-zero", func(l *inspect.HeapLayout) { l.Arena.Size = 0 }},
		{"arena-limit", func(l *inspect.HeapLayout) { l.Arena.Size = 65537 }},
		{"chunk-zero", func(l *inspect.HeapLayout) { l.Chunk.Size = 0 }},
		{"chunk-limit", func(l *inspect.HeapLayout) { l.Chunk.Size = math.MaxUint64 }},
		{"arena-empty", func(l *inspect.HeapLayout) { l.Arena.Fields = nil }},
		{"chunk-empty", func(l *inspect.HeapLayout) { l.Chunk.Fields = nil }},
		{"next-missing", func(l *inspect.HeapLayout) { delete(l.Arena.Fields, "next") }},
		{"invalid-encoding-without-fastbins", func(l *inspect.HeapLayout) {
			delete(l.Arena.Fields, "fastbinsY")
			l.FastLink = "auto"
		}},
		{"bins-missing", func(l *inspect.HeapLayout) { delete(l.Arena.Fields, "bins") }},
		{"fd-missing", func(l *inspect.HeapLayout) { delete(l.Chunk.Fields, "fd") }},
		{"bk-missing", func(l *inspect.HeapLayout) { delete(l.Chunk.Fields, "bk") }},
		{"unknown-arena", func(l *inspect.HeapLayout) { l.Arena.Fields["padding"] = inspect.HeapField{} }},
		{"unknown-chunk", func(l *inspect.HeapLayout) { l.Chunk.Fields["prev_size"] = inspect.HeapField{} }},
		{"nonadjacent-links", func(l *inspect.HeapLayout) {
			delete(l.Chunk.Fields, "fd_nextsize")
			f := l.Chunk.Fields["bk"]
			f.Offset = 32
			l.Chunk.Fields["bk"] = f
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := heapTestLayout()
			test.change(&layout)
			if err := layout.Validate(); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatal(err)
			}
			if _, err := inspect.ParseHeapLayout(heapTestJSON(t, layout)); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatal(err)
			}
		})
	}
}

func TestHeapLayoutValidationRejectsInvalidFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		field  string
		change func(*inspect.HeapField)
	}{
		{"zero-width", "mutex", func(f *inspect.HeapField) { f.Width = 0 }},
		{"bad-width", "mutex", func(f *inspect.HeapField) { f.Width = 3 }},
		{"wide-width", "mutex", func(f *inspect.HeapField) { f.Width = 16 }},
		{"zero-count", "fastbinsY", func(f *inspect.HeapField) { f.Count = 0 }},
		{"huge-count", "fastbinsY", func(f *inspect.HeapField) { f.Count = math.MaxUint64 }},
		{"fastbins-count", "fastbinsY", func(f *inspect.HeapField) { f.Count = 257 }},
		{"one-bin", "bins", func(f *inspect.HeapField) { f.Count = 1 }},
		{"odd-bins", "bins", func(f *inspect.HeapField) { f.Count = 3 }},
		{"too-many-bins", "bins", func(f *inspect.HeapField) { f.Count = 4098 }},
		{"scalar-array", "mutex", func(f *inspect.HeapField) { f.Count = 2 }},
		{"short-pointer", "next", func(f *inspect.HeapField) { f.Width, f.Stride = 4, 4 }},
		{"narrow-stride", "bins", func(f *inspect.HeapField) { f.Stride = 4 }},
		{"wide-stride", "bins", func(f *inspect.HeapField) { f.Stride = 16 }},
		{"scalar-stride", "mutex", func(f *inspect.HeapField) { f.Stride = 8 }},
		{"overflow-stride", "fastbinsY", func(f *inspect.HeapField) { f.Stride = math.MaxUint64 }},
		{"offset-overflow", "next", func(f *inspect.HeapField) { f.Offset = math.MaxUint64 }},
		{"past-end", "next", func(f *inspect.HeapField) { f.Offset = 2200 }},
		{"partial-field", "next", func(f *inspect.HeapField) { f.Offset = 2199 }},
		{"partial-array", "bins", func(f *inspect.HeapField) { f.Offset = 2192 }},
		{"scalar-overlap", "mutex", func(f *inspect.HeapField) { f.Offset = 3 }},
		{"array-overlap", "binmap", func(f *inspect.HeapField) { f.Offset = 2140 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := heapTestLayout()
			field := layout.Arena.Fields[test.field]
			test.change(&field)
			layout.Arena.Fields[test.field] = field
			if err := layout.Validate(); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatal(err)
			}
		})
	}
}

func TestHeapLayoutValidationAcceptsExplicitBounds(t *testing.T) {
	layout := heapTestLayout()
	layout.Arena = inspect.HeapRecord{Size: 65536, Fields: map[string]inspect.HeapField{
		"bins":      {Offset: 0, Width: 8, Count: 4096, Stride: 8},
		"fastbinsY": {Offset: 32768, Width: 8, Count: 256, Stride: 8},
		"next":      {Offset: 65528, Width: 8, Count: 1, Stride: 8},
	}}
	layout.Chunk.Size = 65536
	if err := layout.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, width := range []uint64{1, 2, 4, 8} {
		layout.Arena.Fields["flags"] = inspect.HeapField{Offset: 34816, Width: width, Count: 1, Stride: width}
		if err := layout.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	layout.Arena = inspect.HeapRecord{Size: 32, Fields: map[string]inspect.HeapField{
		"bins":      {Offset: 0, Width: 8, Count: 2, Stride: 8},
		"fastbinsY": {Offset: 16, Width: 8, Count: 1, Stride: 8},
		"next":      {Offset: 24, Width: 8, Count: 1, Stride: 8},
	}}
	layout.Chunk = inspect.HeapRecord{Size: 16, Fields: map[string]inspect.HeapField{
		"fd": {Offset: 0, Width: 8, Count: 1, Stride: 8},
		"bk": {Offset: 8, Width: 8, Count: 1, Stride: 8},
	}}
	if err := layout.Validate(); err != nil {
		t.Fatal(err)
	}
}

type heapTestAttr struct {
	name  dwarf.Attr
	form  uint64
	value any
}

type heapTestDIE struct {
	id       string
	tag      dwarf.Tag
	attrs    []heapTestAttr
	children []*heapTestDIE
}

func heapTestNumber(name dwarf.Attr, value uint64) heapTestAttr {
	return heapTestAttr{name: name, form: 0x0f, value: value}
}

func heapTestString(name dwarf.Attr, value string) heapTestAttr {
	return heapTestAttr{name: name, form: 0x08, value: value}
}

func heapTestReference(name dwarf.Attr, value string) heapTestAttr {
	return heapTestAttr{name: name, form: 0x13, value: value}
}

func (entry *heapTestDIE) find(id string) *heapTestDIE {
	if entry.id == id {
		return entry
	}
	for _, child := range entry.children {
		if found := child.find(id); found != nil {
			return found
		}
	}
	return nil
}

func (entry *heapTestDIE) replace(attr heapTestAttr) {
	for index, previous := range entry.attrs {
		if previous.name == attr.name {
			entry.attrs[index] = attr
			return
		}
	}
	entry.attrs = append(entry.attrs, attr)
}

func (entry *heapTestDIE) remove(attr dwarf.Attr) {
	for index, previous := range entry.attrs {
		if previous.name == attr {
			entry.attrs = append(entry.attrs[:index], entry.attrs[index+1:]...)
			return
		}
	}
}

func heapTestDWARFTree() *heapTestDIE {
	root := &heapTestDIE{id: "cu", tag: dwarf.TagCompileUnit, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrLanguage, 0x001d)}}
	for _, basic := range []struct {
		id       string
		width    uint64
		encoding uint64
	}{{"int", 4, 5}, {"uint", 4, 7}, {"size", 8, 7}} {
		root.children = append(root.children, &heapTestDIE{id: basic.id, tag: dwarf.TagBaseType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, basic.id), heapTestNumber(dwarf.AttrByteSize, basic.width), heapTestNumber(dwarf.AttrEncoding, basic.encoding)}})
	}
	for _, id := range []string{"arena", "chunk"} {
		root.children = append(root.children, &heapTestDIE{id: id + "_ptr", tag: dwarf.TagPointerType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrByteSize, 8), heapTestReference(dwarf.AttrType, id)}})
	}
	for _, array := range []struct {
		id      string
		element string
		count   uint64
	}{{"fastbinsY", "chunk_ptr", 10}, {"bins", "chunk_ptr", 254}, {"binmap", "uint", 4}} {
		root.children = append(root.children, &heapTestDIE{id: array.id + "_array", tag: dwarf.TagArrayType, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, array.element)}, children: []*heapTestDIE{{id: array.id + "_range", tag: dwarf.TagSubrangeType, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, "size"), heapTestNumber(dwarf.AttrUpperBound, array.count-1)}}}})
	}
	layout := heapTestLayout()
	for _, record := range []struct {
		id     string
		name   string
		layout inspect.HeapRecord
		fields []string
	}{
		{"arena", "malloc_state", layout.Arena, []string{"mutex", "flags", "have_fastchunks", "fastbinsY", "top", "last_remainder", "bins", "binmap", "next", "next_free", "attached_threads", "system_mem", "max_system_mem"}},
		{"chunk", "malloc_chunk", layout.Chunk, []string{"mchunk_prev_size", "mchunk_size", "fd", "bk", "fd_nextsize", "bk_nextsize"}},
	} {
		entry := &heapTestDIE{id: record.id, tag: dwarf.TagStructType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, record.name), heapTestNumber(dwarf.AttrByteSize, record.layout.Size)}}
		for _, name := range record.fields {
			typeID := "size"
			switch name {
			case "mutex", "flags", "have_fastchunks":
				typeID = "int"
			case "fastbinsY", "bins", "binmap":
				typeID = name + "_array"
			case "next", "next_free":
				typeID = "arena_ptr"
			case "top", "last_remainder", "fd", "bk", "fd_nextsize", "bk_nextsize":
				typeID = "chunk_ptr"
			}
			entry.children = append(entry.children, &heapTestDIE{id: record.id + "." + name, tag: dwarf.TagMember, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, name), heapTestReference(dwarf.AttrType, typeID), heapTestNumber(dwarf.AttrDataMemberLoc, record.layout.Fields[name].Offset)}})
		}
		root.children = append(root.children, entry)
	}
	root.children = append(root.children,
		&heapTestDIE{id: "qualified_arena", tag: dwarf.TagConstType, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, "arena")}},
		&heapTestDIE{id: "arena_alias", tag: dwarf.TagTypedef, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "arena_alias"), heapTestReference(dwarf.AttrType, "qualified_arena")}},
	)
	return root
}

func heapTestULEB(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

func heapTestDWARF(t *testing.T, root *heapTestDIE, order binary.ByteOrder, addressSize byte) (*dwarf.Data, map[string]dwarf.Offset) {
	t.Helper()
	var abbrev []byte
	info := make([]byte, 11)
	order.PutUint16(info[4:6], 4)
	info[10] = addressSize
	offsets := make(map[string]dwarf.Offset)
	var references []struct {
		index  int
		target string
	}
	nextAbbrev := uint64(1)
	var emit func(*heapTestDIE)
	emit = func(entry *heapTestDIE) {
		number := nextAbbrev
		nextAbbrev++
		abbrev = heapTestULEB(abbrev, number)
		abbrev = heapTestULEB(abbrev, uint64(entry.tag))
		if len(entry.children) == 0 {
			abbrev = append(abbrev, 0)
		} else {
			abbrev = append(abbrev, 1)
		}
		for _, attr := range entry.attrs {
			abbrev = heapTestULEB(abbrev, uint64(attr.name))
			abbrev = heapTestULEB(abbrev, attr.form)
		}
		abbrev = append(abbrev, 0, 0)
		offsets[entry.id] = dwarf.Offset(len(info))
		info = heapTestULEB(info, number)
		for _, attr := range entry.attrs {
			switch attr.form {
			case 0x08:
				info = append(info, attr.value.(string)...)
				info = append(info, 0)
			case 0x0f:
				info = heapTestULEB(info, attr.value.(uint64))
			case 0x0b, 0x0c:
				info = append(info, byte(attr.value.(uint64)))
			case 0x0d:
				info = append(info, 0x7f)
			case 0x13:
				references = append(references, struct {
					index  int
					target string
				}{len(info), attr.value.(string)})
				info = append(info, 0, 0, 0, 0)
			case 0x18:
				value := attr.value.([]byte)
				info = heapTestULEB(info, uint64(len(value)))
				info = append(info, value...)
			default:
				t.Fatalf("unsupported test form %#x", attr.form)
			}
		}
		for _, child := range entry.children {
			emit(child)
		}
		if len(entry.children) != 0 {
			info = append(info, 0)
		}
	}
	emit(root)
	abbrev = append(abbrev, 0)
	for _, reference := range references {
		offset, ok := offsets[reference.target]
		if !ok {
			t.Fatalf("unknown reference %q", reference.target)
		}
		order.PutUint32(info[reference.index:reference.index+4], uint32(offset))
	}
	order.PutUint32(info[:4], uint32(len(info)-4))
	data, err := dwarf.New(abbrev, nil, nil, info, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return data, offsets
}

func TestHeapLayoutFromDWARFExactTypes(t *testing.T) {
	for _, encoding := range []string{"plain", "safe-link-12"} {
		for _, typeID := range []string{"arena", "qualified_arena", "arena_alias"} {
			data, offsets := heapTestDWARF(t, heapTestDWARFTree(), binary.LittleEndian, 8)
			layout, err := inspect.HeapLayoutFromDWARF(data, offsets[typeID], encoding)
			want := heapTestLayout()
			want.FastLink = encoding
			if err != nil || !reflect.DeepEqual(layout, want) {
				t.Fatalf("type=%s layout=%+v err=%v", typeID, layout, err)
			}
		}
	}
}

func TestHeapLayoutFromDWARFUsesDeclaredLayout(t *testing.T) {
	root := heapTestDWARFTree()
	want := heapTestLayout()
	for _, record := range []struct {
		id     string
		shift  uint64
		layout *inspect.HeapRecord
	}{{"arena", 16, &want.Arena}, {"chunk", 8, &want.Chunk}} {
		record.layout.Size += record.shift
		root.find(record.id).replace(heapTestNumber(dwarf.AttrByteSize, record.layout.Size))
		for name, field := range record.layout.Fields {
			field.Offset += record.shift
			record.layout.Fields[name] = field
			root.find(record.id + "." + name).replace(heapTestNumber(dwarf.AttrDataMemberLoc, field.Offset))
		}
	}
	for name, count := range map[string]uint64{"bins": 4, "fastbinsY": 3, "binmap": 1} {
		field := want.Arena.Fields[name]
		field.Count = count
		want.Arena.Fields[name] = field
		root.find(name + "_range").replace(heapTestNumber(dwarf.AttrUpperBound, count-1))
	}
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	layout, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain")
	if err != nil || !reflect.DeepEqual(layout, want) {
		t.Fatalf("layout=%+v err=%v", layout, err)
	}
}

func TestHeapLayoutFromDWARFRejectsUnsupportedTypes(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*heapTestDIE)
	}{
		{"arena-name", func(r *heapTestDIE) { r.find("arena").replace(heapTestString(dwarf.AttrName, "other")) }},
		{"chunk-name", func(r *heapTestDIE) { r.find("chunk").replace(heapTestString(dwarf.AttrName, "other")) }},
		{"arena-union", func(r *heapTestDIE) { r.find("arena").tag = dwarf.TagUnionType }},
		{"chunk-union", func(r *heapTestDIE) { r.find("chunk").tag = dwarf.TagUnionType }},
		{"incomplete-arena", func(r *heapTestDIE) {
			r.find("arena").attrs = append(r.find("arena").attrs, heapTestAttr{dwarf.AttrDeclaration, 0x0c, uint64(1)})
		}},
		{"incomplete-chunk", func(r *heapTestDIE) {
			r.find("chunk").attrs = append(r.find("chunk").attrs, heapTestAttr{dwarf.AttrDeclaration, 0x0c, uint64(1)})
		}},
		{"missing-size", func(r *heapTestDIE) { r.find("arena").remove(dwarf.AttrByteSize) }},
		{"zero-size", func(r *heapTestDIE) { r.find("arena").replace(heapTestNumber(dwarf.AttrByteSize, 0)) }},
		{"huge-size", func(r *heapTestDIE) { r.find("arena").replace(heapTestNumber(dwarf.AttrByteSize, 65537)) }},
		{"dynamic-size", func(r *heapTestDIE) { r.find("arena").replace(heapTestAttr{dwarf.AttrByteSize, 0x18, []byte{0x30}}) }},
		{"unknown-member", func(r *heapTestDIE) { r.find("arena.mutex").replace(heapTestString(dwarf.AttrName, "other")) }},
		{"duplicate-member", func(r *heapTestDIE) { r.find("arena.flags").replace(heapTestString(dwarf.AttrName, "mutex")) }},
		{"nonmember", func(r *heapTestDIE) { r.find("arena.mutex").tag = dwarf.TagVariable }},
		{"duplicate-attribute", func(r *heapTestDIE) {
			r.find("arena").attrs = append(r.find("arena").attrs, heapTestNumber(dwarf.AttrByteSize, 2200))
		}},
		{"missing-offset", func(r *heapTestDIE) { r.find("arena.mutex").remove(dwarf.AttrDataMemberLoc) }},
		{"expression-offset", func(r *heapTestDIE) {
			r.find("arena.mutex").replace(heapTestAttr{dwarf.AttrDataMemberLoc, 0x18, []byte{0x23, 0x00}})
		}},
		{"negative-offset", func(r *heapTestDIE) {
			r.find("arena.mutex").replace(heapTestAttr{dwarf.AttrDataMemberLoc, 0x0d, int64(-1)})
		}},
		{"bitfield", func(r *heapTestDIE) {
			r.find("arena.mutex").attrs = append(r.find("arena.mutex").attrs, heapTestNumber(dwarf.AttrBitSize, 4))
		}},
		{"zero-bitfield", func(r *heapTestDIE) {
			r.find("arena.mutex").attrs = append(r.find("arena.mutex").attrs, heapTestNumber(dwarf.AttrBitSize, 0))
		}},
		{"bit-offset", func(r *heapTestDIE) {
			r.find("arena.mutex").attrs = append(r.find("arena.mutex").attrs, heapTestNumber(dwarf.AttrBitOffset, 0))
		}},
		{"data-bit-offset", func(r *heapTestDIE) {
			r.find("arena.mutex").attrs = append(r.find("arena.mutex").attrs, heapTestNumber(dwarf.AttrDataBitOffset, 0))
		}},
		{"scalar-array", func(r *heapTestDIE) { r.find("arena.mutex").replace(heapTestReference(dwarf.AttrType, "binmap_array")) }},
		{"array-scalar", func(r *heapTestDIE) { r.find("arena.bins").replace(heapTestReference(dwarf.AttrType, "chunk_ptr")) }},
		{"wrong-pointer-target", func(r *heapTestDIE) { r.find("arena.next").replace(heapTestReference(dwarf.AttrType, "chunk_ptr")) }},
		{"integer-pointer", func(r *heapTestDIE) { r.find("arena.next").replace(heapTestReference(dwarf.AttrType, "size")) }},
		{"pointer-integer", func(r *heapTestDIE) {
			r.find("arena.system_mem").replace(heapTestReference(dwarf.AttrType, "chunk_ptr"))
		}},
		{"wrong-chunk-target", func(r *heapTestDIE) { r.find("chunk.fd").replace(heapTestReference(dwarf.AttrType, "arena_ptr")) }},
		{"short-pointer", func(r *heapTestDIE) { r.find("chunk_ptr").replace(heapTestNumber(dwarf.AttrByteSize, 4)) }},
		{"address-class", func(r *heapTestDIE) {
			r.find("chunk_ptr").attrs = append(r.find("chunk_ptr").attrs, heapTestNumber(dwarf.AttrAddrClass, 1))
		}},
		{"float", func(r *heapTestDIE) { r.find("int").replace(heapTestNumber(dwarf.AttrEncoding, 4)) }},
		{"unknown-encoding", func(r *heapTestDIE) { r.find("int").replace(heapTestNumber(dwarf.AttrEncoding, 99)) }},
		{"missing-encoding", func(r *heapTestDIE) { r.find("int").remove(dwarf.AttrEncoding) }},
		{"wide-integer", func(r *heapTestDIE) { r.find("int").replace(heapTestNumber(dwarf.AttrByteSize, 16)) }},
		{"big-endian-integer", func(r *heapTestDIE) {
			r.find("int").attrs = append(r.find("int").attrs, heapTestNumber(dwarf.AttrEndianity, 1))
		}},
		{"unknown-endian-integer", func(r *heapTestDIE) {
			r.find("int").attrs = append(r.find("int").attrs, heapTestNumber(dwarf.AttrEndianity, 3))
		}},
		{"typedef-cycle", func(r *heapTestDIE) {
			r.find("qualified_arena").replace(heapTestReference(dwarf.AttrType, "arena_alias"))
		}},
		{"wrapper-size", func(r *heapTestDIE) {
			r.find("qualified_arena").attrs = append(r.find("qualified_arena").attrs, heapTestNumber(dwarf.AttrByteSize, 8))
		}},
		{"void-typedef", func(r *heapTestDIE) { r.find("qualified_arena").remove(dwarf.AttrType) }},
		{"void-pointer", func(r *heapTestDIE) { r.find("chunk_ptr").remove(dwarf.AttrType) }},
		{"member-size", func(r *heapTestDIE) {
			r.find("arena.mutex").attrs = append(r.find("arena.mutex").attrs, heapTestNumber(dwarf.AttrByteSize, 8))
		}},
		{"overlap", func(r *heapTestDIE) { r.find("arena.mutex").replace(heapTestNumber(dwarf.AttrDataMemberLoc, 4)) }},
		{"bounds", func(r *heapTestDIE) { r.find("arena.next").replace(heapTestNumber(dwarf.AttrDataMemberLoc, 65535)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := heapTestDWARFTree()
			test.change(root)
			data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
			layout, err := inspect.HeapLayoutFromDWARF(data, offsets["arena_alias"], "plain")
			if err == nil || !reflect.DeepEqual(layout, inspect.HeapLayout{}) {
				t.Fatalf("layout=%+v err=%v", layout, err)
			}
		})
	}
}

func TestHeapLayoutFromDWARFRejectsUnsupportedArrays(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*heapTestDIE)
	}{
		{"incomplete", func(r *heapTestDIE) { r.find("bins_range").remove(dwarf.AttrUpperBound) }},
		{"no-subrange", func(r *heapTestDIE) { r.find("bins_array").children = nil }},
		{"multidimensional", func(r *heapTestDIE) {
			r.find("bins_array").children = append(r.find("bins_array").children, &heapTestDIE{id: "other_range", tag: dwarf.TagSubrangeType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrCount, 2)}})
		}},
		{"nested-array", func(r *heapTestDIE) { r.find("bins_array").replace(heapTestReference(dwarf.AttrType, "binmap_array")) }},
		{"array-cycle", func(r *heapTestDIE) { r.find("bins_array").replace(heapTestReference(dwarf.AttrType, "bins_array")) }},
		{"huge-upper", func(r *heapTestDIE) { r.find("bins_range").replace(heapTestNumber(dwarf.AttrUpperBound, 4096)) }},
		{"overflow-upper", func(r *heapTestDIE) {
			r.find("bins_range").replace(heapTestNumber(dwarf.AttrUpperBound, math.MaxUint64))
		}},
		{"empty-count", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestNumber(dwarf.AttrCount, 0))
		}},
		{"huge-count", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestNumber(dwarf.AttrCount, 4097))
		}},
		{"inconsistent-count", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestNumber(dwarf.AttrCount, 253))
		}},
		{"dynamic-upper", func(r *heapTestDIE) {
			r.find("bins_range").replace(heapTestAttr{dwarf.AttrUpperBound, 0x18, []byte{0x30}})
		}},
		{"dynamic-count", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestAttr{dwarf.AttrCount, 0x18, []byte{0x30}})
		}},
		{"nonzero-lower", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestNumber(dwarf.AttrLowerBound, 1))
		}},
		{"dynamic-lower", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestAttr{dwarf.AttrLowerBound, 0x18, []byte{0x30}})
		}},
		{"non-c-default-bound", func(r *heapTestDIE) { r.replace(heapTestNumber(dwarf.AttrLanguage, 8)) }},
		{"missing-default-bound", func(r *heapTestDIE) { r.remove(dwarf.AttrLanguage) }},
		{"duplicate-cu-language", func(r *heapTestDIE) {
			r.attrs = append(r.attrs, heapTestNumber(dwarf.AttrLanguage, 8))
		}},
		{"unknown-ordering", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestNumber(dwarf.AttrOrdering, 2))
		}},
		{"dynamic-ordering", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestAttr{dwarf.AttrOrdering, 0x18, []byte{0x30}})
		}},
		{"dynamic-rank", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestAttr{dwarf.AttrRank, 0x18, []byte{0x30}})
		}},
		{"byte-stride", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestNumber(dwarf.AttrStride, 16))
		}},
		{"bit-stride", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestNumber(dwarf.AttrStrideSize, 32))
		}},
		{"range-stride", func(r *heapTestDIE) {
			r.find("bins_range").attrs = append(r.find("bins_range").attrs, heapTestNumber(dwarf.AttrStride, 16))
		}},
		{"dynamic-stride", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestAttr{dwarf.AttrStride, 0x18, []byte{0x30}})
		}},
		{"array-size", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestNumber(dwarf.AttrByteSize, 254))
		}},
		{"allocated", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestNumber(dwarf.AttrAllocated, 1))
		}},
		{"associated", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestNumber(dwarf.AttrAssociated, 1))
		}},
		{"data-location", func(r *heapTestDIE) {
			r.find("bins_array").attrs = append(r.find("bins_array").attrs, heapTestAttr{dwarf.AttrDataLocation, 0x18, []byte{0x30}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := heapTestDWARFTree()
			test.change(root)
			data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
			layout, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain")
			if err == nil || !reflect.DeepEqual(layout, inspect.HeapLayout{}) {
				t.Fatalf("layout=%+v err=%v", layout, err)
			}
		})
	}
}

func TestHeapLayoutFromDWARFExplicitArrayMetadata(t *testing.T) {
	root := heapTestDWARFTree()
	root.remove(dwarf.AttrLanguage)
	for _, array := range []struct {
		name  string
		count uint64
		width uint64
	}{{"bins", 254, 8}, {"fastbinsY", 10, 8}, {"binmap", 4, 4}} {
		rangeEntry := root.find(array.name + "_range")
		rangeEntry.remove(dwarf.AttrUpperBound)
		rangeEntry.attrs = append(rangeEntry.attrs, heapTestNumber(dwarf.AttrCount, array.count), heapTestNumber(dwarf.AttrLowerBound, 0), heapTestNumber(dwarf.AttrStride, array.width))
		arrayEntry := root.find(array.name + "_array")
		arrayEntry.attrs = append(arrayEntry.attrs, heapTestNumber(dwarf.AttrByteSize, array.count*array.width), heapTestNumber(dwarf.AttrStrideSize, array.width*8))
	}
	root.find("int").attrs = append(root.find("int").attrs, heapTestNumber(dwarf.AttrEndianity, 2))
	root.find("arena.mutex").attrs = append(root.find("arena.mutex").attrs, heapTestNumber(dwarf.AttrByteSize, 4))
	root.find("qualified_arena").attrs = append(root.find("qualified_arena").attrs, heapTestNumber(dwarf.AttrByteSize, 2200))
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	layout, err := inspect.HeapLayoutFromDWARF(data, offsets["qualified_arena"], "plain")
	if err != nil || !reflect.DeepEqual(layout, heapTestLayout()) {
		t.Fatalf("layout=%+v err=%v", layout, err)
	}
}

func TestHeapLayoutFromDWARFDefaultPointerSize(t *testing.T) {
	root := heapTestDWARFTree()
	root.find("arena_ptr").remove(dwarf.AttrByteSize)
	root.find("chunk_ptr").remove(dwarf.AttrByteSize)
	root.children = append(root.children, &heapTestDIE{id: "sized_chunk_pointer", tag: dwarf.TagTypedef, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, "chunk_ptr"), heapTestNumber(dwarf.AttrByteSize, 8)}})
	root.find("arena.top").replace(heapTestReference(dwarf.AttrType, "sized_chunk_pointer"))
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	layout, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain")
	if err != nil || !reflect.DeepEqual(layout, heapTestLayout()) {
		t.Fatalf("layout=%+v err=%v", layout, err)
	}
	data, offsets = heapTestDWARF(t, root, binary.LittleEndian, 4)
	if _, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain"); err == nil {
		t.Fatal("inherited pointer width from wrong compilation unit")
	}
}

func TestHeapLayoutFromDWARFExactPointerIdentity(t *testing.T) {
	for _, name := range []string{"arena", "chunk"} {
		t.Run(name, func(t *testing.T) {
			root := heapTestDWARFTree()
			clone := *root.find(name)
			clone.id = "clone"
			root.children = append(root.children, &clone, &heapTestDIE{id: "clone_ptr", tag: dwarf.TagPointerType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrByteSize, 8), heapTestReference(dwarf.AttrType, "clone")}})
			member := "arena.next"
			if name == "chunk" {
				member = "arena.top"
			}
			root.find(member).replace(heapTestReference(dwarf.AttrType, "clone_ptr"))
			data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
			if _, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain"); err == nil {
				t.Fatal("accepted different pointee DIE with matching name and layout")
			}
		})
	}
}

func TestHeapLayoutFromDWARFInputBoundaries(t *testing.T) {
	if _, err := inspect.HeapLayoutFromDWARF(nil, 0, "plain"); err == nil {
		t.Fatal("nil DWARF accepted")
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, addressSize := range []byte{4, 8} {
			if order == binary.LittleEndian && addressSize == 8 {
				continue
			}
			data, offsets := heapTestDWARF(t, heapTestDWARFTree(), order, addressSize)
			if _, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain"); err == nil {
				t.Fatalf("accepted order=%v addressSize=%d", order, addressSize)
			}
		}
	}
	data, offsets := heapTestDWARF(t, heapTestDWARFTree(), binary.LittleEndian, 8)
	for _, encoding := range []string{"", "auto", "safe-link", "glibc-2.42"} {
		if _, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], encoding); err == nil {
			t.Fatalf("accepted encoding %q", encoding)
		}
	}
	for _, offset := range []dwarf.Offset{0, 1, offsets["chunk"], offsets["cu"], math.MaxUint32} {
		if _, err := inspect.HeapLayoutFromDWARF(data, offset, "plain"); err == nil {
			t.Fatalf("accepted offset %#x", offset)
		}
	}
}

func TestHeapLayoutFromDWARFRejectsAttributePayloadReference(t *testing.T) {
	root := heapTestDWARFTree()
	carrier := &heapTestDIE{id: "carrier", tag: dwarf.TagVariable, attrs: []heapTestAttr{{dwarf.AttrConstValue, 0x18, []byte{0, 0, 0, 0, 0}}}}
	root.children = append(root.children, carrier)
	var wrapperCode, count uint64
	var visit func(*heapTestDIE)
	visit = func(entry *heapTestDIE) {
		count++
		if entry.id == "qualified_arena" {
			wrapperCode = count
		}
		for _, child := range entry.children {
			visit(child)
		}
	}
	visit(root)
	if count >= 128 || wrapperCode == 0 {
		t.Fatal("fixture abbreviation width changed")
	}
	_, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	payload := []byte{byte(wrapperCode), 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(payload[1:], uint32(offsets["arena"]))
	carrier.attrs[0].value = payload
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	interior := offsets["carrier"] + 2
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}
		if entry.Offset == interior {
			t.Fatal("fixture payload is an actual DIE boundary")
		}
	}
	if _, err := inspect.HeapLayoutFromDWARF(data, interior, "plain"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("accepted type reference inside an attribute payload: %v", err)
	}
}

func TestHeapLayoutFromDWARFWrapperAndGraphBounds(t *testing.T) {
	t.Run("wrapper-depth", func(t *testing.T) {
		root := heapTestDWARFTree()
		previous := "arena"
		for index := range 65 {
			id := fmt.Sprintf("wrapper%d", index)
			root.children = append(root.children, &heapTestDIE{id: id, tag: dwarf.TagTypedef, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, previous)}})
			previous = id
		}
		data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
		if _, err := inspect.HeapLayoutFromDWARF(data, offsets["wrapper63"], "plain"); err != nil {
			t.Fatal(err)
		}
		if _, err := inspect.HeapLayoutFromDWARF(data, offsets[previous], "plain"); err == nil || !strings.Contains(err.Error(), "depth exceeds") {
			t.Fatal(err)
		}
	})
	t.Run("type-graph", func(t *testing.T) {
		root := heapTestDWARFTree()
		for _, member := range []string{"mutex", "flags", "have_fastchunks", "attached_threads", "system_mem"} {
			previous := "int"
			if member == "attached_threads" || member == "system_mem" {
				previous = "size"
			}
			for index := range 60 {
				id := fmt.Sprintf("%s-wrapper%d", member, index)
				root.children = append(root.children, &heapTestDIE{id: id, tag: dwarf.TagTypedef, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, previous)}})
				previous = id
			}
			root.find("arena." + member).replace(heapTestReference(dwarf.AttrType, previous))
		}
		data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
		if _, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain"); err == nil || !strings.Contains(err.Error(), "graph exceeds") {
			t.Fatal(err)
		}
	})
}

func TestHeapLayoutWithoutFastbins(t *testing.T) {
	for _, encoding := range []string{"", "plain", "safe-link-12"} {
		layout := heapTestLayout()
		delete(layout.Arena.Fields, "fastbinsY")
		delete(layout.Arena.Fields, "have_fastchunks")
		layout.FastLink = encoding
		if err := layout.Validate(); err != nil {
			t.Fatal(err)
		}
		data := heapTestJSON(t, layout)
		parsed, err := inspect.ParseHeapLayout(data)
		if err != nil || !reflect.DeepEqual(parsed, layout) {
			t.Fatalf("layout=%+v err=%v", parsed, err)
		}
		if encoding == "" {
			data = bytes.Replace(data, []byte(`,"fast_link":""`), nil, 1)
			if parsed, err := inspect.ParseHeapLayout(data); err != nil || !reflect.DeepEqual(parsed, layout) {
				t.Fatalf("missing unused encoding: %+v %v", parsed, err)
			}
		}
		root := heapTestDWARFTree()
		arena := root.find("arena")
		children := arena.children[:0]
		for _, member := range arena.children {
			if member.id != "arena.fastbinsY" && member.id != "arena.have_fastchunks" {
				children = append(children, member)
			}
		}
		arena.children = children
		dwarfData, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
		parsed, err = inspect.HeapLayoutFromDWARF(dwarfData, offsets["arena"], encoding)
		if err != nil || !reflect.DeepEqual(parsed, layout) {
			t.Fatalf("DWARF layout=%+v err=%v", parsed, err)
		}
	}
}

func heapTestTcacheLayout(counter string, width, count uint64) inspect.HeapLayout {
	layout := heapTestLayout()
	entriesOffset := (width*count + 7) &^ uint64(7)
	layout.Tcache = &inspect.HeapRecord{Size: entriesOffset + 8*count, Fields: map[string]inspect.HeapField{
		"entries": {Offset: entriesOffset, Width: 8, Count: count, Stride: 8},
	}}
	if counter != "" {
		layout.Tcache.Fields[counter] = inspect.HeapField{Offset: 0, Width: width, Count: count, Stride: width}
	}
	layout.TcacheEntry = &inspect.HeapRecord{Size: 16, Fields: map[string]inspect.HeapField{
		"next": {Offset: 0, Width: 8, Count: 1, Stride: 8},
		"key":  {Offset: 8, Width: 8, Count: 1, Stride: 8},
	}}
	layout.TcacheLink = "safe-link-12"
	return layout
}

func TestHeapLayoutTcacheJSONRoundTrip(t *testing.T) {
	for _, counter := range []string{"", "counts", "num_slots"} {
		for _, width := range []uint64{1, 2, 4, 8} {
			for _, encoding := range []string{"plain", "safe-link-12"} {
				layout := heapTestTcacheLayout(counter, width, 76)
				layout.TcacheLink = encoding
				if err := layout.Validate(); err != nil {
					t.Fatal(err)
				}
				parsed, err := inspect.ParseHeapLayout(heapTestJSON(t, layout))
				if err != nil || !reflect.DeepEqual(parsed, layout) {
					t.Fatalf("layout=%+v err=%v", parsed, err)
				}
				delete(layout.TcacheEntry.Fields, "key")
				if _, err := inspect.ParseHeapLayout(heapTestJSON(t, layout)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestHeapLayoutTcacheJSONStrict(t *testing.T) {
	valid := heapTestJSON(t, heapTestTcacheLayout("num_slots", 2, 76))
	var object map[string]json.RawMessage
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]json.RawMessage)
	}{
		{"missing-root", func(o map[string]json.RawMessage) { delete(o, "tcache") }},
		{"missing-entry", func(o map[string]json.RawMessage) { delete(o, "tcache_entry") }},
		{"missing-encoding", func(o map[string]json.RawMessage) { delete(o, "tcache_link") }},
		{"null-root", func(o map[string]json.RawMessage) { o["tcache"] = json.RawMessage("null") }},
		{"null-entry", func(o map[string]json.RawMessage) { o["tcache_entry"] = json.RawMessage("null") }},
		{"null-encoding", func(o map[string]json.RawMessage) { o["tcache_link"] = json.RawMessage("null") }},
		{"empty-encoding", func(o map[string]json.RawMessage) { o["tcache_link"] = json.RawMessage(`""`) }},
		{"inferred-encoding", func(o map[string]json.RawMessage) { o["tcache_link"] = json.RawMessage(`"auto"`) }},
		{"unknown-root-member", func(o map[string]json.RawMessage) {
			o["tcache"] = bytes.Replace(o["tcache"], []byte(`"num_slots"`), []byte(`"unknown"`), 1)
		}},
		{"unknown-entry-member", func(o map[string]json.RawMessage) {
			o["tcache_entry"] = bytes.Replace(o["tcache_entry"], []byte(`"key"`), []byte(`"unknown"`), 1)
		}},
		{"duplicate-member", func(o map[string]json.RawMessage) {
			o["tcache_entry"] = bytes.Replace(o["tcache_entry"], []byte(`"fields":{`), []byte(`"fields":{"key":{"offset":8,"width":8,"count":1,"stride":8},`), 1)
		}},
		{"duplicate-property", func(o map[string]json.RawMessage) {
			o["tcache_entry"] = bytes.Replace(o["tcache_entry"], []byte(`"width":8`), []byte(`"width":8,"width":8`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified := make(map[string]json.RawMessage, len(object))
			for key, value := range object {
				modified[key] = bytes.Clone(value)
			}
			test.change(modified)
			data, err := json.Marshal(modified)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := inspect.ParseHeapLayout(data)
			if !errors.Is(err, target.ErrInvalidArgument) || !reflect.DeepEqual(parsed, inspect.HeapLayout{}) {
				t.Fatalf("layout=%+v err=%v", parsed, err)
			}
		})
	}
	for _, key := range []string{"tcache", "tcache_entry", "tcache_link"} {
		data := append(bytes.Clone(valid[:len(valid)-1]), []byte(`,"`+key+`":`)...)
		data = append(data, object[key]...)
		data = append(data, '}')
		if _, err := inspect.ParseHeapLayout(data); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("duplicate %s: %v", key, err)
		}
	}
}

func TestHeapLayoutTcacheValidationRejectsInvalidRecords(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*inspect.HeapLayout)
	}{
		{"root-only", func(l *inspect.HeapLayout) { l.TcacheEntry, l.TcacheLink = nil, "" }},
		{"entry-only", func(l *inspect.HeapLayout) { l.Tcache, l.TcacheLink = nil, "" }},
		{"encoding-only", func(l *inspect.HeapLayout) { l.Tcache, l.TcacheEntry = nil, nil }},
		{"no-entries", func(l *inspect.HeapLayout) { delete(l.Tcache.Fields, "entries") }},
		{"no-next", func(l *inspect.HeapLayout) { delete(l.TcacheEntry.Fields, "next") }},
		{"both-counters", func(l *inspect.HeapLayout) {
			l.Tcache.Fields["counts"] = inspect.HeapField{Offset: l.Tcache.Size, Width: 2, Count: 76, Stride: 2}
			l.Tcache.Size += 152
		}},
		{"counter-count", func(l *inspect.HeapLayout) {
			field := l.Tcache.Fields["num_slots"]
			field.Count--
			l.Tcache.Fields["num_slots"] = field
		}},
		{"short-key", func(l *inspect.HeapLayout) {
			field := l.TcacheEntry.Fields["key"]
			field.Width, field.Stride = 4, 4
			l.TcacheEntry.Fields["key"] = field
		}},
		{"short-pointer", func(l *inspect.HeapLayout) {
			field := l.Tcache.Fields["entries"]
			field.Width, field.Stride = 4, 4
			l.Tcache.Fields["entries"] = field
		}},
		{"overlap", func(l *inspect.HeapLayout) {
			field := l.TcacheEntry.Fields["key"]
			field.Offset = 0
			l.TcacheEntry.Fields["key"] = field
		}},
		{"overflow-offset", func(l *inspect.HeapLayout) {
			field := l.Tcache.Fields["entries"]
			field.Offset = math.MaxUint64
			l.Tcache.Fields["entries"] = field
		}},
		{"overflow-count", func(l *inspect.HeapLayout) {
			field := l.Tcache.Fields["entries"]
			field.Count = math.MaxUint64
			l.Tcache.Fields["entries"] = field
		}},
		{"noncontiguous", func(l *inspect.HeapLayout) {
			field := l.Tcache.Fields["entries"]
			field.Stride = 16
			l.Tcache.Fields["entries"] = field
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := heapTestTcacheLayout("num_slots", 2, 76)
			test.change(&layout)
			if err := layout.Validate(); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatal(err)
			}
		})
	}
}

func heapTestTcacheTree(counter string, width, count uint64) *heapTestDIE {
	root := heapTestDWARFTree()
	layout := heapTestTcacheLayout(counter, width, count)
	root.children = append(root.children,
		&heapTestDIE{id: "counter_int", tag: dwarf.TagBaseType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "counter_int"), heapTestNumber(dwarf.AttrByteSize, width), heapTestNumber(dwarf.AttrEncoding, 7)}},
		&heapTestDIE{id: "tcache_entry_ptr", tag: dwarf.TagPointerType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrByteSize, 8), heapTestReference(dwarf.AttrType, "tcache_entry")}},
		&heapTestDIE{id: "tcache_ptr", tag: dwarf.TagPointerType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrByteSize, 8), heapTestReference(dwarf.AttrType, "tcache")}},
	)
	for _, array := range []struct {
		id      string
		element string
	}{{"entries", "tcache_entry_ptr"}, {"counter", "counter_int"}} {
		root.children = append(root.children, &heapTestDIE{id: "tcache_" + array.id + "_array", tag: dwarf.TagArrayType, attrs: []heapTestAttr{heapTestReference(dwarf.AttrType, array.element)}, children: []*heapTestDIE{{id: "tcache_" + array.id + "_range", tag: dwarf.TagSubrangeType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrCount, count)}}}})
	}
	root.children = append(root.children,
		&heapTestDIE{id: "tcache_entry", tag: dwarf.TagStructType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "tcache_entry"), heapTestNumber(dwarf.AttrByteSize, layout.TcacheEntry.Size)}, children: []*heapTestDIE{
			{id: "tcache_entry.next", tag: dwarf.TagMember, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "next"), heapTestReference(dwarf.AttrType, "tcache_entry_ptr"), heapTestNumber(dwarf.AttrDataMemberLoc, 0)}},
			{id: "tcache_entry.key", tag: dwarf.TagMember, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "key"), heapTestReference(dwarf.AttrType, "size"), heapTestNumber(dwarf.AttrDataMemberLoc, 8)}},
		}},
		&heapTestDIE{id: "tcache", tag: dwarf.TagStructType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "tcache_perthread_struct"), heapTestNumber(dwarf.AttrByteSize, layout.Tcache.Size)}, children: []*heapTestDIE{
			{id: "tcache.entries", tag: dwarf.TagMember, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "entries"), heapTestReference(dwarf.AttrType, "tcache_entries_array"), heapTestNumber(dwarf.AttrDataMemberLoc, layout.Tcache.Fields["entries"].Offset)}},
		}},
		&heapTestDIE{id: "tcache_alias", tag: dwarf.TagTypedef, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "tcache_perthread_struct"), heapTestReference(dwarf.AttrType, "tcache")}},
	)
	if counter != "" {
		tcache := root.find("tcache")
		tcache.children = append(tcache.children, &heapTestDIE{id: "tcache.counter", tag: dwarf.TagMember, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, counter), heapTestReference(dwarf.AttrType, "tcache_counter_array"), heapTestNumber(dwarf.AttrDataMemberLoc, 0)}})
	}
	return root
}

func TestHeapTcacheLayoutFromDWARFExactLayouts(t *testing.T) {
	for _, counter := range []string{"", "counts", "num_slots"} {
		for _, width := range []uint64{1, 2, 4, 8} {
			root := heapTestTcacheTree(counter, width, 76)
			want := heapTestTcacheLayout(counter, width, 76)
			data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
			gotRoot, gotEntry, err := inspect.HeapTcacheLayoutFromDWARF(data, offsets["tcache_alias"])
			if err != nil || !reflect.DeepEqual(gotRoot, *want.Tcache) || !reflect.DeepEqual(gotEntry, *want.TcacheEntry) {
				t.Fatalf("root=%+v entry=%+v err=%v", gotRoot, gotEntry, err)
			}
			root.find("tcache_entry.key").replace(heapTestReference(dwarf.AttrType, "tcache_ptr"))
			data, offsets = heapTestDWARF(t, root, binary.LittleEndian, 8)
			gotRoot, gotEntry, err = inspect.HeapTcacheLayoutFromDWARF(data, offsets["tcache"])
			if err != nil || !reflect.DeepEqual(gotRoot, *want.Tcache) || !reflect.DeepEqual(gotEntry, *want.TcacheEntry) {
				t.Fatalf("raw pointer key: root=%+v entry=%+v err=%v", gotRoot, gotEntry, err)
			}
		}
	}
}

func TestHeapTcacheLayoutFromDWARFRejectsInvalidTypes(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*heapTestDIE)
	}{
		{"wrong-root", func(r *heapTestDIE) { r.find("tcache").replace(heapTestString(dwarf.AttrName, "other")) }},
		{"wrong-entry", func(r *heapTestDIE) { r.find("tcache_entry").replace(heapTestString(dwarf.AttrName, "other")) }},
		{"wrong-next", func(r *heapTestDIE) {
			r.find("tcache_entry.next").replace(heapTestReference(dwarf.AttrType, "tcache_ptr"))
		}},
		{"wrong-entries", func(r *heapTestDIE) {
			r.find("tcache_entries_array").replace(heapTestReference(dwarf.AttrType, "chunk_ptr"))
		}},
		{"integer-next", func(r *heapTestDIE) { r.find("tcache_entry.next").replace(heapTestReference(dwarf.AttrType, "size")) }},
		{"pointer-counter", func(r *heapTestDIE) {
			r.find("tcache_counter_array").replace(heapTestReference(dwarf.AttrType, "tcache_entry_ptr"))
		}},
		{"scalar-counter", func(r *heapTestDIE) {
			r.find("tcache.counter").replace(heapTestReference(dwarf.AttrType, "counter_int"))
		}},
		{"counter-mismatch", func(r *heapTestDIE) { r.find("tcache_counter_range").replace(heapTestNumber(dwarf.AttrCount, 75)) }},
		{"short-key", func(r *heapTestDIE) { r.find("tcache_entry.key").replace(heapTestReference(dwarf.AttrType, "uint")) }},
		{"array-key", func(r *heapTestDIE) {
			r.find("tcache_entry.key").replace(heapTestReference(dwarf.AttrType, "tcache_counter_array"))
		}},
		{"short-pointer", func(r *heapTestDIE) { r.find("tcache_entry_ptr").replace(heapTestNumber(dwarf.AttrByteSize, 4)) }},
		{"unknown-member", func(r *heapTestDIE) { r.find("tcache_entry.key").replace(heapTestString(dwarf.AttrName, "other")) }},
		{"bitfield", func(r *heapTestDIE) {
			r.find("tcache_entry.key").attrs = append(r.find("tcache_entry.key").attrs, heapTestNumber(dwarf.AttrBitSize, 8))
		}},
		{"expression-offset", func(r *heapTestDIE) {
			r.find("tcache_entry.next").replace(heapTestAttr{dwarf.AttrDataMemberLoc, 0x18, []byte{0x23, 0}})
		}},
		{"both-counters", func(r *heapTestDIE) {
			member := *r.find("tcache.counter")
			member.id, member.attrs = "tcache.counts", append([]heapTestAttr(nil), member.attrs...)
			member.replace(heapTestString(dwarf.AttrName, "counts"))
			member.replace(heapTestNumber(dwarf.AttrDataMemberLoc, 760))
			r.find("tcache").children = append(r.find("tcache").children, &member)
			r.find("tcache").replace(heapTestNumber(dwarf.AttrByteSize, 912))
		}},
		{"different-entry-identity", func(r *heapTestDIE) {
			entry := *r.find("tcache_entry")
			entry.id = "different_entry"
			r.children = append(r.children, &entry, &heapTestDIE{id: "different_entry_ptr", tag: dwarf.TagPointerType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrByteSize, 8), heapTestReference(dwarf.AttrType, "different_entry")}})
			r.find("tcache_entry.next").replace(heapTestReference(dwarf.AttrType, "different_entry_ptr"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := heapTestTcacheTree("num_slots", 2, 76)
			test.change(root)
			data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
			gotRoot, gotEntry, err := inspect.HeapTcacheLayoutFromDWARF(data, offsets["tcache"])
			if err == nil || !reflect.DeepEqual(gotRoot, inspect.HeapRecord{}) || !reflect.DeepEqual(gotEntry, inspect.HeapRecord{}) {
				t.Fatalf("root=%+v entry=%+v err=%v", gotRoot, gotEntry, err)
			}
		})
	}
}

func TestHeapRecordFromDWARFExplicitSelection(t *testing.T) {
	root := heapTestDWARFTree()
	root.find("arena.mutex").replace(heapTestReference(dwarf.AttrType, "arena"))
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	fields := []string{"bins", "next", "flags"}
	record, err := inspect.HeapRecordFromDWARF(data, offsets["arena_alias"], "malloc_state", fields)
	want := inspect.HeapRecord{Size: 2200, Fields: make(map[string]inspect.HeapField)}
	for _, name := range fields {
		want.Fields[name] = heapTestLayout().Arena.Fields[name]
	}
	if err != nil || !reflect.DeepEqual(record, want) {
		t.Fatalf("record=%+v err=%v", record, err)
	}
	fields[0] = "changed"
	if !reflect.DeepEqual(record, want) {
		t.Fatal("result aliases requested field slice")
	}
}

func TestHeapRecordFromDWARFRawPointers(t *testing.T) {
	for _, pointee := range []string{"void", "incomplete"} {
		root := heapTestDWARFTree()
		pointer := &heapTestDIE{id: "raw_pointer", tag: dwarf.TagPointerType, attrs: []heapTestAttr{heapTestNumber(dwarf.AttrByteSize, 8)}}
		if pointee == "incomplete" {
			root.children = append(root.children, &heapTestDIE{id: "forward_struct", tag: dwarf.TagStructType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "forward_struct"), {dwarf.AttrDeclaration, 0x0c, uint64(1)}}})
			pointer.attrs = append(pointer.attrs, heapTestReference(dwarf.AttrType, "forward_struct"))
		}
		root.children = append(root.children, pointer)
		root.find("arena.top").replace(heapTestReference(dwarf.AttrType, "raw_pointer"))
		data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
		record, err := inspect.HeapRecordFromDWARF(data, offsets["arena"], "malloc_state", []string{"top"})
		if err != nil || record.Fields["top"] != heapTestLayout().Arena.Fields["top"] {
			t.Fatalf("%s pointer: %+v %v", pointee, record, err)
		}
		if _, err := inspect.HeapLayoutFromDWARF(data, offsets["arena"], "plain"); err == nil {
			t.Fatal("strict arena target identity was weakened")
		}
	}
}

func TestHeapRecordFromDWARFRejectsInvalidSelection(t *testing.T) {
	root := heapTestDWARFTree()
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	for _, test := range []struct {
		name   string
		expect string
		fields []string
	}{
		{"empty-name", "", []string{"next"}},
		{"wrong-name", "heap_info", []string{"next"}},
		{"alias-name", "arena_alias", []string{"next"}},
		{"no-fields", "malloc_state", nil},
		{"empty-field", "malloc_state", []string{""}},
		{"duplicate-field", "malloc_state", []string{"next", "next"}},
		{"missing-field", "malloc_state", []string{"sbrk_base"}},
		{"long-name", strings.Repeat("x", 257), []string{"next"}},
		{"long-field", "malloc_state", []string{strings.Repeat("x", 257)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := inspect.HeapRecordFromDWARF(data, offsets["arena"], test.expect, test.fields)
			if !errors.Is(err, target.ErrInvalidArgument) || !reflect.DeepEqual(record, inspect.HeapRecord{}) {
				t.Fatalf("record=%+v err=%v", record, err)
			}
		})
	}
	if _, err := inspect.HeapRecordFromDWARF(nil, 0, "malloc_state", []string{"next"}); err == nil {
		t.Fatal("nil DWARF accepted")
	}
	if _, _, err := inspect.HeapTcacheLayoutFromDWARF(nil, 0); err == nil {
		t.Fatal("nil tcache DWARF accepted")
	}
}

func TestHeapRecordFromDWARFFieldCountBound(t *testing.T) {
	root := heapTestDWARFTree()
	entry := &heapTestDIE{id: "selected", tag: dwarf.TagStructType, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, "selected"), heapTestNumber(dwarf.AttrByteSize, 520)}}
	var fields []string
	for index := range 65 {
		name := fmt.Sprintf("field%d", index)
		fields = append(fields, name)
		entry.children = append(entry.children, &heapTestDIE{id: name, tag: dwarf.TagMember, attrs: []heapTestAttr{heapTestString(dwarf.AttrName, name), heapTestReference(dwarf.AttrType, "size"), heapTestNumber(dwarf.AttrDataMemberLoc, uint64(index)*8)}})
	}
	root.children = append(root.children, entry)
	data, offsets := heapTestDWARF(t, root, binary.LittleEndian, 8)
	if _, err := inspect.HeapRecordFromDWARF(data, offsets["selected"], "selected", fields[:64]); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.HeapRecordFromDWARF(data, offsets["selected"], "selected", fields); err == nil {
		t.Fatal("accepted more than 64 selected fields")
	}
}
