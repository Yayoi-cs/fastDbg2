package inspect

import (
	"bytes"
	"cmp"
	"debug/dwarf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"

	"fastdbg2/target"
)

type HeapField struct {
	Offset uint64 `json:"offset"`
	Width  uint64 `json:"width"`
	Count  uint64 `json:"count"`
	Stride uint64 `json:"stride"`
}

type HeapRecord struct {
	Size   uint64               `json:"size"`
	Fields map[string]HeapField `json:"fields"`
}

type HeapLayout struct {
	Schema      uint32      `json:"schema"`
	Allocator   string      `json:"allocator"`
	Arch        string      `json:"arch"`
	Endian      string      `json:"endian"`
	Pointer     uint64      `json:"pointer"`
	Arena       HeapRecord  `json:"arena"`
	Chunk       HeapRecord  `json:"chunk"`
	FastLink    string      `json:"fast_link"`
	Tcache      *HeapRecord `json:"tcache,omitempty"`
	TcacheEntry *HeapRecord `json:"tcache_entry,omitempty"`
	TcacheLink  string      `json:"tcache_link,omitempty"`
}

func ParseHeapLayout(data []byte) (HeapLayout, error) {
	if len(data) == 0 || len(data) > 65536 {
		return HeapLayout{}, heapLayoutError("JSON size must be 1..65536 bytes")
	}
	root, err := heapJSONObject(data, []string{"schema", "allocator", "arch", "endian", "pointer", "arena", "chunk", "fast_link", "tcache", "tcache_entry", "tcache_link"})
	if err != nil {
		return HeapLayout{}, err
	}
	var layout HeapLayout
	schema, err := heapJSONUint(root["schema"])
	if err != nil || schema != 1 {
		return HeapLayout{}, heapLayoutError("schema must be 1")
	}
	layout.Schema = uint32(schema)
	for _, field := range []struct {
		name string
		out  *string
	}{{"allocator", &layout.Allocator}, {"arch", &layout.Arch}, {"endian", &layout.Endian}} {
		if err := heapJSONString(root[field.name], field.out); err != nil {
			return HeapLayout{}, fmt.Errorf("heap layout %s: %w", field.name, err)
		}
	}
	if value, exists := root["fast_link"]; exists {
		if err := heapJSONString(value, &layout.FastLink); err != nil {
			return HeapLayout{}, fmt.Errorf("heap layout fast_link: %w", err)
		}
	}
	layout.Pointer, err = heapJSONUint(root["pointer"])
	if err != nil {
		return HeapLayout{}, fmt.Errorf("heap layout pointer: %w", err)
	}
	for _, record := range []struct {
		name string
		out  *HeapRecord
	}{{"arena", &layout.Arena}, {"chunk", &layout.Chunk}} {
		*record.out, err = heapJSONRecord(root[record.name], record.name)
		if err != nil {
			return HeapLayout{}, fmt.Errorf("heap layout %s: %w", record.name, err)
		}
	}
	_, hasTcache := root["tcache"]
	_, hasTcacheEntry := root["tcache_entry"]
	_, hasTcacheLink := root["tcache_link"]
	if hasTcache || hasTcacheEntry || hasTcacheLink {
		if !hasTcache || !hasTcacheEntry || !hasTcacheLink {
			return HeapLayout{}, heapLayoutError("tcache, tcache_entry, and tcache_link must be supplied together")
		}
		for _, record := range []struct {
			name string
			out  **HeapRecord
		}{{"tcache", &layout.Tcache}, {"tcache_entry", &layout.TcacheEntry}} {
			parsed, err := heapJSONRecord(root[record.name], record.name)
			if err != nil {
				return HeapLayout{}, fmt.Errorf("heap layout %s: %w", record.name, err)
			}
			*record.out = &parsed
		}
		if err := heapJSONString(root["tcache_link"], &layout.TcacheLink); err != nil {
			return HeapLayout{}, fmt.Errorf("heap layout tcache_link: %w", err)
		}
	}
	if err := layout.Validate(); err != nil {
		return HeapLayout{}, err
	}
	return layout, nil
}

func (layout HeapLayout) Validate() error {
	if layout.Schema != 1 || layout.Allocator != "glibc" || layout.Arch != "amd64" || layout.Endian != "little" || layout.Pointer != 8 {
		return heapLayoutError("requires schema 1, glibc, amd64, little endian, and 8-byte pointers")
	}
	_, hasFastbins := layout.Arena.Fields["fastbinsY"]
	if (hasFastbins || layout.FastLink != "") && layout.FastLink != "plain" && layout.FastLink != "safe-link-12" {
		return heapLayoutError("fast_link must be plain or safe-link-12, and is required when fastbinsY is present")
	}
	for _, item := range []struct {
		name   string
		record HeapRecord
	}{{"arena", layout.Arena}, {"chunk", layout.Chunk}} {
		if err := heapValidateRecord(item.name, item.record); err != nil {
			return err
		}
	}
	for _, name := range []string{"next", "bins"} {
		if _, ok := layout.Arena.Fields[name]; !ok {
			return heapLayoutError("arena field %q is required", name)
		}
	}
	for _, name := range []string{"fd", "bk"} {
		if _, ok := layout.Chunk.Fields[name]; !ok {
			return heapLayoutError("chunk field %q is required", name)
		}
	}
	if layout.Chunk.Fields["bk"].Offset != layout.Chunk.Fields["fd"].Offset+8 {
		return heapLayoutError("chunk bk must immediately follow fd")
	}
	if layout.Tcache != nil || layout.TcacheEntry != nil || layout.TcacheLink != "" {
		if layout.Tcache == nil || layout.TcacheEntry == nil || layout.TcacheLink != "plain" && layout.TcacheLink != "safe-link-12" {
			return heapLayoutError("tcache and tcache_entry require an explicit plain or safe-link-12 tcache_link")
		}
		return heapValidateTcache(*layout.Tcache, *layout.TcacheEntry)
	}
	return nil
}

func heapValidateTcache(root, entry HeapRecord) error {
	if err := heapValidateRecord("tcache", root); err != nil {
		return err
	}
	if err := heapValidateRecord("tcache_entry", entry); err != nil {
		return err
	}
	entries, exists := root.Fields["entries"]
	if !exists {
		return heapLayoutError("tcache entries is required")
	}
	if _, exists := entry.Fields["next"]; !exists {
		return heapLayoutError("tcache_entry next is required")
	}
	var counters int
	for _, name := range []string{"counts", "num_slots"} {
		if field, exists := root.Fields[name]; exists {
			counters++
			if field.Count != entries.Count {
				return heapLayoutError("tcache %s and entries must have the same count", name)
			}
		}
	}
	if counters > 1 {
		return heapLayoutError("tcache cannot declare both counts and num_slots")
	}
	return nil
}

func heapLayoutError(format string, args ...any) error {
	return fmt.Errorf("heap layout: %s: %w", fmt.Sprintf(format, args...), target.ErrInvalidArgument)
}

func heapFieldKind(record, field string) (pointer, array, allowed bool) {
	if record == "arena" {
		switch field {
		case "mutex", "flags", "have_fastchunks", "attached_threads", "system_mem", "max_system_mem":
			return false, false, true
		case "top", "last_remainder", "next", "next_free":
			return true, false, true
		case "fastbinsY", "bins":
			return true, true, true
		case "binmap":
			return false, true, true
		}
	}
	if record == "chunk" {
		switch field {
		case "mchunk_prev_size", "mchunk_size":
			return false, false, true
		case "fd", "bk", "fd_nextsize", "bk_nextsize":
			return true, false, true
		}
	}
	if record == "tcache" {
		switch field {
		case "entries":
			return true, true, true
		case "counts", "num_slots":
			return false, true, true
		}
	}
	if record == "tcache_entry" {
		switch field {
		case "next":
			return true, false, true
		case "key":
			return false, false, true
		}
	}
	return false, false, false
}

func heapValidateRecord(name string, record HeapRecord) error {
	if err := heapValidateRecordBounds(name, record); err != nil {
		return err
	}
	for _, fieldName := range slices.Sorted(maps.Keys(record.Fields)) {
		field := record.Fields[fieldName]
		pointer, array, allowed := heapFieldKind(name, fieldName)
		if !allowed {
			return heapLayoutError("unknown %s field %q", name, fieldName)
		}
		if pointer && field.Width != 8 || !array && field.Count != 1 {
			return heapLayoutError("%s.%s has invalid pointer width or scalar count", name, fieldName)
		}
		if name == "arena" && (fieldName == "fastbinsY" && field.Count > 256 || fieldName == "bins" && (field.Count < 2 || field.Count%2 != 0)) {
			return heapLayoutError("arena.%s has invalid array count", fieldName)
		}
		if name == "tcache_entry" && fieldName == "key" && field.Width != 8 {
			return heapLayoutError("tcache_entry.key must be 8 bytes")
		}
	}
	return nil
}

func heapValidateRecordBounds(name string, record HeapRecord) error {
	if record.Size == 0 || record.Size > 65536 {
		return heapLayoutError("%s size must be 1..65536 bytes", name)
	}
	if len(record.Fields) == 0 || len(record.Fields) > 64 {
		return heapLayoutError("%s has an invalid field count", name)
	}
	type interval struct {
		start uint64
		end   uint64
		name  string
	}
	var intervals []interval
	for _, fieldName := range slices.Sorted(maps.Keys(record.Fields)) {
		field := record.Fields[fieldName]
		if field.Width != 1 && field.Width != 2 && field.Width != 4 && field.Width != 8 {
			return heapLayoutError("%s.%s width must be 1, 2, 4, or 8", name, fieldName)
		}
		if field.Count == 0 || field.Count > 4096 || field.Stride != field.Width {
			return heapLayoutError("%s.%s has invalid count or stride", name, fieldName)
		}
		if field.Offset >= record.Size || field.Width > record.Size-field.Offset || field.Count-1 > (record.Size-field.Offset-field.Width)/field.Stride {
			return heapLayoutError("%s.%s extends beyond the record", name, fieldName)
		}
		intervals = append(intervals, interval{field.Offset, field.Offset + field.Count*field.Width, fieldName})
	}
	slices.SortFunc(intervals, func(a, b interval) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(a.name, b.name))
	})
	for index := 1; index < len(intervals); index++ {
		if intervals[index].start < intervals[index-1].end {
			return heapLayoutError("%s.%s overlaps %s", name, intervals[index].name, intervals[index-1].name)
		}
	}
	return nil
}

func heapJSONObject(data []byte, names []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, heapLayoutError("expected JSON object")
	}
	result := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, heapLayoutError("invalid JSON object: %v", err)
		}
		name, ok := token.(string)
		if !ok || !slices.Contains(names, name) {
			return nil, heapLayoutError("unknown JSON key %q", name)
		}
		if _, exists := result[name]; exists {
			return nil, heapLayoutError("duplicate JSON key %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, heapLayoutError("invalid JSON value: %v", err)
		}
		result[name] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') {
		return nil, heapLayoutError("unterminated JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, heapLayoutError("trailing JSON data")
	}
	return result, nil
}

func heapJSONUint(raw json.RawMessage) (uint64, error) {
	var value uint64
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' {
		return 0, heapLayoutError("expected unsigned JSON integer")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, heapLayoutError("invalid unsigned JSON integer: %v", err)
	}
	return value, nil
}

func heapJSONString(raw json.RawMessage, out *string) error {
	if len(raw) == 0 || raw[0] != '"' {
		return heapLayoutError("expected JSON string")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return heapLayoutError("invalid JSON string: %v", err)
	}
	return nil
}

func heapJSONRecord(raw json.RawMessage, name string) (HeapRecord, error) {
	object, err := heapJSONObject(raw, []string{"size", "fields"})
	if err != nil {
		return HeapRecord{}, err
	}
	size, err := heapJSONUint(object["size"])
	if err != nil {
		return HeapRecord{}, err
	}
	allowed := []string{"mchunk_prev_size", "mchunk_size", "fd", "bk", "fd_nextsize", "bk_nextsize"}
	switch name {
	case "arena":
		allowed = []string{"mutex", "flags", "have_fastchunks", "fastbinsY", "top", "last_remainder", "bins", "binmap", "next", "next_free", "attached_threads", "system_mem", "max_system_mem"}
	case "tcache":
		allowed = []string{"entries", "counts", "num_slots"}
	case "tcache_entry":
		allowed = []string{"next", "key"}
	}
	fields, err := heapJSONObject(object["fields"], allowed)
	if err != nil {
		return HeapRecord{}, err
	}
	record := HeapRecord{Size: size, Fields: make(map[string]HeapField, len(fields))}
	for _, fieldName := range slices.Sorted(maps.Keys(fields)) {
		values, err := heapJSONObject(fields[fieldName], []string{"offset", "width", "count", "stride"})
		if err != nil {
			return HeapRecord{}, fmt.Errorf("field %q: %w", fieldName, err)
		}
		var field HeapField
		for _, value := range []struct {
			name string
			out  *uint64
		}{{"offset", &field.Offset}, {"width", &field.Width}, {"count", &field.Count}, {"stride", &field.Stride}} {
			*value.out, err = heapJSONUint(values[value.name])
			if err != nil {
				return HeapRecord{}, fmt.Errorf("field %q %s: %w", fieldName, value.name, err)
			}
		}
		record.Fields[fieldName] = field
	}
	return record, nil
}

type heapDWARF struct {
	data       *dwarf.Data
	entries    map[dwarf.Offset]*dwarf.Entry
	unitReader *dwarf.Reader
	units      []heapDWARFUnit
	boundaries []dwarf.Offset
	scanned    dwarf.Offset
	steps      int
	depth      int
}

type heapDWARFUnit struct {
	offset   dwarf.Offset
	language uint64
}

type heapDWARFShape struct {
	width   uint64
	count   uint64
	pointer bool
	array   bool
	pointee dwarf.Offset
}

func HeapLayoutFromDWARF(data *dwarf.Data, arenaType dwarf.Offset, fastLink string) (HeapLayout, error) {
	if data == nil || fastLink != "" && fastLink != "plain" && fastLink != "safe-link-12" {
		return HeapLayout{}, heapLayoutError("DWARF data and a supported fast-link encoding are required")
	}
	parser := heapDWARF{data: data, entries: make(map[dwarf.Offset]*dwarf.Entry)}
	arena, err := parser.unwrap(arenaType)
	if err != nil {
		return HeapLayout{}, err
	}
	if arena.Tag != dwarf.TagStructType || arena.Val(dwarf.AttrName) != "malloc_state" {
		return HeapLayout{}, heapLayoutError("arena type must be a malloc_state struct")
	}
	var chunkType dwarf.Offset
	arenaRecord, err := parser.record(arena, "arena", arena.Offset, &chunkType)
	if err != nil {
		return HeapLayout{}, err
	}
	if chunkType == 0 {
		return HeapLayout{}, heapLayoutError("malloc_state has no malloc_chunk pointer")
	}
	chunk, err := parser.entry(chunkType)
	if err != nil {
		return HeapLayout{}, err
	}
	chunkRecord, err := parser.record(chunk, "chunk", arena.Offset, &chunkType)
	if err != nil {
		return HeapLayout{}, err
	}
	layout := HeapLayout{Schema: 1, Allocator: "glibc", Arch: "amd64", Endian: "little", Pointer: 8, Arena: arenaRecord, Chunk: chunkRecord, FastLink: fastLink}
	if err := layout.Validate(); err != nil {
		return HeapLayout{}, err
	}
	return layout, nil
}

func HeapTcacheLayoutFromDWARF(data *dwarf.Data, rootType dwarf.Offset) (HeapRecord, HeapRecord, error) {
	if data == nil {
		return HeapRecord{}, HeapRecord{}, heapLayoutError("DWARF data is required")
	}
	parser := heapDWARF{data: data, entries: make(map[dwarf.Offset]*dwarf.Entry)}
	root, err := parser.unwrap(rootType)
	if err != nil {
		return HeapRecord{}, HeapRecord{}, err
	}
	var entryType dwarf.Offset
	rootRecord, err := parser.record(root, "tcache", root.Offset, &entryType)
	if err != nil {
		return HeapRecord{}, HeapRecord{}, err
	}
	if entryType == 0 {
		return HeapRecord{}, HeapRecord{}, heapLayoutError("tcache_perthread_struct has no tcache_entry pointer")
	}
	entry, err := parser.entry(entryType)
	if err != nil {
		return HeapRecord{}, HeapRecord{}, err
	}
	entryRecord, err := parser.record(entry, "tcache_entry", root.Offset, &entryType)
	if err != nil {
		return HeapRecord{}, HeapRecord{}, err
	}
	if err := heapValidateTcache(rootRecord, entryRecord); err != nil {
		return HeapRecord{}, HeapRecord{}, err
	}
	return rootRecord, entryRecord, nil
}

func HeapRecordFromDWARF(data *dwarf.Data, typeOffset dwarf.Offset, expectedName string, fields []string) (HeapRecord, error) {
	if data == nil || expectedName == "" || len(expectedName) > 256 || len(fields) == 0 || len(fields) > 64 {
		return HeapRecord{}, heapLayoutError("DWARF data, an exact struct name, and 1..64 field names are required")
	}
	wanted := make(map[string]bool, len(fields))
	for _, name := range fields {
		if name == "" || len(name) > 256 || wanted[name] {
			return HeapRecord{}, heapLayoutError("invalid or duplicate selected field %q", name)
		}
		wanted[name] = true
	}
	parser := heapDWARF{data: data, entries: make(map[dwarf.Offset]*dwarf.Entry)}
	entry, err := parser.unwrap(typeOffset)
	if err != nil {
		return HeapRecord{}, err
	}
	size, children, err := parser.structMembers(entry, expectedName, 256)
	if err != nil {
		return HeapRecord{}, err
	}
	record := HeapRecord{Size: size, Fields: make(map[string]HeapField, len(fields))}
	seen := make(map[string]bool, len(children))
	for _, member := range children {
		name, ok := member.Val(dwarf.AttrName).(string)
		if member.Tag != dwarf.TagMember || !ok || name == "" || seen[name] {
			return HeapRecord{}, heapLayoutError("invalid or duplicate DWARF struct member at %#x", member.Offset)
		}
		seen[name] = true
		if !wanted[name] {
			continue
		}
		field, _, err := parser.member(member, false)
		if err != nil {
			return HeapRecord{}, fmt.Errorf("heap layout %s.%s: %w", expectedName, name, err)
		}
		record.Fields[name] = field
	}
	for _, name := range fields {
		if _, exists := record.Fields[name]; !exists {
			return HeapRecord{}, heapLayoutError("DWARF %s field %q is unavailable", expectedName, name)
		}
	}
	if err := heapValidateRecordBounds(expectedName, record); err != nil {
		return HeapRecord{}, err
	}
	return record, nil
}

func (parser *heapDWARF) entry(offset dwarf.Offset) (*dwarf.Entry, error) {
	if entry, ok := parser.entries[offset]; ok {
		return entry, nil
	}
	if len(parser.entries) >= 256 {
		return nil, heapLayoutError("DWARF type graph exceeds 256 entries")
	}
	if err := parser.scanThrough(offset); err != nil {
		return nil, err
	}
	reader := parser.data.Reader()
	reader.Seek(offset)
	entry, err := reader.Next()
	if err != nil {
		return nil, fmt.Errorf("heap layout DWARF at %#x: %w", offset, err)
	}
	if entry == nil || entry.Offset != offset || entry.Tag == 0 {
		return nil, heapLayoutError("missing DWARF entry at %#x", offset)
	}
	if reader.AddressSize() != 8 || reader.ByteOrder() != binary.LittleEndian {
		return nil, heapLayoutError("DWARF requires little-endian 8-byte addresses")
	}
	if err := heapDWARFAttributes(entry); err != nil {
		return nil, err
	}
	parser.entries[offset] = entry
	return entry, nil
}

func heapDWARFAttributes(entry *dwarf.Entry) error {
	if len(entry.Field) > 64 {
		return heapLayoutError("DWARF attribute count exceeds 64 at %#x", entry.Offset)
	}
	seen := make(map[dwarf.Attr]bool, len(entry.Field))
	for _, field := range entry.Field {
		if seen[field.Attr] {
			return heapLayoutError("duplicate DWARF attribute %s at %#x", field.Attr, entry.Offset)
		}
		seen[field.Attr] = true
	}
	for _, attr := range []dwarf.Attr{dwarf.AttrBitSize, dwarf.AttrBitOffset, dwarf.AttrDataBitOffset, dwarf.AttrDataLocation, dwarf.AttrAllocated, dwarf.AttrAssociated, dwarf.AttrSpecification, dwarf.AttrAbstractOrigin, dwarf.AttrRank} {
		if entry.AttrField(attr) != nil {
			return heapLayoutError("unsupported DWARF attribute %s at %#x", attr, entry.Offset)
		}
	}
	if field := entry.AttrField(dwarf.AttrDeclaration); field != nil && field.Val != false {
		return heapLayoutError("incomplete DWARF type at %#x", entry.Offset)
	}
	if field := entry.AttrField(dwarf.AttrEndianity); field != nil {
		value, err := heapDWARFUint(entry, dwarf.AttrEndianity)
		if err != nil || value != 0 && value != 2 {
			return heapLayoutError("unsupported DWARF endianity at %#x", entry.Offset)
		}
	}
	return nil
}

func heapDWARFUint(entry *dwarf.Entry, attr dwarf.Attr) (uint64, error) {
	field := entry.AttrField(attr)
	if field == nil || field.Class != dwarf.ClassConstant {
		return 0, heapLayoutError("DWARF %s at %#x must be an explicit constant", attr, entry.Offset)
	}
	switch value := field.Val.(type) {
	case int64:
		if value >= 0 {
			return uint64(value), nil
		}
	case uint64:
		return value, nil
	}
	return 0, heapLayoutError("DWARF %s at %#x must be nonnegative", attr, entry.Offset)
}

func heapDWARFType(entry *dwarf.Entry) (dwarf.Offset, error) {
	field := entry.AttrField(dwarf.AttrType)
	if field != nil && field.Class == dwarf.ClassReference {
		if offset, ok := field.Val.(dwarf.Offset); ok && offset != 0 {
			return offset, nil
		}
	}
	return 0, heapLayoutError("DWARF type reference at %#x is missing or unsupported", entry.Offset)
}

func heapDWARFSize(entry *dwarf.Entry) (uint64, error) {
	if entry.Tag == dwarf.TagPointerType && entry.AttrField(dwarf.AttrByteSize) == nil {
		return 8, nil
	}
	return heapDWARFUint(entry, dwarf.AttrByteSize)
}

func (parser *heapDWARF) unwrap(offset dwarf.Offset) (*dwarf.Entry, error) {
	seen := make(map[dwarf.Offset]bool)
	var sizes []uint64
	for range 65 {
		if seen[offset] {
			return nil, heapLayoutError("DWARF typedef or qualifier cycle at %#x", offset)
		}
		seen[offset] = true
		entry, err := parser.entry(offset)
		if err != nil {
			return nil, err
		}
		switch entry.Tag {
		case dwarf.TagTypedef, dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType, dwarf.TagAtomicType, dwarf.TagImmutableType:
			if entry.Children {
				return nil, heapLayoutError("DWARF type wrapper has children at %#x", offset)
			}
			if entry.AttrField(dwarf.AttrByteSize) != nil {
				size, err := heapDWARFSize(entry)
				if err != nil {
					return nil, err
				}
				sizes = append(sizes, size)
			}
			offset, err = heapDWARFType(entry)
			if err != nil {
				return nil, err
			}
		default:
			if len(sizes) != 0 {
				size, err := heapDWARFSize(entry)
				if err != nil {
					return nil, err
				}
				for _, declared := range sizes {
					if declared != size {
						return nil, heapLayoutError("DWARF type wrapper has inconsistent size at %#x", offset)
					}
				}
			}
			return entry, nil
		}
	}
	return nil, heapLayoutError("DWARF type wrapper depth exceeds 64")
}

func (parser *heapDWARF) children(parent *dwarf.Entry, limit int) ([]*dwarf.Entry, error) {
	if !parent.Children {
		return nil, nil
	}
	reader := parser.data.Reader()
	reader.Seek(parent.Offset)
	if _, err := reader.Next(); err != nil {
		return nil, err
	}
	var children []*dwarf.Entry
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, heapLayoutError("unterminated DWARF children at %#x", parent.Offset)
		}
		if entry.Tag == 0 {
			return children, nil
		}
		if len(children) >= limit || entry.Children {
			return nil, heapLayoutError("unsupported DWARF children at %#x", parent.Offset)
		}
		if err := heapDWARFAttributes(entry); err != nil {
			return nil, err
		}
		children = append(children, entry)
	}
}

func (parser *heapDWARF) structMembers(entry *dwarf.Entry, expected string, limit int) (uint64, []*dwarf.Entry, error) {
	if entry.Tag != dwarf.TagStructType || entry.Val(dwarf.AttrName) != expected {
		return 0, nil, heapLayoutError("type must be a complete %s struct", expected)
	}
	size, err := heapDWARFUint(entry, dwarf.AttrByteSize)
	if err != nil || size == 0 || size > 65536 {
		return 0, nil, heapLayoutError("DWARF %s size must be 1..65536", expected)
	}
	children, err := parser.children(entry, limit)
	if err != nil {
		return 0, nil, err
	}
	return size, children, nil
}

func (parser *heapDWARF) member(member *dwarf.Entry, followPointers bool) (HeapField, heapDWARFShape, error) {
	offset, err := heapDWARFUint(member, dwarf.AttrDataMemberLoc)
	if err != nil {
		return HeapField{}, heapDWARFShape{}, err
	}
	typeOffset, err := heapDWARFType(member)
	if err != nil {
		return HeapField{}, heapDWARFShape{}, err
	}
	shape, err := parser.shape(typeOffset, followPointers)
	if err != nil {
		return HeapField{}, heapDWARFShape{}, err
	}
	if member.AttrField(dwarf.AttrByteSize) != nil {
		memberSize, err := heapDWARFUint(member, dwarf.AttrByteSize)
		if err != nil || memberSize != shape.width*shape.count {
			return HeapField{}, heapDWARFShape{}, heapLayoutError("DWARF member at %#x has an inconsistent size", member.Offset)
		}
	}
	return HeapField{Offset: offset, Width: shape.width, Count: shape.count, Stride: shape.width}, shape, nil
}

func (parser *heapDWARF) record(entry *dwarf.Entry, name string, rootType dwarf.Offset, linkedType *dwarf.Offset) (HeapRecord, error) {
	expected := "malloc_state"
	linkedName := "malloc_chunk"
	switch name {
	case "chunk":
		expected = "malloc_chunk"
	case "tcache":
		expected, linkedName = "tcache_perthread_struct", "tcache_entry"
	case "tcache_entry":
		expected, linkedName = "tcache_entry", "tcache_entry"
	}
	size, children, err := parser.structMembers(entry, expected, 15)
	if err != nil {
		return HeapRecord{}, err
	}
	record := HeapRecord{Size: size, Fields: make(map[string]HeapField, len(children))}
	for _, member := range children {
		fieldName, ok := member.Val(dwarf.AttrName).(string)
		pointer, array, allowed := heapFieldKind(name, fieldName)
		if member.Tag != dwarf.TagMember || !ok || !allowed {
			return HeapRecord{}, heapLayoutError("unsupported DWARF %s member at %#x", name, member.Offset)
		}
		if _, exists := record.Fields[fieldName]; exists {
			return HeapRecord{}, heapLayoutError("duplicate DWARF %s member %q", name, fieldName)
		}
		rawKey := name == "tcache_entry" && fieldName == "key"
		field, shape, err := parser.member(member, !rawKey)
		if err != nil {
			return HeapRecord{}, fmt.Errorf("heap layout %s.%s: %w", name, fieldName, err)
		}
		if !rawKey && shape.pointer != pointer || shape.array != array {
			return HeapRecord{}, heapLayoutError("DWARF %s.%s has the wrong scalar, array, or pointer type", name, fieldName)
		}
		if pointer {
			if name == "arena" && (fieldName == "next" || fieldName == "next_free") {
				if shape.pointee != rootType {
					return HeapRecord{}, heapLayoutError("DWARF %s.%s does not point to the same malloc_state", name, fieldName)
				}
			} else {
				pointee, err := parser.entry(shape.pointee)
				if err != nil {
					return HeapRecord{}, err
				}
				if pointee.Tag != dwarf.TagStructType || pointee.Val(dwarf.AttrName) != linkedName || *linkedType != 0 && *linkedType != pointee.Offset {
					return HeapRecord{}, heapLayoutError("DWARF %s.%s has an inconsistent %s target", name, fieldName, linkedName)
				}
				*linkedType = pointee.Offset
			}
		}
		record.Fields[fieldName] = field
	}
	return record, nil
}

func (parser *heapDWARF) shape(offset dwarf.Offset, followPointers bool) (heapDWARFShape, error) {
	entry, err := parser.unwrap(offset)
	if err != nil {
		return heapDWARFShape{}, err
	}
	var array *dwarf.Entry
	if entry.Tag == dwarf.TagArrayType {
		array = entry
		elementOffset, err := heapDWARFType(entry)
		if err != nil {
			return heapDWARFShape{}, err
		}
		entry, err = parser.unwrap(elementOffset)
		if err != nil {
			return heapDWARFShape{}, err
		}
	}
	shape := heapDWARFShape{count: 1}
	if entry.Children {
		return shape, heapLayoutError("DWARF field element must be a primitive type")
	}
	shape.width, err = heapDWARFSize(entry)
	if err != nil || shape.width != 1 && shape.width != 2 && shape.width != 4 && shape.width != 8 {
		return shape, heapLayoutError("DWARF element width must be 1, 2, 4, or 8")
	}
	switch entry.Tag {
	case dwarf.TagPointerType:
		if shape.width != 8 || entry.AttrField(dwarf.AttrAddrClass) != nil {
			return shape, heapLayoutError("DWARF pointers must be ordinary 8-byte pointers")
		}
		shape.pointer = true
		if followPointers || entry.AttrField(dwarf.AttrType) != nil {
			pointeeOffset, err := heapDWARFType(entry)
			if err != nil {
				return shape, err
			}
			if followPointers {
				pointee, err := parser.unwrap(pointeeOffset)
				if err != nil {
					return shape, err
				}
				shape.pointee = pointee.Offset
			} else if err := parser.scanThrough(pointeeOffset); err != nil {
				return shape, err
			}
		}
	case dwarf.TagBaseType:
		encoding, err := heapDWARFUint(entry, dwarf.AttrEncoding)
		if err != nil || encoding != 0x05 && encoding != 0x06 && encoding != 0x07 && encoding != 0x08 {
			return shape, heapLayoutError("DWARF scalar must have an integer encoding")
		}
	default:
		return shape, heapLayoutError("unsupported DWARF field type %s", entry.Tag)
	}
	if array != nil {
		shape.array = true
		shape.count, err = parser.arrayCount(array, shape.width)
		if err != nil {
			return shape, err
		}
	}
	return shape, nil
}

func (parser *heapDWARF) arrayCount(array *dwarf.Entry, width uint64) (uint64, error) {
	if array.AttrField(dwarf.AttrOrdering) != nil {
		order, err := heapDWARFUint(array, dwarf.AttrOrdering)
		if err != nil || order > 1 {
			return 0, heapLayoutError("unsupported DWARF array ordering")
		}
	}
	children, err := parser.children(array, 1)
	if err != nil {
		return 0, err
	}
	if len(children) != 1 || children[0].Tag != dwarf.TagSubrangeType {
		return 0, heapLayoutError("DWARF array must have exactly one complete subrange")
	}
	rangeEntry := children[0]
	if rangeEntry.AttrField(dwarf.AttrLowerBound) != nil {
		lower, err := heapDWARFUint(rangeEntry, dwarf.AttrLowerBound)
		if err != nil || lower != 0 {
			return 0, heapLayoutError("DWARF array lower bound must be zero")
		}
	} else if err := parser.requireCLanguage(array.Offset); err != nil {
		return 0, err
	}
	var count uint64
	if rangeEntry.AttrField(dwarf.AttrCount) != nil {
		count, err = heapDWARFUint(rangeEntry, dwarf.AttrCount)
		if err != nil || count == 0 || count > 4096 {
			return 0, heapLayoutError("DWARF array count must be 1..4096")
		}
	}
	if rangeEntry.AttrField(dwarf.AttrUpperBound) != nil {
		upper, err := heapDWARFUint(rangeEntry, dwarf.AttrUpperBound)
		if err != nil || upper >= 4096 || count != 0 && count != upper+1 {
			return 0, heapLayoutError("DWARF array upper bound is invalid or inconsistent")
		}
		count = upper + 1
	}
	if count == 0 {
		return 0, heapLayoutError("DWARF array count is unavailable")
	}
	for _, entry := range []*dwarf.Entry{array, rangeEntry} {
		for _, size := range []struct {
			attr dwarf.Attr
			want uint64
		}{{dwarf.AttrStride, width}, {dwarf.AttrStrideSize, width * 8}} {
			if entry.AttrField(size.attr) != nil {
				value, err := heapDWARFUint(entry, size.attr)
				if err != nil || value != size.want {
					return 0, heapLayoutError("DWARF arrays must be contiguous")
				}
			}
		}
	}
	if array.AttrField(dwarf.AttrByteSize) != nil {
		size, err := heapDWARFUint(array, dwarf.AttrByteSize)
		if err != nil || size != width*count {
			return 0, heapLayoutError("DWARF array byte size is inconsistent")
		}
	}
	return count, nil
}

func (parser *heapDWARF) scanThrough(offset dwarf.Offset) error {
	if parser.unitReader == nil {
		parser.unitReader = parser.data.Reader()
	}
	for parser.scanned < offset {
		if parser.steps >= 1048576 {
			return heapLayoutError("DWARF entry scan exceeds 1048576 entries")
		}
		parser.steps++
		entry, err := parser.unitReader.Next()
		if err != nil {
			return err
		}
		if entry == nil {
			return heapLayoutError("DWARF entry at %#x is unavailable", offset)
		}
		if entry.Tag == 0 {
			parser.depth--
			if parser.depth < 0 {
				return heapLayoutError("DWARF compilation-unit nesting is invalid")
			}
			continue
		}
		parser.scanned = entry.Offset
		parser.boundaries = append(parser.boundaries, entry.Offset)
		if parser.depth == 0 {
			if len(parser.units) >= 4096 {
				return heapLayoutError("DWARF compilation-unit count exceeds 4096")
			}
			var language uint64
			if entry.Tag == dwarf.TagCompileUnit {
				if err := heapDWARFAttributes(entry); err != nil {
					return err
				}
				language, _ = heapDWARFUint(entry, dwarf.AttrLanguage)
			}
			parser.units = append(parser.units, heapDWARFUnit{offset: entry.Offset, language: language})
		}
		if entry.Children {
			parser.depth++
			if parser.depth > 256 {
				return heapLayoutError("DWARF nesting exceeds 256")
			}
		}
	}
	if _, found := slices.BinarySearch(parser.boundaries, offset); !found {
		return heapLayoutError("DWARF offset %#x is not an entry boundary", offset)
	}
	return nil
}

func (parser *heapDWARF) requireCLanguage(offset dwarf.Offset) error {
	if err := parser.scanThrough(offset); err != nil {
		return err
	}
	index, found := slices.BinarySearchFunc(parser.units, offset, func(unit heapDWARFUnit, value dwarf.Offset) int {
		if unit.offset < value {
			return -1
		}
		if unit.offset > value {
			return 1
		}
		return 0
	})
	if !found {
		index--
	}
	if index >= 0 {
		switch parser.units[index].language {
		case 0x0001, 0x0002, 0x0004, 0x000c, 0x0019, 0x001a, 0x001d, 0x0021, 0x002a, 0x002b, 0x002c, 0x003a, 0x003e:
			return nil
		}
	}
	return heapLayoutError("DWARF array without an explicit lower bound requires a C-family compilation unit")
}
