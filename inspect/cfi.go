package inspect

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"fastdbg2/target"
)

type CFIReader func(context.Context, target.Address, []byte) (int, error)

type CFISectionKind uint8

const (
	CFIEHFrame CFISectionKind = iota + 1
	CFIDebugFrame
)

const (
	cfiSectionLimit = 32 << 20
	cfiRecordLimit  = 1 << 20
	cfiEntryLimit   = 262144
)

type CFISection struct {
	Kind     CFISectionKind
	Address  target.Address
	Data     []byte
	LoadBias uint64
	Source   string
}

type CFIIndex struct {
	frames    []*CFIFrame
	prefixEnd []target.Address
}

type CFIFrame struct {
	start         target.Address
	end           target.Address
	source        string
	entry         target.Address
	cie           cfiCIE
	program       cfiProgram
	debug         bool
	loadBias      uint64
	sectionOffset uint64
	raw           []byte
	cieRaw        []byte
}

type cfiCIE struct {
	codeAlign       uint64
	dataAlign       int64
	returnRegister  uint64
	signal          bool
	pointerEncoding byte
	addressSize     byte
	initial         cfiProgram
	augmentation    string
	lsdaEncoding    byte
}

type cfiProgram struct {
	data    []byte
	address target.Address
}

type cfiPointerBases struct {
	text     *uint64
	data     *uint64
	function *uint64
}

type cfiRecord struct {
	address target.Address
	offset  uint64
	data    []byte
	body    int
	idSize  int
	id      uint64
}

type cfiParser struct {
	ctx        context.Context
	kind       CFISectionKind
	source     string
	loadBias   uint64
	read       CFIReader
	records    map[uint64]cfiRecord
	cies       map[uint64]cfiCIE
	frameBase  target.Address
	bytes      uint64
	fromHeader bool
}

func (frame *CFIFrame) Range() (target.Address, target.Address) {
	if frame == nil {
		return 0, 0
	}
	return frame.start, frame.end
}

func (frame *CFIFrame) Source() string {
	if frame == nil {
		return ""
	}
	return frame.source
}

func (frame *CFIFrame) Entry() target.Address {
	if frame == nil {
		return 0
	}
	return frame.entry
}

func ParseCFISection(ctx context.Context, section CFISection, read CFIReader) (index *CFIIndex, err error) {
	if ctx == nil || (section.Kind != CFIEHFrame && section.Kind != CFIDebugFrame) {
		return nil, fmt.Errorf("CFI section: %w", target.ErrInvalidArgument)
	}
	defer func() {
		if cancellation := ctx.Err(); cancellation != nil {
			index = nil
			if !errors.Is(err, cancellation) {
				err = errors.Join(err, cancellation)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(section.Data) > cfiSectionLimit {
		return nil, fmt.Errorf("CFI section size: %w", target.ErrOverflow)
	}
	if _, err := cfiAdd(uint64(section.Address), uint64(len(section.Data))); err != nil {
		return nil, err
	}
	if section.Kind == CFIEHFrame && section.LoadBias != 0 {
		return nil, fmt.Errorf("runtime .eh_frame load bias: %w", target.ErrInvalidArgument)
	}
	parser := cfiParser{
		ctx: ctx, kind: section.Kind, source: section.Source, loadBias: section.LoadBias,
		read: read, records: make(map[uint64]cfiRecord), cies: make(map[uint64]cfiCIE),
		frameBase: section.Address,
	}
	data := bytes.Clone(section.Data)
	var ordered []uint64
	for offset := 0; offset < len(data); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(data)-offset >= 4 && binary.LittleEndian.Uint32(data[offset:]) == 0 && section.Kind == CFIEHFrame {
			if !cfiZero(data[offset:]) {
				return nil, fmt.Errorf("CFI bytes after terminator: %w", target.ErrInvalidArgument)
			}
			break
		}
		if len(ordered) == cfiEntryLimit {
			return nil, fmt.Errorf("CFI record count: %w", target.ErrOverflow)
		}
		record, err := cfiParseRecord(data[offset:], section.Kind, target.Address(uint64(section.Address)+uint64(offset)), uint64(offset))
		if err != nil {
			return nil, fmt.Errorf("CFI %q record %#x: %w", section.Source, offset, err)
		}
		parser.records[uint64(offset)] = record
		ordered = append(ordered, uint64(offset))
		offset += len(record.data)
	}
	for _, offset := range ordered {
		record := parser.records[offset]
		if parser.isCIE(record) {
			if _, err := parser.parseCIE(record); err != nil {
				return nil, fmt.Errorf("CFI %q CIE %#x: %w", section.Source, offset, err)
			}
		}
	}
	var frames []*CFIFrame
	for _, offset := range ordered {
		record := parser.records[offset]
		if parser.isCIE(record) {
			continue
		}
		frame, err := parser.parseFDE(record)
		if err != nil {
			return nil, fmt.Errorf("CFI %q FDE %#x: %w", section.Source, offset, err)
		}
		frames = append(frames, frame)
	}
	index = cfiMakeIndex(frames)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return index, nil
}

func ReadCFIHeader(ctx context.Context, address target.Address, size uint64, source string, read CFIReader) (index *CFIIndex, err error) {
	if ctx == nil || read == nil || size < 4 {
		return nil, fmt.Errorf("CFI header: %w", target.ErrInvalidArgument)
	}
	defer func() {
		if cancellation := ctx.Err(); cancellation != nil {
			index = nil
			if !errors.Is(err, cancellation) {
				err = errors.Join(err, cancellation)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size > cfiSectionLimit {
		return nil, fmt.Errorf("CFI header size: %w", target.ErrOverflow)
	}
	if _, err := cfiAdd(uint64(address), size); err != nil {
		return nil, err
	}
	data := make([]byte, int(size))
	if err := cfiRead(ctx, read, address, data); err != nil {
		return nil, err
	}
	if data[0] != 1 {
		return nil, fmt.Errorf("CFI header version %d: %w", data[0], target.ErrUnsupported)
	}
	if data[1] == 0xff || data[2] == 0xff || data[3] == 0xff {
		return nil, fmt.Errorf("CFI header omitted search table: %w", target.ErrUnavailable)
	}
	if data[2]&0xf0 != 0 {
		return nil, fmt.Errorf("CFI header count encoding %#x: %w", data[2], target.ErrInvalidArgument)
	}
	offset := 4
	headerBase := uint64(address)
	bases := cfiPointerBases{data: &headerBase}
	frameBase, err := cfiDecodePointer(ctx, data, &offset, address, data[1], bases, read)
	if err != nil {
		return nil, fmt.Errorf("CFI header frame pointer: %w", err)
	}
	if frameBase == 0 {
		return nil, fmt.Errorf("CFI header null frame pointer: %w", target.ErrInvalidArgument)
	}
	count, signed, err := cfiEncodedScalar(data, &offset, address, data[2])
	if err != nil {
		return nil, fmt.Errorf("CFI header count: %w", err)
	}
	if signed && int64(count) < 0 {
		return nil, fmt.Errorf("CFI header negative count: %w", target.ErrInvalidArgument)
	}
	if count > cfiEntryLimit {
		return nil, fmt.Errorf("CFI header count: %w", target.ErrOverflow)
	}
	if err := cfiValidateEncoding(data[3], false); err != nil {
		return nil, fmt.Errorf("CFI header table encoding: %w", err)
	}
	parser := cfiParser{
		ctx: ctx, kind: CFIEHFrame, source: source, read: read,
		records: make(map[uint64]cfiRecord), cies: make(map[uint64]cfiCIE),
		frameBase: target.Address(frameBase), bytes: size, fromHeader: true,
	}
	frames := make([]*CFIFrame, 0, int(count))
	var previous uint64
	for i := uint64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start, err := cfiDecodePointer(ctx, data, &offset, address, data[3], bases, read)
		if err != nil {
			return nil, fmt.Errorf("CFI header table start %d: %w", i, err)
		}
		entry, err := cfiDecodePointer(ctx, data, &offset, address, data[3], bases, read)
		if err != nil {
			return nil, fmt.Errorf("CFI header table FDE %d: %w", i, err)
		}
		if entry == 0 {
			return nil, fmt.Errorf("CFI header null FDE pointer: %w", target.ErrInvalidArgument)
		}
		if i != 0 && start < previous {
			return nil, fmt.Errorf("CFI header unsorted table: %w", target.ErrInvalidArgument)
		}
		previous = start
		record, err := parser.readRecord(target.Address(entry))
		if err != nil {
			return nil, fmt.Errorf("CFI header FDE %#x: %w", entry, err)
		}
		frame, err := parser.parseFDE(record)
		if err != nil {
			return nil, fmt.Errorf("CFI header FDE %#x: %w", entry, err)
		}
		if uint64(frame.start) != start {
			return nil, fmt.Errorf("CFI header table start differs from FDE: %w", target.ErrInvalidArgument)
		}
		frames = append(frames, frame)
	}
	if !cfiZero(data[offset:]) {
		return nil, fmt.Errorf("CFI header trailing data: %w", target.ErrInvalidArgument)
	}
	if err := parser.checkRecordOverlap(); err != nil {
		return nil, err
	}
	index, err = MergeCFIIndexes(cfiMakeIndex(frames))
	if cancellation := ctx.Err(); cancellation != nil {
		return nil, errors.Join(cancellation, err)
	}
	return index, err
}

func MergeCFIIndexes(indexes ...*CFIIndex) (*CFIIndex, error) {
	var frames []*CFIFrame
	for _, index := range indexes {
		if index == nil {
			return nil, fmt.Errorf("nil CFI index: %w", target.ErrInvalidArgument)
		}
		if len(index.frames) > cfiEntryLimit-len(frames) {
			return nil, fmt.Errorf("CFI merged record count: %w", target.ErrOverflow)
		}
		frames = append(frames, index.frames...)
	}
	slices.SortFunc(frames, cfiCompareFrames)
	frames = slices.CompactFunc(frames, cfiSameFrame)
	return cfiMakeIndex(frames), nil
}

func (index *CFIIndex) Lookup(pc target.Address) (*CFIFrame, error) {
	if index == nil {
		return nil, fmt.Errorf("CFI index: %w", target.ErrUnavailable)
	}
	end := sort.Search(len(index.frames), func(i int) bool { return index.frames[i].start > pc })
	var found *CFIFrame
	for i := end - 1; i >= 0 && index.prefixEnd[i] > pc; i-- {
		frame := index.frames[i]
		if pc >= frame.end {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("CFI address %#x has multiple covering FDEs: %w", pc, target.ErrAmbiguous)
		}
		found = frame
	}
	if found == nil {
		return nil, fmt.Errorf("CFI address %#x: %w", pc, target.ErrNotFound)
	}
	return found, nil
}

func cfiMakeIndex(frames []*CFIFrame) *CFIIndex {
	frames = slices.Clone(frames)
	slices.SortFunc(frames, cfiCompareFrames)
	index := &CFIIndex{frames: frames, prefixEnd: make([]target.Address, len(frames))}
	var end target.Address
	for i, frame := range frames {
		end = max(end, frame.end)
		index.prefixEnd[i] = end
	}
	return index
}

func cfiCompareFrames(a, b *CFIFrame) int {
	return cmp.Or(cfiCompareFrameState(a, b), cmp.Compare(a.source, b.source))
}

func cfiCompareFrameState(a, b *CFIFrame) int {
	identity := 0
	if a.debug != b.debug {
		if a.debug {
			identity = 1
		} else {
			identity = -1
		}
	} else if a.debug {
		identity = cmp.Or(cmp.Compare(a.source, b.source), cmp.Compare(a.sectionOffset, b.sectionOffset))
	}
	signal := 0
	if a.cie.signal != b.cie.signal {
		if a.cie.signal {
			signal = 1
		} else {
			signal = -1
		}
	}
	if order := cmp.Or(
		cmp.Compare(a.start, b.start), cmp.Compare(a.end, b.end),
		identity, cmp.Compare(a.entry, b.entry), cmp.Compare(a.loadBias, b.loadBias),
		cmp.Compare(a.cie.initial.address, b.cie.initial.address),
		cmp.Compare(a.program.address, b.program.address),
		cmp.Compare(a.cie.codeAlign, b.cie.codeAlign), cmp.Compare(a.cie.dataAlign, b.cie.dataAlign),
		cmp.Compare(a.cie.returnRegister, b.cie.returnRegister),
		cmp.Compare(a.cie.pointerEncoding, b.cie.pointerEncoding), cmp.Compare(a.cie.addressSize, b.cie.addressSize),
		cmp.Compare(a.cie.augmentation, b.cie.augmentation), cmp.Compare(a.cie.lsdaEncoding, b.cie.lsdaEncoding), signal,
	); order != 0 {
		return order
	}
	for _, data := range [][2][]byte{{a.raw, b.raw}, {a.cieRaw, b.cieRaw}, {a.program.data, b.program.data}, {a.cie.initial.data, b.cie.initial.data}} {
		if order := bytes.Compare(data[0], data[1]); order != 0 {
			return order
		}
	}
	return 0
}

func cfiSameFrame(a, b *CFIFrame) bool {
	if a.debug && a.source == "" {
		return false
	}
	return cfiCompareFrameState(a, b) == 0
}

func cfiParseRecord(data []byte, kind CFISectionKind, address target.Address, offset uint64) (cfiRecord, error) {
	if len(data) < 4 {
		return cfiRecord{}, fmt.Errorf("CFI record length: %w", target.ErrInvalidArgument)
	}
	length := uint64(binary.LittleEndian.Uint32(data))
	body, idSize := 4, 4
	if length == math.MaxUint32 {
		if len(data) < 12 {
			return cfiRecord{}, fmt.Errorf("CFI extended record length: %w", target.ErrInvalidArgument)
		}
		length = binary.LittleEndian.Uint64(data[4:])
		body = 12
		if kind == CFIDebugFrame {
			idSize = 8
		}
	} else if length >= 0xfffffff0 {
		return cfiRecord{}, fmt.Errorf("CFI reserved record length: %w", target.ErrInvalidArgument)
	}
	if length > cfiRecordLimit-uint64(body) {
		return cfiRecord{}, fmt.Errorf("CFI record size: %w", target.ErrOverflow)
	}
	if length < uint64(idSize) || length > uint64(len(data)-body) {
		return cfiRecord{}, fmt.Errorf("CFI record bounds: %w", target.ErrInvalidArgument)
	}
	if _, err := cfiAdd(uint64(address), uint64(body)+length); err != nil {
		return cfiRecord{}, err
	}
	id := uint64(binary.LittleEndian.Uint32(data[body:]))
	if idSize == 8 {
		id = binary.LittleEndian.Uint64(data[body:])
	}
	return cfiRecord{address: address, offset: offset, data: data[:body+int(length)], body: body, idSize: idSize, id: id}, nil
}

func (parser *cfiParser) isCIE(record cfiRecord) bool {
	if parser.kind == CFIEHFrame {
		return record.id == 0
	}
	if record.idSize == 8 {
		return record.id == math.MaxUint64
	}
	return record.id == math.MaxUint32
}

func (parser *cfiParser) parseCIE(record cfiRecord) (cfiCIE, error) {
	if err := parser.ctx.Err(); err != nil {
		return cfiCIE{}, err
	}
	if cie, ok := parser.cies[record.offset]; ok {
		return cie, nil
	}
	if !parser.isCIE(record) {
		return cfiCIE{}, fmt.Errorf("CFI reference is not a CIE: %w", target.ErrInvalidArgument)
	}
	offset := record.body + record.idSize
	version, err := cfiByte(record.data, &offset)
	if err != nil {
		return cfiCIE{}, err
	}
	if version != 1 && version != 3 && version != 4 {
		return cfiCIE{}, fmt.Errorf("CIE version %d: %w", version, target.ErrUnsupported)
	}
	end := bytes.IndexByte(record.data[offset:], 0)
	if end < 0 {
		return cfiCIE{}, fmt.Errorf("CIE augmentation terminator: %w", target.ErrInvalidArgument)
	}
	augmentation := string(record.data[offset : offset+end])
	offset += end + 1
	if err := cfiValidateAugmentation(augmentation); err != nil {
		return cfiCIE{}, err
	}
	cie := cfiCIE{addressSize: 8, augmentation: augmentation, lsdaEncoding: 0xff}
	if version == 4 {
		cie.addressSize, err = cfiByte(record.data, &offset)
		if err != nil {
			return cfiCIE{}, err
		}
		segment, err := cfiByte(record.data, &offset)
		if err != nil {
			return cfiCIE{}, err
		}
		if cie.addressSize != 8 || segment != 0 {
			return cfiCIE{}, fmt.Errorf("CIE address size %d segment size %d: %w", cie.addressSize, segment, target.ErrUnsupported)
		}
	}
	cie.codeAlign, err = cfiULEB(record.data, &offset)
	if err != nil {
		return cfiCIE{}, err
	}
	if cie.codeAlign == 0 {
		return cfiCIE{}, fmt.Errorf("CIE zero code alignment: %w", target.ErrInvalidArgument)
	}
	cie.dataAlign, err = cfiSLEB(record.data, &offset)
	if err != nil {
		return cfiCIE{}, err
	}
	if version == 1 {
		value, err := cfiByte(record.data, &offset)
		if err != nil {
			return cfiCIE{}, err
		}
		cie.returnRegister = uint64(value)
	} else {
		cie.returnRegister, err = cfiULEB(record.data, &offset)
		if err != nil {
			return cfiCIE{}, err
		}
	}
	if augmentation != "" {
		length, err := cfiULEB(record.data, &offset)
		if err != nil {
			return cfiCIE{}, err
		}
		if length > uint64(len(record.data)-offset) {
			return cfiCIE{}, fmt.Errorf("CIE augmentation length: %w", target.ErrInvalidArgument)
		}
		end := offset + int(length)
		data := record.data[:end]
		for _, letter := range augmentation[1:] {
			switch letter {
			case 'P':
				encoding, err := cfiByte(data, &offset)
				if err != nil {
					return cfiCIE{}, err
				}
				if encoding != 0xff {
					if _, _, err := cfiEncodedScalar(data, &offset, record.address, encoding); err != nil {
						return cfiCIE{}, err
					}
				}
			case 'L', 'R':
				encoding, err := cfiByte(data, &offset)
				if err != nil {
					return cfiCIE{}, err
				}
				if err := cfiValidateEncoding(encoding, letter == 'L'); err != nil {
					return cfiCIE{}, err
				}
				if letter == 'L' {
					cie.lsdaEncoding = encoding
				} else {
					cie.pointerEncoding = encoding
				}
			case 'S':
				cie.signal = true
			}
		}
		if offset != end {
			return cfiCIE{}, fmt.Errorf("CIE augmentation excess data: %w", target.ErrInvalidArgument)
		}
	}
	cie.initial = cfiProgram{data: record.data[offset:], address: record.address + target.Address(offset)}
	parser.cies[record.offset] = cie
	return cie, nil
}

func cfiValidateAugmentation(value string) error {
	if value == "" {
		return nil
	}
	if value[0] != 'z' {
		return fmt.Errorf("CIE augmentation %q: %w", value, target.ErrUnsupported)
	}
	var seen uint8
	for _, letter := range value[1:] {
		var mask uint8
		switch letter {
		case 'P':
			mask = 1
		case 'L':
			mask = 2
		case 'R':
			mask = 4
		case 'S':
			mask = 8
		default:
			return fmt.Errorf("CIE augmentation %q: %w", value, target.ErrUnsupported)
		}
		if seen&mask != 0 {
			return fmt.Errorf("CIE duplicate augmentation %q: %w", value, target.ErrUnsupported)
		}
		seen |= mask
	}
	return nil
}

func (parser *cfiParser) parseFDE(record cfiRecord) (*CFIFrame, error) {
	if err := parser.ctx.Err(); err != nil {
		return nil, err
	}
	if parser.isCIE(record) {
		return nil, fmt.Errorf("CFI reference is not an FDE: %w", target.ErrInvalidArgument)
	}
	cieOffset := record.id
	if parser.kind == CFIEHFrame {
		fieldOffset := record.offset + uint64(record.body)
		if record.id > fieldOffset {
			return nil, fmt.Errorf("CFI CIE backward reference: %w", target.ErrInvalidArgument)
		}
		cieOffset = fieldOffset - record.id
	}
	cieRecord, ok := parser.records[cieOffset]
	if !ok {
		if !parser.fromHeader {
			return nil, fmt.Errorf("CFI CIE reference is not a record boundary: %w", target.ErrInvalidArgument)
		}
		cieAddress, err := cfiAdd(uint64(parser.frameBase), cieOffset)
		if err != nil {
			return nil, err
		}
		cieRecord, err = parser.readRecord(target.Address(cieAddress))
		if err != nil {
			return nil, err
		}
	}
	cie, err := parser.parseCIE(cieRecord)
	if err != nil {
		return nil, err
	}
	offset := record.body + record.idSize
	start, err := cfiDecodePointer(parser.ctx, record.data, &offset, record.address, cie.pointerEncoding, cfiPointerBases{}, parser.read)
	if err != nil {
		return nil, err
	}
	if parser.kind == CFIDebugFrame {
		start, err = cfiAdd(start, parser.loadBias)
		if err != nil {
			return nil, err
		}
	}
	length, signed, err := cfiEncodedScalar(record.data, &offset, record.address, cie.pointerEncoding&0x0f)
	if err != nil {
		return nil, err
	}
	if signed && int64(length) < 0 {
		return nil, fmt.Errorf("CFI negative FDE range: %w", target.ErrInvalidArgument)
	}
	end, err := cfiAdd(start, length)
	if err != nil {
		return nil, err
	}
	if cie.augmentation != "" {
		length, err := cfiULEB(record.data, &offset)
		if err != nil {
			return nil, err
		}
		if length > uint64(len(record.data)-offset) {
			return nil, fmt.Errorf("FDE augmentation length: %w", target.ErrInvalidArgument)
		}
		end := offset + int(length)
		if length != 0 && cie.lsdaEncoding != 0xff {
			if _, _, err := cfiEncodedScalar(record.data[:end], &offset, record.address, cie.lsdaEncoding); err != nil {
				return nil, err
			}
		}
		if offset != end {
			return nil, fmt.Errorf("FDE augmentation excess data: %w", target.ErrInvalidArgument)
		}
	}
	return &CFIFrame{
		start: target.Address(start), end: target.Address(end), source: parser.source, entry: record.address,
		cie: cie, program: cfiProgram{data: record.data[offset:], address: record.address + target.Address(offset)},
		debug: parser.kind == CFIDebugFrame, loadBias: parser.loadBias, sectionOffset: record.offset,
		raw: record.data, cieRaw: cieRecord.data,
	}, nil
}

func (parser *cfiParser) checkRecordOverlap() error {
	records := make([]cfiRecord, 0, len(parser.records))
	for _, record := range parser.records {
		records = append(records, record)
	}
	slices.SortFunc(records, func(a, b cfiRecord) int { return cmp.Compare(a.address, b.address) })
	var end target.Address
	for _, record := range records {
		if err := parser.ctx.Err(); err != nil {
			return err
		}
		if record.address < end {
			return fmt.Errorf("CFI referenced records overlap: %w", target.ErrInvalidArgument)
		}
		end = record.address + target.Address(len(record.data))
	}
	return nil
}

func (parser *cfiParser) readRecord(address target.Address) (cfiRecord, error) {
	if address < parser.frameBase {
		return cfiRecord{}, fmt.Errorf("CFI record precedes .eh_frame: %w", target.ErrInvalidArgument)
	}
	offset := uint64(address - parser.frameBase)
	if record, ok := parser.records[offset]; ok {
		return record, nil
	}
	if len(parser.records) >= cfiEntryLimit {
		return cfiRecord{}, fmt.Errorf("CFI record count: %w", target.ErrOverflow)
	}
	header := make([]byte, 4, 12)
	if err := cfiRead(parser.ctx, parser.read, address, header); err != nil {
		return cfiRecord{}, err
	}
	length := uint64(binary.LittleEndian.Uint32(header))
	if length == math.MaxUint32 {
		header = header[:12]
		next, err := cfiAdd(uint64(address), 4)
		if err != nil {
			return cfiRecord{}, err
		}
		if err := cfiRead(parser.ctx, parser.read, target.Address(next), header[4:]); err != nil {
			return cfiRecord{}, err
		}
		length = binary.LittleEndian.Uint64(header[4:])
	} else if length >= 0xfffffff0 {
		return cfiRecord{}, fmt.Errorf("CFI reserved record length: %w", target.ErrInvalidArgument)
	}
	if length < 4 {
		return cfiRecord{}, fmt.Errorf("CFI record bounds: %w", target.ErrInvalidArgument)
	}
	total, err := cfiAdd(length, uint64(len(header)))
	if err != nil {
		return cfiRecord{}, err
	}
	if total > cfiRecordLimit || total > cfiSectionLimit-parser.bytes {
		return cfiRecord{}, fmt.Errorf("CFI record read budget: %w", target.ErrOverflow)
	}
	if _, err := cfiAdd(uint64(address), total); err != nil {
		return cfiRecord{}, err
	}
	data := make([]byte, int(total))
	copy(data, header)
	if err := cfiRead(parser.ctx, parser.read, address+target.Address(len(header)), data[len(header):]); err != nil {
		return cfiRecord{}, err
	}
	record, err := cfiParseRecord(data, CFIEHFrame, address, offset)
	if err != nil {
		return cfiRecord{}, err
	}
	parser.bytes += total
	parser.records[offset] = record
	return record, nil
}

func cfiDecodePointer(ctx context.Context, data []byte, offset *int, address target.Address, encoding byte, bases cfiPointerBases, read CFIReader) (uint64, error) {
	if ctx == nil || offset == nil || *offset < 0 || *offset > len(data) {
		return 0, fmt.Errorf("CFI pointer: %w", target.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := cfiValidateEncoding(encoding, false); err != nil {
		return 0, err
	}
	field, err := cfiAdd(uint64(address), uint64(*offset))
	if err != nil {
		return 0, err
	}
	value, signed, err := cfiEncodedScalar(data, offset, address, encoding)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, nil
	}
	var base uint64
	switch encoding & 0x70 {
	case 0, 0x50:
	case 0x10:
		base = field
	case 0x20, 0x30, 0x40:
		var known *uint64
		switch encoding & 0x70 {
		case 0x20:
			known = bases.text
		case 0x30:
			known = bases.data
		case 0x40:
			known = bases.function
		}
		if known == nil {
			return 0, fmt.Errorf("CFI pointer base for %#x: %w", encoding, target.ErrUnsupported)
		}
		base = *known
	}
	if encoding&0x70 != 0 && encoding&0x70 != 0x50 {
		if signed && int64(value) < 0 {
			magnitude := uint64(-(int64(value) + 1)) + 1
			if magnitude > base {
				return 0, fmt.Errorf("CFI relative pointer underflow: %w", target.ErrOverflow)
			}
			value = base - magnitude
		} else {
			value, err = cfiAdd(base, value)
			if err != nil {
				return 0, err
			}
		}
	}
	if encoding&0x80 != 0 {
		if read == nil {
			return 0, fmt.Errorf("CFI indirect pointer: %w", target.ErrUnavailable)
		}
		var pointer [8]byte
		if err := cfiRead(ctx, read, target.Address(value), pointer[:]); err != nil {
			return 0, err
		}
		value = binary.LittleEndian.Uint64(pointer[:])
	}
	return value, nil
}

func cfiValidateEncoding(encoding byte, omit bool) error {
	if encoding == 0xff && omit {
		return nil
	}
	switch encoding & 0x0f {
	case 0, 1, 2, 3, 4, 8, 9, 10, 11, 12:
	default:
		return fmt.Errorf("CFI pointer format %#x: %w", encoding, target.ErrUnsupported)
	}
	switch encoding & 0x70 {
	case 0, 0x10, 0x20, 0x30, 0x40:
	case 0x50:
		if encoding&0x0f != 0 {
			return fmt.Errorf("CFI aligned pointer format %#x: %w", encoding, target.ErrUnsupported)
		}
	default:
		return fmt.Errorf("CFI pointer application %#x: %w", encoding, target.ErrUnsupported)
	}
	return nil
}

func cfiEncodedScalar(data []byte, offset *int, address target.Address, encoding byte) (uint64, bool, error) {
	if offset == nil || *offset < 0 || *offset > len(data) {
		return 0, false, fmt.Errorf("CFI encoded scalar bounds: %w", target.ErrInvalidArgument)
	}
	if err := cfiValidateEncoding(encoding, false); err != nil {
		return 0, false, err
	}
	if encoding&0x70 == 0x50 {
		field, err := cfiAdd(uint64(address), uint64(*offset))
		if err != nil {
			return 0, false, err
		}
		padding := (8 - field%8) % 8
		if padding > uint64(len(data)-*offset) {
			return 0, false, fmt.Errorf("CFI aligned pointer bounds: %w", target.ErrInvalidArgument)
		}
		*offset += int(padding)
	}
	format := encoding & 0x0f
	if format == 1 {
		value, err := cfiULEB(data, offset)
		return value, false, err
	}
	if format == 9 {
		value, err := cfiSLEB(data, offset)
		return uint64(value), true, err
	}
	size := 8
	switch format {
	case 2, 10:
		size = 2
	case 3, 11:
		size = 4
	}
	if len(data)-*offset < size {
		return 0, false, fmt.Errorf("CFI scalar bounds: %w", target.ErrInvalidArgument)
	}
	var value uint64
	switch size {
	case 2:
		value = uint64(binary.LittleEndian.Uint16(data[*offset:]))
		if format == 10 {
			value = uint64(int64(int16(value)))
		}
	case 4:
		value = uint64(binary.LittleEndian.Uint32(data[*offset:]))
		if format == 11 {
			value = uint64(int64(int32(value)))
		}
	case 8:
		value = binary.LittleEndian.Uint64(data[*offset:])
	}
	*offset += size
	return value, format&8 != 0, nil
}

func cfiULEB(data []byte, offset *int) (uint64, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		b, err := cfiByte(data, offset)
		if err != nil {
			return 0, err
		}
		if i == 9 && b > 1 {
			return 0, fmt.Errorf("CFI ULEB128: %w", target.ErrOverflow)
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("CFI ULEB128: %w", target.ErrOverflow)
}

func cfiSLEB(data []byte, offset *int) (int64, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		b, err := cfiByte(data, offset)
		if err != nil {
			return 0, err
		}
		if i == 9 && b != 0 && b != 0x7f {
			return 0, fmt.Errorf("CFI SLEB128: %w", target.ErrOverflow)
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			if i < 9 && b&0x40 != 0 {
				value |= math.MaxUint64 << (7 * (i + 1))
			}
			return int64(value), nil
		}
	}
	return 0, fmt.Errorf("CFI SLEB128: %w", target.ErrOverflow)
}

func cfiByte(data []byte, offset *int) (byte, error) {
	if offset == nil || *offset < 0 || *offset >= len(data) {
		return 0, fmt.Errorf("CFI operand bounds: %w", target.ErrInvalidArgument)
	}
	value := data[*offset]
	*offset++
	return value, nil
}

func cfiRead(ctx context.Context, read CFIReader, address target.Address, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := cfiAdd(uint64(address), uint64(len(data))); err != nil {
		return err
	}
	if read == nil {
		return fmt.Errorf("CFI memory reader: %w", target.ErrUnavailable)
	}
	n, err := read(ctx, address, data)
	if n < 0 || n > len(data) {
		return errors.Join(ctx.Err(), err, fmt.Errorf("CFI reader count: %w", target.ErrInvalidArgument))
	}
	if n != len(data) {
		return errors.Join(ctx.Err(), &target.PartialError{Op: "read CFI", Completed: n, Total: len(data), Err: err})
	}
	if err != nil {
		return errors.Join(ctx.Err(), err)
	}
	return ctx.Err()
}

func cfiAdd(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, fmt.Errorf("CFI address addition: %w", target.ErrOverflow)
	}
	return a + b, nil
}

func cfiZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
