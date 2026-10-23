package inspect

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"testing"

	"fastdbg2/target"
)

func cfiTestRecord(kind CFISectionKind, wide bool, id uint64, body []byte) []byte {
	idSize, prefix := 4, 4
	if wide {
		prefix = 12
		if kind == CFIDebugFrame {
			idSize = 8
		}
	}
	data := make([]byte, prefix+idSize+len(body))
	if wide {
		binary.LittleEndian.PutUint32(data, math.MaxUint32)
		binary.LittleEndian.PutUint64(data[4:], uint64(idSize+len(body)))
	} else {
		binary.LittleEndian.PutUint32(data, uint32(idSize+len(body)))
	}
	if idSize == 8 {
		binary.LittleEndian.PutUint64(data[prefix:], id)
	} else {
		binary.LittleEndian.PutUint32(data[prefix:], uint32(id))
	}
	copy(data[prefix+idSize:], body)
	return data
}

func cfiTestCIE(kind CFISectionKind, wide bool, version byte, augmentation string, augmentationData, program []byte) []byte {
	id := uint64(0)
	if kind == CFIDebugFrame {
		id = math.MaxUint64
	}
	body := append([]byte{version}, []byte(augmentation)...)
	body = append(body, 0)
	if version == 4 {
		body = append(body, 8, 0)
	}
	body = append(body, 1, 0x78, 16)
	if augmentation != "" && augmentation[0] == 'z' {
		body = binary.AppendUvarint(body, uint64(len(augmentationData)))
		body = append(body, augmentationData...)
	}
	body = append(body, program...)
	return cfiTestRecord(kind, wide, id, body)
}

func cfiTestFDE(kind CFISectionKind, wide bool, sectionBase target.Address, offset, cieOffset, start, length uint64, encoding byte, augmented bool, augmentationData, program []byte) []byte {
	id, prefix, idSize := cieOffset, uint64(4), uint64(4)
	if wide {
		prefix = 12
		if kind == CFIDebugFrame {
			idSize = 8
		}
	}
	if kind == CFIEHFrame {
		id = offset + prefix - cieOffset
	}
	var body []byte
	switch encoding {
	case 0:
		body = binary.LittleEndian.AppendUint64(body, start)
		body = binary.LittleEndian.AppendUint64(body, length)
	case 0x1b:
		field := uint64(sectionBase) + offset + prefix + idSize
		body = binary.LittleEndian.AppendUint32(body, uint32(int64(start)-int64(field)))
		body = binary.LittleEndian.AppendUint32(body, uint32(length))
	default:
		panic("unsupported test encoding")
	}
	if augmented {
		body = binary.AppendUvarint(body, uint64(len(augmentationData)))
		body = append(body, augmentationData...)
	}
	body = append(body, program...)
	return cfiTestRecord(kind, wide, id, body)
}

func cfiTestSection(kind CFISectionKind, wide bool, version byte, base target.Address, bias uint64, ranges ...[2]uint64) (CFISection, []uint64) {
	data := cfiTestCIE(kind, wide, version, "", nil, []byte{0x0c, 7, 8, 0x90, 1})
	var offsets []uint64
	for _, interval := range ranges {
		offset := uint64(len(data))
		offsets = append(offsets, offset)
		data = append(data, cfiTestFDE(kind, wide, base, offset, 0, interval[0], interval[1], 0, false, nil, []byte{0x42})...)
	}
	return CFISection{Kind: kind, Address: base, Data: data, LoadBias: bias, Source: "test module"}, offsets
}

func TestCFISectionVersionsAndRecordFormats(t *testing.T) {
	for _, kind := range []CFISectionKind{CFIEHFrame, CFIDebugFrame} {
		for _, wide := range []bool{false, true} {
			for _, version := range []byte{1, 3, 4} {
				t.Run(fmt.Sprintf("%d/%t/%d", kind, wide, version), func(t *testing.T) {
					bias := uint64(0)
					if kind == CFIDebugFrame {
						bias = 0x100000
					}
					section, offsets := cfiTestSection(kind, wide, version, 0x8000, bias, [2]uint64{0x1000, 0x20})
					index, err := ParseCFISection(context.Background(), section, nil)
					if err != nil {
						t.Fatal(err)
					}
					frame, err := index.Lookup(target.Address(bias + 0x1005))
					if err != nil {
						t.Fatal(err)
					}
					start, end := frame.Range()
					if uint64(start) != bias+0x1000 || uint64(end) != bias+0x1020 || frame.Entry() != section.Address+target.Address(offsets[0]) || frame.Source() != section.Source {
						t.Fatalf("frame = %#v", frame)
					}
					if frame.cie.codeAlign != 1 || frame.cie.dataAlign != -8 || frame.cie.returnRegister != 16 || frame.cie.addressSize != 8 {
						t.Fatalf("CIE = %#v", frame.cie)
					}
					if !bytes.Equal(frame.cie.initial.data, []byte{0x0c, 7, 8, 0x90, 1}) || !bytes.Equal(frame.program.data, []byte{0x42}) {
						t.Fatalf("program = %x, initial = %x", frame.program.data, frame.cie.initial.data)
					}
					clear(section.Data)
					if frame.program.data[0] != 0x42 || frame.cie.initial.data[0] != 0x0c {
						t.Fatal("index retained caller-owned mutable data")
					}
					for _, address := range []target.Address{target.Address(bias + 0x0fff), target.Address(bias + 0x1020)} {
						if _, err := index.Lookup(address); !errors.Is(err, target.ErrNotFound) {
							t.Fatalf("lookup %#x = %v", address, err)
						}
					}
				})
			}
		}
	}
}

func TestCFIAugmentationsAndPCRelativePointers(t *testing.T) {
	for _, augmentation := range []string{"zPLRS", "zSRLP"} {
		t.Run(augmentation, func(t *testing.T) {
			var augmentationData []byte
			for _, letter := range augmentation[1:] {
				switch letter {
				case 'P':
					augmentationData = append(augmentationData, 0x9b, 0x12, 0x34, 0, 0)
				case 'L':
					augmentationData = append(augmentationData, 0x9b)
				case 'R':
					augmentationData = append(augmentationData, 0x1b)
				}
			}
			data := cfiTestCIE(CFIEHFrame, false, 1, augmentation, augmentationData, []byte{0x0c, 7, 8})
			data = append(data, cfiTestFDE(CFIEHFrame, false, 0x8000, uint64(len(data)), 0, 0x1000, 0x10, 0x1b, true, []byte{0x78, 0x56, 0, 0}, []byte{0x41})...)
			reads := 0
			index, err := ParseCFISection(context.Background(), CFISection{Kind: CFIEHFrame, Address: 0x8000, Data: data}, func(context.Context, target.Address, []byte) (int, error) {
				reads++
				return 0, target.ErrUnavailable
			})
			if err != nil {
				t.Fatal(err)
			}
			frame, err := index.Lookup(0x1000)
			if err != nil || !frame.cie.signal || reads != 0 || !bytes.Equal(frame.program.data, []byte{0x41}) {
				t.Fatalf("frame = %#v, reads = %d, error = %v", frame, reads, err)
			}
		})
	}
}

func TestCFILSDAEncodingAllowsEmptyFDEAugmentation(t *testing.T) {
	for _, wide := range []bool{false, true} {
		data := cfiTestCIE(CFIEHFrame, wide, 1, "zLR", []byte{0x1b, 0x1b}, []byte{0x0c, 7, 8, 0x90, 1})
		data = append(data, cfiTestFDE(CFIEHFrame, wide, 0x8000, uint64(len(data)), 0, 0x1000, 0x10, 0x1b, true, nil, []byte{0x41})...)
		index, err := ParseCFISection(context.Background(), CFISection{Kind: CFIEHFrame, Address: 0x8000, Data: data, Source: "empty LSDA"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := index.Lookup(0x1000)
		if err != nil || !bytes.Equal(frame.program.data, []byte{0x41}) {
			t.Fatalf("wide=%t frame=%+v error=%v", wide, frame, err)
		}
	}
}

func TestCFISectionRejectsMalformedMetadata(t *testing.T) {
	section, offsets := cfiTestSection(CFIEHFrame, false, 1, 0x8000, 0, [2]uint64{0x1000, 0x20})
	base := section.Data
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"short length", []byte{1, 2, 3}, target.ErrInvalidArgument},
		{"reserved length", []byte{0xf0, 0xff, 0xff, 0xff}, target.ErrInvalidArgument},
		{"short extended", []byte{0xff, 0xff, 0xff, 0xff}, target.ErrInvalidArgument},
		{"huge extended", append([]byte{0xff, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0xff}, 8)...), target.ErrOverflow},
		{"short body", base[:len(base)-1], target.ErrInvalidArgument},
		{"bad version", cfiTestCIE(CFIEHFrame, false, 2, "", nil, nil), target.ErrUnsupported},
		{"unknown augmentation", cfiTestCIE(CFIEHFrame, false, 1, "zRX", []byte{0}, nil), target.ErrUnsupported},
		{"duplicate augmentation", cfiTestCIE(CFIEHFrame, false, 1, "zRR", []byte{0, 0}, nil), target.ErrUnsupported},
		{"legacy augmentation", cfiTestCIE(CFIEHFrame, false, 1, "eh", nil, nil), target.ErrUnsupported},
		{"missing R", cfiTestCIE(CFIEHFrame, false, 1, "zR", nil, nil), target.ErrInvalidArgument},
		{"extra augmentation", cfiTestCIE(CFIEHFrame, false, 1, "zR", []byte{0, 1}, nil), target.ErrInvalidArgument},
		{"omitted FDE encoding", cfiTestCIE(CFIEHFrame, false, 1, "zR", []byte{0xff}, nil), target.ErrUnsupported},
		{"unknown encoding", cfiTestCIE(CFIEHFrame, false, 1, "zR", []byte{7}, nil), target.ErrUnsupported},
		{"garbage after terminator", append(append(bytes.Clone(base), 0, 0, 0, 0), 1), target.ErrInvalidArgument},
	}
	mutate := func(name string, change func([]byte), want error) {
		data := bytes.Clone(base)
		change(data)
		tests = append(tests, struct {
			name string
			data []byte
			want error
		}{name, data, want})
	}
	mutate("backward underflow", func(data []byte) { binary.LittleEndian.PutUint32(data[offsets[0]+4:], math.MaxUint32) }, target.ErrInvalidArgument)
	mutate("CIE interior", func(data []byte) { binary.LittleEndian.PutUint32(data[offsets[0]+4:], uint32(offsets[0]+3)) }, target.ErrInvalidArgument)
	mutate("zero code alignment", func(data []byte) { data[10] = 0 }, target.ErrInvalidArgument)
	mutate("range overflow", func(data []byte) { binary.LittleEndian.PutUint64(data[offsets[0]+8:], math.MaxUint64-5) }, target.ErrOverflow)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			section.Data = test.data
			index, err := ParseCFISection(context.Background(), section, func(context.Context, target.Address, []byte) (int, error) {
				reads++
				return 0, nil
			})
			if index != nil || !errors.Is(err, test.want) || reads != 0 {
				t.Fatalf("index = %v, error = %v, reads = %d", index, err, reads)
			}
		})
	}
}

func TestCFISectionV4AddressAndSegmentSizes(t *testing.T) {
	for _, entry := range []struct {
		address byte
		segment byte
	}{{4, 0}, {8, 1}, {0, 0}} {
		data := cfiTestCIE(CFIDebugFrame, false, 4, "", nil, nil)
		data[10], data[11] = entry.address, entry.segment
		if index, err := ParseCFISection(context.Background(), CFISection{Kind: CFIDebugFrame, Data: data}, nil); index != nil || !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("address %d segment %d: %v, %v", entry.address, entry.segment, index, err)
		}
	}
}

func TestCFIDebugFrameForwardCIEAndLargeReference(t *testing.T) {
	for _, wide := range []bool{false, true} {
		fde := cfiTestFDE(CFIDebugFrame, wide, 0, 0, 0, 0x2000, 8, 0, false, nil, nil)
		prefix := 4
		if wide {
			prefix = 12
			binary.LittleEndian.PutUint64(fde[prefix:], uint64(len(fde)))
		} else {
			binary.LittleEndian.PutUint32(fde[prefix:], uint32(len(fde)))
		}
		data := append(bytes.Clone(fde), cfiTestCIE(CFIDebugFrame, wide, 3, "", nil, nil)...)
		index, err := ParseCFISection(context.Background(), CFISection{Kind: CFIDebugFrame, Data: data, Source: "object"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := index.Lookup(0x2000); err != nil {
			t.Fatal(err)
		}
		if wide {
			binary.LittleEndian.PutUint64(data[prefix:], uint64(1)<<32+uint64(len(fde)))
		} else {
			binary.LittleEndian.PutUint32(data[prefix:], uint32(len(fde)+1))
		}
		if result, err := ParseCFISection(context.Background(), CFISection{Kind: CFIDebugFrame, Data: data}, nil); result != nil || !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("invalid CIE reference = %v, %v", result, err)
		}
	}
}

func TestCFIIndexNestedOverlapAndMergeIdentity(t *testing.T) {
	section, _ := cfiTestSection(CFIEHFrame, false, 1, 0x8000, 0,
		[2]uint64{0x1000, 0x100}, [2]uint64{0x1020, 5}, [2]uint64{0x1040, 5}, [2]uint64{0x1080, 0})
	index, err := ParseCFISection(context.Background(), section, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range []target.Address{0x1020, 0x1044} {
		if _, err := index.Lookup(pc); !errors.Is(err, target.ErrAmbiguous) {
			t.Fatalf("overlap %#x: %v", pc, err)
		}
	}
	for _, pc := range []target.Address{0x1000, 0x1025, 0x1050, 0x1080, 0x10ff} {
		if _, err := index.Lookup(pc); err != nil {
			t.Fatalf("unique %#x: %v", pc, err)
		}
	}
	single, _ := cfiTestSection(CFIEHFrame, false, 1, 0x9000, 0, [2]uint64{0x2000, 8})
	first, err := ParseCFISection(context.Background(), single, nil)
	if err != nil {
		t.Fatal(err)
	}
	single.Source = "second label for same physical metadata"
	second, err := ParseCFISection(context.Background(), single, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeCFIIndexes(first, second, first)
	if err != nil || len(merged.frames) != 1 {
		t.Fatalf("exact merge = %v, %v", merged, err)
	}
	single.Data[len(single.Data)-1] = 0x43
	changed, err := ParseCFISection(context.Background(), single, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err = MergeCFIIndexes(first, changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := merged.Lookup(0x2001); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("changed bytes at same address = %v", err)
	}
	single.Address++
	differentEntry, err := ParseCFISection(context.Background(), single, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err = MergeCFIIndexes(changed, differentEntry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := merged.Lookup(0x2000); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("different physical entries = %v", err)
	}
	debug, _ := cfiTestSection(CFIDebugFrame, false, 3, 0, 0, [2]uint64{0x3000, 8})
	d1, err := ParseCFISection(context.Background(), debug, nil)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ParseCFISection(context.Background(), debug, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err = MergeCFIIndexes(d1, d2)
	if err != nil || len(merged.frames) != 1 {
		t.Fatalf("debug exact merge = %v, %v", merged, err)
	}
	debug.Source = "other debug file"
	d3, err := ParseCFISection(context.Background(), debug, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err = MergeCFIIndexes(d1, d3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := merged.Lookup(0x3000); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("different debug sources = %v", err)
	}
}

func TestCFIPointerEncodings(t *testing.T) {
	tests := []struct {
		name     string
		encoding byte
		data     []byte
		address  target.Address
		bases    cfiPointerBases
		want     uint64
	}{
		{"absolute", 0, binary.LittleEndian.AppendUint64(nil, 0x1020304050607080), 0, cfiPointerBases{}, 0x1020304050607080},
		{"uleb", 1, []byte{0xe5, 0x8e, 0x26}, 0, cfiPointerBases{}, 624485},
		{"u16", 2, []byte{0x34, 0x12}, 0, cfiPointerBases{}, 0x1234},
		{"u32", 3, []byte{0x78, 0x56, 0x34, 0x12}, 0, cfiPointerBases{}, 0x12345678},
		{"u64", 4, binary.LittleEndian.AppendUint64(nil, math.MaxUint64), 0, cfiPointerBases{}, math.MaxUint64},
		{"signed", 8, binary.LittleEndian.AppendUint64(nil, math.MaxUint64-1), 0, cfiPointerBases{}, math.MaxUint64 - 1},
		{"sleb", 9, []byte{0x7e}, 0, cfiPointerBases{}, math.MaxUint64 - 1},
		{"s16", 10, []byte{0xfe, 0xff}, 0, cfiPointerBases{}, math.MaxUint64 - 1},
		{"s32", 11, []byte{0xfe, 0xff, 0xff, 0xff}, 0, cfiPointerBases{}, math.MaxUint64 - 1},
		{"s64", 12, binary.LittleEndian.AppendUint64(nil, math.MaxUint64-1), 0, cfiPointerBases{}, math.MaxUint64 - 1},
		{"pcrel negative", 0x1b, []byte{0xfc, 0xff, 0xff, 0xff}, 0x1000, cfiPointerBases{}, 0xffc},
		{"pcrel positive", 0x13, []byte{4, 0, 0, 0}, 0x1000, cfiPointerBases{}, 0x1004},
		{"raw null pcrel", 0x1b, []byte{0, 0, 0, 0}, 0x1000, cfiPointerBases{}, 0},
		{"raw null missing base", 0x3b, []byte{0, 0, 0, 0}, 0x1000, cfiPointerBases{}, 0},
	}
	base := uint64(0x1000)
	for _, encoding := range []byte{0x22, 0x32, 0x42} {
		tests = append(tests, struct {
			name     string
			encoding byte
			data     []byte
			address  target.Address
			bases    cfiPointerBases
			want     uint64
		}{fmt.Sprintf("base %#x", encoding), encoding, []byte{4, 0}, 0, cfiPointerBases{text: &base, data: &base, function: &base}, 0x1004})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			offset := 0
			value, err := cfiDecodePointer(context.Background(), test.data, &offset, test.address, test.encoding, test.bases, nil)
			if err != nil || value != test.want || offset != len(test.data) {
				t.Fatalf("value %#x, offset %d, error %v", value, offset, err)
			}
		})
	}
	data := append(bytes.Repeat([]byte{0x55}, 5), binary.LittleEndian.AppendUint64(nil, 0x1234)...)
	offset := 0
	value, err := cfiDecodePointer(context.Background(), data, &offset, 0x1003, 0x50, cfiPointerBases{}, nil)
	if err != nil || value != 0x1234 || offset != 13 {
		t.Fatalf("aligned = %#x, %d, %v", value, offset, err)
	}
}

func TestCFIPointerRejectsMalformedAndPreservesReadFailures(t *testing.T) {
	tests := []struct {
		name     string
		encoding byte
		data     []byte
		address  target.Address
		want     error
	}{
		{"unknown format", 5, nil, 0, target.ErrUnsupported},
		{"unknown application", 0x60, nil, 0, target.ErrUnsupported},
		{"nonpointer aligned", 0x53, nil, 0, target.ErrUnsupported},
		{"omitted", 0xff, nil, 0, target.ErrUnsupported},
		{"short scalar", 3, []byte{0}, 0, target.ErrInvalidArgument},
		{"missing data base", 0x33, []byte{1, 0, 0, 0}, 0, target.ErrUnsupported},
		{"missing text base", 0x23, []byte{1, 0, 0, 0}, 0, target.ErrUnsupported},
		{"missing function base", 0x43, []byte{1, 0, 0, 0}, 0, target.ErrUnsupported},
		{"relative underflow", 0x1b, []byte{0xfe, 0xff, 0xff, 0xff}, 1, target.ErrOverflow},
		{"relative overflow", 0x13, []byte{2, 0, 0, 0}, math.MaxUint64 - 1, target.ErrOverflow},
		{"uleb overflow", 1, bytes.Repeat([]byte{0xff}, 10), 0, target.ErrOverflow},
		{"sleb overflow", 9, append(bytes.Repeat([]byte{0xff}, 9), 1), 0, target.ErrOverflow},
		{"uleb truncated", 1, []byte{0x80}, 0, target.ErrInvalidArgument},
		{"sleb truncated", 9, []byte{0x80}, 0, target.ErrInvalidArgument},
		{"aligned truncated", 0x50, make([]byte, 3), 1, target.ErrInvalidArgument},
		{"indirect unavailable", 0x80, binary.LittleEndian.AppendUint64(nil, 0x1000), 0, target.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			offset := 0
			value, err := cfiDecodePointer(context.Background(), test.data, &offset, test.address, test.encoding, cfiPointerBases{}, nil)
			if value != 0 || !errors.Is(err, test.want) {
				t.Fatalf("value = %#x, error = %v", value, err)
			}
		})
	}
	for _, readError := range []error{target.ErrStale, target.ErrUnavailable, context.Canceled} {
		for _, count := range []int{0, 4, 8} {
			offset := 0
			value, err := cfiDecodePointer(context.Background(), binary.LittleEndian.AppendUint64(nil, 0x1000), &offset, 0, 0x80, cfiPointerBases{}, func(ctx context.Context, address target.Address, data []byte) (int, error) {
				if address != 0x1000 || len(data) != 8 {
					t.Fatalf("read = %#x, %d", address, len(data))
				}
				return count, readError
			})
			if value != 0 || !errors.Is(err, readError) || count != 8 && !errors.Is(err, target.ErrPartial) {
				t.Fatalf("read failure = %#x, %v", value, err)
			}
		}
	}
	offset := 0
	value, err := cfiDecodePointer(context.Background(), binary.LittleEndian.AppendUint64(nil, 0x1000), &offset, 0, 0x80, cfiPointerBases{}, func(ctx context.Context, address target.Address, data []byte) (int, error) {
		binary.LittleEndian.PutUint64(data, 0x12345678)
		return len(data), nil
	})
	if err != nil || value != 0x12345678 {
		t.Fatalf("indirect = %#x, %v", value, err)
	}
}

type cfiTestRegion struct {
	address target.Address
	data    []byte
}

func cfiTestRead(regions []cfiTestRegion, calls *int) CFIReader {
	return func(ctx context.Context, address target.Address, data []byte) (int, error) {
		if calls != nil {
			*calls++
		}
		for _, region := range regions {
			if address < region.address || uint64(address-region.address) > uint64(len(region.data)) {
				continue
			}
			offset := uint64(address - region.address)
			if uint64(len(data)) <= uint64(len(region.data))-offset {
				copy(data, region.data[offset:])
				return len(data), nil
			}
		}
		return 0, target.ErrUnavailable
	}
}

func cfiTestHeader(section CFISection, offsets []uint64, starts []uint64, address target.Address) []byte {
	header := []byte{1, 0x1b, 3, 0x3b}
	header = binary.LittleEndian.AppendUint32(header, uint32(int64(section.Address)-int64(address+4)))
	header = binary.LittleEndian.AppendUint32(header, uint32(len(offsets)))
	for i, offset := range offsets {
		header = binary.LittleEndian.AppendUint32(header, uint32(int64(starts[i])-int64(address)))
		header = binary.LittleEndian.AppendUint32(header, uint32(int64(section.Address+target.Address(offset))-int64(address)))
	}
	return header
}

func TestCFIHeaderBoundedRecordsCIECacheAndSectionMerge(t *testing.T) {
	section, offsets := cfiTestSection(CFIEHFrame, false, 1, 0x9000, 0, [2]uint64{0x1000, 0x20}, [2]uint64{0x2000, 0x30})
	header := cfiTestHeader(section, offsets, []uint64{0x1000, 0x2000}, 0x8000)
	calls := 0
	reader := cfiTestRead([]cfiTestRegion{{0x8000, header}, {section.Address, section.Data}}, &calls)
	index, err := ReadCFIHeader(context.Background(), 0x8000, uint64(len(header)), "runtime header", reader)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 7 {
		t.Fatalf("record reads = %d, want 7", calls)
	}
	for _, pc := range []target.Address{0x1000, 0x202f} {
		if _, err := index.Lookup(pc); err != nil {
			t.Fatal(err)
		}
	}
	fromSection, err := ParseCFISection(context.Background(), section, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeCFIIndexes(index, fromSection)
	if err != nil || len(merged.frames) != 2 {
		t.Fatalf("header/section merge = %v, %v", merged, err)
	}
	clear(header)
	clear(section.Data)
	if frame, err := merged.Lookup(0x1000); err != nil || frame.program.data[0] != 0x42 {
		t.Fatalf("owned header data = %v, %v", frame, err)
	}
}

func TestCFIHeaderRejectsMalformedMetadata(t *testing.T) {
	section, offsets := cfiTestSection(CFIEHFrame, false, 1, 0x9000, 0, [2]uint64{0x1000, 0x20}, [2]uint64{0x2000, 0x30})
	base := cfiTestHeader(section, offsets, []uint64{0x1000, 0x2000}, 0x8000)
	tests := []struct {
		name   string
		change func([]byte)
		want   error
	}{
		{"version", func(data []byte) { data[0] = 2 }, target.ErrUnsupported},
		{"omitted table", func(data []byte) { data[3] = 0xff }, target.ErrUnavailable},
		{"null frame pointer", func(data []byte) { clear(data[4:8]) }, target.ErrInvalidArgument},
		{"relative count", func(data []byte) { data[2] |= 0x10 }, target.ErrInvalidArgument},
		{"indirect count", func(data []byte) { data[2] |= 0x80 }, target.ErrInvalidArgument},
		{"negative count", func(data []byte) { data[2] = 11; binary.LittleEndian.PutUint32(data[8:], math.MaxUint32) }, target.ErrInvalidArgument},
		{"excess count", func(data []byte) { binary.LittleEndian.PutUint32(data[8:], cfiEntryLimit+1) }, target.ErrOverflow},
		{"null FDE", func(data []byte) { clear(data[16:20]) }, target.ErrInvalidArgument},
		{"CIE instead of FDE", func(data []byte) { binary.LittleEndian.PutUint32(data[16:], 0x1000) }, target.ErrInvalidArgument},
		{"unmapped FDE", func(data []byte) { binary.LittleEndian.PutUint32(data[16:], 0x2000) }, target.ErrUnavailable},
		{"FDE before section", func(data []byte) { binary.LittleEndian.PutUint32(data[16:], 0x0fff) }, target.ErrInvalidArgument},
		{"start mismatch", func(data []byte) { data[12]++ }, target.ErrInvalidArgument},
		{"unsorted", func(data []byte) { copy(data[12:20], base[20:28]); copy(data[20:28], base[12:20]) }, target.ErrInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := bytes.Clone(base)
			test.change(header)
			reader := cfiTestRead([]cfiTestRegion{{0x8000, header}, {section.Address, section.Data}}, nil)
			index, err := ReadCFIHeader(context.Background(), 0x8000, uint64(len(header)), "test", reader)
			if index != nil || !errors.Is(err, test.want) {
				t.Fatalf("index = %v, error = %v", index, err)
			}
		})
	}
	for size := 4; size < len(base); size++ {
		reader := cfiTestRead([]cfiTestRegion{{0x8000, base}, {section.Address, section.Data}}, nil)
		if index, err := ReadCFIHeader(context.Background(), 0x8000, uint64(size), "test", reader); index != nil || !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("short header %d = %v, %v", size, index, err)
		}
	}
}

func TestCFIInputLimitsAndCancellation(t *testing.T) {
	section, _ := cfiTestSection(CFIEHFrame, false, 1, 0x8000, 0, [2]uint64{0x1000, 8})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if index, err := ParseCFISection(ctx, section, nil); index != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v, %v", index, err)
	}
	if index, err := ParseCFISection(nil, section, nil); index != nil || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context = %v, %v", index, err)
	}
	for _, bad := range []CFISection{
		{Kind: 3}, {Kind: CFIEHFrame, Data: section.Data, LoadBias: 1},
		{Kind: CFIEHFrame, Address: math.MaxUint64, Data: section.Data},
		{Kind: CFIEHFrame, Data: make([]byte, cfiSectionLimit+1)},
	} {
		if index, err := ParseCFISection(context.Background(), bad, nil); index != nil || err == nil {
			t.Fatalf("invalid section = %v, %v", index, err)
		}
	}
	if index, err := ReadCFIHeader(ctx, 1, 4, "", func(context.Context, target.Address, []byte) (int, error) {
		t.Fatal("read after cancellation")
		return 0, nil
	}); index != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled header = %v, %v", index, err)
	}
	if index, err := ReadCFIHeader(context.Background(), 1, cfiSectionLimit+1, "", func(context.Context, target.Address, []byte) (int, error) {
		t.Fatal("read beyond budget")
		return 0, nil
	}); index != nil || !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("header budget = %v, %v", index, err)
	}
	if index, err := MergeCFIIndexes(nil); index != nil || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil merge = %v, %v", index, err)
	}
	var index *CFIIndex
	if frame, err := index.Lookup(1); frame != nil || !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("nil lookup = %v, %v", frame, err)
	}
	var frame *CFIFrame
	if start, end := frame.Range(); start != 0 || end != 0 || frame.Source() != "" || frame.Entry() != 0 {
		t.Fatal("nil frame accessors")
	}
}

func TestCFILEBBoundaries(t *testing.T) {
	for _, value := range []uint64{0, 1, 127, 128, 1 << 32, math.MaxUint64} {
		data := binary.AppendUvarint(nil, value)
		offset := 0
		got, err := cfiULEB(data, &offset)
		if err != nil || got != value || offset != len(data) {
			t.Fatalf("ULEB %#x = %#x, %d, %v", value, got, offset, err)
		}
	}
	for _, value := range []int64{0, -1, 63, 64, -64, -65, math.MinInt64, math.MaxInt64} {
		var data []byte
		left := value
		for {
			b := byte(left & 0x7f)
			left >>= 7
			if left == 0 && b&0x40 == 0 || left == -1 && b&0x40 != 0 {
				data = append(data, b)
				break
			}
			data = append(data, b|0x80)
		}
		offset := 0
		got, err := cfiSLEB(data, &offset)
		if err != nil || got != value || offset != len(data) {
			t.Fatalf("SLEB %d = %d, %d, %v", value, got, offset, err)
		}
	}
}

func TestCFIReaderCancellationCannotBeLost(t *testing.T) {
	for _, count := range []int{-1, 0, 4, 8, 9} {
		for _, failure := range []error{nil, target.ErrStale, target.ErrUnavailable} {
			t.Run(fmt.Sprintf("%d/%v", count, failure), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				offset := 0
				value, err := cfiDecodePointer(ctx, binary.LittleEndian.AppendUint64(nil, 0x1000), &offset, 0, 0x80, cfiPointerBases{}, func(context.Context, target.Address, []byte) (int, error) {
					cancel()
					return count, failure
				})
				if value != 0 || !errors.Is(err, context.Canceled) || failure != nil && !errors.Is(err, failure) {
					t.Fatalf("canceled read = %#x, %v", value, err)
				}
			})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	index, err := ReadCFIHeader(ctx, 0x1000, 8, "", func(context.Context, target.Address, []byte) (int, error) {
		cancel()
		return 0, nil
	})
	if index != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, target.ErrPartial) {
		t.Fatalf("canceled header = %v, %v", index, err)
	}
}

func TestCFIHeaderRejectsOverlappingPhysicalRecords(t *testing.T) {
	base := target.Address(0x9000)
	first := cfiTestCIE(CFIEHFrame, false, 1, "", nil, nil)
	secondOffset := uint64(len(first))
	second := cfiTestCIE(CFIEHFrame, false, 1, "", nil, nil)
	first = append(first, second...)
	binary.LittleEndian.PutUint32(first, uint32(len(first)-4))
	offset1 := uint64(len(first))
	fde1 := cfiTestFDE(CFIEHFrame, false, base, offset1, 0, 0x1000, 8, 0, false, nil, nil)
	offset2 := offset1 + uint64(len(fde1))
	fde2 := cfiTestFDE(CFIEHFrame, false, base, offset2, secondOffset, 0x2000, 8, 0, false, nil, nil)
	section := CFISection{Kind: CFIEHFrame, Address: base, Data: append(append(first, fde1...), fde2...)}
	header := cfiTestHeader(section, []uint64{offset1, offset2}, []uint64{0x1000, 0x2000}, 0x8000)
	reader := cfiTestRead([]cfiTestRegion{{0x8000, header}, {base, section.Data}}, nil)
	if index, err := ReadCFIHeader(context.Background(), 0x8000, uint64(len(header)), "", reader); index != nil || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("overlapping CIE = %v, %v", index, err)
	}
}

func TestCFIHeaderDuplicateEntryAndExtendedLengths(t *testing.T) {
	section, offsets := cfiTestSection(CFIEHFrame, true, 3, 0x9000, 0, [2]uint64{0x1000, 8})
	header := cfiTestHeader(section, []uint64{offsets[0], offsets[0]}, []uint64{0x1000, 0x1000}, 0x8000)
	calls := 0
	reader := cfiTestRead([]cfiTestRegion{{0x8000, header}, {section.Address, section.Data}}, &calls)
	index, err := ReadCFIHeader(context.Background(), 0x8000, uint64(len(header)), "", reader)
	if err != nil || len(index.frames) != 1 || calls != 7 {
		t.Fatalf("duplicate extended entry = %v, calls %d, %v", index, calls, err)
	}
}

func TestCFIDebugFrameWithoutSourceIdentityIsNotDeduplicated(t *testing.T) {
	section, _ := cfiTestSection(CFIDebugFrame, false, 3, 0, 0, [2]uint64{0x1000, 8})
	section.Source = ""
	first, err := ParseCFISection(context.Background(), section, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseCFISection(context.Background(), section, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeCFIIndexes(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := merged.Lookup(0x1000); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("unknown physical identity = %v", err)
	}
}

func TestCFIExtendedRecordAddressCannotWrap(t *testing.T) {
	for _, address := range []target.Address{math.MaxUint64, math.MaxUint64 - 2, math.MaxUint64 - 4, math.MaxUint64 - 11} {
		calls := 0
		parser := cfiParser{
			ctx: context.Background(), kind: CFIEHFrame,
			records: make(map[uint64]cfiRecord), cies: make(map[uint64]cfiCIE),
			read: func(ctx context.Context, location target.Address, data []byte) (int, error) {
				calls++
				if location != address || len(data) != 4 {
					t.Fatalf("unexpected wrapped or extended read %#x+%d", location, len(data))
				}
				binary.LittleEndian.PutUint32(data, math.MaxUint32)
				return len(data), nil
			},
		}
		if _, err := parser.readRecord(address); !errors.Is(err, target.ErrOverflow) {
			t.Fatalf("address %#x: %v", address, err)
		}
		if address > math.MaxUint64-4 && calls != 0 || address <= math.MaxUint64-4 && calls != 1 {
			t.Fatalf("address %#x: %d callback calls", address, calls)
		}
	}
}
