package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"fastdbg2/target"
)

type searchTestReader func(target.Address, []byte) (int, error)

func (read searchTestReader) ReadMemory(address target.Address, data []byte) (int, error) {
	return read(address, data)
}

func TestSearchArgumentsPreserveLiteralPatternsAndBounds(t *testing.T) {
	tests := []struct {
		kind string
		args string
		want searchArguments
	}{
		{"search-string", `"hello world" 0x1000 "0x1000 + 32"`, searchArguments{value: "hello world", bounds: []string{"0x1000", "0x1000 + 32"}, maxBytes: searchDefaultBytes, maxMatches: searchDefaultMatches}},
		{"search-string", `-- --literal`, searchArguments{value: "--literal", bounds: []string{}, maxBytes: searchDefaultBytes, maxMatches: searchDefaultMatches}},
		{"search-value", `--size 4 --endian big --max-bytes 64 --max-matches 2 0x4142`, searchArguments{value: "0x4142", bounds: []string{}, width: 4, bigEndian: true, maxBytes: 64, maxMatches: 2}},
		{"findruction", `'mov rax, 0x1234; ret' $rip`, searchArguments{value: "mov rax, 0x1234; ret", bounds: []string{"$rip"}, maxBytes: searchDefaultBytes, maxMatches: searchDefaultMatches}},
		{"search-string", `'$(printf nope)'`, searchArguments{value: "$(printf nope)", bounds: []string{}, maxBytes: searchDefaultBytes, maxMatches: searchDefaultMatches}},
	}
	for _, test := range tests {
		t.Run(test.args, func(t *testing.T) {
			got, err := parseSearchArguments(test.kind, test.args)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got=%#v want=%#v err=%v", got, test.want, err)
			}
		})
	}
}

func TestSearchArgumentsRejectAmbiguousOrUnboundedInput(t *testing.T) {
	for _, args := range []string{"", `""`, "one two three four", "--size 0 1", "--size 9 1", "--size 8 --size 8 1", "--endian native 1", "--max-bytes 0 1", "--max-bytes 1073741825 1", "--max-matches 65537 1", "--max-matches -1 1", "--unknown 1 1", "--size", `'unterminated`, strings.Repeat("a", 4*searchMaxPattern+1025)} {
		if _, err := parseSearchArguments("search-value", args); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("input length=%d err=%v", len(args), err)
		}
	}
	for _, kind := range []string{"search-string", "findruction", "other"} {
		if _, err := parseSearchArguments(kind, "--size 2 1"); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("kind=%s err=%v", kind, err)
		}
	}
}

func TestSearchValueEncodingMatchesLegacyMinimalWidth(t *testing.T) {
	tests := []struct {
		value uint64
		width int
		big   bool
		want  []byte
	}{
		{0, 0, false, []byte{0}},
		{0x4142, 0, false, []byte{0x42, 0x41}},
		{0x4142, 4, false, []byte{0x42, 0x41, 0, 0}},
		{0x4142, 4, true, []byte{0, 0, 0x41, 0x42}},
		{0x4142, 0, true, []byte{0x41, 0x42}},
		{math.MaxUint64, 8, false, bytes.Repeat([]byte{0xff}, 8)},
		{1 << 56, 0, false, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	}
	for _, test := range tests {
		got, err := searchValueBytes(test.value, test.width, test.big)
		if err != nil || !bytes.Equal(got, test.want) {
			t.Fatalf("%#v: got=%x err=%v", test, got, err)
		}
	}
	if _, err := searchValueBytes(256, 1, false); !errors.Is(err, target.ErrOverflow) {
		t.Fatal(err)
	}
	for _, size := range []int{-1, 9} {
		if _, err := searchValueBytes(0, size, false); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
}

func TestSearchMapBoundsUseExactEligibleIntersections(t *testing.T) {
	maps := []procMap{{Start: 0, End: 10, Read: true}, {Start: 10, End: 20, Execute: true}, {Start: 24, End: 30, Read: true, Execute: true}}
	for _, test := range []struct {
		bounds []target.Address
		code   bool
		want   []searchSpan
	}{
		{nil, false, []searchSpan{{0, 10}, {24, 30}}},
		{[]target.Address{0, 26}, false, []searchSpan{{0, 10}, {24, 26}}},
		{[]target.Address{4}, false, []searchSpan{{4, 10}}},
		{[]target.Address{9, 26}, true, []searchSpan{{10, 20}, {24, 26}}},
		{[]target.Address{10}, true, []searchSpan{{10, 20}}},
	} {
		got, scope, err := searchMapSpans(maps, test.bounds, test.code)
		if err != nil || !reflect.DeepEqual(got, test.want) || !strings.Contains(scope, "mappings") {
			t.Fatalf("%#v: got=%v scope=%q err=%v", test, got, scope, err)
		}
	}
	for _, bounds := range [][]target.Address{{10}, {21}, {30}, {0, 0}, {20, 10}, {11, 19}, {0, 1, 2}} {
		if _, _, err := searchMapSpans(maps, bounds, false); err == nil {
			t.Fatalf("accepted %v", bounds)
		}
	}
	for _, invalid := range [][]procMap{{{Start: 3, End: 3, Read: true}}, {{Start: 3, End: 4, Read: true}, {Start: 2, End: 3, Read: true}}, {{Start: 3, End: 6, Read: true}, {Start: 5, End: 7, Read: true}}} {
		if _, _, err := searchMapSpans(invalid, nil, false); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
}

func searchSliceReader(base target.Address, data []byte) searchTestReader {
	return func(address target.Address, dst []byte) (int, error) {
		if address < base || uint64(address-base) > uint64(len(data)) {
			return 0, syscall.EFAULT
		}
		n := copy(dst, data[int(address-base):])
		if n < len(dst) {
			return n, io.EOF
		}
		return n, nil
	}
}

func TestSearchScanFindsOverlapsChunkAndMappingBoundaries(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, 2*searchChunkBytes+20)
	copy(data[searchChunkBytes-2:], []byte("ababa"))
	copy(data[2*searchChunkBytes-2:], []byte("ababa"))
	base := target.Address(0x8000)
	spans := []searchSpan{{base, base + searchChunkBytes + 1}, {base + searchChunkBytes + 1, base + target.Address(len(data))}}
	got, err := scanSearch(context.Background(), searchSliceReader(base, data), spans, []byte("aba"), searchDefaultBytes, searchDefaultMatches)
	want := []target.Address{base + searchChunkBytes - 2, base + searchChunkBytes, base + 2*searchChunkBytes - 2, base + 2*searchChunkBytes}
	if err != nil || !reflect.DeepEqual(got.addresses, want) || got.bytesRead != uint64(len(data)) {
		t.Fatalf("got=%#v want=%v err=%v", got, want, err)
	}
}

func TestSearchScanKeepsMaximumPatternStateAcrossSmallMappings(t *testing.T) {
	pattern := append(bytes.Repeat([]byte{'a'}, searchMaxPattern-1), 'b')
	data := append([]byte{'x', 'x'}, pattern...)
	data = append(data, bytes.Repeat([]byte{'x'}, 7)...)
	second := target.Address(len(data))
	data = append(data, pattern...)
	var spans []searchSpan
	for offset := 0; offset < len(data); offset += 1023 {
		spans = append(spans, searchSpan{target.Address(offset), target.Address(min(offset+1023, len(data)))})
	}
	result, err := scanSearch(context.Background(), searchSliceReader(0, data), spans, pattern, searchDefaultBytes, 10)
	if err != nil || !reflect.DeepEqual(result.addresses, []target.Address{2, second}) || result.bytesRead != uint64(len(data)) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestSearchScanReusesOneBoundedReadBuffer(t *testing.T) {
	var buffer *byte
	var calls int
	reader := searchTestReader(func(_ target.Address, data []byte) (int, error) {
		calls++
		if len(data) == 0 || len(data) > searchChunkBytes {
			t.Fatalf("read length=%d", len(data))
		}
		if buffer == nil {
			buffer = &data[0]
		} else if buffer != &data[0] {
			t.Fatal("read buffer was replaced")
		}
		clear(data)
		return len(data), nil
	})
	result, err := scanSearch(context.Background(), reader, []searchSpan{{0, 3*searchChunkBytes + 7}}, []byte{1}, searchDefaultBytes, 10)
	if err != nil || calls != 4 || result.bytesRead != 3*searchChunkBytes+7 || len(result.addresses) != 0 {
		t.Fatalf("calls=%d result=%#v err=%v", calls, result, err)
	}
}

func TestSearchScanDoesNotJoinGapsOrFailedMappings(t *testing.T) {
	for _, failMiddle := range []bool{false, true} {
		var readCalls []target.Address
		reader := searchTestReader(func(address target.Address, data []byte) (int, error) {
			readCalls = append(readCalls, address)
			switch address {
			case 10:
				return copy(data, "ab"), nil
			case 12:
				return 0, syscall.EIO
			case 14:
				return copy(data, "aba"), nil
			}
			return 0, syscall.EFAULT
		})
		spans := []searchSpan{{10, 12}, {14, 17}}
		if failMiddle {
			spans = []searchSpan{{10, 12}, {12, 14}, {14, 17}}
		}
		got, err := scanSearch(context.Background(), reader, spans, []byte("aba"), 100, 10)
		if !reflect.DeepEqual(got.addresses, []target.Address{14}) || got.bytesRead != 5 || (err != nil) != failMiddle {
			t.Fatalf("failed=%t got=%#v err=%v calls=%v", failMiddle, got, err, readCalls)
		}
		if failMiddle && (!errors.Is(err, syscall.EIO) || !errors.Is(err, target.ErrPartial)) {
			t.Fatal(err)
		}
	}
}

func TestSearchScanPublishesOnlyConfirmedPartialBytes(t *testing.T) {
	for _, readErr := range []error{nil, io.ErrUnexpectedEOF, syscall.EIO} {
		reader := searchTestReader(func(_ target.Address, data []byte) (int, error) {
			copy(data, []byte{0, 'a', 0, 'a'})
			return 3, readErr
		})
		result, err := scanSearch(context.Background(), reader, []searchSpan{{0, 4}}, []byte{0}, 100, 10)
		if !reflect.DeepEqual(result.addresses, []target.Address{0, 2}) || result.bytesRead != 3 || !errors.Is(err, target.ErrPartial) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
}

func TestSearchScanStaleAndCancellationDiscardAllBufferedMatches(t *testing.T) {
	for _, failure := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		reader := searchTestReader(func(address target.Address, data []byte) (int, error) {
			copy(data, "aaaa")
			if address == 10 {
				return len(data), failure
			}
			return len(data), nil
		})
		result, err := scanSearch(context.Background(), reader, []searchSpan{{0, 4}, {10, 14}}, []byte{'a'}, 100, 10)
		if len(result.addresses) != 0 || result.bytesRead != 0 || !errors.Is(err, failure) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader := searchTestReader(func(_ target.Address, data []byte) (int, error) { cancel(); return len(data), nil })
	result, err := scanSearch(ctx, reader, []searchSpan{{0, 4}}, []byte{0}, 100, 10)
	if len(result.addresses) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestSearchScanLimitsAreExplicitAndBoundReads(t *testing.T) {
	var readBytes int
	reader := searchTestReader(func(_ target.Address, data []byte) (int, error) {
		readBytes += len(data)
		clear(data)
		return len(data), nil
	})
	result, err := scanSearch(context.Background(), reader, []searchSpan{{0, 20}}, []byte{0}, 5, 10)
	if readBytes != 5 || result.bytesRead != 5 || len(result.addresses) != 5 || !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("bytes=%d result=%#v err=%v", readBytes, result, err)
	}
	readBytes = 0
	result, err = scanSearch(context.Background(), reader, []searchSpan{{0, 1000000}}, []byte{0}, searchDefaultBytes, 3)
	if readBytes != searchChunkBytes || !reflect.DeepEqual(result.addresses, []target.Address{0, 1, 2}) || !errors.Is(err, target.ErrPartial) {
		t.Fatalf("bytes=%d result=%#v err=%v", readBytes, result, err)
	}
	result, err = scanSearch(context.Background(), reader, []searchSpan{{0, 3}}, []byte{0}, 3, 3)
	if len(result.addresses) != 3 || err != nil {
		t.Fatalf("exact limit result=%#v err=%v", result, err)
	}
	result, err = scanSearch(context.Background(), reader, []searchSpan{{0, 3}, {8, 9}}, []byte{0}, 3, 3)
	if len(result.addresses) != 3 || !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("additional span result=%#v err=%v", result, err)
	}
}

func TestSearchScanRejectsInvalidReaderCountsAndRanges(t *testing.T) {
	for _, count := range []int{-1, 3} {
		reader := searchTestReader(func(target.Address, []byte) (int, error) { return count, nil })
		if _, err := scanSearch(context.Background(), reader, []searchSpan{{1, 3}}, []byte{0}, 10, 10); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	reader := searchTestReader(func(_ target.Address, data []byte) (int, error) { return len(data), nil })
	for _, spans := range [][]searchSpan{{{1, 1}}, {{3, 5}, {4, 6}}, {{3, 5}, {1, 2}}} {
		if _, err := scanSearch(context.Background(), reader, spans, []byte{0}, 10, 10); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, pattern := range [][]byte{nil, make([]byte, searchMaxPattern+1)} {
		if _, err := scanSearch(context.Background(), reader, []searchSpan{{0, 1}}, pattern, 10, 10); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	if _, err := scanSearch(nil, reader, nil, []byte{0}, 10, 10); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

type searchCommandSession struct {
	*controllerTestSession
	reader     searchTestReader
	codeReader searchTestReader
	rawTokens  []target.MemoryToken
	codeTokens []target.MemoryToken
}

func (s *searchCommandSession) ReadSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	s.rawTokens = append(s.rawTokens, token)
	return s.reader(address, data)
}

func (s *searchCommandSession) ReadCodeMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	s.codeTokens = append(s.codeTokens, token)
	return s.codeReader(address, data)
}

func searchCommandFixture(t *testing.T) (*Controller, *searchCommandSession, *bytes.Buffer, procMap) {
	t.Helper()
	output := new(bytes.Buffer)
	c, base := runningController(t, output)
	owner, err := c.launch(c.path, nil)
	if owner != nil {
		t.Cleanup(func() {
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	base.pid, base.snapshot.Threads[0].TID = owner.PID(), owner.PID()
	session := &searchCommandSession{controllerTestSession: base}
	c.session = session
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", owner.PID()))
	if err != nil {
		t.Fatal(err)
	}
	maps, err := parseProcMaps(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range maps {
		if mapping.Read && mapping.Execute && mapping.End-mapping.Start >= 64 {
			return c, session, output, mapping
		}
	}
	t.Fatal("no executable mapping")
	return nil, nil, nil, procMap{}
}

func TestSearchCommandsReadExactTokenAndLiteralString(t *testing.T) {
	c, session, output, mapping := searchCommandFixture(t)
	data := []byte("xxhello worldxxhello world!!")
	session.reader = searchSliceReader(mapping.Start, data)
	args := fmt.Sprintf(`"hello world" %#x %#x`, mapping.Start, mapping.Start+target.Address(len(data)))
	if err := c.commandSearch(context.Background(), "search-string", args); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Source     : live-raw", "2 confirmed byte match(es)", fmt.Sprintf("0x%016x", mapping.Start+2), fmt.Sprintf("0x%016x", mapping.Start+15), "Status     : complete"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %s", want, output.String())
		}
	}
	if len(session.rawTokens) != 1 || session.rawTokens[0] != session.snapshot.Memory || len(session.codeTokens) != 0 {
		t.Fatalf("raw=%v code=%v", session.rawTokens, session.codeTokens)
	}
}

func TestSearchCommandsValueWidthAndOverflow(t *testing.T) {
	c, session, output, mapping := searchCommandFixture(t)
	data := []byte{0x42, 0x41, 0, 0, 0, 0, 0x41, 0x42}
	session.reader = searchSliceReader(mapping.Start, data)
	for _, flags := range []string{"", "--size 4", "--size 4 --endian big"} {
		output.Reset()
		args := fmt.Sprintf("%s 0x4142 %#x %#x", flags, mapping.Start, mapping.Start+8)
		if err := c.commandSearch(context.Background(), "search-value", args); err != nil || !strings.Contains(output.String(), "1 confirmed byte match(es)") {
			t.Fatalf("flags=%s output=%s err=%v", flags, output.String(), err)
		}
	}
	output.Reset()
	before := len(session.rawTokens)
	if err := c.commandSearch(context.Background(), "search-value", "--size 1 256"); !errors.Is(err, target.ErrOverflow) || len(session.rawTokens) != before || output.Len() != 0 {
		t.Fatalf("output=%s reads=%v err=%v", output.String(), session.rawTokens, err)
	}
}

func TestSearchCommandStalePartialAndOutputErrors(t *testing.T) {
	for _, failure := range []error{target.ErrStale, syscall.EIO} {
		c, session, output, mapping := searchCommandFixture(t)
		session.reader = func(_ target.Address, data []byte) (int, error) { copy(data, "aaa"); return 3, failure }
		args := fmt.Sprintf("a %#x %#x", mapping.Start, mapping.Start+4)
		err := c.commandSearch(context.Background(), "search-string", args)
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if failure == target.ErrStale && output.Len() != 0 || failure == syscall.EIO && !strings.Contains(output.String(), "3 confirmed byte match(es)") {
			t.Fatalf("failure=%v output=%s", failure, output.String())
		}
	}
	c, session, output, mapping := searchCommandFixture(t)
	session.reader = func(_ target.Address, data []byte) (int, error) {
		copy(data, "aaaa")
		session.snapshot.Memory.Revision++
		return len(data), nil
	}
	args := fmt.Sprintf("a %#x %#x", mapping.Start, mapping.Start+4)
	if err := c.commandSearch(context.Background(), "search-string", args); !errors.Is(err, target.ErrStale) || output.Len() != 0 {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
	c, session, _, mapping = searchCommandFixture(t)
	session.reader = searchSliceReader(mapping.Start, []byte("aaaa"))
	c.out = searchFailureWriter{}
	args = fmt.Sprintf("a %#x %#x", mapping.Start, mapping.Start+4)
	err := c.commandSearch(context.Background(), "search-string", args)
	var outputError *OutputError
	if !errors.As(err, &outputError) || !errors.Is(err, syscall.EPIPE) {
		t.Fatal(err)
	}
}

type searchFailureWriter struct{}

func (searchFailureWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

func TestFindructionUsesLogicalCodeAndRejectsRelocations(t *testing.T) {
	c, session, output, mapping := searchCommandFixture(t)
	session.reader = func(target.Address, []byte) (int, error) { t.Fatal("raw memory read"); return 0, nil }
	session.codeReader = searchSliceReader(mapping.Start, []byte{0xcc, 0x90, 0x90, 0xc3})
	args := fmt.Sprintf(`"nop; nop" %#x %#x`, mapping.Start, mapping.Start+4)
	if err := c.commandSearch(context.Background(), "findruction", args); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Source     : live-logical") || !strings.Contains(output.String(), "1 confirmed byte match(es)") || !strings.Contains(output.String(), fmt.Sprintf("0x%016x", mapping.Start+1)) {
		t.Fatal(output.String())
	}
	if len(session.codeTokens) != 1 || session.codeTokens[0] != session.snapshot.Memory || len(session.rawTokens) != 0 {
		t.Fatalf("raw=%v code=%v", session.rawTokens, session.codeTokens)
	}
	output.Reset()
	if err := c.commandSearch(context.Background(), "findruction", `"call missing_search_symbol"`); err == nil || output.Len() != 0 || len(session.codeTokens) != 1 {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}

func searchELFFixture(t *testing.T, mutate func([]byte)) string {
	t.Helper()
	data := make([]byte, 0x110)
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint16(data[58:], 64)
	binary.LittleEndian.PutUint32(data[64:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(data[68:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(data[72:], 0x100)
	binary.LittleEndian.PutUint64(data[80:], 0x4000)
	binary.LittleEndian.PutUint64(data[96:], 16)
	binary.LittleEndian.PutUint64(data[104:], 32)
	copy(data[0x100:], []byte{0xcc, 0x90, 0x90, 0xc3})
	if mutate != nil {
		mutate(data)
	}
	path := filepath.Join(t.TempDir(), "search-image")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindructionOfflineELFReportsOnlyUnrelocatedFileFacts(t *testing.T) {
	output := new(bytes.Buffer)
	c := &Controller{out: output, path: searchELFFixture(t, nil)}
	if err := c.commandSearch(context.Background(), "findruction", `"nop; nop"`); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Source     : file-unrelocated", "1 confirmed byte match(es)", "elf-vaddr=0x0000000000004001 file-offset=0x101"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %s", want, output.String())
		}
	}
	output.Reset()
	if err := c.commandSearch(context.Background(), "findruction", `"nop" 0x4000 0x4010`); !errors.Is(err, target.ErrInvalidState) || output.Len() != 0 {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}

func TestSearchOfflineELFRejectsMalformedSegmentsAndNonExecutableData(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(data []byte) { binary.LittleEndian.PutUint64(data[72:], 0x111) },
		func(data []byte) { binary.LittleEndian.PutUint64(data[96:], 17) },
		func(data []byte) { binary.LittleEndian.PutUint64(data[104:], 1) },
		func(data []byte) { binary.LittleEndian.PutUint64(data[80:], math.MaxUint64) },
		func(data []byte) { binary.LittleEndian.PutUint32(data[68:], uint32(elf.PF_R)) },
		func(data []byte) { binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_AARCH64)) },
	} {
		output := new(bytes.Buffer)
		c := &Controller{out: output, path: searchELFFixture(t, mutate)}
		if err := c.searchConfiguredELF(context.Background(), []byte{0}, searchArguments{maxBytes: 1024, maxMatches: 10}); err == nil || output.Len() != 0 {
			t.Fatalf("output=%s err=%v", output.String(), err)
		}
	}
}

func TestSearchOfflineELFQuotaIsExplicit(t *testing.T) {
	for _, limits := range []searchArguments{{maxBytes: 2, maxMatches: 10}, {maxBytes: 1024, maxMatches: 1}} {
		output := new(bytes.Buffer)
		c := &Controller{out: output, path: searchELFFixture(t, nil)}
		err := c.searchConfiguredELF(context.Background(), []byte{0x90}, limits)
		if !errors.Is(err, target.ErrPartial) || !errors.Is(err, target.ErrOverflow) || !strings.Contains(output.String(), "Status     : partial") || !strings.Contains(output.String(), "1 confirmed byte match(es)") {
			t.Fatalf("limits=%#v output=%s err=%v", limits, output.String(), err)
		}
	}
}

func TestSearchLiveNativeETEXECAndPIE(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie=%t", pie), func(t *testing.T) {
			fixture := newExpansionIntegration(t, pie)
			for _, command := range []string{
				`search-string "native commands" expansion_text "expansion_text + 16"`,
				`search-value 0x8877665544332211 expansion_words "expansion_words + 8"`,
				`search-value --size 1 0xcc expansion_point "expansion_point + 3"`,
				`findruction "nop; nop; ret" expansion_point "expansion_point + 3"`,
			} {
				output := fixture.command(t, command)
				if !strings.Contains(output, "1 confirmed byte match(es)") || !strings.Contains(output, "Status     : complete") {
					t.Fatalf("%s: %s", command, output)
				}
			}
			fixture.command(t, "continue")
			output := fixture.command(t, `findruction "nop; nop; ret" expansion_point "expansion_point + 3"`)
			if !strings.Contains(output, "Source     : live-logical") || !strings.Contains(output, "1 confirmed byte match(es)") || !strings.Contains(output, "Status     : complete") {
				t.Fatal(output)
			}
		})
	}
}
