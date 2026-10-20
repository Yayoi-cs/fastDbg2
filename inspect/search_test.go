package inspect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"fastdbg2/target"
)

type searchReaderFunc func(target.Address, []byte) (int, error)

func (f searchReaderFunc) ReadMemory(address target.Address, dst []byte) (int, error) {
	return f(address, dst)
}

func testSearchReader(t *testing.T, base target.Address, data []byte) MemoryReader {
	t.Helper()
	var reading atomic.Bool
	var next uint64
	return searchReaderFunc(func(address target.Address, dst []byte) (int, error) {
		if !reading.CompareAndSwap(false, true) {
			t.Error("memory reads overlapped")
		}
		defer reading.Store(false)
		if address < base || uint64(address-base) != next {
			t.Errorf("memory read at %#x; expected %#x", address, base+target.Address(next))
			return 0, target.ErrInvalidArgument
		}
		n := copy(dst, data[next:])
		next += uint64(n)
		if n != len(dst) {
			return n, io.EOF
		}
		return n, nil
	})
}

func TestSearchChunkBoundariesAndOverlappingMatches(t *testing.T) {
	for _, tt := range []struct {
		name    string
		data    string
		pattern string
		want    []target.Address
	}{
		{"crossing", "012abc456abc9", "abc", []target.Address{103, 109}},
		{"overlapping", "aaaaa", "aaa", []target.Address{100, 101, 102}},
		{"single_byte", "banana", "a", []target.Address{101, 103, 105}},
		{"whole_range", "needle", "needle", []target.Address{100}},
		{"no_match", "aaaaaaaa", "bbb", nil},
		{"short_range", "ab", "abc", nil},
		{"empty_range", "", "a", nil},
	} {
		for chunk := 1; chunk <= len(tt.data)+2; chunk++ {
			for _, workers := range []int{0, 1, 2, 8} {
				t.Run(tt.name, func(t *testing.T) {
					reader := testSearchReader(t, 100, []byte(tt.data))
					got, err := Search(context.Background(), reader, 100, uint64(len(tt.data)), []byte(tt.pattern), SearchOptions{ChunkSize: chunk, Workers: workers})
					if err != nil || !slices.Equal(got, tt.want) {
						t.Fatalf("chunk %d, workers %d: got %v, %v; want %v", chunk, workers, got, err, tt.want)
					}
				})
			}
		}
	}
}

func TestSearchBytesMatchesSerialReference(t *testing.T) {
	data := bytes.Repeat([]byte("ababcabc"), 30_000)
	pattern := []byte("abc")
	want := referenceSearch(0x1000, data, pattern)
	for _, workers := range []int{0, 1, 2, 8, 1000} {
		got, err := SearchBytes(context.Background(), 0x1000, data, pattern, workers)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("workers %d: got %d matches, %v; want %d matches", workers, len(got), err, len(want))
		}
	}
}

func TestSearchBytesPatternLargerThanDefaultChunk(t *testing.T) {
	pattern := bytes.Repeat([]byte{1}, 70_000)
	pattern[len(pattern)-1] = 2
	data := append(bytes.Repeat([]byte{0}, 32_000), pattern...)
	data = append(data, pattern...)
	got, err := SearchBytes(context.Background(), 100, data, pattern, 4)
	want := []target.Address{32_100, 102_100}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
}

func TestSearchLongRepeatedPatternFindsEveryOverlappingMatch(t *testing.T) {
	data := bytes.Repeat([]byte{'a'}, 100_000)
	pattern := bytes.Repeat([]byte{'a'}, 8192)
	want := make([]target.Address, len(data)-len(pattern)+1)
	for i := range want {
		want[i] = 100 + target.Address(i)
	}
	got, err := SearchBytes(context.Background(), 100, data, pattern, 4)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("byte search got %d matches, %v; want %d matches", len(got), err, len(want))
	}
	reader := testSearchReader(t, 100, data)
	got, err = Search(context.Background(), reader, 100, uint64(len(data)), pattern, SearchOptions{ChunkSize: 1024, Workers: 4})
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("stream search got %d matches, %v; want %d matches", len(got), err, len(want))
	}
}

func TestSearchReturnsObservedPrefixWithReadError(t *testing.T) {
	readErr := errors.New("unmapped memory")
	data := []byte("ababa")
	reader := testSearchReader(t, 100, data)
	got, err := Search(context.Background(), searchReaderFunc(func(address target.Address, dst []byte) (int, error) {
		n, err := reader.ReadMemory(address, dst)
		if err != nil {
			return n, readErr
		}
		return n, nil
	}), 100, 10, []byte("aba"), SearchOptions{ChunkSize: 4, Workers: 3})
	want := []target.Address{100, 102}
	var partial *target.PartialError
	if !errors.Is(err, readErr) || !errors.Is(err, target.ErrPartial) || !errors.As(err, &partial) || !slices.Equal(got, want) {
		t.Fatalf("got %v, %v; want %v and partial read error", got, err, want)
	}
	if partial.Completed != 1 || partial.Total != 4 {
		t.Fatalf("partial = %+v; want 1 of 4", partial)
	}
}

func TestSearchHandlesShortReadWithoutError(t *testing.T) {
	got, err := Search(context.Background(), searchReaderFunc(func(address target.Address, dst []byte) (int, error) {
		return copy(dst, []byte("aba")), nil
	}), 100, 8, []byte("aba"), SearchOptions{ChunkSize: 4})
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, target.ErrPartial) || !slices.Equal(got, []target.Address{100}) {
		t.Fatalf("got %v, %v; want [100] and unexpected EOF", got, err)
	}
}

func TestSearchHandlesFullReadWithError(t *testing.T) {
	readErr := errors.New("transport closed")
	got, err := Search(context.Background(), searchReaderFunc(func(address target.Address, dst []byte) (int, error) {
		return copy(dst, []byte("ababa")), readErr
	}), 100, 5, []byte("aba"), SearchOptions{})
	if !errors.Is(err, readErr) || !slices.Equal(got, []target.Address{100, 102}) {
		t.Fatalf("got %v, %v; want [100 102] and read error", got, err)
	}
}

func TestSearchValidatesReaderCount(t *testing.T) {
	for _, count := range []int{-1, 5} {
		reader := searchReaderFunc(func(target.Address, []byte) (int, error) { return count, nil })
		if _, err := Search(context.Background(), reader, 0, 4, []byte{1}, SearchOptions{}); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("reader count %d: %v; want ErrInvalidArgument", count, err)
		}
	}
}

func TestSearchInvalidArguments(t *testing.T) {
	reader := searchReaderFunc(func(target.Address, []byte) (int, error) {
		t.Fatal("unexpected memory read")
		return 0, nil
	})
	for _, options := range []SearchOptions{{ChunkSize: -1}, {Workers: -1}} {
		if _, err := Search(context.Background(), reader, 0, 1, []byte{1}, options); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("options %+v: %v; want ErrInvalidArgument", options, err)
		}
	}
	for _, size := range []uint64{0, 1} {
		if _, err := Search(context.Background(), reader, 0, size, nil, SearchOptions{}); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("empty pattern, size %d: %v; want ErrInvalidArgument", size, err)
		}
	}
	if _, err := Search(context.Background(), nil, 0, 1, []byte{1}, SearchOptions{}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil reader: %v; want ErrInvalidArgument", err)
	}
	if _, err := Search(nil, reader, 0, 1, []byte{1}, SearchOptions{}); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context: %v; want ErrInvalidArgument", err)
	}
	if _, err := SearchBytes(context.Background(), 0, nil, []byte{1}, -1); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("negative workers: %v; want ErrInvalidArgument", err)
	}
	if _, err := SearchBytes(context.Background(), 0, nil, nil, 0); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("empty pattern: %v; want ErrInvalidArgument", err)
	}
}

func TestSearchAddressBounds(t *testing.T) {
	reader := testSearchReader(t, math.MaxUint64, []byte{1})
	got, err := Search(context.Background(), reader, math.MaxUint64, 1, []byte{1}, SearchOptions{ChunkSize: math.MaxInt, Workers: math.MaxInt})
	if err != nil || !slices.Equal(got, []target.Address{math.MaxUint64}) {
		t.Fatalf("last address: %v, %v", got, err)
	}
	if _, err := Search(context.Background(), reader, math.MaxUint64, 2, []byte{1}, SearchOptions{}); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("range overflow: %v; want ErrOverflow", err)
	}
	got, err = SearchBytes(context.Background(), math.MaxUint64, []byte{1}, []byte{1}, 0)
	if err != nil || !slices.Equal(got, []target.Address{math.MaxUint64}) {
		t.Fatalf("last address bytes: %v, %v", got, err)
	}
	if _, err := SearchBytes(context.Background(), math.MaxUint64, []byte{1, 2}, []byte{1}, 0); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("bytes overflow: %v; want ErrOverflow", err)
	}
}

func TestSearchCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := searchReaderFunc(func(target.Address, []byte) (int, error) {
		t.Fatal("unexpected memory read")
		return 0, nil
	})
	if got, err := Search(ctx, reader, 0, 1, []byte{1}, SearchOptions{}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("pre-canceled search: %v, %v", got, err)
	}
	if got, err := SearchBytes(ctx, 0, []byte{1}, []byte{1}, 1); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("pre-canceled bytes search: %v, %v", got, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	reader = searchReaderFunc(func(address target.Address, dst []byte) (int, error) {
		cancel()
		for i := range dst {
			dst[i] = 1
		}
		return len(dst), nil
	})
	if got, err := Search(ctx, reader, 0, 100, []byte{1}, SearchOptions{ChunkSize: 2, Workers: 4}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancel during read: %v, %v", got, err)
	}
}

func referenceSearch(base target.Address, data, pattern []byte) []target.Address {
	var matches []target.Address
	for i := 0; i <= len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			matches = append(matches, base+target.Address(i))
		}
	}
	return matches
}

func FuzzSearchMatchesSerialReference(f *testing.F) {
	f.Add([]byte("aaaaaaa"), []byte("aaa"), uint8(2), uint8(3))
	f.Add([]byte("abc012abc"), []byte("abc"), uint8(4), uint8(2))
	f.Add([]byte("abc"), []byte("abcdef"), uint8(1), uint8(0))
	f.Fuzz(func(t *testing.T, data, pattern []byte, chunk, workers uint8) {
		if len(pattern) == 0 || len(data) > 4096 || len(pattern) > 4096 {
			t.Skip()
		}
		want := referenceSearch(100, data, pattern)
		reader := testSearchReader(t, 100, data)
		got, err := Search(context.Background(), reader, 100, uint64(len(data)), pattern, SearchOptions{ChunkSize: 1 + int(chunk), Workers: int(workers % 8)})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	})
}

func BenchmarkSearchBytesWorkerCount(b *testing.B) {
	for _, dense := range []bool{false, true} {
		data := bytes.Repeat([]byte{'a'}, 1<<20)
		pattern := bytes.Repeat([]byte{'a'}, 4096)
		name := "dense"
		if !dense {
			pattern[len(pattern)-1] = 'b'
			name = "absent"
		}
		for _, workers := range []int{1, 4} {
			b.Run(name+"/workers="+strconv.Itoa(workers), func(b *testing.B) {
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := SearchBytes(context.Background(), 0, data, pattern, workers); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
