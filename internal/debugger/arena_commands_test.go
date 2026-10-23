package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func heapGraphTestLayout() inspect.HeapLayout {
	field := func(offset, width, count uint64) inspect.HeapField {
		return inspect.HeapField{Offset: offset, Width: width, Count: count, Stride: width}
	}
	return inspect.HeapLayout{
		Schema: 1, Allocator: "glibc", Arch: "amd64", Endian: "little", Pointer: 8, FastLink: "plain",
		Arena: inspect.HeapRecord{Size: 96, Fields: map[string]inspect.HeapField{
			"mutex": field(0, 4, 1), "fastbinsY": field(8, 8, 2), "top": field(24, 8, 1),
			"bins": field(32, 8, 4), "next": field(64, 8, 1), "attached_threads": field(72, 8, 1),
			"system_mem": field(80, 8, 1), "max_system_mem": field(88, 8, 1),
		}},
		Chunk: inspect.HeapRecord{Size: 64, Fields: map[string]inspect.HeapField{
			"mchunk_prev_size": field(8, 8, 1), "mchunk_size": field(16, 8, 1),
			"fd": field(24, 8, 1), "bk": field(32, 8, 1), "fd_nextsize": field(40, 8, 1), "bk_nextsize": field(48, 8, 1),
		}},
	}
}

func heapGraphTestLayoutFile(t *testing.T, layout inspect.HeapLayout) string {
	t.Helper()
	data, err := json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "layout.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func heapGraphTestArena(layout inspect.HeapLayout, address target.Address) []byte {
	data := make([]byte, layout.Arena.Size)
	binary.LittleEndian.PutUint64(data[layout.Arena.Fields["next"].Offset:], uint64(address))
	bins, fd := layout.Arena.Fields["bins"], layout.Chunk.Fields["fd"]
	for index := uint64(0); index < bins.Count/2; index++ {
		offset := bins.Offset + index*2*bins.Stride
		sentinel := uint64(address) + offset - fd.Offset
		binary.LittleEndian.PutUint64(data[offset:], sentinel)
		binary.LittleEndian.PutUint64(data[offset+8:], sentinel)
	}
	return data
}

func heapGraphTestMemory(fixture *inspectionReadFixture, records map[target.Address][]byte) {
	fixture.readRaw = func(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if token != fixture.snapshot.Memory {
			return 0, target.ErrStale
		}
		data, exists := records[address]
		if !exists {
			return 0, fmt.Errorf("unmapped fixture address %#x: %w", address, target.ErrUnavailable)
		}
		n := copy(dst, data)
		if n != len(dst) {
			return n, io.ErrUnexpectedEOF
		}
		return n, nil
	}
}

func TestHeapGraphArgumentGrammar(t *testing.T) {
	for _, test := range []struct {
		input string
		arena bool
		want  heapGraphArguments
	}{
		{"--layout-file x.json 0x1000", true, heapGraphArguments{layoutFile: "x.json", expression: "0x1000"}},
		{"--all --layout-file 'x y.json' '$rsp + 8'", true, heapGraphArguments{layoutFile: "x y.json", expression: "$rsp + 8", all: true}},
		{"--layout-file x.json -- '`symbol with spaces`'", false, heapGraphArguments{layoutFile: "x.json", expression: "`symbol with spaces`"}},
		{"--module main --fast-link plain", false, heapGraphArguments{module: "main", fastLink: "plain"}},
		{"--module main --debug-file 'x y.debug' --fast-link safe-link-12 --all 0x4000", true, heapGraphArguments{module: "main", debugFile: "x y.debug", fastLink: "safe-link-12", all: true, expression: "0x4000"}},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := parseHeapGraphArguments(test.input, test.arena)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got=%+v error=%v want=%+v", got, err, test.want)
			}
		})
	}
}

func TestHeapGraphInvalidArgumentsDoNotInspect(t *testing.T) {
	for _, input := range []string{
		"", "0x1000", "--layout-file", "--layout-file x.json", "--layout-file x.json 1 2",
		"--layout-file x.json ''", "--layout-file x.json 'unterminated", "--layout-file x.json --layout-file y.json 1",
		"--layout-file x.json --module main 1", "--layout-file x.json --debug-file a 1", "--layout-file x.json --fast-link plain 1",
		"--module", "--module main", "--module main --fast-link guess", "--debug-file x --fast-link plain",
		"--module main --fast-link plain --fast-link plain", "--bad x", "--all --all --layout-file x.json 1", "--layout-file -- 1",
	} {
		t.Run(input, func(t *testing.T) {
			if input == "" {
				if _, err := parseHeapGraphArguments(input, true); !errors.Is(err, target.ErrInvalidArgument) {
					t.Fatal(err)
				}
				return
			}
			controller, fixture, output := newInspectionTestController()
			err := controller.showArenas(context.Background(), input)
			if !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("error=%v fixture=%+v output=%q", err, fixture, output.String())
			}
		})
	}
	if _, err := parseHeapGraphArguments("--all --layout-file x.json 1", false); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestArenaExplicitLayoutUsesOneSnapshotAndDerivedFields(t *testing.T) {
	layout := heapGraphTestLayout()
	path := heapGraphTestLayoutFile(t, layout)
	controller, fixture, output := newInspectionTestController()
	arena := heapGraphTestArena(layout, 0x1000)
	binary.LittleEndian.PutUint64(arena[72:], 3)
	heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: arena})
	if err := controller.showArenas(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[arena]", "user-selected", "arena[0] 0x0000000000001000", "+0x48 attached_threads", "0x0000000000000003", "observed-arenas=1 requested-bytes=96", "thread ownership are not inferred"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q output=%q", want, output.String())
		}
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 0 || len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x1000, 96}) {
		t.Fatalf("unexpected reads=%+v", fixture)
	}
}

func TestArenaRingAndNonRootCycle(t *testing.T) {
	for _, mode := range []string{"ring", "null", "non-root-cycle"} {
		t.Run(mode, func(t *testing.T) {
			layout := heapGraphTestLayout()
			path := heapGraphTestLayoutFile(t, layout)
			controller, fixture, output := newInspectionTestController()
			first, second := heapGraphTestArena(layout, 0x1000), heapGraphTestArena(layout, 0x2000)
			binary.LittleEndian.PutUint64(first[64:], 0x2000)
			next := uint64(0x1000)
			if mode == "null" {
				next = 0
			} else if mode == "non-root-cycle" {
				next = 0x2000
			}
			binary.LittleEndian.PutUint64(second[64:], next)
			heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: first, 0x2000: second})
			err := controller.showArenas(context.Background(), fmt.Sprintf("--layout-file %q --all 0x1000", path))
			if mode == "ring" && err != nil || mode != "ring" && !errors.Is(err, target.ErrInvalidState) || len(fixture.stackCalls) != 2 || !strings.Contains(output.String(), "observed-arenas=2") {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
			if mode != "ring" && !strings.Contains(err.Error(), "in-progress allocator update") {
				t.Fatal(err)
			}
		})
	}
}

func TestArenaConfirmedPrefixAndStaleDiscard(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			layout := heapGraphTestLayout()
			path := heapGraphTestLayoutFile(t, layout)
			controller, fixture, output := newInspectionTestController()
			fixture.readRaw = func(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
				for index := range dst {
					dst[index] = 0xff
				}
				if stale {
					return 80, target.ErrStale
				}
				return 73, io.ErrUnexpectedEOF
			}
			err := controller.showArenas(context.Background(), fmt.Sprintf("--layout-file %q --all 0x1000", path))
			if stale {
				if !errors.Is(err, target.ErrStale) || output.Len() != 0 {
					t.Fatalf("error=%v output=%q", err, output.String())
				}
			} else if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(output.String(), "attached_threads   <unconfirmed>") || !strings.Contains(output.String(), "73/96 confirmed bytes") {
				t.Fatalf("error=%v output=%q", err, output.String())
			}
			if len(fixture.stackCalls) != 1 {
				t.Fatalf("retried partial or stale read: %v", fixture.stackCalls)
			}
		})
	}
}

func TestHeapGraphReaderCacheBudgetAndOverflow(t *testing.T) {
	_, fixture, _ := newInspectionTestController()
	heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: make([]byte, 32), math.MaxUint64: {0x7f}})
	reader := newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)
	for range 2 {
		if data, err := reader.read(0x1000, 32); err != nil || len(data) != 32 {
			t.Fatalf("data=%v error=%v", data, err)
		}
	}
	if len(fixture.stackCalls) != 1 || reader.bytes != 32 {
		t.Fatalf("cache reread: reads=%v bytes=%d", fixture.stackCalls, reader.bytes)
	}
	if _, err := reader.read(math.MaxUint64, 2); !errors.Is(err, target.ErrOverflow) || len(fixture.stackCalls) != 1 {
		t.Fatal(err)
	}
	if data, err := reader.read(math.MaxUint64, 1); err != nil || len(data) != 1 || data[0] != 0x7f {
		t.Fatalf("highest byte data=%v error=%v", data, err)
	}
	reader.bytes = heapGraphMaxBytes - 1
	if _, err := reader.read(0x2000, 2); !errors.Is(err, target.ErrUnavailable) || !reader.exhausted || len(fixture.stackCalls) != 2 {
		t.Fatalf("budget error=%v reads=%v", err, fixture.stackCalls)
	}
}

func TestHeapGraphCancellationNeverPublishes(t *testing.T) {
	layout := heapGraphTestLayout()
	path := heapGraphTestLayoutFile(t, layout)
	controller, fixture, output := newInspectionTestController()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.readRaw = func(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
		copy(dst, heapGraphTestArena(layout, 0x1000))
		cancel()
		return len(dst), nil
	}
	err := controller.showArenas(ctx, fmt.Sprintf("--layout-file %q 0x1000", path))
	if !errors.Is(err, context.Canceled) || output.Len() != 0 || len(fixture.stackCalls) != 1 {
		t.Fatalf("error=%v output=%q reads=%v", err, output.String(), fixture.stackCalls)
	}
}

func TestHeapGraphLayoutReadIsBoundedAndBeforeSnapshot(t *testing.T) {
	for _, mode := range []string{"oversized", "directory", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			if mode != "directory" {
				path = filepath.Join(path, "layout.json")
				data := []byte(`{"unknown":1}`)
				if mode == "oversized" {
					data = []byte(strings.Repeat(" ", heapGraphMaxJSON+1))
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			controller, fixture, output := newInspectionTestController()
			err := controller.showArenas(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path))
			if err == nil || fixture.snapshotReads != 0 || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("error=%v fixture=%+v output=%q", err, fixture, output.String())
			}
		})
	}
}

func TestArenaTraversalHasGlobalArenaBound(t *testing.T) {
	layout := heapGraphTestLayout()
	_, fixture, _ := newInspectionTestController()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		data := heapGraphTestArena(layout, address)
		binary.LittleEndian.PutUint64(data[64:], uint64(address)+0x1000)
		return copy(dst, data), nil
	}
	reader := newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)
	arenas, err := walkHeapArenas(heapGraphInput{layout: layout, address: 0x1000, reader: reader}, true)
	if !errors.Is(err, target.ErrUnavailable) || len(arenas) != heapGraphMaxArenas || len(fixture.stackCalls) != heapGraphMaxArenas || reader.nodes != heapGraphMaxArenas {
		t.Fatalf("error=%v arenas=%d reads=%d nodes=%d", err, len(arenas), len(fixture.stackCalls), reader.nodes)
	}
}

type heapGraphCancelWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
}

func (writer *heapGraphCancelWriter) Write(data []byte) (int, error) {
	n, err := writer.buffer.Write(data)
	writer.cancel()
	return n, err
}

func TestHeapGraphRenderingCancellationStopsAtConfirmedPrefix(t *testing.T) {
	for _, bins := range []bool{false, true} {
		t.Run(fmt.Sprint(bins), func(t *testing.T) {
			layout := heapGraphTestLayout()
			path := heapGraphTestLayoutFile(t, layout)
			controller, fixture, _ := newInspectionTestController()
			heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: heapGraphTestArena(layout, 0x1000)})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writer := &heapGraphCancelWriter{cancel: cancel}
			controller.out = writer
			command := controller.showArenas
			if bins {
				command = controller.showBins
			}
			err := command(ctx, fmt.Sprintf("--layout-file %q 0x1000", path))
			if !errors.Is(err, context.Canceled) || strings.Contains(writer.buffer.String(), "schema=") || strings.Contains(writer.buffer.String(), "observed-") || len(fixture.stackCalls) != 1 {
				t.Fatalf("error=%v output=%q reads=%v", err, writer.buffer.String(), fixture.stackCalls)
			}
		})
	}
}
