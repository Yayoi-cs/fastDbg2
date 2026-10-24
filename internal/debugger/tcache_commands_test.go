package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func heapTcacheTestLayout() inspect.HeapLayout {
	layout := heapGraphTestLayout()
	layout.Tcache = &inspect.HeapRecord{Size: 32, Fields: map[string]inspect.HeapField{
		"num_slots": {Offset: 0, Width: 2, Count: 2, Stride: 2},
		"entries":   {Offset: 8, Width: 8, Count: 2, Stride: 8},
	}}
	layout.TcacheEntry = &inspect.HeapRecord{Size: 64, Fields: map[string]inspect.HeapField{
		"next": {Offset: 24, Width: 8, Count: 1, Stride: 8},
		"key":  {Offset: 32, Width: 8, Count: 1, Stride: 8},
	}}
	layout.TcacheLink = "safe-link-12"
	return layout
}

func TestExplicitTcacheUsesActualNextFieldAndRawCounter(t *testing.T) {
	layout := heapTcacheTestLayout()
	path := heapGraphTestLayoutFile(t, layout)
	controller, fixture, output := newInspectionTestController()
	root := make([]byte, 32)
	binary.LittleEndian.PutUint16(root, 60000)
	binary.LittleEndian.PutUint64(root[8:], 0xff0)
	entry := make([]byte, 40)
	binary.LittleEndian.PutUint64(entry[24:], 1)
	binary.LittleEndian.PutUint64(entry[32:], 0x12345678)
	heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: heapGraphTestArena(layout, 0x1000), 0x2000: root, 0xff0: entry})
	err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q --tcache '0x1000 + 0x1000' 0x1000", path))
	if err != nil || !strings.Contains(output.String(), "num_slots.raw=60000 count=1") || !strings.Contains(output.String(), "next=0x0000000000000000 key.raw=0x0000000012345678") {
		t.Fatalf("error=%v output=%q", err, output.String())
	}
	if fixture.snapshotReads != 1 || len(fixture.stackCalls) != 3 || fixture.stackCalls[2] != (contextMemoryCall{fixture.snapshot.Memory, 0xff0, 40}) {
		t.Fatalf("reads=%v snapshots=%d", fixture.stackCalls, fixture.snapshotReads)
	}
}

func TestExplicitTcacheRequiresLayoutBeforeSnapshot(t *testing.T) {
	path := heapGraphTestLayoutFile(t, heapGraphTestLayout())
	controller, fixture, output := newInspectionTestController()
	err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q --tcache 0x2000 0x1000", path))
	if !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 || len(fixture.stackCalls) != 0 || output.Len() != 0 {
		t.Fatalf("error=%v fixture=%+v output=%q", err, fixture, output.String())
	}
	for _, args := range []string{"--module main --fast-link plain --tcache 1", "--tcache 1", "--layout-file x --tcache 1 --tcache 2 3"} {
		if _, err := parseHeapGraphArguments(args, false); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
	if _, err := parseHeapGraphArguments("--layout-file x --tcache 1 2", true); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestTcacheCyclesDuplicatesAndGlobalBudget(t *testing.T) {
	for _, mode := range []string{"cycle", "duplicate", "budget"} {
		t.Run(mode, func(t *testing.T) {
			layout := heapTcacheTestLayout()
			layout.TcacheLink = "plain"
			_, fixture, _ := newInspectionTestController()
			root, entry := make([]byte, 32), make([]byte, 40)
			binary.LittleEndian.PutUint64(root[8:], 0x3000)
			if mode == "cycle" {
				binary.LittleEndian.PutUint64(entry[24:], 0x3000)
			} else if mode == "duplicate" {
				binary.LittleEndian.PutUint64(root[16:], 0x3000)
			}
			heapGraphTestMemory(fixture, map[target.Address][]byte{0x2000: root, 0x3000: entry})
			reader := newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)
			if mode == "budget" {
				reader.nodes = heapGraphMaxNodes - 1
			}
			observation, err := walkHeapTcache(heapGraphInput{layout: layout, reader: reader}, 0x2000)
			want := target.ErrInvalidState
			reads := 2
			if mode == "budget" {
				want, reads = target.ErrUnavailable, 1
			}
			if !errors.Is(err, want) || len(fixture.stackCalls) != reads || len(observation.bins) == 0 {
				t.Fatalf("error=%v observation=%+v reads=%v", err, observation, fixture.stackCalls)
			}
		})
	}
}

func TestTcachePartialAndStaleNeverDecodeUnconfirmed(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			layout := heapTcacheTestLayout()
			_, fixture, _ := newInspectionTestController()
			fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
				if address == 0x2000 {
					binary.LittleEndian.PutUint64(dst[8:], 0x3000)
					return len(dst), nil
				}
				for index := range dst {
					dst[index] = 0xff
				}
				if stale {
					return 31, target.ErrStale
				}
				return 31, io.ErrUnexpectedEOF
			}
			input := heapGraphInput{layout: layout, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
			observation, err := walkHeapTcache(input, 0x2000)
			if stale {
				if !errors.Is(err, target.ErrStale) || len(observation.bins) != 0 {
					t.Fatalf("error=%v observation=%+v", err, observation)
				}
			} else if !errors.Is(err, io.ErrUnexpectedEOF) || observation.bins[0].nodes[0].linked || observation.bins[0].complete {
				t.Fatalf("error=%v observation=%+v", err, observation)
			}
			if len(fixture.stackCalls) != 2 {
				t.Fatal(fixture.stackCalls)
			}
		})
	}
}
