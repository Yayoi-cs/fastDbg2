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

func heapGraphTestChunk(layout inspect.HeapLayout, fd, bk uint64) []byte {
	data := make([]byte, layout.Chunk.Size)
	binary.LittleEndian.PutUint64(data[layout.Chunk.Fields["mchunk_size"].Offset:], 0x47)
	binary.LittleEndian.PutUint64(data[layout.Chunk.Fields["fd"].Offset:], fd)
	binary.LittleEndian.PutUint64(data[layout.Chunk.Fields["bk"].Offset:], bk)
	return data
}

func TestBinsDerivedSentinelsAndExplicitEncoding(t *testing.T) {
	for _, encoding := range []string{"plain", "safe-link-12"} {
		t.Run(encoding, func(t *testing.T) {
			layout := heapGraphTestLayout()
			layout.FastLink = encoding
			path := heapGraphTestLayoutFile(t, layout)
			controller, fixture, output := newInspectionTestController()
			arena := heapGraphTestArena(layout, 0x1000)
			binary.LittleEndian.PutUint64(arena[8:], 0x3000)
			binary.LittleEndian.PutUint64(arena[32:], 0x5000)
			binary.LittleEndian.PutUint64(arena[40:], 0x6000)
			fd1, fd2 := uint64(0x4000), uint64(0)
			if encoding == "safe-link-12" {
				fd1 ^= (0x3000 + 24) >> 12
				fd2 ^= (0x4000 + 24) >> 12
			}
			heapGraphTestMemory(fixture, map[target.Address][]byte{
				0x1000: arena,
				0x3000: heapGraphTestChunk(layout, fd1, 0xfeedface),
				0x4000: heapGraphTestChunk(layout, fd2, 0xdeadbeef),
				0x5000: heapGraphTestChunk(layout, 0x6000, 0x1008),
				0x6000: heapGraphTestChunk(layout, 0x1008, 0x5000),
			})
			err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"[bins]", "tcache is not inspected", "fastbinsY[0] head=0x0000000000003000 nodes=2 complete=true", "sentinel=0x0000000000001008 nodes=2 complete=true", "mchunk_size.raw=0x47", "observed-nodes=5 requested-bytes=240"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("missing=%q output=%q", want, output.String())
				}
			}
			if strings.Contains(output.String(), "feedface") || strings.Contains(output.String(), "deadbeef") || strings.Contains(output.String(), "status=free") || len(fixture.stackCalls) != 5 || fixture.snapshotReads != 1 {
				t.Fatalf("non-field inference output=%q reads=%v", output.String(), fixture.stackCalls)
			}
			for _, call := range fixture.stackCalls {
				if call.token != fixture.snapshot.Memory || call.address >= 0x3000 && call.address < 0x5000 && call.size != 32 || call.address >= 0x5000 && call.size != 40 {
					t.Fatalf("wrong token or excessive chunk read: %+v", call)
				}
			}
		})
	}
}

func TestBinsLinkInconsistenciesRemainObservations(t *testing.T) {
	for _, mode := range []string{"predecessor", "tail", "null", "cycle", "cross-bin"} {
		t.Run(mode, func(t *testing.T) {
			layout := heapGraphTestLayout()
			path := heapGraphTestLayoutFile(t, layout)
			controller, fixture, output := newInspectionTestController()
			arena := heapGraphTestArena(layout, 0x1000)
			binary.LittleEndian.PutUint64(arena[32:], 0x3000)
			binary.LittleEndian.PutUint64(arena[40:], 0x3000)
			fd, bk := uint64(0x1008), uint64(0x1008)
			switch mode {
			case "predecessor":
				bk = 0x1234
			case "tail":
				binary.LittleEndian.PutUint64(arena[40:], 0x1234)
			case "null":
				fd = 0
			case "cycle":
				fd = 0x3000
			case "cross-bin":
				binary.LittleEndian.PutUint64(arena[8:], 0x3000)
				fd = 0
			}
			heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: arena, 0x3000: heapGraphTestChunk(layout, fd, bk)})
			err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path))
			if !errors.Is(err, target.ErrInvalidState) || !strings.Contains(err.Error(), "in-progress allocator update") || strings.Contains(output.String(), "corrupt") || len(fixture.stackCalls) != 2 {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestBinsNeverRetryAlternateEncoding(t *testing.T) {
	layout := heapGraphTestLayout()
	layout.FastLink = "safe-link-12"
	path := heapGraphTestLayoutFile(t, layout)
	controller, fixture, output := newInspectionTestController()
	arena := heapGraphTestArena(layout, 0x1000)
	binary.LittleEndian.PutUint64(arena[8:], 0x3000)
	heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: arena, 0x3000: heapGraphTestChunk(layout, 0, 0)})
	err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path))
	if !errors.Is(err, target.ErrUnavailable) || len(fixture.stackCalls) != 3 || fixture.stackCalls[2].address != 3 || !strings.Contains(output.String(), "next=0x0000000000000003") {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestBinsPartialAndStaleNodesDoNotInventLinks(t *testing.T) {
	for _, mode := range []string{"partial", "stale", "full-error"} {
		t.Run(mode, func(t *testing.T) {
			layout := heapGraphTestLayout()
			path := heapGraphTestLayoutFile(t, layout)
			controller, fixture, output := newInspectionTestController()
			arena := heapGraphTestArena(layout, 0x1000)
			binary.LittleEndian.PutUint64(arena[8:], 0x3000)
			fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
				if address == 0x1000 {
					return copy(dst, arena), nil
				}
				copy(dst, heapGraphTestChunk(layout, 0x4000, 0))
				if mode == "stale" {
					return len(dst), target.ErrStale
				}
				if mode == "full-error" {
					return len(dst), io.ErrUnexpectedEOF
				}
				return 25, io.ErrUnexpectedEOF
			}
			err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path))
			if mode == "stale" {
				if !errors.Is(err, target.ErrStale) || output.Len() != 0 {
					t.Fatalf("error=%v output=%q", err, output.String())
				}
			} else if !errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(output.String(), "next=0x") || !strings.Contains(output.String(), "<incomplete node:") {
				t.Fatalf("error=%v output=%q", err, output.String())
			}
			if len(fixture.stackCalls) != 2 {
				t.Fatalf("retried incomplete node: %v", fixture.stackCalls)
			}
		})
	}
}

func TestHeapBinGlobalNodeBudgetAllowsExactLimit(t *testing.T) {
	for _, headroom := range []int{1, 2} {
		t.Run(fmt.Sprint(headroom), func(t *testing.T) {
			layout := heapGraphTestLayout()
			_, fixture, _ := newInspectionTestController()
			heapGraphTestMemory(fixture, map[target.Address][]byte{0x3000: heapGraphTestChunk(layout, 0x4000, 0), 0x4000: heapGraphTestChunk(layout, 0, 0)})
			reader := newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)
			reader.nodes = heapGraphMaxNodes - headroom
			input := heapGraphInput{layout: layout, reader: reader}
			result := walkHeapBin(input, heapBinObservation{name: "fastbinsY[0]", fast: true, head: 0x3000}, make(map[target.Address]string))
			if headroom == 1 && (!errors.Is(result.err, target.ErrUnavailable) || result.complete || !reader.exhausted) || headroom == 2 && (result.err != nil || !result.complete || reader.exhausted) {
				t.Fatalf("result=%+v reader=%+v", result, reader)
			}
			if len(fixture.stackCalls) != headroom {
				t.Fatal(fixture.stackCalls)
			}
		})
	}
}

func TestHeapBinsDoNotUseHaveFastchunksOrBinmapAsProof(t *testing.T) {
	layout := heapGraphTestLayout()
	layout.Arena.Fields["have_fastchunks"] = inspect.HeapField{Offset: 4, Width: 4, Count: 1, Stride: 4}
	path := heapGraphTestLayoutFile(t, layout)
	controller, fixture, output := newInspectionTestController()
	arena := heapGraphTestArena(layout, 0x1000)
	binary.LittleEndian.PutUint64(arena[8:], 0x3000)
	heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: arena, 0x3000: heapGraphTestChunk(layout, 0, 0)})
	if err := controller.showBins(context.Background(), fmt.Sprintf("--layout-file %q 0x1000", path)); err != nil || !strings.Contains(output.String(), "nodes=1 complete=true") || len(fixture.stackCalls) != 2 {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestHeapBinsSafeLinkUsesActualFieldAddressAcrossPage(t *testing.T) {
	layout := heapGraphTestLayout()
	layout.FastLink = "safe-link-12"
	_, fixture, _ := newInspectionTestController()
	heapGraphTestMemory(fixture, map[target.Address][]byte{0xff0: heapGraphTestChunk(layout, 1, 0)})
	reader := newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)
	result := walkHeapBin(heapGraphInput{layout: layout, reader: reader}, heapBinObservation{name: "fastbinsY[0]", fast: true, head: 0xff0}, make(map[target.Address]string))
	if result.err != nil || !result.complete || len(result.nodes) != 1 || result.nodes[0].next != 0 || len(fixture.stackCalls) != 1 {
		t.Fatalf("result=%+v reads=%v", result, fixture.stackCalls)
	}
}

func TestHeapBinsEmptySentinelRequiresMatchingTail(t *testing.T) {
	layout := heapGraphTestLayout()
	_, fixture, _ := newInspectionTestController()
	reader := newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)
	result := walkHeapBin(heapGraphInput{layout: layout, reader: reader}, heapBinObservation{name: "normal-bin[1]", sentinel: 0x1008, head: 0x1008, tail: 0x2000}, make(map[target.Address]string))
	if !errors.Is(result.err, target.ErrInvalidState) || result.complete || len(fixture.stackCalls) != 0 {
		t.Fatalf("result=%+v reads=%v", result, fixture.stackCalls)
	}
}
