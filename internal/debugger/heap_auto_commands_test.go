package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestAutomaticHeapArgumentGrammar(t *testing.T) {
	for _, args := range []string{"", "--all -v -n", "-a 'main_arena + 0' --verbose", "--arena-addr 0x1000 --no-pager"} {
		if _, err := parseAutomaticHeapArguments(args, false); err != nil {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
	for _, args := range []string{"1", "--all --arena 1", "-a", "--unknown", "-v --verbose", "-n --no-pager", "--all --all", "-a ''", "-a 'bad"} {
		if _, err := parseAutomaticHeapArguments(args, false); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
	for _, args := range []string{"--all", "-v", "-c 5", "-f"} {
		if _, err := parseAutomaticHeapArguments(args, true); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("visual args=%q error=%v", args, err)
		}
	}
}

func TestAutomaticHeapNoArgumentsRequireTargetNotInternalFlags(t *testing.T) {
	controller := &Controller{}
	for _, command := range []func(context.Context, string) error{controller.showBins, controller.showVisualHeap, controller.showArenas} {
		if err := command(context.Background(), ""); !errors.Is(err, target.ErrInvalidState) || errors.Is(err, target.ErrInvalidArgument) || strings.Contains(err.Error(), "--layout") {
			t.Fatalf("no-argument command error=%v", err)
		}
	}
}

func TestGlibc244BinBoundariesAreSourceFormulas(t *testing.T) {
	policy, err := heapPolicyForAllocator(automaticHeapTestContext(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		size  uint64
		index uint64
	}{
		{0x20, 0}, {0x410, 63}, {0x420, 64}, {0x7f0, 64}, {0x800, 65}, {0x1000, 66}, {0x3ffff0, 75},
	} {
		index, valid := policy.tcacheIndex(test.size)
		minimum, maximum, known := policy.tcacheRange(index)
		if !valid || index != test.index || !known || test.size < minimum || test.size > maximum {
			t.Fatalf("size=%#x index=%d valid=%t range=%#x..%#x", test.size, index, valid, minimum, maximum)
		}
	}
	for index := uint64(0); index < 76; index++ {
		minimum, maximum, ok := policy.tcacheRange(index)
		low, lowOK := policy.tcacheIndex(minimum)
		high, highOK := policy.tcacheIndex(maximum)
		if !ok || !lowOK || !highOK || low != index || high != index {
			t.Fatalf("tcache range index=%d range=%#x..%#x low=%d high=%d", index, minimum, maximum, low, high)
		}
	}
	if policy.normalName(63) != "small" || policy.normalName(64) != "large" || policy.largeIndex(0x400) != 64 || policy.largeIndex(0x810) != 80 {
		t.Fatal("small/large boundary differs from bin_at/largebin_index_64")
	}
	for index := uint64(64); index <= 126; index++ {
		minimum, maximum, ok := policy.largeRange(index)
		if !ok || policy.largeIndex(minimum) != index || policy.largeIndex(maximum) != index || minimum > maximum {
			t.Fatalf("normal range index=%d range=%#x..%#x", index, minimum, maximum)
		}
	}
}

func automaticHeapTestContext(t *testing.T) *allocatorContext {
	t.Helper()
	profiles, err := knownAllocatorProfiles()
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles=%d error=%v", len(profiles), err)
	}
	profile := profiles[0]
	return &allocatorContext{
		Layout: cloneAllocatorLayout(profile.Layout), MainArena: 0x1000, ThreadArena: 0x1000,
		Tcache: 0x3000, TcacheState: "active", Parameters: allocatorParameters{TcacheCount: 16},
		Alignment: 16, MinChunkSize: 32, ChunkHeaderSize: 16, SizeFlags: 7,
		ThreadRef: target.ThreadRef{ID: 9}, TID: 123,
		SmallBinCount: profile.Constants.SmallBinCount, NormalBinCount: profile.Constants.NormalBinCount, FastBinShift: profile.Constants.FastBinShift, TcacheSmallBinCount: profile.Constants.TcacheSmallBinCount, TcacheLargeBinCount: profile.Constants.TcacheLargeBinCount, Semantics: profile.Semantics,
	}
}

func TestAutomaticTcacheChecksKnownSourceInvariantsWithoutGuessing(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-class", "misaligned", "too-many-slots", "large-unsorted", "mmapped"} {
		t.Run(mode, func(t *testing.T) {
			allocator := automaticHeapTestContext(t)
			controller, fixture, output := newInspectionTestController()
			layout := allocator.Layout
			arena := heapGraphTestArena(layout, allocator.MainArena)
			binary.LittleEndian.PutUint64(arena[layout.Arena.Fields["top"].Offset:], 0x9000)
			cache := make([]byte, layout.Tcache.Size)
			counter, entries := layout.Tcache.Fields["num_slots"], layout.Tcache.Fields["entries"]
			for index := uint64(0); index < counter.Count; index++ {
				binary.LittleEndian.PutUint16(cache[counter.Offset+index*counter.Stride:], 16)
			}
			index, head, size, slots := uint64(0), uint64(0x5010), uint64(0x21), uint16(15)
			if mode == "wrong-class" {
				size = 0x31
			} else if mode == "misaligned" {
				head++
			} else if mode == "too-many-slots" {
				slots = 17
			} else if mode == "mmapped" {
				size = 0x23
			} else if mode == "large-unsorted" {
				index, size, slots = 64, 0x601, 14
			}
			binary.LittleEndian.PutUint16(cache[counter.Offset+index*counter.Stride:], slots)
			binary.LittleEndian.PutUint64(cache[entries.Offset+index*entries.Stride:], head)
			chunk := make([]byte, 32)
			binary.LittleEndian.PutUint64(chunk[8:], size)
			binary.LittleEndian.PutUint64(chunk[16:], 0x5010>>12)
			records := map[target.Address][]byte{0x1000: arena, 0x3000: cache, 0x5000: chunk[:16], 0x5010: chunk[16:]}
			if mode == "large-unsorted" {
				binary.LittleEndian.PutUint64(chunk[16:], 0x6010^(0x5010>>12))
				other := make([]byte, 32)
				binary.LittleEndian.PutUint64(other[8:], 0x501)
				binary.LittleEndian.PutUint64(other[16:], 0x6010>>12)
				records[0x6000], records[0x6010] = other[:16], other[16:]
			}
			heapGraphTestMemory(fixture, records)
			input := heapGraphInput{layout: layout, address: 0x1000, alignment: 16, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
			observation, err := collectAutomaticHeap(allocator, input, false)
			if mode == "valid" && err != nil || mode != "valid" && !errors.Is(err, target.ErrInvalidState) {
				t.Fatalf("error=%v", err)
			}
			text, formatErr := formatAutomaticBins(context.Background(), observation, controller.renderer, false)
			if formatErr != nil || !strings.Contains(text, "thread=9 TID=123") || !strings.Contains(text, "not present in this allocator build") {
				t.Fatalf("format error=%v text=%q", formatErr, text)
			}
			if mode == "valid" && (!strings.Contains(text, "chunk=0x0000000000005000 size=0x20") || !strings.Contains(text, "num_slots.raw=15 observed=1 complete=true")) {
				t.Fatal(text)
			}
			if output.Len() != 0 {
				t.Fatal("collector published before metadata confirmation")
			}
		})
	}
}

func TestAutomaticTcacheInactiveAndDisabledDoNotReadDummyLists(t *testing.T) {
	for _, state := range []string{"inactive", "disabled", "null"} {
		t.Run(state, func(t *testing.T) {
			allocator := automaticHeapTestContext(t)
			allocator.TcacheState = state
			_, fixture, _ := newInspectionTestController()
			arena := heapGraphTestArena(allocator.Layout, 0x1000)
			binary.LittleEndian.PutUint64(arena[allocator.Layout.Arena.Fields["top"].Offset:], 0x9000)
			heapGraphTestMemory(fixture, map[target.Address][]byte{0x1000: arena})
			input := heapGraphInput{layout: allocator.Layout, address: 0x1000, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
			observation, err := collectAutomaticHeap(allocator, input, false)
			if err != nil || observation.tcache != nil || len(fixture.stackCalls) != 1 {
				t.Fatalf("state=%s error=%v reads=%v", state, err, fixture.stackCalls)
			}
		})
	}
}

func TestAutomaticNormalBinsUseActualBinIndexBoundary(t *testing.T) {
	allocator := automaticHeapTestContext(t)
	_, fixture, _ := newInspectionTestController()
	input := heapGraphInput{layout: allocator.Layout, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
	for _, pair := range [][2]uint64{{63, 0x3f0}, {64, 0x400}} {
		t.Run(fmt.Sprint(pair), func(t *testing.T) {
			data := make([]byte, 32)
			binary.LittleEndian.PutUint64(data[8:], pair[1]|1)
			observation := heapBinsObservation{bins: []heapBinObservation{{index: pair[0], name: "normal", complete: true, nodes: []heapBinNode{{address: 0x5000, data: data, linked: true}}}}}
			if err := validateAutomaticBins(allocator, input, &observation); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func automaticOldHeapTestContext(t *testing.T) *allocatorContext {
	t.Helper()
	allocator := automaticHeapTestContext(t)
	allocator.Layout.Arena = heapGraphTestLayout().Arena
	allocator.Layout.FastLink = "safe-link-12"
	allocator.Layout.Tcache = &inspect.HeapRecord{Size: 640, Fields: map[string]inspect.HeapField{
		"counts":  {Offset: 0, Width: 2, Count: 64, Stride: 2},
		"entries": {Offset: 128, Width: 8, Count: 64, Stride: 8},
	}}
	allocator.FastBinShift, allocator.TcacheLargeBinCount = 4, 0
	allocator.Semantics.TcacheCounterMode = "counts"
	allocator.Semantics.TcacheStateMode = "null-shutdown"
	allocator.Semantics.TcacheSmallBinsField = "tcache_bins"
	allocator.Semantics.TcacheMaxBytesMode = "request-limit"
	allocator.Semantics.HeapMaxMode = "huge-pages-times-four"
	allocator.Parameters.TcacheCount = 7
	return allocator
}

func TestAutomaticOldCountsCapacityZeroKeepsAnActiveAllocatedCache(t *testing.T) {
	for _, capacity := range []uint64{0, 7} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			allocator := automaticOldHeapTestContext(t)
			allocator.Parameters.TcacheCount = capacity
			controller, fixture, _ := newInspectionTestController()
			arena := heapGraphTestArena(allocator.Layout, allocator.MainArena)
			binary.LittleEndian.PutUint64(arena[allocator.Layout.Arena.Fields["top"].Offset:], 0x9000)
			cache := make([]byte, allocator.Layout.Tcache.Size)
			heapGraphTestMemory(fixture, map[target.Address][]byte{allocator.MainArena: arena, allocator.Tcache: cache})
			input := heapGraphInput{layout: allocator.Layout, address: allocator.MainArena, alignment: allocator.Alignment, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
			observation, err := collectAutomaticHeap(allocator, input, false)
			if err != nil || observation.tcache == nil || len(observation.tcache.bins) != 64 || len(fixture.stackCalls) != 2 {
				t.Fatalf("error=%v tcache=%+v reads=%v", err, observation.tcache, fixture.stackCalls)
			}
			text, err := formatAutomaticBins(context.Background(), observation, controller.renderer, true)
			if err != nil || !strings.Contains(text, "counts.raw=0 observed=0 complete=true") || strings.Contains(text, "num_slots") || strings.Contains(text, "disabled") || strings.Contains(text, "tcache[idx=64") {
				t.Fatalf("error=%v text=%q", err, text)
			}
		})
	}
}

func TestAutomaticOldFastBinsValidateClassAndNeverInventBackPointers(t *testing.T) {
	for _, size := range []uint64{0x31, 0x41} {
		t.Run(fmt.Sprintf("%x", size), func(t *testing.T) {
			allocator := automaticOldHeapTestContext(t)
			allocator.TcacheState = "null"
			controller, fixture, _ := newInspectionTestController()
			arena := heapGraphTestArena(allocator.Layout, allocator.MainArena)
			binary.LittleEndian.PutUint64(arena[allocator.Layout.Arena.Fields["top"].Offset:], 0x9000)
			fast := allocator.Layout.Arena.Fields["fastbinsY"]
			binary.LittleEndian.PutUint64(arena[fast.Offset+fast.Stride:], 0x5000)
			chunk := make([]byte, 24)
			binary.LittleEndian.PutUint64(chunk[8:], size)
			binary.LittleEndian.PutUint64(chunk[16:], 0x5010>>12)
			heapGraphTestMemory(fixture, map[target.Address][]byte{allocator.MainArena: arena, 0x5000: chunk})
			input := heapGraphInput{layout: allocator.Layout, address: allocator.MainArena, alignment: allocator.Alignment, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
			observation, err := collectAutomaticHeap(allocator, input, false)
			if size == 0x31 && err != nil || size == 0x41 && !errors.Is(err, target.ErrInvalidState) {
				t.Fatal(err)
			}
			text, formatErr := formatAutomaticBins(context.Background(), observation, controller.renderer, false)
			if formatErr != nil || !strings.Contains(text, "fast[idx=1 size=0x30]") || !strings.Contains(text, "fd.stored=0x0000000000000005 next=0x0000000000000000") || strings.Contains(text, "bk=") || len(fixture.stackCalls) != 2 || fixture.stackCalls[1].size != 24 {
				t.Fatalf("error=%v text=%q reads=%v", formatErr, text, fixture.stackCalls)
			}
		})
	}
}

func TestAutomaticHeapRejectsUnprovedSemanticCombinationsBeforeReads(t *testing.T) {
	for _, mode := range []string{"counter", "large-count", "fast", "normal-count"} {
		t.Run(mode, func(t *testing.T) {
			allocator := automaticHeapTestContext(t)
			switch mode {
			case "counter":
				allocator.Semantics.TcacheCounterMode = "counts"
			case "large-count":
				allocator.TcacheLargeBinCount = 0
			case "fast":
				allocator.FastBinShift = 4
			case "normal-count":
				allocator.NormalBinCount = 127
			}
			_, fixture, _ := newInspectionTestController()
			input := heapGraphInput{layout: allocator.Layout, address: allocator.MainArena, reader: newHeapGraphReader(context.Background(), fixture, fixture.snapshot.Memory)}
			if _, err := collectAutomaticHeap(allocator, input, false); err == nil || len(fixture.stackCalls) != 0 {
				t.Fatalf("error=%v reads=%v", err, fixture.stackCalls)
			}
		})
	}
}
