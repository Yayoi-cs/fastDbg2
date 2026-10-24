package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

func heapVisualTestLayout() inspect.HeapLayout {
	layout := heapGraphTestLayout()
	for name, field := range layout.Chunk.Fields {
		field.Offset -= 8
		layout.Chunk.Fields[name] = field
	}
	return layout
}

func heapVisualTestChunk(rawSize uint64) []byte {
	data := make([]byte, max(16, rawSize&^7))
	binary.LittleEndian.PutUint64(data[8:], rawSize)
	for index := 16; index < len(data); index++ {
		data[index] = byte('A' + index%16)
	}
	return data
}

func heapVisualTestInput(ctx context.Context, base target.Address, data []byte) (heapGraphInput, *inspectionReadFixture) {
	_, fixture, _ := newInspectionTestController()
	fixture.readRaw = func(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if token != fixture.snapshot.Memory {
			return 0, target.ErrStale
		}
		if address < base || uint64(address-base) >= uint64(len(data)) {
			return 0, target.ErrUnavailable
		}
		n := copy(dst, data[address-base:])
		if n != len(dst) {
			return n, io.ErrUnexpectedEOF
		}
		return n, nil
	}
	return heapGraphInput{layout: heapVisualTestLayout(), proof: "exact fixture layout", reader: newHeapGraphReader(ctx, fixture, fixture.snapshot.Memory)}, fixture
}

func heapVisualTestRender(t *testing.T, observation heapVisualObservation) string {
	t.Helper()
	text, err := renderHeapVisual(context.Background(), observation, display.Renderer{})
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestHeapVisualCompleteRowsMembershipAndNextBits(t *testing.T) {
	data := append(heapVisualTestChunk(0x101), heapVisualTestChunk(0x30)...)
	data = append(data, heapVisualTestChunk(0x41)...)
	data = append(data, heapVisualTestChunk(0x1001)...)
	input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
	members := map[target.Address][]heapVisualMembership{0x1130: {{Label: "tcache thread=7 bin=2", Complete: false}}}
	extent := heapVisualExtent{Base: 0xffd, Start: 0x1000, End: 0x2170, Top: 0x1170, Arena: 0x9000, Label: "main"}
	observation, err := collectHeapVisual(input, []heapVisualExtent{extent}, members)
	if err != nil || len(observation.extents) != 1 || !observation.extents[0].complete || len(observation.extents[0].chunks) != 4 {
		t.Fatalf("error=%v observation=%+v", err, observation)
	}
	output := heapVisualTestRender(t, observation)
	for _, want := range []string{
		"|+0x00000|+0x00003:", "0x0000000000000101", "0x0000000000000030",
		"| <- tcache thread=7 bin=2 (incomplete list)", "| <- top",
		"* 254 lines, 0xfe0 bytes", "* 14 lines, 0xe0 bytes",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q in output:\n%s", want, output)
		}
	}
	if input.reader.nodes != 4 || input.reader.bytes != 4464 || len(fixture.stackCalls) != 8 {
		t.Fatalf("nodes=%d bytes=%d calls=%+v", input.reader.nodes, input.reader.bytes, fixture.stackCalls)
	}
	for _, call := range fixture.stackCalls {
		if call.token != fixture.snapshot.Memory || call.address+target.Address(call.size) > extent.End {
			t.Fatalf("unexpected read: %+v", call)
		}
	}
	if strings.Contains(output, "status=allocated") || strings.Contains(output, "status=free") || strings.Contains(output, "\x1b") || strings.Contains(output, "omitted") {
		t.Fatal(output)
	}
}

func TestHeapVisualLayoutAndExtentValidationDoesNotRead(t *testing.T) {
	for _, name := range []string{"nil-reader", "nil-context", "nil-session", "missing-prev", "missing-size", "offset", "width", "stride", "arch", "empty", "too-many", "base", "empty-range", "start-alignment", "end-alignment", "top-low", "top-end", "top-alignment", "overlap", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			input, fixture := heapVisualTestInput(context.Background(), 0x1000, heapVisualTestChunk(0x21))
			extents := []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1020, Top: 0x1000}}
			switch name {
			case "nil-reader":
				input.reader = nil
			case "nil-context":
				input.reader.ctx = nil
			case "nil-session":
				input.reader.session = nil
			case "missing-prev":
				delete(input.layout.Chunk.Fields, "mchunk_prev_size")
			case "missing-size":
				delete(input.layout.Chunk.Fields, "mchunk_size")
			case "offset":
				input.layout = heapGraphTestLayout()
			case "width":
				input.layout.Chunk.Fields["mchunk_size"] = inspect.HeapField{Offset: 8, Width: 4, Count: 1, Stride: 4}
			case "stride":
				input.layout.Chunk.Fields["mchunk_size"] = inspect.HeapField{Offset: 8, Width: 8, Count: 1, Stride: 16}
			case "arch":
				input.layout.Arch = "aarch64"
			case "empty":
				extents = nil
			case "too-many":
				extents = make([]heapVisualExtent, heapGraphMaxArenas+1)
			case "base":
				extents[0].Base = 0x1001
			case "empty-range":
				extents[0].End = 0x1000
			case "start-alignment":
				extents[0].Start++
			case "end-alignment":
				extents[0].End++
			case "top-low":
				extents[0].Top = 0xff0
			case "top-end":
				extents[0].Top = 0x1020
			case "top-alignment":
				extents[0].Top = 0x1001
			case "overlap":
				extents = append(extents, heapVisualExtent{Base: 0x1000, Start: 0x1010, End: 0x1030})
			case "duplicate":
				extents = append(extents, extents[0])
			}
			observation, err := collectHeapVisual(input, extents, nil)
			if err == nil || len(observation.extents) != 0 || len(fixture.stackCalls) != 0 {
				t.Fatalf("error=%v observation=%+v reads=%v", err, observation, fixture.stackCalls)
			}
		})
	}
}

func TestHeapVisualSourceFencepostStopsBeforeForeignGap(t *testing.T) {
	for _, top := range []target.Address{0, 0x1100} {
		for _, flag := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("top_%x/P_%d", top, flag), func(t *testing.T) {
				data := append(heapVisualTestChunk(0x21), heapVisualTestChunk(0x10|flag)...)
				input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
				observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1200, Top: top}}, nil)
				if !errors.Is(err, target.ErrUnavailable) || len(observation.extents[0].chunks) != 2 || observation.extents[0].complete || len(fixture.stackCalls) != 3 {
					t.Fatalf("error=%v observation=%+v calls=%v", err, observation, fixture.stackCalls)
				}
				output := heapVisualTestRender(t, observation)
				for _, want := range []string{"| <- boundary", "foreign sbrk gap", "not fully inspected", fmt.Sprintf("0x%016x", uint64(16)+flag)} {
					if !strings.Contains(output, want) {
						t.Fatalf("missing %q:\n%s", want, output)
					}
				}
				if strings.Contains(output, "corrupt") || fixture.stackCalls[2].address != 0x1020 || fixture.stackCalls[2].size != 16 {
					t.Fatalf("scanned or guessed after fencepost: %s %+v", output, fixture.stackCalls)
				}
			})
		}
	}
}

func heapVisualTestRetiredInput(ctx context.Context, predecessor, flag uint64) (heapGraphInput, *inspectionReadFixture, []heapVisualExtent) {
	old := append(heapVisualTestChunk(0x21), heapVisualTestChunk(predecessor|flag)...)
	terminal := heapVisualTestChunk(1)
	binary.LittleEndian.PutUint64(terminal, predecessor)
	old = append(old, terminal...)
	data := make([]byte, 0x2000+len(old))
	copy(data, heapVisualTestChunk(0x41))
	copy(data[0x2000:], old)
	input, fixture := heapVisualTestInput(ctx, 0x1000, data)
	end := target.Address(0x3000 + len(old))
	return input, fixture, []heapVisualExtent{
		{Base: 0x3000, Start: 0x3000, End: end, Arena: 0x9000, TerminalFencepost: end - 16, Label: "older proven heap_info"},
		{Base: 0x1000, Start: 0x1000, End: 0x1040, Top: 0x1000, Arena: 0x9000, Label: "current proven heap_info"},
	}
}

func TestHeapVisualValidatedHeapInfoTailContinuesToSuppliedCurrentTop(t *testing.T) {
	for _, predecessor := range []uint64{16, 32} {
		for _, flag := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("size_%d/P_%d", predecessor, flag), func(t *testing.T) {
				input, fixture, extents := heapVisualTestRetiredInput(context.Background(), predecessor, flag)
				observation, err := collectHeapVisual(input, extents, nil)
				if err != nil || len(observation.extents) != 2 || !observation.extents[0].complete || !observation.extents[1].complete || len(observation.extents[0].chunks) != 3 || len(observation.extents[1].chunks) != 1 {
					t.Fatalf("error=%v observation=%+v", err, observation)
				}
				if observation.extents[1].chunks[0].address != 0x1000 || !observation.extents[1].chunks[0].top || observation.extents[1].chunks[0].ordinal != 3 || input.reader.nodes != 4 || input.reader.bytes != 32+predecessor+16+64 {
					t.Fatalf("current top skipped or ordinals reset: reader=%+v observation=%+v", input.reader, observation)
				}
				for _, call := range fixture.stackCalls {
					inside := false
					for _, extent := range extents {
						inside = inside || call.address >= extent.Start && call.address+target.Address(call.size) <= extent.End
					}
					if !inside || call.token != fixture.snapshot.Memory {
						t.Fatalf("scanned between supplied extents: %+v", call)
					}
				}
				output := heapVisualTestRender(t, observation)
				for _, want := range []string{"| <- fencepost", "0x0000000000000001", "0x0000000000003000|", "0x0000000000001000|", "| <- top"} {
					if !strings.Contains(output, want) {
						t.Fatalf("missing %q:\n%s", want, output)
					}
				}
			})
		}
	}
}

func TestHeapVisualTerminalFencepostRequiresProvenGeometryAndContinuation(t *testing.T) {
	for _, mode := range []string{"last-extent", "missing-current-top", "other-arena", "zero-arena", "wrong-terminal", "top-and-terminal", "short-tail"} {
		t.Run(mode, func(t *testing.T) {
			input, fixture, extents := heapVisualTestRetiredInput(context.Background(), 16, 0)
			switch mode {
			case "last-extent":
				extents = extents[:1]
			case "missing-current-top":
				extents[1].Top = 0
			case "other-arena":
				extents[1].Arena++
			case "zero-arena":
				extents[0].Arena, extents[1].Arena = 0, 0
			case "wrong-terminal":
				extents[0].TerminalFencepost -= 16
			case "top-and-terminal":
				extents[0].Top = extents[0].Start
			case "short-tail":
				extents[0].Start = extents[0].TerminalFencepost
			}
			observation, err := collectHeapVisual(input, extents, nil)
			if !errors.Is(err, target.ErrInvalidArgument) || len(observation.extents) != 0 || len(fixture.stackCalls) != 0 {
				t.Fatalf("unproven continuation: error=%v reads=%v observation=%+v", err, fixture.stackCalls, observation)
			}
		})
	}
}

func TestHeapVisualMalformedOrUnprovenTailNeverSkipsToCurrentTop(t *testing.T) {
	for _, mode := range []string{"no-marker", "footer-mismatch", "terminal-size", "predecessor-flags", "predecessor-crosses-terminal", "misplaced-boundary", "terminal-partial", "terminal-stale", "current-node-budget", "current-byte-budget", "current-read-error"} {
		t.Run(mode, func(t *testing.T) {
			input, fixture, extents := heapVisualTestRetiredInput(context.Background(), 16, 0)
			baseRead := fixture.readRaw
			terminal := extents[0].TerminalFencepost
			fixture.readRaw = func(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
				n, err := baseRead(token, address, dst)
				switch mode {
				case "footer-mismatch":
					if address == terminal {
						binary.LittleEndian.PutUint64(dst, 32)
					}
				case "terminal-size":
					if address == terminal {
						binary.LittleEndian.PutUint64(dst[8:], 0x11)
					}
				case "predecessor-flags":
					if address == terminal-16 {
						binary.LittleEndian.PutUint64(dst[8:], 0x15)
					}
				case "predecessor-crosses-terminal":
					if address == terminal-16 {
						binary.LittleEndian.PutUint64(dst[8:], 0x21)
					}
				case "misplaced-boundary":
					if address == extents[0].Start {
						binary.LittleEndian.PutUint64(dst[8:], 0x11)
					}
				case "terminal-partial":
					if address == terminal {
						return 7, io.ErrUnexpectedEOF
					}
				case "terminal-stale":
					if address == terminal {
						return n, target.ErrStale
					}
				case "current-read-error":
					if address == extents[1].Start {
						return 0, target.ErrUnavailable
					}
				}
				return n, err
			}
			if mode == "no-marker" {
				extents[0].TerminalFencepost = 0
			}
			if mode == "current-node-budget" {
				input.reader.nodes = heapGraphMaxNodes - 3
			}
			if mode == "current-byte-budget" {
				input.reader.bytes = heapGraphMaxBytes - uint64(extents[0].End-extents[0].Start)
			}
			observation, err := collectHeapVisual(input, extents, nil)
			if err == nil {
				t.Fatalf("skipped current top successfully: %+v", observation)
			}
			if mode == "terminal-stale" {
				if !errors.Is(err, target.ErrStale) || !reflect.DeepEqual(observation, heapVisualObservation{}) {
					t.Fatalf("stale prefix retained: %v %+v", err, observation)
				}
				return
			}
			if len(observation.extents) != 2 || observation.extents[1].complete {
				t.Fatalf("current top silently skipped: %v %+v", err, observation)
			}
			if !strings.HasPrefix(mode, "current-") {
				for _, call := range fixture.stackCalls {
					if call.address < 0x3000 {
						t.Fatalf("continued after unconfirmed tail: %+v error=%v", call, err)
					}
				}
			}
			output := heapVisualTestRender(t, observation)
			if !strings.Contains(output, "[0x0000000000001000, 0x0000000000001040) is not fully inspected") || !strings.Contains(output, "incomplete") || strings.Contains(output, "| <- top") {
				t.Fatal(output)
			}
		})
	}
}

func TestHeapVisualZeroOptionalAddressesNeverBecomeMarkers(t *testing.T) {
	input, _ := heapVisualTestInput(context.Background(), 0, heapVisualTestChunk(0x21))
	observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0, Start: 0, End: 32}}, nil)
	if err != nil || !observation.extents[0].complete || observation.extents[0].chunks[0].top || observation.extents[0].chunks[0].terminal {
		t.Fatalf("zero marker misclassified: error=%v observation=%+v", err, observation)
	}
}

func TestHeapVisualInvalidSizesDoNotTraverseOrDecodePayload(t *testing.T) {
	for _, test := range []struct {
		name       string
		start, end target.Address
		top        target.Address
		raw        uint64
		want       error
	}{
		{"zero-cycle", 0x1000, 0x2000, 0, 1, target.ErrInvalidState},
		{"undersized", 0x1000, 0x2000, 0, 9, target.ErrInvalidState},
		{"unaligned", 0x1000, 0x2000, 0, 0x29, target.ErrInvalidState},
		{"mmapped", 0x1000, 0x2000, 0, 0x23, target.ErrInvalidState},
		{"non-source-fence", 0x1000, 0x2000, 0, 0x15, target.ErrInvalidState},
		{"fence-at-top", 0x1000, 0x2000, 0x1000, 0x11, target.ErrInvalidState},
		{"range", 0x1000, 0x1020, 0, 0x41, target.ErrInvalidState},
		{"passes-top", 0x1000, 0x1100, 0x1020, 0x41, target.ErrInvalidState},
		{"overflow-cycle", target.Address(math.MaxUint64 - 31), target.Address(math.MaxUint64 - 15), 0, 0x41, target.ErrOverflow},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, 16)
			binary.LittleEndian.PutUint64(data[8:], test.raw)
			input, fixture := heapVisualTestInput(context.Background(), test.start, data)
			observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: test.start, Start: test.start, End: test.end, Top: test.top}}, nil)
			if !errors.Is(err, test.want) || len(fixture.stackCalls) != 1 || len(observation.extents) != 1 || len(observation.extents[0].chunks) != 1 || observation.extents[0].complete {
				t.Fatalf("error=%v calls=%v observation=%+v", err, fixture.stackCalls, observation)
			}
			output := heapVisualTestRender(t, observation)
			if strings.Contains(output, "corrupt") || !strings.Contains(output, "incomplete") {
				t.Fatal(output)
			}
		})
	}
}

func TestHeapVisualNeverReadsSuccessorBeyondEndOrTop(t *testing.T) {
	for _, test := range []struct {
		name string
		top  target.Address
		end  target.Address
	}{
		{"non-top-end", 0, 0x1020},
		{"top-exact-end", 0x1000, 0x1020},
		{"top-before-end", 0x1000, 0x1100},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, fixture := heapVisualTestInput(context.Background(), 0x1000, heapVisualTestChunk(0x21))
			observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: test.end, Top: test.top}}, nil)
			if err != nil || len(fixture.stackCalls) != 2 || input.reader.bytes != 32 || !observation.extents[0].complete {
				t.Fatalf("error=%v reads=%v observation=%+v", err, fixture.stackCalls, observation)
			}
			output := heapVisualTestRender(t, observation)
			if observation.extents[0].chunks[0].nextInUse != -1 || strings.Contains(output, "in-use bit") || strings.Contains(output, "not traversed") {
				t.Fatal(output)
			}
		})
	}
}

func TestHeapVisualPartialHeaderAndPayloadNeverPadOrRetry(t *testing.T) {
	for _, stage := range []string{"header", "payload"} {
		for _, count := range []int{0, 1, 7, 8, 15, 16, 17, -1} {
			t.Run(fmt.Sprintf("%s_%d", stage, count), func(t *testing.T) {
				input, fixture := heapVisualTestInput(context.Background(), 0x1000, heapVisualTestChunk(0x21))
				baseRead := fixture.readRaw
				fixture.readRaw = func(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
					if stage == "header" && address == 0x1000 || stage == "payload" && address == 0x1010 {
						for index := range dst {
							dst[index] = 0xfe
						}
						return count, io.ErrUnexpectedEOF
					}
					return baseRead(token, address, dst)
				}
				observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1020, Top: 0x1000}}, nil)
				if err == nil || len(observation.extents) != 1 || observation.extents[0].complete {
					t.Fatalf("error=%v observation=%+v", err, observation)
				}
				wantCalls := 1
				if stage == "payload" {
					wantCalls = 2
				}
				if len(fixture.stackCalls) != wantCalls {
					t.Fatalf("retried partial read: %v", fixture.stackCalls)
				}
				output := heapVisualTestRender(t, observation)
				if stage == "header" && (strings.Contains(output, "| <- top") || !strings.Contains(output, "not decoded")) {
					t.Fatal(output)
				}
				if count > 0 && count < 8 && (!strings.Contains(output, "bytes["+strings.Repeat("fe", count)+"]") || strings.Contains(output, "0x00000000000000fe")) {
					t.Fatalf("partial word invented:\n%s", output)
				}
				if observation.extents[0].complete || !strings.Contains(output, "incomplete") {
					t.Fatal(output)
				}
			})
		}
	}
}

func TestHeapVisualFatalReadsDiscardEarlierObservations(t *testing.T) {
	for _, failure := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded, &heapGraphProofError{err: target.ErrUnavailable}} {
		for _, failAddress := range []target.Address{0x1000, 0x1010, 0x1020, 0x1030} {
			t.Run(fmt.Sprintf("%v_%x", failure, failAddress), func(t *testing.T) {
				data := append(heapVisualTestChunk(0x21), heapVisualTestChunk(0x21)...)
				input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
				baseRead := fixture.readRaw
				fixture.readRaw = func(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
					if address == failAddress {
						return len(dst), failure
					}
					return baseRead(token, address, dst)
				}
				observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1040, Top: 0x1020}}, nil)
				if !errors.Is(err, failure) || !reflect.DeepEqual(observation, heapVisualObservation{}) {
					t.Fatalf("error=%v retained observation=%+v", err, observation)
				}
			})
		}
	}
}

func TestHeapVisualSharedNodeAndByteBudgets(t *testing.T) {
	for _, mode := range []string{"node-before", "node-second", "byte-before", "byte-header-only", "byte-payload-prefix", "exact", "oversized-normal", "oversized-TOP"} {
		t.Run(mode, func(t *testing.T) {
			data := append(heapVisualTestChunk(0x21), heapVisualTestChunk(0x21)...)
			if strings.HasPrefix(mode, "oversized-") {
				data = heapVisualTestChunk(heapGraphMaxBytes + 33)
			}
			input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
			switch mode {
			case "node-before":
				input.reader.nodes = heapGraphMaxNodes
			case "node-second":
				input.reader.nodes = heapGraphMaxNodes - 1
			case "byte-before":
				input.reader.bytes = heapGraphMaxBytes
			case "byte-header-only":
				input.reader.bytes = heapGraphMaxBytes - 16
			case "byte-payload-prefix":
				input.reader.bytes = heapGraphMaxBytes - 23
			case "exact":
				input.reader.nodes = heapGraphMaxNodes - 2
				input.reader.bytes = heapGraphMaxBytes - 64
			}
			extent := heapVisualExtent{Base: 0x1000, Start: 0x1000, End: 0x1000 + target.Address(len(data))}
			if mode == "oversized-TOP" {
				extent.Top = 0x1000
			}
			observation, err := collectHeapVisual(input, []heapVisualExtent{extent}, nil)
			if mode == "exact" {
				if err != nil || !observation.extents[0].complete || input.reader.nodes != heapGraphMaxNodes || input.reader.bytes != heapGraphMaxBytes || input.reader.exhausted {
					t.Fatalf("exact budget error=%v reader=%+v observation=%+v", err, input.reader, observation)
				}
				return
			}
			if !errors.Is(err, target.ErrUnavailable) || !input.reader.exhausted || len(observation.extents) != 1 || observation.extents[0].complete || input.reader.bytes > heapGraphMaxBytes || input.reader.nodes > heapGraphMaxNodes {
				t.Fatalf("budget error=%v reader=%+v observation=%+v", err, input.reader, observation)
			}
			output := heapVisualTestRender(t, observation)
			if !strings.Contains(output, "incomplete") || strings.Contains(output, "payload bytes omitted by display limit") || strings.Contains(output, "payload=complete") {
				t.Fatal(output)
			}
			if mode == "byte-payload-prefix" && (len(fixture.stackCalls) != 2 || fixture.stackCalls[1].size != 7 || !strings.Contains(output, "7/16 requested bytes confirmed")) {
				t.Fatalf("prefix not retained: %v %s", fixture.stackCalls, output)
			}
		})
	}
}

func TestHeapVisualCachedPayloadDoesNotSpendBudgetTwice(t *testing.T) {
	input, fixture := heapVisualTestInput(context.Background(), 0x1000, heapVisualTestChunk(0x21))
	if _, err := input.reader.read(0x1010, 16); err != nil {
		t.Fatal(err)
	}
	input.reader.bytes = heapGraphMaxBytes - 16
	observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1020}}, nil)
	if err != nil || input.reader.bytes != heapGraphMaxBytes || len(fixture.stackCalls) != 2 || !observation.extents[0].complete {
		t.Fatalf("error=%v reader=%+v calls=%v", err, input.reader, fixture.stackCalls)
	}
}

type heapVisualCancelContext struct {
	context.Context
	checks int
	limit  int
}

func (ctx *heapVisualCancelContext) Err() error {
	ctx.checks++
	if ctx.checks >= ctx.limit {
		return context.Canceled
	}
	return nil
}

func TestHeapVisualCancellationDiscardsCollectionAndRenderedPrefix(t *testing.T) {
	for _, phase := range []string{"collect", "render"} {
		for _, limit := range []int{1, 2, 4, 8, 16, 32} {
			t.Run(fmt.Sprintf("%s_%d", phase, limit), func(t *testing.T) {
				ctx := &heapVisualCancelContext{Context: context.Background(), limit: limit}
				input, _ := heapVisualTestInput(context.Background(), 0x1000, heapVisualTestChunk(0x1001))
				if phase == "collect" {
					input.reader.ctx = ctx
				}
				observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x2000}}, nil)
				if phase == "collect" {
					if ctx.checks >= limit && (!errors.Is(err, context.Canceled) || !reflect.DeepEqual(observation, heapVisualObservation{})) {
						t.Fatalf("cancellation retained observations: error=%v observation=%+v", err, observation)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				output, err := renderHeapVisual(ctx, observation, display.Renderer{})
				if !errors.Is(err, context.Canceled) || output != "" {
					t.Fatalf("render cancellation: error=%v prefix=%q", err, output)
				}
			})
		}
	}
}

func TestHeapVisualExactRowCompressionAndControlSafety(t *testing.T) {
	data := heapVisualTestChunk(0x101)
	copy(data[16:32], []byte("ABCD\x1b\x00\xff\nABCDEFGH"))
	copy(data[32:48], data[16:32])
	copy(data[48:64], data[16:32])
	copy(data[64:80], data[16:32])
	data[79] = '!'
	input, _ := heapVisualTestInput(context.Background(), 0x1000, data)
	members := map[target.Address][]heapVisualMembership{0x1000: {{Label: "free\x1b[2J\nspoof", Complete: true}, {Label: "second", Complete: false}}}
	observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1100, Label: "heap\nspoof"}}, members)
	if err != nil {
		t.Fatal(err)
	}
	plain := heapVisualTestRender(t, observation)
	for _, want := range []string{"* 2 lines, 0x20 bytes", "0x0000000000001040|+0x00040", "ABCD....ABCDEFGH", "ABCD....ABCDEFG!", "| <- free\\x1b[2J\\nspoof, second (incomplete list)"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "\x1b") || strings.Contains(plain, "\nspoof") || strings.Contains(plain, "in-use bit") {
		t.Fatal(plain)
	}
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	colored, err := renderHeapVisual(context.Background(), observation, renderer)
	if err != nil || !strings.Contains(colored, "\x1b[") || regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(colored, "") != plain {
		t.Fatalf("color changed facts: error=%v output=%q", err, colored)
	}
	renderer, err = display.NewRenderer(display.Options{Mode: display.ColorAuto, IsTerminal: true, Term: "xterm", NoColor: "1"})
	if err != nil {
		t.Fatal(err)
	}
	withoutColor, err := renderHeapVisual(context.Background(), observation, renderer)
	if err != nil || withoutColor != plain {
		t.Fatalf("NO_COLOR changed facts: error=%v output=%q", err, withoutColor)
	}
}

func TestHeapVisualNormalPayloadBeyondOldPreviewIsRetained(t *testing.T) {
	for _, top := range []target.Address{0, 0x1000} {
		t.Run(fmt.Sprintf("top_%x", top), func(t *testing.T) {
			data := heapVisualTestChunk(0x1001)
			binary.LittleEndian.PutUint64(data[0x708:], 0x8877665544332211)
			input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
			observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x2000, Top: top}}, nil)
			if err != nil || input.reader.bytes != 0x1000 || len(fixture.stackCalls) != 2 || fixture.stackCalls[1].size != 0xff0 {
				t.Fatalf("payload truncated: error=%v calls=%v bytes=%d", err, fixture.stackCalls, input.reader.bytes)
			}
			output := heapVisualTestRender(t, observation)
			if !strings.Contains(output, "0x0000000000001700|+0x00700") || !strings.Contains(output, "0x8877665544332211") || strings.Contains(output, "payload bytes omitted") {
				t.Fatal(output)
			}
		})
	}
}

func TestHeapVisualPaletteUsesVisualOrdinalForWholeRows(t *testing.T) {
	var data []byte
	for index := 0; index < 7; index++ {
		data = append(data, heapVisualTestChunk(0x51)...)
	}
	input, _ := heapVisualTestInput(context.Background(), 0x1000, data)
	input.reader.nodes = 29
	observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1230}}, map[target.Address][]heapVisualMembership{0x1000: {{Label: "tcache[0]", Complete: true}}})
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	colored, err := renderHeapVisual(context.Background(), observation, renderer)
	if err != nil {
		t.Fatal(err)
	}
	styles := []display.Style{display.StyleRed, display.StyleGreen, display.StyleYellow, display.StyleBlue, display.StylePurple, display.StyleCyan, display.StyleRed}
	plain := heapVisualTestRender(t, observation)
	for index, style := range styles {
		if observation.extents[0].chunks[index].ordinal != index {
			t.Fatalf("bin budget shifted visual ordinal: %+v", observation.extents[0].chunks[index])
		}
		address := target.Address(0x1000 + index*0x50)
		for _, line := range strings.Split(plain, "\n") {
			if strings.HasPrefix(line, fmt.Sprintf("0x%016x|", address)) || strings.HasPrefix(line, fmt.Sprintf("0x%016x|", address+16)) || line == "    * 3 lines, 0x30 bytes" {
				painted := renderer.Text(style, line)
				if !strings.Contains(colored, painted+"\n") || strings.Count(painted, "\x1b[") != 2 {
					t.Fatalf("row not painted once with chunk style: %q\n%s", painted, colored)
				}
			}
		}
	}
	if strings.Contains(plain, "list complete") || strings.Contains(plain, "; observed") || !strings.Contains(plain, "| <- tcache[0]") || strings.Contains(plain, "observed list links") {
		t.Fatal(plain)
	}
}

func TestHeapVisualContainsOnlyRowsAndAnnotations(t *testing.T) {
	data := append(heapVisualTestChunk(0x41), heapVisualTestChunk(0x41)...)
	input, _ := heapVisualTestInput(context.Background(), 0x1000, data)
	input.proof = "internal provenance"
	observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: 0xffd, Start: 0x1000, End: 0x1080, Top: 0x1040, Arena: 0x9000, Label: "internal extent label"}}, map[target.Address][]heapVisualMembership{0x1000: {{Label: "tcache[0x40]", Complete: true}}})
	if err != nil {
		t.Fatal(err)
	}
	output := heapVisualTestRender(t, observation)
	want := "0x0000000000001000|+0x00000|+0x00003: 0x0000000000000000 0x0000000000000041 | ........A....... |\n" +
		"0x0000000000001010|+0x00010|+0x00013: 0x4847464544434241 0x504f4e4d4c4b4a49 | ABCDEFGHIJKLMNOP | <- tcache[0x40]\n" +
		"    * 2 lines, 0x20 bytes\n" +
		"0x0000000000001040|+0x00000|+0x00043: 0x0000000000000000 0x0000000000000041 | ........A....... |\n" +
		"0x0000000000001050|+0x00010|+0x00053: 0x4847464544434241 0x504f4e4d4c4b4a49 | ABCDEFGHIJKLMNOP | <- top\n" +
		"    * 2 lines, 0x20 bytes\n"
	if output != want {
		t.Fatalf("unexpected visual heap output:\n%s\nwant:\n%s", output, want)
	}
	for _, forbidden := range []string{"[visual-heap]", "heap[", "headers=", "complete=", "provenance", "payload-policy", "Membership", "Address", "internal"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("internal output %q: %s", forbidden, output)
		}
	}
}

func TestHeapVisualCompressionNeverMergesPartialRow(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 40)
	var output strings.Builder
	err := renderHeapVisualRows(context.Background(), &output, display.Renderer{}, heapVisualExtent{Base: 0x1000}, 0x1000, 16, data, "", true, display.StyleChanged)
	if err != nil || !strings.Contains(output.String(), "* 1 lines, 0x10 bytes") || !strings.Contains(output.String(), "0x0000000000001030|+0x00030") || !strings.Contains(output.String(), "0xabababababababab <unavailable>") {
		t.Fatalf("partial row compression: error=%v output=%s", err, output.String())
	}
}

func TestHeapVisualExtentOrderRemainsCallerDefined(t *testing.T) {
	data := append(heapVisualTestChunk(0x21), heapVisualTestChunk(0x21)...)
	input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
	extents := []heapVisualExtent{{Base: 0x1020, Start: 0x1020, End: 0x1040, Label: "second"}, {Base: 0x1000, Start: 0x1000, End: 0x1020, Label: "first"}}
	observation, err := collectHeapVisual(input, extents, nil)
	if err != nil || len(fixture.stackCalls) != 4 || fixture.stackCalls[0].address != 0x1020 || fixture.stackCalls[2].address != 0x1000 {
		t.Fatalf("error=%v calls=%v", err, fixture.stackCalls)
	}
	output := heapVisualTestRender(t, observation)
	if !strings.HasPrefix(output, "0x0000000000001020|") || strings.Index(output, "0x0000000000001000|") <= strings.Index(output, "0x0000000000001020|") {
		t.Fatal(output)
	}
}

func TestHeapVisualIncompletePrefixListsAllUnvisitedExtents(t *testing.T) {
	data := append(heapVisualTestChunk(1), make([]byte, 16)...)
	data = append(data, heapVisualTestChunk(0x21)...)
	input, fixture := heapVisualTestInput(context.Background(), 0x1000, data)
	extents := []heapVisualExtent{{Base: 0x1000, Start: 0x1000, End: 0x1020}, {Base: 0x1020, Start: 0x1020, End: 0x1040, Label: "unvisited"}}
	observation, err := collectHeapVisual(input, extents, nil)
	if !errors.Is(err, target.ErrInvalidState) || len(fixture.stackCalls) != 1 || len(observation.extents) != 2 {
		t.Fatalf("error=%v calls=%v observation=%+v", err, fixture.stackCalls, observation)
	}
	output := heapVisualTestRender(t, observation)
	if !strings.Contains(output, "[0x0000000000001020, 0x0000000000001040) is not fully inspected") {
		t.Fatal(output)
	}
}

func TestHeapVisualRendererEmptyAndFatalNeverPublishHeading(t *testing.T) {
	if text, err := renderHeapVisual(context.Background(), heapVisualObservation{}, display.Renderer{}); text != "" || err != nil {
		t.Fatalf("empty observation: text=%q error=%v", text, err)
	}
	for _, failure := range []error{target.ErrStale, context.Canceled, &heapGraphProofError{err: target.ErrUnavailable}} {
		text, err := renderHeapVisual(context.Background(), heapVisualObservation{proof: "unconfirmed", err: failure}, display.Renderer{})
		if text != "" || !errors.Is(err, failure) {
			t.Fatalf("fatal observation: text=%q error=%v", text, err)
		}
	}
}

type heapVisualRecordingSession struct {
	session
	calls []contextMemoryCall
}

func (session *heapVisualRecordingSession) ReadSpaceMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	session.calls = append(session.calls, contextMemoryCall{token: token, address: address, size: len(dst)})
	return session.session.ReadSpaceMemory(token, address, dst)
}

func TestHeapVisualNativeSmallChunkAtUnmappedGuardPage(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native visual-heap requires linux/amd64")
	}
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprintf("pie_%t", pie), func(t *testing.T) {
			executable, _ := heapDWARFCompileFixture(t, pie, false)
			var output bytes.Buffer
			controller := New(&output, display.Renderer{})
			t.Cleanup(func() {
				if err := controller.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := controller.Configure(executable, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, command := range [][2]string{{"break", "heap_probe"}, {"run", ""}} {
				if _, err := controller.Execute(ctx, command[0], command[1]); err != nil {
					t.Fatalf("%s: %v\n%s", command[0], err, output.String())
				}
			}
			snapshot, thread, err := controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			pointerAddress, err := controller.evaluate(ctx, "normal_chunk", snapshot, thread)
			if err != nil {
				t.Fatal(err)
			}
			var pointer [8]byte
			if n, err := controller.session.ReadSpaceMemory(snapshot.Memory, pointerAddress, pointer[:]); err != nil || n != 8 {
				t.Fatalf("pointer read n=%d error=%v", n, err)
			}
			address := target.Address(binary.LittleEndian.Uint64(pointer[:]))
			var oversized [48]byte
			if n, err := controller.session.ReadSpaceMemory(snapshot.Memory, address, oversized[:]); n != 32 || !errors.Is(err, target.ErrPartial) {
				t.Fatalf("guard page not established: n=%d error=%v", n, err)
			}
			recording := &heapVisualRecordingSession{session: controller.session}
			input := heapGraphInput{layout: heapVisualTestLayout(), proof: "explicit 32-byte guarded fixture", reader: newHeapGraphReader(ctx, recording, snapshot.Memory)}
			observation, err := collectHeapVisual(input, []heapVisualExtent{{Base: address, Start: address, End: address + 32, Top: address, Label: "guard"}}, nil)
			if err != nil || !observation.extents[0].complete || len(recording.calls) != 2 || input.reader.bytes != 32 {
				t.Fatalf("guarded collection: error=%v calls=%v", err, recording.calls)
			}
			for _, call := range recording.calls {
				if call.size != 16 || call.token != snapshot.Memory || call.address < address || call.address+target.Address(call.size) > address+32 {
					t.Fatalf("read outside exact chunk: %+v", call)
				}
			}
			if text := heapVisualTestRender(t, observation); !strings.Contains(text, "| <- top") || !strings.Contains(text, "0x0000000000000021") || strings.Contains(text, "complete=") {
				t.Fatal(text)
			}
			after, err := controller.session.Snapshot()
			if err != nil || after.Sequence != snapshot.Sequence || after.Memory != snapshot.Memory {
				t.Fatalf("read mutated tracee: error=%v before=%+v after=%+v", err, snapshot, after)
			}
		})
	}
}
