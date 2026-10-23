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
	"strings"
	"testing"

	"fastdbg2/target"
)

func heapLayoutTestWords(words ...uint64) []byte {
	data := make([]byte, len(words)*8)
	for i, word := range words {
		binary.LittleEndian.PutUint64(data[i*8:], word)
	}
	return data
}

func heapLayoutTestController() (*Controller, *inspectionReadFixture, *bytes.Buffer) {
	controller, fixture, output := newInspectionTestController()
	fixture.stack = heapLayoutTestWords(0x10, 0x47, 0x1122334455667788, 0xffeeddccbbaa9988, 0x0102030405060708, 0x0807060504030201)
	return controller, fixture, output
}

func TestHeapLayoutArgumentSyntax(t *testing.T) {
	for _, test := range []struct {
		input       string
		visual      bool
		expressions []string
		words       int
	}{
		{"--layout glibc-amd64 0x1000", false, []string{"0x1000"}, 0},
		{"--layout glibc-amd64 --words 4 $rsp - 16", false, []string{"$rsp - 16"}, 4},
		{"--words 0 --layout glibc-amd64 `symbol  with spaces` + 8", false, []string{"`symbol  with spaces` + 8"}, 0},
		{"--layout glibc-amd64 -- 0x1000", false, []string{"0x1000"}, 0},
		{"--layout glibc-amd64 0x1000 0x2000", true, []string{"0x1000", "0x2000"}, 0},
		{"--layout glibc-amd64 '$rsp + 32' \"$rsp + 64\"", true, []string{"$rsp + 32", "$rsp + 64"}, 0},
		{"--layout glibc-amd64 -- '`a b`' '`a b` + 32'", true, []string{"`a b`", "`a b` + 32"}, 0},
	} {
		t.Run(fmt.Sprintf("%t/%s", test.visual, test.input), func(t *testing.T) {
			arguments, err := parseHeapLayoutArguments(test.input, test.visual)
			if err != nil || arguments.words != test.words || !reflect.DeepEqual(arguments.expressions, test.expressions) {
				t.Fatalf("arguments=%+v error=%v", arguments, err)
			}
		})
	}
}

func TestHeapLayoutInvalidArgumentsNeverInspectTarget(t *testing.T) {
	for _, test := range []struct {
		input  string
		visual bool
		err    error
	}{
		{"", false, target.ErrUnsupported},
		{"0x1000", false, target.ErrUnsupported},
		{"--layout musl-amd64 0x1000", false, target.ErrUnsupported},
		{"--layout", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --layout glibc-amd64 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words 1 --words 2 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words -1 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words +1 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words 0x1 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words 5 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words 18446744073709551616 0x1000", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words", false, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --bad 1 0x1000", false, target.ErrInvalidArgument},
		{"", true, target.ErrUnsupported},
		{"0x1000 0x2000", true, target.ErrUnsupported},
		{"--layout glibc-amd64", true, target.ErrInvalidArgument},
		{"--layout glibc-amd64 0x1000", true, target.ErrInvalidArgument},
		{"--layout glibc-amd64 0x1000 0x2000 0x3000", true, target.ErrInvalidArgument},
		{"--layout glibc-amd64 --words 1 0x1000 0x2000", true, target.ErrInvalidArgument},
		{"--layout glibc-amd64 '' 0x2000", true, target.ErrInvalidArgument},
		{"--layout glibc-amd64 0x1000 '0x2000", true, target.ErrInvalidArgument},
		{"--layout glibc-amd64 0x1000 0x2000\x00", true, target.ErrInvalidArgument},
	} {
		t.Run(fmt.Sprintf("%t/%s", test.visual, test.input), func(t *testing.T) {
			if test.visual && test.input == "" {
				if _, err := parseHeapLayoutArguments(test.input, true); !errors.Is(err, test.err) {
					t.Fatalf("explicit layout parser error=%v", err)
				}
				return
			}
			controller, fixture, output := heapLayoutTestController()
			run := controller.showHeapChunk
			if test.visual {
				run = controller.showVisualHeap
			}
			err := run(context.Background(), test.input)
			if !errors.Is(err, test.err) || fixture.snapshotReads != 0 || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("error=%v snapshots=%d reads=%v output=%q", err, fixture.snapshotReads, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestHeapChunkExplicitRawLayoutAndWords(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	if err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 --words 4 0x1000"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[chunk]", "Layout     : glibc-amd64 (user-selected)", "allocation ownership and state are not determined",
		"header=0x0000000000001000", "+0x00 prev_size", "0x0000000000000010", "+0x08 raw_size", "0x0000000000000047",
		"+0x10 stored_word[0]", "0x1122334455667788", "+0x18 stored_word[1]", "0xffeeddccbbaa9988",
		"+0x20 stored_word[2]", "0x0102030405060708", "+0x28 stored_word[3]", "0x0807060504030201",
		"size=0x40 PREV_INUSE=1 IS_MMAPPED=1 NON_MAIN_ARENA=1 (raw bits)",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %q", want, output.String())
		}
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 0 || len(fixture.stackCalls) != 1 ||
		fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x1000, 48}) || len(fixture.codeCalls) != 0 {
		t.Fatalf("unexpected token reads: %+v", fixture)
	}
	for _, unwanted := range []string{"fd=", "bk=", "status=free", "status=allocated", "libc version", "arena="} {
		if strings.Contains(output.String(), unwanted) {
			t.Fatalf("inferred state %q in output=%q", unwanted, output.String())
		}
	}
}

func TestHeapChunkDefaultReadsOnlyHeader(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	if err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 $rsp + 16"); err != nil {
		t.Fatal(err)
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != fixture.snapshot.Threads[0].Token ||
		len(fixture.stackCalls) != 1 || fixture.stackCalls[0] != (contextMemoryCall{fixture.snapshot.Memory, 0x70000010, 16}) || strings.Contains(output.String(), "stored_word") {
		t.Fatalf("unexpected reads=%+v output=%q", fixture, output.String())
	}
}

func TestHeapChunkExtraWordsAreExplicitRawOffsetsNotOwnedPayload(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	binary.LittleEndian.PutUint64(fixture.stack[8:16], 0x21)
	if err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 --words 4 0x1000"); err != nil {
		t.Fatal(err)
	}
	if len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 48 ||
		!strings.Contains(output.String(), "+0x28 stored_word[3]") || !strings.Contains(output.String(), "size=0x20") ||
		!strings.Contains(output.String(), "Extra words are explicit raw reads at header+offset; no ownership within this chunk is asserted.") {
		t.Fatalf("reads=%v output=%q", fixture.stackCalls, output.String())
	}
}

func TestHeapChunkDeclaredSizeOverflowIsReportedAfterRawDisplay(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	fixture.stack = heapLayoutTestWords(0, 0xfffffffffffffff1)
	err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 0x1000")
	if !errors.Is(err, target.ErrOverflow) || len(fixture.stackCalls) != 1 ||
		!strings.Contains(output.String(), "0xfffffffffffffff1") || !strings.Contains(output.String(), "<structurally invalid layout>") {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestHeapChunkFlagsDoNotInferAllocationState(t *testing.T) {
	for flags := uint64(0); flags < 8; flags++ {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			fixture.stack = heapLayoutTestWords(math.MaxUint64, 0x40|flags)
			if err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 0x1000"); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("size=0x40 PREV_INUSE=%d IS_MMAPPED=%d NON_MAIN_ARENA=%d (raw bits)", flags&1, flags>>1&1, flags>>2&1)
			if !strings.Contains(output.String(), want) || !strings.Contains(output.String(), "0xffffffffffffffff") {
				t.Fatalf("output=%q", output.String())
			}
		})
	}
}

func TestHeapChunkStructurallyInvalidDataStillDisplayedAsRaw(t *testing.T) {
	for _, test := range []struct {
		address uint64
		rawSize uint64
	}{
		{0x1000, 0}, {0x1000, 7}, {0x1000, 0x11}, {0x1000, 0x29}, {0x1008, 0x41},
	} {
		t.Run(fmt.Sprintf("%x/%x", test.address, test.rawSize), func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			fixture.stack = heapLayoutTestWords(0x12345678, test.rawSize)
			err := controller.showHeapChunk(context.Background(), fmt.Sprintf("--layout glibc-amd64 %#x", test.address))
			if !errors.Is(err, target.ErrInvalidArgument) || !strings.Contains(output.String(), fmt.Sprintf("0x%016x", test.rawSize)) ||
				!strings.Contains(output.String(), "<structurally invalid layout>") || len(fixture.stackCalls) != 1 {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestHeapChunkPartialBytesAreNeverPadded(t *testing.T) {
	for _, n := range []int{0, 1, 7, 8, 9, 12, 15, 16, 17, 23} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			fixture.stack = heapLayoutTestWords(0x1122334455667788, 0x47, 0xffeeddccbbaa9988)[:n]
			fixture.stackErr = io.ErrUnexpectedEOF
			err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 --words 1 0x1000")
			if !errors.Is(err, io.ErrUnexpectedEOF) || n > 0 && !errors.Is(err, target.ErrPartial) || len(fixture.stackCalls) != 1 {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
			if strings.Contains(output.String(), "size=0x40 PREV_INUSE") != (n >= 16) || strings.Contains(output.String(), "0x1122334455667788") != (n >= 8) || strings.Contains(output.String(), "0xffeeddccbbaa9988") {
				t.Fatalf("unconfirmed value output=%q", output.String())
			}
			if strings.Contains(output.String(), "<partial bytes:") != (n%8 != 0) {
				t.Fatalf("missing partial marker output=%q", output.String())
			}
		})
	}
}

func TestHeapChunkReadOverflowAndUnsupportedTargets(t *testing.T) {
	for _, test := range []struct {
		name string
		args string
		edit func(*inspectionReadFixture)
		err  error
	}{
		{"overflow-header", "--layout glibc-amd64 0xfffffffffffffff1", nil, target.ErrOverflow},
		{"overflow-words", "--layout glibc-amd64 --words 1 0xfffffffffffffff0", nil, target.ErrOverflow},
		{"architecture", "--layout glibc-amd64 0x1000", func(f *inspectionReadFixture) { f.snapshot.Architecture = target.AArch64 }, target.ErrUnsupported},
		{"memory-token", "--layout glibc-amd64 0x1000", func(f *inspectionReadFixture) { f.snapshot.Memory.Revision = 0 }, target.ErrUnavailable},
		{"running", "--layout glibc-amd64 0x1000", func(f *inspectionReadFixture) { f.snapshot.State = target.StateRunning }, target.ErrInvalidState},
		{"listening", "--layout glibc-amd64 0x1000", func(f *inspectionReadFixture) { f.snapshot.Threads[0].Listening = true }, target.ErrInvalidState},
		{"bad-expression", "--layout glibc-amd64 0x1000 4", nil, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			if test.edit != nil {
				test.edit(fixture)
			}
			err := controller.showHeapChunk(context.Background(), test.args)
			if !errors.Is(err, test.err) || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestVisualHeapExplicitRangeAndOneSnapshot(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	start := target.Address(0x70000000)
	headers := map[target.Address][]byte{
		start:        heapLayoutTestWords(0xdeadbeef, 0x21),
		start + 0x20: heapLayoutTestWords(0x20, 0x37),
		start + 0x50: heapLayoutTestWords(0x30, 0x40),
	}
	fixture.readRaw = func(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
		data, ok := headers[address]
		if !ok || len(dst) != heapLayoutHeaderSize || token != fixture.snapshot.Memory {
			t.Fatalf("unexpected read token=%+v address=%#x count=%d", token, address, len(dst))
		}
		return copy(dst, data), nil
	}
	if err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 '$rsp' '$rsp + 0x90'"); err != nil {
		t.Fatal(err)
	}
	if fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 || len(fixture.stackCalls) != 3 ||
		!strings.Contains(output.String(), "headers=3 covered=0x90") || !strings.Contains(output.String(), "P=1 M=1 A=1") ||
		!strings.Contains(output.String(), "Layout     : glibc-amd64 (user-selected)") {
		t.Fatalf("reads=%+v output=%q", fixture, output.String())
	}
}

func TestVisualHeapRejectsInvalidRangeBeforeMemory(t *testing.T) {
	for _, input := range []string{
		"0x1000 0x1000", "0x2000 0x1000", "0x1001 0x2000", "0x1000 0x2001", "0 0x100010",
		"0xfffffffffffffff0 '0xfffffffffffffff0 + 32'",
	} {
		t.Run(input, func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 "+input)
			if err == nil || len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestVisualHeapRejectsMalformedTraversalWithoutLoopOrOutOfRangeRead(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   string
		rawSize uint64
		err     error
	}{
		{"zero-progress", "0x1000 0x1040", 1, target.ErrInvalidArgument},
		{"too-small", "0x1000 0x1040", 0x11, target.ErrInvalidArgument},
		{"unaligned-size", "0x1000 0x1040", 0x29, target.ErrInvalidArgument},
		{"past-end", "0x1000 0x1030", 0x41, target.ErrInvalidArgument},
		{"fencepost", "0x1000 0x1010", 0x21, target.ErrInvalidArgument},
		{"wrap", "0xffffffffffffffe0 0xfffffffffffffff0", 0x41, target.ErrOverflow},
		{"huge-size", "0x1000 0x1040", 0xfffffffffffffff1, target.ErrOverflow},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			fixture.stack = heapLayoutTestWords(0, test.rawSize)
			err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 "+test.input)
			if !errors.Is(err, test.err) || len(fixture.stackCalls) != 1 || fixture.stackCalls[0].size != 16 ||
				!strings.Contains(output.String(), "<structurally invalid range/layout>") || strings.Contains(output.String(), "\nheaders=") {
				t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
			}
		})
	}
}

func TestVisualHeapMaximumChunksAndBytes(t *testing.T) {
	for _, count := range []int{heapLayoutMaxChunks, heapLayoutMaxChunks + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			fixture.stack = heapLayoutTestWords(0, 0x21)
			err := controller.showVisualHeap(context.Background(), fmt.Sprintf("--layout glibc-amd64 0 %#x", count*32))
			if len(fixture.stackCalls) != heapLayoutMaxChunks || count == heapLayoutMaxChunks && err != nil || count > heapLayoutMaxChunks && !errors.Is(err, target.ErrUnavailable) {
				t.Fatalf("error=%v reads=%d", err, len(fixture.stackCalls))
			}
			if strings.Contains(output.String(), "headers=4096 covered=") != (count == heapLayoutMaxChunks) {
				t.Fatalf("completion mismatch count=%d", count)
			}
			for i, call := range fixture.stackCalls {
				if call.address != target.Address(i*32) || call.size != heapLayoutHeaderSize || call.token != fixture.snapshot.Memory {
					t.Fatalf("unexpected read #%d: %+v", i, call)
				}
			}
		})
	}
	controller, fixture, output := heapLayoutTestController()
	fixture.stack = heapLayoutTestWords(0, heapLayoutMaxBytes|1)
	if err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 0 0x100000"); err != nil || len(fixture.stackCalls) != 1 || !strings.Contains(output.String(), "headers=1 covered=0x100000") {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestVisualHeapPartialSecondHeaderStopsAtConfirmedPrefix(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if address == 0x1000 {
			return copy(dst, heapLayoutTestWords(0, 0x21)), nil
		}
		return copy(dst, []byte{0x11, 0x22, 0x33}), io.ErrUnexpectedEOF
	}
	err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 0x1000 0x1060")
	if !errors.Is(err, target.ErrPartial) || len(fixture.stackCalls) != 2 || !strings.Contains(output.String(), "0x0000000000001020 <partial header bytes: 11 22 33>") ||
		strings.Count(output.String(), "raw_size=") != 1 || strings.Contains(output.String(), "0x0000000000001040") || strings.Contains(output.String(), "headers=2 covered=") {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestVisualHeapStaleSecondHeaderDoesNotRetryOrRenderStaleBytes(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	fixture.readRaw = func(_ target.MemoryToken, address target.Address, dst []byte) (int, error) {
		if address == 0x1000 {
			return copy(dst, heapLayoutTestWords(0, 0x21)), nil
		}
		return copy(dst, heapLayoutTestWords(0xdeadbeef, 0x41)), target.ErrStale
	}
	err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 0x1000 0x1060")
	if !errors.Is(err, target.ErrStale) || fixture.snapshotReads != 1 || len(fixture.stackCalls) != 2 ||
		strings.Count(output.String(), "raw_size=") != 1 || strings.Contains(output.String(), "deadbeef") ||
		strings.Contains(output.String(), "\nheaders=") {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestVisualHeapFullReadWithErrorRendersConfirmedHeaderButDoesNotContinue(t *testing.T) {
	controller, fixture, output := heapLayoutTestController()
	fixture.stackErr = io.ErrUnexpectedEOF
	err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 0x1000 0x1080")
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(fixture.stackCalls) != 1 ||
		strings.Count(output.String(), "raw_size=") != 1 || strings.Contains(output.String(), "\nheaders=") {
		t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
	}
}

func TestHeapLayoutStaleAndInvalidReadCounts(t *testing.T) {
	for _, visual := range []bool{false, true} {
		for _, test := range []struct {
			name  string
			count int
			err   error
			want  error
		}{
			{"stale-full", 16, target.ErrStale, target.ErrStale},
			{"stale-partial", 8, target.ErrStale, target.ErrStale},
			{"negative", -1, nil, target.ErrUnknown},
			{"too-large", 17, nil, target.ErrUnknown},
			{"short-nil", 8, nil, io.ErrUnexpectedEOF},
		} {
			t.Run(fmt.Sprintf("%t/%s", visual, test.name), func(t *testing.T) {
				controller, fixture, output := heapLayoutTestController()
				fixture.stackCount, fixture.stackErr = &test.count, test.err
				var err error
				if visual {
					err = controller.showVisualHeap(context.Background(), "--layout glibc-amd64 0x1000 0x1040")
				} else {
					err = controller.showHeapChunk(context.Background(), "--layout glibc-amd64 0x1000")
				}
				if !errors.Is(err, test.want) || len(fixture.stackCalls) != 1 || fixture.snapshotReads != 1 || strings.Contains(output.String(), "raw_size=") || strings.Contains(output.String(), "size=0x40") {
					t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
				}
				if errors.Is(test.err, target.ErrStale) && strings.Contains(output.String(), "0x0000000000000010") {
					t.Fatalf("stale bytes leaked: %q", output.String())
				}
			})
		}
	}
}

func TestHeapLayoutCancellationAndOutputErrors(t *testing.T) {
	commands := []struct {
		name string
		run  func(*Controller, context.Context) error
	}{
		{"chunk", func(c *Controller, ctx context.Context) error {
			return c.showHeapChunk(ctx, "--layout glibc-amd64 0x1000")
		}},
		{"visual", func(c *Controller, ctx context.Context) error {
			return c.showVisualHeap(ctx, "--layout glibc-amd64 0x1000 0x1080")
		}},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			t.Run("canceled-before", func(t *testing.T) {
				controller, fixture, output := heapLayoutTestController()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := command.run(controller, ctx); !errors.Is(err, context.Canceled) || fixture.snapshotReads != 0 || output.Len() != 0 {
					t.Fatalf("error=%v snapshots=%d output=%q", err, fixture.snapshotReads, output.String())
				}
			})
			t.Run("nil-context", func(t *testing.T) {
				controller, fixture, _ := heapLayoutTestController()
				if err := command.run(controller, nil); !errors.Is(err, target.ErrInvalidArgument) || fixture.snapshotReads != 0 {
					t.Fatalf("error=%v snapshots=%d", err, fixture.snapshotReads)
				}
			})
			t.Run("canceled-read", func(t *testing.T) {
				controller, fixture, output := heapLayoutTestController()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fixture.readRaw = func(_ target.MemoryToken, _ target.Address, dst []byte) (int, error) {
					cancel()
					return copy(dst, fixture.stack), io.ErrUnexpectedEOF
				}
				err := command.run(controller, ctx)
				if !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrUnexpectedEOF) || len(fixture.stackCalls) != 1 || strings.Contains(output.String(), "raw_size") {
					t.Fatalf("error=%v reads=%v output=%q", err, fixture.stackCalls, output.String())
				}
			})
			t.Run("output-error", func(t *testing.T) {
				controller, fixture, _ := heapLayoutTestController()
				controller.out = contextFailingWriter{err: io.ErrClosedPipe}
				err := command.run(controller, context.Background())
				var outputErr *OutputError
				if !errors.As(err, &outputErr) || !errors.Is(err, io.ErrClosedPipe) || len(fixture.stackCalls) > 1 {
					t.Fatalf("error=%v reads=%v", err, fixture.stackCalls)
				}
			})
		})
	}
}

func TestVisualHeapOutputFailureStopsBeforeNextRead(t *testing.T) {
	controller, fixture, _ := heapLayoutTestController()
	controller.out = controllerTestWriter(func(data []byte) (int, error) {
		if bytes.Contains(data, []byte("raw_size=")) {
			return 0, io.ErrClosedPipe
		}
		return len(data), nil
	})
	if err := controller.showVisualHeap(context.Background(), "--layout glibc-amd64 0x1000 0x1080"); !errors.Is(err, io.ErrClosedPipe) || len(fixture.stackCalls) != 1 {
		t.Fatalf("error=%v reads=%v", err, fixture.stackCalls)
	}
}

func TestHeapLayoutCanceledExpressionNeverReadsMemory(t *testing.T) {
	for _, visual := range []bool{false, true} {
		t.Run(fmt.Sprint(visual), func(t *testing.T) {
			controller, fixture, output := heapLayoutTestController()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture.onReadRegisters = cancel
			var err error
			if visual {
				err = controller.showVisualHeap(ctx, "--layout glibc-amd64 '$rsp' '$rsp + 32'")
			} else {
				err = controller.showHeapChunk(ctx, "--layout glibc-amd64 $rsp")
			}
			if !errors.Is(err, context.Canceled) || fixture.snapshotReads != 1 || len(fixture.registerTokens) != 1 ||
				len(fixture.stackCalls) != 0 || output.Len() != 0 {
				t.Fatalf("error=%v reads=%+v output=%q", err, fixture, output.String())
			}
		})
	}
}

func TestHeapChunkOutputErrorRetainsPartialReadError(t *testing.T) {
	controller, fixture, _ := heapLayoutTestController()
	fixture.stack = fixture.stack[:12]
	fixture.stackErr = io.ErrUnexpectedEOF
	controller.out = contextFailingWriter{err: io.ErrClosedPipe}
	err := controller.showHeapChunk(context.Background(), "--layout glibc-amd64 0x1000")
	var outputErr *OutputError
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, target.ErrPartial) || !errors.As(err, &outputErr) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error=%v", err)
	}
}
