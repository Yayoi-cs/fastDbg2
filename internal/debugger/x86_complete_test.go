package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"fastdbg2/target"
)

func TestX86HeapUnwindAndSelectedTLS(t *testing.T) {
	for _, count := range []string{"2", "0"} {
		t.Run("tcache-"+count, func(t *testing.T) {
			t.Setenv("GLIBC_TUNABLES", "glibc.malloc.arena_max=2:glibc.malloc.tcache_count="+count)
			source, err := os.ReadFile("testdata/x86_heap.c")
			if err != nil {
				t.Fatal(err)
			}
			f, _ := newLegacyFixture(t, true, false, string(source), "checkpoint", false, "-m32", "-pthread", "-O1", "-fomit-frame-pointer")
			output := f.command(t, "bt")
			for _, name := range []string{"checkpoint", "<main+", "_start"} {
				if !strings.Contains(output, name) {
					t.Fatalf("CFI trace missing %s: %s", name, output)
				}
			}
			frame := f.command(t, "stackframe")
			if !strings.Contains(frame, "$esp") || !strings.Contains(frame, "$eip") || strings.Contains(frame, "$rip") {
				t.Fatal(frame)
			}
			f.command(t, "arena --all")
			bins := f.command(t, "bins --all")
			if count == "2" && (!strings.Contains(bins, "tcache[idx=4 size=0x50]") || !strings.Contains(bins, "small[idx=5 bin=6 size=0x50]")) {
				t.Fatalf("i386 size classes: %s", bins)
			}
			visual := f.command(t, "vis -n")
			if !strings.Contains(visual, "<- top") || !strings.Contains(visual, "|+0x00008|") {
				t.Fatal(visual)
			}
			if strings.Contains(visual, "[visual") || strings.Contains(visual, "provenance=") {
				t.Fatal("metadata leaked into visual heap")
			}
			if output := f.command(t, "thread apply all gs_base"); strings.Count(output, "gs_base =") != 2 {
				t.Fatal(output)
			}
			var bases []target.Address
			for _, selection := range []struct {
				id    int
				probe string
			}{{1, "main_tls"}, {2, "worker_tls"}} {
				f.command(t, fmt.Sprintf("thread %d", selection.id))
				snapshot, thread, err := f.controller.stopped()
				if err != nil {
					t.Fatal(err)
				}
				base, err := f.controller.selectedSegmentBase(snapshot, thread, "gs")
				if err != nil {
					t.Fatal(err)
				}
				want := binary.LittleEndian.Uint32(f.read(t, selection.probe, 4))
				if uint64(base) != uint64(want) {
					t.Fatalf("kernel GDT base %#x differs from tracee __builtin_thread_pointer %#x", base, want)
				}
				bases = append(bases, base)
				f.command(t, "gs_base")
				f.command(t, "fs_base")
				var arena target.Address
				err = f.controller.withAllocatorContext(context.Background(), snapshot, thread, func(info *allocatorContext) error {
					if info.Layout.Pointer != 4 || info.ChunkHeaderSize != 8 || info.Alignment != 16 {
						return target.ErrInvalidArgument
					}
					arena = info.ThreadArena
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				f.command(t, fmt.Sprintf("vis -n -a %#x", arena))
				output := f.command(t, "bins --all")
				if count == "2" && selection.id == 2 && !strings.Contains(output, "tcache[idx=8 size=0x90]") {
					t.Fatal(output)
				}
				f.command(t, "bt")
				if selection.id == 1 {
					pointer := binary.LittleEndian.Uint32(f.read(t, "guards", 4))
					chunk := f.command(t, fmt.Sprintf("chunk --layout glibc-x86 %#x", pointer-8))
					if !strings.Contains(chunk, "size=0x30") {
						t.Fatal(chunk)
					}
				}
			}
			snapshot, thread, err := f.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			f.command(t, "set $eax 0")
			if _, err := f.controller.selectedSegmentBase(snapshot, thread, "gs"); !errors.Is(err, target.ErrStale) {
				t.Fatalf("stale TLS token accepted: %v", err)
			}
			if bases[0] == bases[1] {
				t.Fatal("thread-local bases reused")
			}
		})
	}
}

func TestX86AllocatorProfileAndBinBoundaries(t *testing.T) {
	data, err := os.ReadFile("testdata/allocator_profiles/cachyos-glibc-244-x86.json")
	if err != nil || string(data) != builtInX86AllocatorProfile {
		t.Fatalf("profile %v", err)
	}
	profile, err := parseAllocatorProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAllocatorProfile(profile); err != nil {
		t.Fatal(err)
	}
	policy := heapBinPolicy{Pointer: 4, Alignment: 16, MinChunkSize: 16, SmallBinCount: 64, NormalBinCount: 128, TcacheSmallBinCount: 64, TcacheLargeBinCount: 12}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	for size := uint64(0x3f0); size < 0x10000; size += 16 {
		expected := uint64(126)
		switch {
		case size>>6 <= 45:
			expected = 49 + (size >> 6)
		case size>>9 <= 20:
			expected = 91 + (size >> 9)
		case size>>12 <= 10:
			expected = 110 + (size >> 12)
		case size>>15 <= 4:
			expected = 119 + (size >> 15)
		case size>>18 <= 2:
			expected = 124 + (size >> 18)
		}
		got := policy.largeIndex(size)
		if got != expected {
			t.Fatalf("size %#x got %d expected %d", size, got, expected)
		}
		low, high, ok := policy.largeRange(got)
		if !ok || size < low || size > high {
			t.Fatalf("large range %#x: %#x-%#x %t", size, low, high, ok)
		}
	}
	mutated := profile
	mutated.Layout = cloneAllocatorLayout(profile.Layout)
	mutated.Layout.Pointer = 8
	if err := validateAllocatorProfile(mutated); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal("cross-ABI profile accepted", err)
	}
}
