package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"fastdbg2/target"
)

func TestAllocatorProfileMatchesReproducibleFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/allocator_profiles/cachyos-glibc-244.json")
	if err != nil || string(data) != builtInAllocatorProfile {
		t.Fatalf("generated profile fixture differs: %v", err)
	}
	profiles, err := knownAllocatorProfiles()
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles=%v error=%v", profiles, err)
	}
	profile := profiles[0]
	if _, exists := profile.Layout.Arena.Fields["fastbinsY"]; exists || profile.Layout.FastLink != "" || profile.Layout.Tcache.Fields["num_slots"].Width != 2 || profile.Layout.Tcache.Fields["entries"].Count != 76 {
		t.Fatalf("incorrect exact 2.44 allocator structure: %+v", profile.Layout)
	}
	clone := cloneAllocatorLayout(profile.Layout)
	delete(clone.Arena.Fields, "bins")
	if _, exists := profile.Layout.Arena.Fields["bins"]; !exists {
		t.Fatal("caller mutation escaped into immutable profile")
	}
}

func TestAllocatorProfileRejectsWrappedCountsAndRequiredMissingHPField(t *testing.T) {
	profiles, err := knownAllocatorProfiles()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := profiles[0]
	wrapped.Constants.TcacheSmallBinCount = math.MaxUint64
	wrapped.Constants.TcacheLargeBinCount = 77
	if err := validateAllocatorProfile(wrapped); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("wrapped count dimensions accepted: %v", err)
	}
	missing := profiles[0]
	missing.MallocPar = cloneAllocatorRecord(missing.MallocPar)
	delete(missing.MallocPar.Fields, "hp_pagesize")
	missing.MallocSourceSHA256 = "4cc41f27261374fd37a66d1b46b78985988d64b45dec6626a4b580eeea282014"
	missing.ArenaSourceSHA256 = "10179896515d85e9cc3bd36ab739d94f78b43686258623b980aae0afdaa99f14"
	source, err := allocatorSemanticsForSource(missing.MallocSourceSHA256, missing.ArenaSourceSHA256)
	if err != nil || source.HeapMaxConditional {
		t.Fatalf("invalid unconditional source fixture: %+v %v", source, err)
	}
	missing.Semantics = source.Semantics
	if err := validateAllocatorProfile(missing); !errors.Is(err, target.ErrInvalidArgument) || !strings.Contains(err.Error(), "requires hp_pagesize") {
		t.Fatalf("unconditional heap maximum lost its required source field: %v", err)
	}
}

type allocatorMetadataTestFixture struct {
	memory  *runtimeELFMemory
	profile allocatorProfile
	libc    *runtimeELFModule
	loader  *runtimeELFModule
	thread  target.ThreadInfo
	regs    []target.Register
	libdata []byte
	lddata  []byte
	tcbdata []byte
}

func allocatorMetadataFixture(t *testing.T) allocatorMetadataTestFixture {
	t.Helper()
	profiles, err := knownAllocatorProfiles()
	if err != nil {
		t.Fatal(err)
	}
	profile := profiles[0]
	profile.Symbols = maps.Clone(profile.Symbols)
	for name, value := range map[string]uint64{"main_arena": 0x1000, "mp_": 0x2000, "__tcache_dummy": 0x3000, "_rtld_global": 0x1000} {
		symbol := profile.Symbols[name]
		symbol.Value = value
		profile.Symbols[name] = symbol
	}
	libdata, lddata, tcbdata := make([]byte, 0x10000), make([]byte, 0x10000), make([]byte, 0x10000)
	memory := runtimeELFTestMemory(t, runtimeELFTestRegion{0x100000, libdata}, runtimeELFTestRegion{0x200000, lddata}, runtimeELFTestRegion{0x300000, tcbdata}, runtimeELFTestRegion{0x400000, make([]byte, 0x2000)})
	libID, _ := hex.DecodeString(profile.LibcBuildID)
	ldID, _ := hex.DecodeString(profile.LoaderBuildID)
	libc := &runtimeELFModule{ID: "test-libc", LoadBias: 0x100000, BuildID: libID, Links: []runtimeELFLink{{Address: 0x204000}}, Loads: []runtimeELFSpan{{0x100000, 0x10000}}, Programs: []elf.ProgHeader{{Type: elf.PT_LOAD, Memsz: 0x10000, Filesz: 0x10000}, {Type: elf.PT_TLS, Memsz: 0x100, Filesz: 0x80}}}
	loader := &runtimeELFModule{ID: "test-loader", LoadBias: 0x200000, BuildID: ldID, Header: 0x200000, AuxiliaryTag: 7, AuxiliaryAddress: 0x200000, Loads: []runtimeELFSpan{{0x200000, 0x10000}}}
	put := func(data []byte, offset, value uint64) { binary.LittleEndian.PutUint64(data[offset:], value) }
	tls := profile.TLS
	put(lddata, 0x4000+tls.LinkMapModIDOffset, 1)
	put(lddata, 0x4000+tls.LinkMapStaticOffset, 0x100)
	put(lddata, 0x4000+tls.LinkMapBlockSizeOffset, 0x100)
	put(lddata, 0x1000+tls.RTLDSlotInfoOffset, 0x205000)
	put(lddata, 0x1000+tls.RTLDGenerationOffset, 4)
	put(lddata, 0x5000+tls.SlotListLengthOffset, 16)
	put(lddata, 0x5000+tls.SlotListEntriesOffset+tls.SlotEntrySize+tls.SlotGenerationOffset, 3)
	put(lddata, 0x5000+tls.SlotListEntriesOffset+tls.SlotEntrySize+tls.SlotMapOffset, 0x204000)
	put(tcbdata, 0x8000+tls.ThreadSelfOffset, 0x308000)
	put(tcbdata, 0x8000+tls.ThreadTCBOffset, 0x308000)
	put(tcbdata, 0x8000+tls.ThreadDTVOffset, 0x304000)
	binary.LittleEndian.PutUint32(tcbdata[0x8000+tls.ThreadTIDOffset:], 123)
	put(tcbdata, 0x4000-tls.DTVEntrySize+tls.DTVGenerationOffset, 16)
	put(tcbdata, 0x4000+tls.DTVGenerationOffset, 4)
	put(tcbdata, 0x4000+tls.DTVEntrySize+tls.DTVPointerOffset, 0x307f00)
	put(tcbdata, 0x7f00+profile.Symbols["thread_arena"].Value, 0x101000)
	put(tcbdata, 0x7f00+profile.Symbols["tcache"].Value, 0x103000)
	for name, value := range map[string]uint64{"tcache_small_bins": 64, "tcache_count": 16, "tcache_max_bytes": 4194304} {
		put(libdata, 0x2000+profile.MallocPar.Fields[name].Offset, value)
	}
	reg := make([]byte, 8)
	binary.LittleEndian.PutUint64(reg, 0x308000)
	return allocatorMetadataTestFixture{memory, profile, libc, loader, target.ThreadInfo{TID: 123}, []target.Register{{Name: "fs_base", Bits: 64, Available: true, Data: reg}}, libdata, lddata, tcbdata}
}

func TestAllocatorProfileSelectionRejectsUnknownIDsAndDuplicateInstances(t *testing.T) {
	f := allocatorMetadataFixture(t)
	view := &runtimeELFView{Modules: []*runtimeELFModule{f.libc, f.loader}}
	if _, libc, _, err := selectAllocatorProfile(view); err != nil || libc != f.libc {
		t.Fatalf("libc=%v error=%v", libc, err)
	}
	other := *f.libc
	other.LoadBias += 0x1000000
	view.Modules = append(view.Modules, &other)
	if _, _, _, err := selectAllocatorProfile(view); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
	view.Modules = view.Modules[:2]
	f.loader.BuildID = []byte{1, 2, 3}
	if _, _, _, err := selectAllocatorProfile(view); !errors.Is(err, target.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestAllocatorMetadataTLSAndSentinels(t *testing.T) {
	for _, test := range []struct {
		pointer uint64
		state   string
	}{{0x103000, "inactive"}, {0x103008, "disabled"}, {0, "null"}, {0x400000, "active"}} {
		f := allocatorMetadataFixture(t)
		binary.LittleEndian.PutUint64(f.tcbdata[0x7f00+f.profile.Symbols["tcache"].Value:], test.pointer)
		info, err := collectAllocatorContext(f.memory, f.profile, f.libc, f.loader, f.thread, f.regs)
		if err != nil || info.MainArena != 0x101000 || info.ThreadArena != 0x101000 || uint64(info.Tcache) != test.pointer || info.TcacheState != test.state || info.Parameters.TcacheCount != 16 {
			t.Fatalf("info=%+v error=%v", info, err)
		}
		extents, err := info.HeapExtents(info.MainArena)
		if err != nil || len(extents) != 0 {
			t.Fatalf("uninitialized main extents=%+v error=%v", extents, err)
		}
	}
}

func TestAllocatorTLSRejectsWrongThreadModuleGenerationsAndPointers(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(allocatorMetadataTestFixture)
		err  error
	}{
		{"wrong self", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint64(f.tcbdata[0x8000+f.profile.TLS.ThreadSelfOffset:], 0x308001)
		}, target.ErrInvalidArgument},
		{"wrong tid", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint32(f.tcbdata[0x8000+f.profile.TLS.ThreadTIDOffset:], 124)
		}, target.ErrStale},
		{"wrong slot", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint64(f.lddata[0x5000+f.profile.TLS.SlotListEntriesOffset+f.profile.TLS.SlotEntrySize+f.profile.TLS.SlotMapOffset:], 0x204001)
		}, target.ErrStale},
		{"future dtv", func(f allocatorMetadataTestFixture) { binary.LittleEndian.PutUint64(f.tcbdata[0x4000:], 5) }, target.ErrInvalidArgument},
		{"insufficient capacity", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint64(f.tcbdata[0x4000-f.profile.TLS.DTVEntrySize:], 0)
		}, target.ErrInvalidArgument},
		{"static mismatch", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint64(f.tcbdata[0x4000+f.profile.TLS.DTVEntrySize:], 0x307f10)
		}, target.ErrInvalidArgument},
		{"wrong block size", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint64(f.lddata[0x4000+f.profile.TLS.LinkMapBlockSizeOffset:], 0x80)
		}, target.ErrInvalidArgument},
		{"null dtv", func(f allocatorMetadataTestFixture) {
			binary.LittleEndian.PutUint64(f.tcbdata[0x8000+f.profile.TLS.ThreadDTVOffset:], 0)
		}, target.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := allocatorMetadataFixture(t)
			test.edit(f)
			if address, err := allocatorTLSBase(f.memory, f.profile, f.libc, f.loader, f.thread, f.regs); address != 0 || !errors.Is(err, test.err) {
				t.Fatalf("address=%#x error=%v", address, err)
			}
		})
	}
}

func TestAllocatorTLSUsesOnlyFormalStaticFallback(t *testing.T) {
	for _, staleGeneration := range []bool{false, true} {
		f := allocatorMetadataFixture(t)
		if staleGeneration {
			binary.LittleEndian.PutUint64(f.tcbdata[0x4000:], 1)
		} else {
			binary.LittleEndian.PutUint64(f.tcbdata[0x4000+f.profile.TLS.DTVEntrySize:], 1)
		}
		if address, err := allocatorTLSBase(f.memory, f.profile, f.libc, f.loader, f.thread, f.regs); err != nil || address != 0x307f00 {
			t.Fatalf("address=%#x error=%v", address, err)
		}
		binary.LittleEndian.PutUint64(f.lddata[0x4000+f.profile.TLS.LinkMapStaticOffset:], 0)
		if address, err := allocatorTLSBase(f.memory, f.profile, f.libc, f.loader, f.thread, f.regs); address != 0 || !errors.Is(err, target.ErrUnavailable) {
			t.Fatalf("missing static proof address=%#x error=%v", address, err)
		}
	}
}

func TestAllocatorChunkAlignmentUsesExactHeaderCoordinates(t *testing.T) {
	for _, test := range []struct{ address, want target.Address }{{0x1000, 0x1000}, {0x1003, 0x1010}, {0x100f, 0x1010}} {
		if got, err := allocatorAlignedChunk(test.address, 16, 16); err != nil || got != test.want {
			t.Fatalf("address=%#x got=%#x error=%v", test.address, got, err)
		}
	}
}

func TestAllocatorClosedHeapTerminalRequiresExactSourcePair(t *testing.T) {
	for _, previous := range []uint64{16, 32} {
		for _, inUse := range []uint64{0, 1} {
			data := make([]byte, 0x1000)
			binary.LittleEndian.PutUint64(data[0xff0:], previous)
			binary.LittleEndian.PutUint64(data[0xff8:], 1)
			binary.LittleEndian.PutUint64(data[0xff0-previous+8:], previous|inUse)
			memory := runtimeELFTestMemory(t, runtimeELFTestRegion{0x1000, data})
			profile, _ := knownAllocatorProfiles()
			info := &allocatorContext{memory: memory, Layout: cloneAllocatorLayout(profile[0].Layout), Alignment: 16, MinChunkSize: 32, ChunkHeaderSize: 16}
			if terminal, err := info.closedHeapFencepost(0x1000, 0x2000); err != nil || terminal != 0x1ff0 {
				t.Fatalf("previous=%d inuse=%d terminal=%#x error=%v", previous, inUse, terminal, err)
			}
			binary.LittleEndian.PutUint64(data[0xff8:], 0x11)
			if _, err := info.closedHeapFencepost(0x1000, 0x2000); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatal(err)
			}
		}
	}
}

const allocatorNativeSource = `#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
uintptr_t allocator_probes[2];
int allocator_tids[2];
static _Atomic int ready;
static int gate[2];
__attribute__((naked,noinline)) void allocator_point(void) { __asm__ volatile("nop\n\tret"); }
static void allocate(int index) {
    void *values[8];
    for (int i=0;i<8;i++) values[i]=malloc(0x40);
    for (int i=0;i<8;i++) free(values[i]);
    allocator_probes[index]=(uintptr_t)values[7];
    allocator_tids[index]=(int)syscall(SYS_gettid);
}
static void *worker(void *ignored) {
    (void)ignored;
    allocate(1);
    atomic_store(&ready,1);
    syscall(SYS_futex,&ready,FUTEX_WAKE_PRIVATE,1,0,0,0);
    char byte;
    read(gate[0],&byte,1);
    return 0;
}
int main(void) {
    if (pipe(gate)) return 90;
    allocate(0);
    pthread_t thread;
    if (pthread_create(&thread,0,worker,0)) return 91;
    while (!atomic_load(&ready)) syscall(SYS_futex,&ready,FUTEX_WAIT_PRIVATE,0,0,0,0);
    allocator_point();
    return 0;
}
`

func TestAllocatorMetadataNativeSelectedTLSAndExactWorkerHeap(t *testing.T) {
	t.Setenv("GLIBC_TUNABLES", "glibc.malloc.arena_max=2:glibc.malloc.tcache_count=16")
	t.Setenv("MALLOC_ARENA_MAX", "2")
	f, _ := newLegacyFixture(t, true, false, allocatorNativeSource, "allocator_point", false)
	probes := f.read(t, "allocator_probes", 16)
	tids := f.read(t, "allocator_tids", 8)
	snapshot, _, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(procTestDirectory(t))
	var tcaches []target.Address
	for index := 0; index < 2; index++ {
		tid := int(binary.LittleEndian.Uint32(tids[index*4:]))
		var selected target.ThreadInfo
		for _, thread := range snapshot.Threads {
			if thread.TID == tid {
				selected = thread
			}
		}
		if selected.TID != tid {
			t.Fatalf("fixture thread %d missing", tid)
		}
		err := f.controller.withAllocatorContext(context.Background(), snapshot, selected, func(info *allocatorContext) error {
			if info.TID != tid || info.TcacheState != "active" || info.ThreadArena == 0 || info.Proof == "" {
				t.Fatalf("context=%+v", info)
			}
			if index == 0 && info.ThreadArena != info.MainArena || index == 1 && info.ThreadArena == info.MainArena {
				t.Fatalf("thread arena selection: main=%#x thread=%#x index=%d", info.MainArena, info.ThreadArena, index)
			}
			entry := info.Layout.Tcache.Fields["entries"]
			data, err := info.memory.bytes(info.Tcache+target.Address(entry.Offset+3*entry.Stride), 8)
			if err != nil || !bytes.Equal(data, probes[index*8:index*8+8]) {
				t.Fatalf("selected TLS tcache head=%x fixture=%x error=%v", data, probes[index*8:index*8+8], err)
			}
			extents, err := info.HeapExtents(info.ThreadArena)
			if err != nil || len(extents) == 0 || extents[len(extents)-1].Top == 0 || extents[0].Arena != info.ThreadArena {
				t.Fatalf("exact arena extents=%+v error=%v", extents, err)
			}
			tcaches = append(tcaches, info.Tcache)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if tcaches[0] == tcaches[1] {
		t.Fatal("selected threads reused one tcache")
	}
}

func TestAllocatorMetadataNativeInactiveWorkerIsNotAnError(t *testing.T) {
	f := newExpansionIntegration(t, true)
	f.breakpoint(t)
	tids := f.read(t, "expansion_tids", 12)
	snapshot, _, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	tid := int(binary.LittleEndian.Uint32(tids[4:]))
	for _, thread := range snapshot.Threads {
		if thread.TID != tid {
			continue
		}
		if err := f.controller.withAllocatorContext(context.Background(), snapshot, thread, func(info *allocatorContext) error {
			if info.ThreadArena != 0 || info.TcacheState != "inactive" {
				t.Fatalf("unallocated selected worker context=%+v", info)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("worker was not found")
}

func TestAllocatorMetadataNativeDisabledTcacheAndHotRead(t *testing.T) {
	t.Setenv("GLIBC_TUNABLES", "glibc.malloc.arena_max=2:glibc.malloc.tcache_count=0")
	f, _ := newLegacyFixture(t, true, false, allocatorNativeSource, "allocator_point", false)
	snapshot, thread, err := f.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 20 {
		if err := f.controller.withAllocatorContext(context.Background(), snapshot, thread, func(info *allocatorContext) error {
			if info.TcacheState != "disabled" || info.Parameters.TcacheCount != 0 {
				t.Fatalf("disabled allocator context=%+v", info)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("20 exact-profile stopped observations: %s; mean %s", time.Since(start), time.Since(start)/20)
}
