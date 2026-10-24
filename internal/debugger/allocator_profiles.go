package debugger

import (
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"strings"
	"sync"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type allocatorSymbol struct {
	Value uint64
	Size  uint64
	Type  uint64
}

type allocatorConstants struct {
	Alignment           uint64
	MinChunkSize        uint64
	ChunkHeaderSize     uint64
	SizeFlags           uint64
	HeapMaxSize         uint64
	TcacheSmallBinCount uint64
	TcacheLargeBinCount uint64
	SmallBinCount       uint64
	NormalBinCount      uint64
	FastBinShift        uint64
}

type allocatorTLSProfile struct {
	ThreadSize             uint64
	TCBSize                uint64
	LinkMapSize            uint64
	ThreadSelfOffset       uint64
	ThreadTCBOffset        uint64
	ThreadDTVOffset        uint64
	ThreadTIDOffset        uint64
	DTVEntrySize           uint64
	DTVGenerationOffset    uint64
	DTVPointerOffset       uint64
	LinkMapModIDOffset     uint64
	LinkMapStaticOffset    uint64
	LinkMapBlockSizeOffset uint64
	RTLDSlotInfoOffset     uint64
	RTLDGenerationOffset   uint64
	SlotListSize           uint64
	SlotListLengthOffset   uint64
	SlotListNextOffset     uint64
	SlotListEntriesOffset  uint64
	SlotEntrySize          uint64
	SlotGenerationOffset   uint64
	SlotMapOffset          uint64
}

type allocatorProfile struct {
	Schema              uint32
	Name                string
	LibcBuildID         string
	LoaderBuildID       string
	SourceRevision      string
	LibcDebugSHA256     string
	LoaderDebugSHA256   string
	MallocSourceSHA256  string
	ArenaSourceSHA256   string
	Layout              inspect.HeapLayout
	MallocPar           inspect.HeapRecord
	HeapInfo            inspect.HeapRecord
	Symbols             map[string]allocatorSymbol
	TLS                 allocatorTLSProfile
	Constants           allocatorConstants
	DummyInactiveOffset uint64
	DummyDisabledOffset uint64
	Semantics           allocatorSemantics
}

var allocatorProfilesOnce sync.Once
var allocatorProfilesValue []allocatorProfile
var allocatorProfilesError error

func knownAllocatorProfiles() ([]allocatorProfile, error) {
	allocatorProfilesOnce.Do(func() {
		for _, raw := range []string{builtInAllocatorProfile, builtInX86AllocatorProfile} {
			profile, err := parseAllocatorProfile([]byte(raw))
			if err != nil {
				allocatorProfilesError = err
				return
			}
			if err := validateAllocatorProfile(profile); err != nil {
				allocatorProfilesError = err
				return
			}
			allocatorProfilesValue = append(allocatorProfilesValue, profile)
		}
	})
	return allocatorProfilesValue, allocatorProfilesError
}

func validateAllocatorProfile(profile allocatorProfile) error {
	if profile.Schema != 1 {
		return fmt.Errorf("unsupported allocator profile schema: %w", target.ErrInvalidArgument)
	}
	for _, id := range []string{profile.LibcBuildID, profile.LoaderBuildID} {
		value, err := hex.DecodeString(id)
		if err != nil || len(value) < 16 || len(value) > 128 || hex.EncodeToString(value) != id {
			return fmt.Errorf("invalid allocator profile build ID: %w", target.ErrInvalidArgument)
		}
	}
	for _, label := range []string{profile.Name, profile.SourceRevision} {
		if label == "" || len(label) > 256 || strings.ContainsAny(label, "\x00\r\n\x1b") {
			return target.ErrInvalidArgument
		}
	}
	for _, hash := range []string{profile.LibcDebugSHA256, profile.LoaderDebugSHA256, profile.MallocSourceSHA256, profile.ArenaSourceSHA256} {
		value, err := hex.DecodeString(hash)
		if err != nil || len(value) != 32 || hex.EncodeToString(value) != hash {
			return fmt.Errorf("invalid allocator profile provenance hash: %w", target.ErrInvalidArgument)
		}
	}
	source, err := allocatorSemanticsForSource(profile.MallocSourceSHA256, profile.ArenaSourceSHA256)
	if err != nil {
		return err
	}
	expected := source.Semantics
	if _, exists := profile.MallocPar.Fields["hp_pagesize"]; !exists && expected.HeapMaxMode == "huge-pages-times-four" {
		if !source.HeapMaxConditional {
			return fmt.Errorf("reviewed allocator source requires hp_pagesize: %w", target.ErrInvalidArgument)
		}
		expected.HeapMaxMode = "constant"
	}
	if expected != profile.Semantics {
		return fmt.Errorf("allocator profile semantics differ from reviewed source hashes: %w", target.ErrInvalidArgument)
	}
	if err := profile.Layout.Validate(); err != nil {
		return err
	}
	word := profile.Layout.Pointer
	minimum := uint64(32)
	heapMax := uint64(1 << 26)
	fastShift := uint64(4)
	if word == 4 {
		minimum = 16
		heapMax = 1 << 20
		fastShift = 3
	}
	constants := profile.Constants
	largeBins := uint64(0)
	if profile.Semantics.TcacheCounterMode == "num_slots" {
		largeBins = 12
	}
	if constants.Alignment != 16 || constants.HeapMaxSize != heapMax || constants.MinChunkSize != minimum || constants.ChunkHeaderSize != 2*word || constants.SizeFlags != 7 ||
		constants.TcacheSmallBinCount != 64 || constants.TcacheLargeBinCount != largeBins ||
		profile.Layout.Tcache == nil || profile.Layout.TcacheEntry == nil || constants.TcacheSmallBinCount+constants.TcacheLargeBinCount != profile.Layout.Tcache.Fields["entries"].Count ||
		constants.SmallBinCount != 64 || constants.NormalBinCount != 128 || profile.Layout.Arena.Fields["bins"].Count != 2*(constants.NormalBinCount-1) {
		return fmt.Errorf("invalid allocator profile constants: %w", target.ErrInvalidArgument)
	}
	_, hasFast := profile.Layout.Arena.Fields["fastbinsY"]
	if hasFast != source.Fastbins || hasFast && (constants.FastBinShift != fastShift || profile.Layout.FastLink != "safe-link-12") || !hasFast && (constants.FastBinShift != 0 || profile.Layout.FastLink != "") {
		return fmt.Errorf("allocator fastbin metadata differs from reviewed source: %w", target.ErrInvalidArgument)
	}
	if field, exists := profile.Layout.Tcache.Fields[profile.Semantics.TcacheCounterMode]; !exists || field.Width != 2 {
		return fmt.Errorf("allocator tcache counter does not match reviewed source: %w", target.ErrInvalidArgument)
	}
	for _, record := range []inspect.HeapRecord{profile.MallocPar, profile.HeapInfo} {
		if record.Size == 0 || record.Size > 65536 || len(record.Fields) == 0 || len(record.Fields) > 64 {
			return target.ErrInvalidArgument
		}
		for name, field := range record.Fields {
			if field.Count != 1 || field.Width != word || field.Stride != word || field.Offset > record.Size || field.Width > record.Size-field.Offset || name == "" {
				return fmt.Errorf("invalid allocator auxiliary record field %q: %w", name, target.ErrInvalidArgument)
			}
		}
	}
	for _, name := range []string{"sbrk_base", "tcache_count", "tcache_max_bytes", profile.Semantics.TcacheSmallBinsField} {
		if _, exists := profile.MallocPar.Fields[name]; !exists {
			return fmt.Errorf("missing allocator parameter field %q: %w", name, target.ErrInvalidArgument)
		}
	}
	for _, name := range []string{"ar_ptr", "prev", "size", "mprotect_size", "pagesize"} {
		if _, exists := profile.HeapInfo.Fields[name]; !exists {
			return fmt.Errorf("missing heap_info field %q: %w", name, target.ErrInvalidArgument)
		}
	}
	for name, width := range map[string]uint64{"main_arena": profile.Layout.Arena.Size, "mp_": profile.MallocPar.Size, "tcache": word, "thread_arena": word} {
		symbol, ok := profile.Symbols[name]
		wantType := uint64(1)
		if name == "tcache" || name == "thread_arena" {
			wantType = 6
		}
		if !ok || symbol.Size != width || symbol.Type != wantType || symbol.Size > math.MaxUint64-symbol.Value {
			return fmt.Errorf("invalid allocator profile symbol %q: %w", name, target.ErrInvalidArgument)
		}
	}
	if profile.Semantics.TcacheStateMode == "dummy" && (profile.Symbols["__tcache_dummy"].Type != 1 || profile.Symbols["__tcache_dummy"].Size < profile.Layout.Tcache.Size ||
		profile.DummyDisabledOffset > profile.Symbols["__tcache_dummy"].Size-profile.Layout.Tcache.Size || profile.DummyInactiveOffset > profile.Symbols["__tcache_dummy"].Size-profile.Layout.Tcache.Size || profile.DummyInactiveOffset == profile.DummyDisabledOffset) ||
		profile.Semantics.TcacheStateMode == "null-shutdown" && (profile.Symbols["tcache_shutting_down"].Type != 6 || profile.Symbols["tcache_shutting_down"].Size != 1 || profile.DummyInactiveOffset != 0 || profile.DummyDisabledOffset != 0) ||
		profile.Symbols["_rtld_global"].Size == 0 || profile.Symbols["_rtld_global"].Type != 1 {
		return fmt.Errorf("invalid allocator profile sentinel or loader: %w", target.ErrInvalidArgument)
	}
	tls := profile.TLS
	if tls.DTVEntrySize > 64 || tls.SlotEntrySize > 64 || tls.TCBSize > tls.ThreadSize || tls.SlotListEntriesOffset != tls.SlotListSize {
		return fmt.Errorf("invalid allocator TLS profile: %w", target.ErrInvalidArgument)
	}
	for _, field := range [][3]uint64{
		{tls.ThreadSelfOffset, word, tls.TCBSize}, {tls.ThreadTCBOffset, word, tls.TCBSize}, {tls.ThreadDTVOffset, word, tls.TCBSize}, {tls.ThreadTIDOffset, 4, tls.ThreadSize},
		{tls.DTVPointerOffset, word, tls.DTVEntrySize}, {tls.DTVGenerationOffset, word, tls.DTVEntrySize},
		{tls.LinkMapModIDOffset, word, tls.LinkMapSize}, {tls.LinkMapStaticOffset, word, tls.LinkMapSize}, {tls.LinkMapBlockSizeOffset, word, tls.LinkMapSize},
		{tls.SlotGenerationOffset, word, tls.SlotEntrySize}, {tls.SlotMapOffset, word, tls.SlotEntrySize}, {tls.SlotListLengthOffset, word, tls.SlotListSize}, {tls.SlotListNextOffset, word, tls.SlotListSize},
		{tls.RTLDGenerationOffset, word, profile.Symbols["_rtld_global"].Size}, {tls.RTLDSlotInfoOffset, word, profile.Symbols["_rtld_global"].Size},
	} {
		if field[2] == 0 || field[2] > 65536 || field[0] > field[2] || field[1] > field[2]-field[0] {
			return fmt.Errorf("allocator TLS field exceeds its exact DWARF record: %w", target.ErrInvalidArgument)
		}
	}
	return nil
}

func cloneAllocatorRecord(record inspect.HeapRecord) inspect.HeapRecord {
	return inspect.HeapRecord{Size: record.Size, Fields: maps.Clone(record.Fields)}
}

func cloneAllocatorLayout(layout inspect.HeapLayout) inspect.HeapLayout {
	layout.Arena = cloneAllocatorRecord(layout.Arena)
	layout.Chunk = cloneAllocatorRecord(layout.Chunk)
	if layout.Tcache != nil {
		record := cloneAllocatorRecord(*layout.Tcache)
		layout.Tcache = &record
	}
	if layout.TcacheEntry != nil {
		record := cloneAllocatorRecord(*layout.TcacheEntry)
		layout.TcacheEntry = &record
	}
	return layout
}

const builtInAllocatorProfile = `{
  "ArenaSourceSHA256": "681fd74b3ddf2011e4dace7e9967c145882dd8889baed8b7ccfcf3404ad9a48e",
  "Constants": {
    "Alignment": 16,
    "ChunkHeaderSize": 16,
    "FastBinShift": 0,
    "HeapMaxSize": 67108864,
    "MinChunkSize": 32,
    "NormalBinCount": 128,
    "SizeFlags": 7,
    "SmallBinCount": 64,
    "TcacheLargeBinCount": 12,
    "TcacheSmallBinCount": 64
  },
  "DummyDisabledOffset": 8,
  "DummyInactiveOffset": 0,
  "HeapInfo": {
    "fields": {
      "ar_ptr": {
        "count": 1,
        "offset": 0,
        "stride": 8,
        "width": 8
      },
      "mprotect_size": {
        "count": 1,
        "offset": 24,
        "stride": 8,
        "width": 8
      },
      "pagesize": {
        "count": 1,
        "offset": 32,
        "stride": 8,
        "width": 8
      },
      "prev": {
        "count": 1,
        "offset": 8,
        "stride": 8,
        "width": 8
      },
      "size": {
        "count": 1,
        "offset": 16,
        "stride": 8,
        "width": 8
      }
    },
    "size": 48
  },
  "Layout": {
    "allocator": "glibc",
    "arch": "amd64",
    "arena": {
      "fields": {
        "attached_threads": {
          "count": 1,
          "offset": 2088,
          "stride": 8,
          "width": 8
        },
        "binmap": {
          "count": 4,
          "offset": 2056,
          "stride": 4,
          "width": 4
        },
        "bins": {
          "count": 254,
          "offset": 24,
          "stride": 8,
          "width": 8
        },
        "flags": {
          "count": 1,
          "offset": 4,
          "stride": 4,
          "width": 4
        },
        "last_remainder": {
          "count": 1,
          "offset": 16,
          "stride": 8,
          "width": 8
        },
        "max_system_mem": {
          "count": 1,
          "offset": 2104,
          "stride": 8,
          "width": 8
        },
        "mutex": {
          "count": 1,
          "offset": 0,
          "stride": 4,
          "width": 4
        },
        "next": {
          "count": 1,
          "offset": 2072,
          "stride": 8,
          "width": 8
        },
        "next_free": {
          "count": 1,
          "offset": 2080,
          "stride": 8,
          "width": 8
        },
        "system_mem": {
          "count": 1,
          "offset": 2096,
          "stride": 8,
          "width": 8
        },
        "top": {
          "count": 1,
          "offset": 8,
          "stride": 8,
          "width": 8
        }
      },
      "size": 2112
    },
    "chunk": {
      "fields": {
        "bk": {
          "count": 1,
          "offset": 24,
          "stride": 8,
          "width": 8
        },
        "bk_nextsize": {
          "count": 1,
          "offset": 40,
          "stride": 8,
          "width": 8
        },
        "fd": {
          "count": 1,
          "offset": 16,
          "stride": 8,
          "width": 8
        },
        "fd_nextsize": {
          "count": 1,
          "offset": 32,
          "stride": 8,
          "width": 8
        },
        "mchunk_prev_size": {
          "count": 1,
          "offset": 0,
          "stride": 8,
          "width": 8
        },
        "mchunk_size": {
          "count": 1,
          "offset": 8,
          "stride": 8,
          "width": 8
        }
      },
      "size": 48
    },
    "endian": "little",
    "fast_link": "",
    "pointer": 8,
    "schema": 1,
    "tcache": {
      "fields": {
        "entries": {
          "count": 76,
          "offset": 152,
          "stride": 8,
          "width": 8
        },
        "num_slots": {
          "count": 76,
          "offset": 0,
          "stride": 2,
          "width": 2
        }
      },
      "size": 760
    },
    "tcache_entry": {
      "fields": {
        "key": {
          "count": 1,
          "offset": 8,
          "stride": 8,
          "width": 8
        },
        "next": {
          "count": 1,
          "offset": 0,
          "stride": 8,
          "width": 8
        }
      },
      "size": 16
    },
    "tcache_link": "safe-link-12"
  },
  "LibcBuildID": "e363db7c8fcc7c06c6f0d2839b2a8ad875b75406",
  "LibcDebugSHA256": "7141d32de0529a8a9d57b102e9ee30c460130d14a48f7b40179d50aa6d5d49cb",
  "LoaderBuildID": "3cad94f849ea29f8e91c1006184fe034fbc58c29",
  "LoaderDebugSHA256": "9beef2b70ee2ea63b5e0f1ccb297dabe1a8fefff6815a901b9ecf79cb7a367d3",
  "MallocPar": {
    "fields": {
      "hp_pagesize": {
        "count": 1,
        "offset": 56,
        "stride": 8,
        "width": 8
      },
      "sbrk_base": {
        "count": 1,
        "offset": 104,
        "stride": 8,
        "width": 8
      },
      "tcache_count": {
        "count": 1,
        "offset": 128,
        "stride": 8,
        "width": 8
      },
      "tcache_max_bytes": {
        "count": 1,
        "offset": 120,
        "stride": 8,
        "width": 8
      },
      "tcache_small_bins": {
        "count": 1,
        "offset": 112,
        "stride": 8,
        "width": 8
      }
    },
    "size": 136
  },
  "MallocSourceSHA256": "654dac271e46a53620451d408ae045d49c1c78487f5e96fddb3546e9ee5a4572",
  "Name": "glibc-cachyos-2.44-r50-x86_64_v3",
  "Schema": 1,
  "Semantics": {
    "HeapMaxMode": "constant",
    "TcacheCounterMode": "num_slots",
    "TcacheMaxBytesMode": "chunk-exclusive",
    "TcacheSmallBinsField": "tcache_small_bins",
    "TcacheStateMode": "dummy"
  },
  "SourceRevision": "1848099f063e",
  "Symbols": {
    "__tcache_dummy": {
      "Size": 768,
      "Type": 1,
      "Value": 2002528
    },
    "_rtld_global": {
      "Size": 2136,
      "Type": 1,
      "Value": 282624
    },
    "main_arena": {
      "Size": 2112,
      "Type": 1,
      "Value": 2427584
    },
    "mp_": {
      "Size": 136,
      "Type": 1,
      "Value": 2425216
    },
    "tcache": {
      "Size": 8,
      "Type": 6,
      "Value": 32
    },
    "thread_arena": {
      "Size": 8,
      "Type": 6,
      "Value": 80
    }
  },
  "TLS": {
    "DTVEntrySize": 16,
    "DTVGenerationOffset": 0,
    "DTVPointerOffset": 0,
    "LinkMapBlockSizeOffset": 1136,
    "LinkMapModIDOffset": 1168,
    "LinkMapSize": 1208,
    "LinkMapStaticOffset": 1160,
    "RTLDGenerationOffset": 2032,
    "RTLDSlotInfoOffset": 1992,
    "SlotEntrySize": 16,
    "SlotGenerationOffset": 0,
    "SlotListEntriesOffset": 16,
    "SlotListLengthOffset": 0,
    "SlotListNextOffset": 8,
    "SlotListSize": 16,
    "SlotMapOffset": 8,
    "TCBSize": 704,
    "ThreadDTVOffset": 8,
    "ThreadSelfOffset": 16,
    "ThreadSize": 2368,
    "ThreadTCBOffset": 0,
    "ThreadTIDOffset": 720
  }
}
`
