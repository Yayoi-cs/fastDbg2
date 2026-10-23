package debugger

import (
	"encoding/json"
	"fastdbg2/target"
	"fmt"
)

type allocatorSemantics struct {
	TcacheCounterMode    string
	TcacheStateMode      string
	TcacheSmallBinsField string
	TcacheMaxBytesMode   string
	HeapMaxMode          string
}

type allocatorSourceSemantics struct {
	Source             string
	MallocSourceSHA256 string
	ArenaSourceSHA256  string
	Fastbins           bool
	HeapMaxConditional bool
	Semantics          allocatorSemantics
}

func allocatorSemanticsForSource(mallocSHA, arenaSHA string) (allocatorSourceSemantics, error) {
	var entries []allocatorSourceSemantics
	if err := json.Unmarshal([]byte(allocatorSourceSemanticsJSON), &entries); err != nil {
		return allocatorSourceSemantics{}, err
	}
	for _, entry := range entries {
		if entry.MallocSourceSHA256 == mallocSHA && entry.ArenaSourceSHA256 == arenaSHA {
			return entry, nil
		}
	}
	return allocatorSourceSemantics{}, fmt.Errorf("allocator source hashes have no reviewed semantics: %w", target.ErrUnsupported)
}

const allocatorSourceSemanticsJSON = `[
  {
    "Source": "glibc-2.35",
    "MallocSourceSHA256": "94275fbd85eeeb063605f8469a7946189ee7b044a4257319982074462ff96c1d",
    "ArenaSourceSHA256": "4ccc6cf3e5db2537c7ffba740d17a7d8d26c8b317693a94d00de7b16368e62d6",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": true
  },
  {
    "Source": "glibc-2.36",
    "MallocSourceSHA256": "596152af35e8259ade01770ed52449f73ad4a64bed9637927bde0c9b793d94dd",
    "ArenaSourceSHA256": "4ccc6cf3e5db2537c7ffba740d17a7d8d26c8b317693a94d00de7b16368e62d6",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": true
  },
  {
    "Source": "glibc-2.37",
    "MallocSourceSHA256": "ea2bb61906631b6417ef36e20006eb61b3528f59878784d22b26dbb5c1f820fa",
    "ArenaSourceSHA256": "cdfdf8b2f5e0b2cfd763244a977adfc21f99079f1970b1bd3b99900726742104",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": true
  },
  {
    "Source": "glibc-2.38",
    "MallocSourceSHA256": "4cc41f27261374fd37a66d1b46b78985988d64b45dec6626a4b580eeea282014",
    "ArenaSourceSHA256": "10179896515d85e9cc3bd36ab739d94f78b43686258623b980aae0afdaa99f14",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": false
  },
  {
    "Source": "glibc-2.39",
    "MallocSourceSHA256": "5c2e41a83c1c4d1ddaaad761088b93469110a79067ba6485eb594a0423048663",
    "ArenaSourceSHA256": "81b608d7eff41299a50f0b6e265d2bd6860f95f324fde89826ea2841062cf1bb",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": false
  },
  {
    "Source": "glibc-2.40",
    "MallocSourceSHA256": "5c2e41a83c1c4d1ddaaad761088b93469110a79067ba6485eb594a0423048663",
    "ArenaSourceSHA256": "81b608d7eff41299a50f0b6e265d2bd6860f95f324fde89826ea2841062cf1bb",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": false
  },
  {
    "Source": "glibc-2.41",
    "MallocSourceSHA256": "7d931418b6bdbd327611fa150489ca007b36d568d081f164c7c727098e3e6bcd",
    "ArenaSourceSHA256": "6c3b3b9b272d2fb7d6a3e625ecfc21722833a40b8d27bfd158dc202473e6d4fc",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "counts",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_bins",
      "TcacheMaxBytesMode": "request-limit",
      "HeapMaxMode": "huge-pages-times-four"
    },
    "HeapMaxConditional": false
  },
  {
    "Source": "glibc-2.42",
    "MallocSourceSHA256": "c99c129727fc9fb881457d71468146e7e1853180b9c969af612bb079709a2221",
    "ArenaSourceSHA256": "e8e549676c621b8bfa099f835302cec964e1a0d5dbed14450a9e3305d71a61e8",
    "Fastbins": true,
    "Semantics": {
      "TcacheCounterMode": "num_slots",
      "TcacheStateMode": "null-shutdown",
      "TcacheSmallBinsField": "tcache_small_bins",
      "TcacheMaxBytesMode": "chunk-exclusive",
      "HeapMaxMode": "constant"
    },
    "HeapMaxConditional": false
  },
  {
    "Source": "glibc-2.43",
    "MallocSourceSHA256": "c0cb1540f6268772fb3abee9a545fd8b436e18620b7d9fd256b95f9e86866302",
    "ArenaSourceSHA256": "be2059ed9fdcb6bf2f85c576a9419491709bf3cd78d16f5838a8f49421df429b",
    "Fastbins": false,
    "Semantics": {
      "TcacheCounterMode": "num_slots",
      "TcacheStateMode": "dummy",
      "TcacheSmallBinsField": "tcache_small_bins",
      "TcacheMaxBytesMode": "chunk-exclusive",
      "HeapMaxMode": "constant"
    },
    "HeapMaxConditional": false
  },
  {
    "Source": "glibc-2.44",
    "MallocSourceSHA256": "654dac271e46a53620451d408ae045d49c1c78487f5e96fddb3546e9ee5a4572",
    "ArenaSourceSHA256": "681fd74b3ddf2011e4dace7e9967c145882dd8889baed8b7ccfcf3404ad9a48e",
    "Fastbins": false,
    "Semantics": {
      "TcacheCounterMode": "num_slots",
      "TcacheStateMode": "dummy",
      "TcacheSmallBinsField": "tcache_small_bins",
      "TcacheMaxBytesMode": "chunk-exclusive",
      "HeapMaxMode": "constant"
    },
    "HeapMaxConditional": false
  }
]
`
