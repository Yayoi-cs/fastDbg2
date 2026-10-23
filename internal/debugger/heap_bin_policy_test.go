package debugger

import (
	"errors"
	"math"
	"testing"

	"fastdbg2/target"
)

func heapTestBinPolicy(fastShift, largeTcache uint64) heapBinPolicy {
	return heapBinPolicy{
		Alignment: 16, MinChunkSize: 32, SmallBinCount: 64, NormalBinCount: 128,
		FastBinShift: fastShift, TcacheSmallBinCount: 64, TcacheLargeBinCount: largeTcache,
	}
}

func TestHeapBinPolicyValidatesExplicitConstants(t *testing.T) {
	for _, fast := range []uint64{0, 4} {
		for _, large := range []uint64{0, 12} {
			if err := heapTestBinPolicy(fast, large).validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, test := range []struct {
		name   string
		change func(*heapBinPolicy)
	}{
		{"zero", func(p *heapBinPolicy) { *p = heapBinPolicy{} }},
		{"alignment", func(p *heapBinPolicy) { p.Alignment = 8 }},
		{"alignment-overflow", func(p *heapBinPolicy) { p.Alignment = math.MaxUint64 }},
		{"minimum", func(p *heapBinPolicy) { p.MinChunkSize = 16 }},
		{"minimum-overflow", func(p *heapBinPolicy) { p.MinChunkSize = math.MaxUint64 }},
		{"small-count", func(p *heapBinPolicy) { p.SmallBinCount = 63 }},
		{"normal-count", func(p *heapBinPolicy) { p.NormalBinCount = 127 }},
		{"normal-count-overflow", func(p *heapBinPolicy) { p.NormalBinCount = math.MaxUint64 }},
		{"fast-shift", func(p *heapBinPolicy) { p.FastBinShift = 3 }},
		{"fast-shift-overflow", func(p *heapBinPolicy) { p.FastBinShift = 64 }},
		{"small-tcache", func(p *heapBinPolicy) { p.TcacheSmallBinCount = 0 }},
		{"small-tcache-overflow", func(p *heapBinPolicy) { p.TcacheSmallBinCount = math.MaxUint64 }},
		{"large-tcache", func(p *heapBinPolicy) { p.TcacheLargeBinCount = 13 }},
		{"large-tcache-overflow", func(p *heapBinPolicy) { p.TcacheLargeBinCount = math.MaxUint64 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := heapTestBinPolicy(4, 12)
			test.change(&policy)
			if err := policy.validate(); !errors.Is(err, target.ErrUnsupported) {
				t.Fatal(err)
			}
			if index, ok := policy.tcacheIndex(0x20); index != 0 || ok {
				t.Fatalf("invalid tcache index %d %t", index, ok)
			}
			if minimum, maximum, ok := policy.tcacheRange(0); minimum != 0 || maximum != 0 || ok {
				t.Fatalf("invalid tcache range %x %x %t", minimum, maximum, ok)
			}
			if policy.normalName(1) != "unsupported" || policy.largeIndex(0x400) != math.MaxUint64 {
				t.Fatal("invalid normal policy used")
			}
			if minimum, maximum, ok := policy.largeRange(64); minimum != 0 || maximum != 0 || ok {
				t.Fatalf("invalid large range %x %x %t", minimum, maximum, ok)
			}
			if index, ok := policy.fastIndex(0x20, 10); index != 0 || ok {
				t.Fatalf("invalid fast index %d %t", index, ok)
			}
			if size, ok := policy.fastRange(0, 10); size != 0 || ok {
				t.Fatalf("invalid fast range %x %t", size, ok)
			}
		})
	}
}

func TestHeapBinPolicyTcacheSourceBoundaries(t *testing.T) {
	for _, large := range []uint64{0, 12} {
		policy := heapTestBinPolicy(4, large)
		for _, test := range []struct {
			size  uint64
			index uint64
		}{
			{0x20, 0}, {0x30, 1}, {0x3f0, 61}, {0x400, 62}, {0x410, 63},
			{0x420, 64}, {0x7f0, 64}, {0x800, 65}, {0xff0, 65},
			{0x1000, 66}, {0x1ff0, 66}, {0x200000, 75}, {0x3ffff0, 75},
		} {
			index, ok := policy.tcacheIndex(test.size)
			if test.index >= 64 && large == 0 {
				if index != 0 || ok {
					t.Fatalf("small-only tcache admitted size %#x: %d %t", test.size, index, ok)
				}
				continue
			}
			minimum, maximum, known := policy.tcacheRange(index)
			if !ok || index != test.index || !known || test.size < minimum || test.size > maximum {
				t.Fatalf("size=%#x index=%d valid=%t range=%#x..%#x", test.size, index, ok, minimum, maximum)
			}
		}
		for _, size := range []uint64{0, 1, 0x10, 0x1f, 0x21, 0x411, 0x421, 0x400000, 0xfffffff0, math.MaxUint64 - 15, math.MaxUint64} {
			if index, ok := policy.tcacheIndex(size); index != 0 || ok {
				t.Fatalf("invalid tcache size=%#x index=%d valid=%t", size, index, ok)
			}
		}
		for _, index := range []uint64{64 + large, 76, 127, math.MaxUint64} {
			if minimum, maximum, ok := policy.tcacheRange(index); minimum != 0 || maximum != 0 || ok {
				t.Fatalf("invalid tcache index=%d range=%#x..%#x valid=%t", index, minimum, maximum, ok)
			}
		}
	}
}

func TestHeapBinPolicyTcacheRangesAreExact(t *testing.T) {
	for _, large := range []uint64{0, 12} {
		policy := heapTestBinPolicy(4, large)
		previous := policy.MinChunkSize - policy.Alignment
		for index := uint64(0); index < 64+large; index++ {
			minimum, maximum, ok := policy.tcacheRange(index)
			low, lowOK := policy.tcacheIndex(minimum)
			high, highOK := policy.tcacheIndex(maximum)
			if !ok || !lowOK || !highOK || low != index || high != index || minimum > maximum || minimum%16 != 0 || maximum%16 != 0 || minimum != previous+16 {
				t.Fatalf("index=%d range=%#x..%#x low=%d high=%d", index, minimum, maximum, low, high)
			}
			if before, ok := policy.tcacheIndex(minimum - 16); index == 0 && ok || index != 0 && (!ok || before != index-1) {
				t.Fatalf("index=%d preceding class=%d valid=%t", index, before, ok)
			}
			if after, ok := policy.tcacheIndex(maximum + 16); index+1 == 64+large && ok || index+1 != 64+large && (!ok || after != index+1) {
				t.Fatalf("index=%d following class=%d valid=%t", index, after, ok)
			}
			previous = maximum
		}
	}
	policy := heapTestBinPolicy(0, 12)
	if minimum, maximum, ok := policy.tcacheRange(64); !ok || minimum != 0x420 || maximum != 0x7f0 {
		t.Fatalf("first logarithmic range=%#x..%#x valid=%t", minimum, maximum, ok)
	}
	if minimum, maximum, ok := policy.tcacheRange(75); !ok || minimum != 0x200000 || maximum != 0x3ffff0 {
		t.Fatalf("last logarithmic range=%#x..%#x valid=%t", minimum, maximum, ok)
	}
}

func TestHeapBinPolicyNormalSourceBoundaries(t *testing.T) {
	policy := heapTestBinPolicy(4, 12)
	for _, test := range []struct {
		index uint64
		name  string
	}{{0, "reserved"}, {1, "unsorted"}, {2, "small"}, {63, "small"}, {64, "large"}, {126, "large"}, {127, "reserved"}, {128, "reserved"}, {math.MaxUint64, "reserved"}} {
		if name := policy.normalName(test.index); name != test.name {
			t.Fatalf("index=%d name=%q want=%q", test.index, name, test.name)
		}
	}
	if policy.normalName(0x3f0/policy.Alignment) != "small" || policy.largeIndex(0x3f0) != math.MaxUint64 || policy.largeIndex(0x400) != 64 {
		t.Fatal("normal small/large boundary differs from explicit AMD64 constants")
	}
	for _, test := range []struct {
		size  uint64
		index uint64
	}{
		{0x400, 64}, {0x430, 64}, {0x440, 65}, {0x7f0, 79}, {0x800, 80}, {0x810, 80},
		{0xc00, 96}, {0xc30, 96}, {0xc40, 97}, {0xdf0, 97}, {0xe00, 98},
		{0x2800, 111}, {0x29f0, 111}, {0x2a00, 112}, {0x2ff0, 112}, {0x3000, 113},
		{0xa000, 120}, {0xaff0, 120}, {0xb000, 120}, {0xfff0, 120}, {0x10000, 121},
		{0x18000, 122}, {0x20000, 123}, {0x27ff0, 123}, {0x28000, 124}, {0x3fff0, 124},
		{0x40000, 125}, {0x7fff0, 125}, {0x80000, 126}, {0xbfff0, 126}, {0xc0000, 126}, {math.MaxUint64 - 15, 126},
	} {
		if index := policy.largeIndex(test.size); index != test.index {
			t.Fatalf("size=%#x index=%d want=%d", test.size, index, test.index)
		}
	}
	for _, size := range []uint64{0, 0x20, 0x3f0, 0x3ff, 0x401, 0x411, math.MaxUint64} {
		if index := policy.largeIndex(size); index != math.MaxUint64 {
			t.Fatalf("invalid large size=%#x index=%d", size, index)
		}
	}
}

func TestHeapBinPolicyLargeRangesAreExact(t *testing.T) {
	policy := heapTestBinPolicy(4, 0)
	previous := uint64(0x3f0)
	for index := uint64(64); index <= 126; index++ {
		minimum, maximum, ok := policy.largeRange(index)
		if !ok || minimum > maximum || minimum%16 != 0 || maximum%16 != 0 || minimum != previous+16 || policy.largeIndex(minimum) != index || policy.largeIndex(maximum) != index {
			t.Fatalf("index=%d range=%#x..%#x", index, minimum, maximum)
		}
		if index != 64 && policy.largeIndex(minimum-16) != index-1 {
			t.Fatalf("index=%d lower edge=%#x", index, minimum)
		}
		if index != 126 && policy.largeIndex(maximum+16) != index+1 {
			t.Fatalf("index=%d upper edge=%#x", index, maximum)
		}
		previous = maximum
	}
	for _, test := range []struct {
		index   uint64
		minimum uint64
		maximum uint64
	}{{64, 0x400, 0x430}, {97, 0xc40, 0xdf0}, {112, 0x2a00, 0x2ff0}, {120, 0xa000, 0xfff0}, {124, 0x28000, 0x3fff0}, {126, 0x80000, math.MaxUint64 - 15}} {
		minimum, maximum, ok := policy.largeRange(test.index)
		if !ok || minimum != test.minimum || maximum != test.maximum {
			t.Fatalf("index=%d range=%#x..%#x want=%#x..%#x", test.index, minimum, maximum, test.minimum, test.maximum)
		}
	}
	for _, index := range []uint64{0, 1, 2, 63, 127, 128, math.MaxUint64} {
		if minimum, maximum, ok := policy.largeRange(index); minimum != 0 || maximum != 0 || ok {
			t.Fatalf("invalid large index=%d range=%#x..%#x valid=%t", index, minimum, maximum, ok)
		}
	}
}

func TestHeapBinPolicyFastSourceBoundaries(t *testing.T) {
	policy := heapTestBinPolicy(4, 0)
	for _, slots := range []uint64{1, 2, 10, 256} {
		for index := uint64(0); index < slots; index++ {
			size, ok := policy.fastRange(index, slots)
			actual, known := policy.fastIndex(size, slots)
			if !ok || !known || actual != index || size != 0x20+index*16 {
				t.Fatalf("slots=%d index=%d size=%#x actual=%d valid=%t", slots, index, size, actual, known)
			}
		}
		if size, ok := policy.fastRange(slots, slots); size != 0 || ok {
			t.Fatalf("index past slots=%d size=%#x valid=%t", slots, size, ok)
		}
		if index, ok := policy.fastIndex(0x20+slots*16, slots); index != 0 || ok {
			t.Fatalf("size past slots=%d index=%d valid=%t", slots, index, ok)
		}
	}
	if index, ok := policy.fastIndex(0x20, 10); index != 0 || !ok {
		t.Fatalf("first fastbin=%d valid=%t", index, ok)
	}
	if index, ok := policy.fastIndex(0xb0, 10); index != 9 || !ok {
		t.Fatalf("last fastbin=%d valid=%t", index, ok)
	}
	for _, size := range []uint64{0, 0x10, 0x1f, 0x21, 0xb1, 0xc0, 0x100000020, math.MaxUint64 - 15, math.MaxUint64} {
		if index, ok := policy.fastIndex(size, 10); index != 0 || ok {
			t.Fatalf("invalid fast size=%#x index=%d valid=%t", size, index, ok)
		}
	}
}

func TestHeapBinPolicyFastDomainDoesNotTruncate(t *testing.T) {
	policy := heapTestBinPolicy(4, 12)
	const maximumSlots = uint64(math.MaxUint32>>4) - 1
	if index, ok := policy.fastIndex(0xfffffff0, maximumSlots); !ok || index != maximumSlots-1 {
		t.Fatalf("last unsigned32 class=%#x valid=%t", index, ok)
	}
	if size, ok := policy.fastRange(maximumSlots-1, maximumSlots); !ok || size != 0xfffffff0 {
		t.Fatalf("last unsigned32 size=%#x valid=%t", size, ok)
	}
	for _, slots := range []uint64{0, maximumSlots + 1, math.MaxUint64} {
		if index, ok := policy.fastIndex(0x20, slots); index != 0 || ok {
			t.Fatalf("invalid slots=%#x index=%#x valid=%t", slots, index, ok)
		}
		if size, ok := policy.fastRange(0, slots); size != 0 || ok {
			t.Fatalf("invalid slots=%#x size=%#x valid=%t", slots, size, ok)
		}
	}
	if index, ok := policy.fastIndex(0x100000000, maximumSlots); index != 0 || ok {
		t.Fatal("unsigned32 truncation accepted")
	}
	if size, ok := policy.fastRange(math.MaxUint64, 10); size != 0 || ok {
		t.Fatal("overflowing index accepted")
	}
	policy.FastBinShift = 0
	if index, ok := policy.fastIndex(0x20, 10); index != 0 || ok {
		t.Fatal("absent fastbins produced a class")
	}
	if size, ok := policy.fastRange(0, 10); size != 0 || ok {
		t.Fatal("absent fastbins produced a range")
	}
}
