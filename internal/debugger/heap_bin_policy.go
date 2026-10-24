package debugger

import (
	"fmt"
	"math"
	"math/bits"

	"fastdbg2/target"
)

type heapBinPolicy struct {
	Pointer             uint64
	Alignment           uint64
	MinChunkSize        uint64
	SmallBinCount       uint64
	NormalBinCount      uint64
	FastBinShift        uint64
	TcacheSmallBinCount uint64
	TcacheLargeBinCount uint64
}

func (policy heapBinPolicy) valid() bool {
	return (policy.Pointer == 0 || policy.Pointer == 4 || policy.Pointer == 8) && policy.Alignment == 16 && policy.MinChunkSize == policy.word()*4 &&
		policy.SmallBinCount == 64 && policy.NormalBinCount == 128 &&
		(policy.FastBinShift == 0 || policy.word() == 8 && policy.FastBinShift == 4 || policy.word() == 4 && policy.FastBinShift == 3) &&
		policy.TcacheSmallBinCount == 64 && (policy.TcacheLargeBinCount == 0 || policy.TcacheLargeBinCount == 12)
}

func (policy heapBinPolicy) validate() error {
	if !policy.valid() {
		return fmt.Errorf("glibc AMD64 bin policy %+v: %w", policy, target.ErrUnsupported)
	}
	return nil
}

func (policy heapBinPolicy) tcacheIndex(size uint64) (uint64, bool) {
	if !policy.valid() || size < policy.MinChunkSize || size%policy.Alignment != 0 {
		return 0, false
	}
	maximumSmall := policy.MinChunkSize + (policy.TcacheSmallBinCount-1)*policy.Alignment
	if size <= maximumSmall {
		return (size - policy.MinChunkSize) / policy.Alignment, true
	}
	index := policy.TcacheSmallBinCount + uint64(bits.Len64(size)-bits.Len64(maximumSmall))
	if index >= policy.TcacheSmallBinCount+policy.TcacheLargeBinCount {
		return 0, false
	}
	return index, true
}

func (policy heapBinPolicy) tcacheRange(index uint64) (uint64, uint64, bool) {
	if !policy.valid() || index >= policy.TcacheSmallBinCount+policy.TcacheLargeBinCount {
		return 0, 0, false
	}
	if index < policy.TcacheSmallBinCount {
		size := policy.MinChunkSize + index*policy.Alignment
		return size, size, true
	}
	maximumSmall := policy.MinChunkSize + (policy.TcacheSmallBinCount-1)*policy.Alignment
	exponent := uint64(bits.Len64(maximumSmall)-1) + index - policy.TcacheSmallBinCount
	minimum := max(uint64(1)<<exponent, maximumSmall+policy.Alignment)
	maximum := (uint64(1) << (exponent + 1)) - policy.Alignment
	return minimum, maximum, true
}

func (policy heapBinPolicy) normalName(index uint64) string {
	if !policy.valid() {
		return "unsupported"
	}
	switch {
	case index == 1:
		return "unsorted"
	case index >= policy.MinChunkSize/policy.Alignment && index < policy.SmallBinCount:
		return "small"
	case index >= policy.SmallBinCount && index < policy.NormalBinCount-1:
		return "large"
	default:
		return "reserved"
	}
}

func (policy heapBinPolicy) largeIndex(size uint64) uint64 {
	if !policy.valid() || size < (policy.SmallBinCount-policy.correction())*policy.Alignment || size%policy.Alignment != 0 {
		return math.MaxUint64
	}
	if policy.correction() == 1 && size>>6 <= 45 {
		return 49 + (size >> 6)
	}
	switch {
	case policy.correction() == 0 && size>>6 <= 48:
		return 48 + (size >> 6)
	case size>>9 <= 20:
		return 91 + (size >> 9)
	case size>>12 <= 10:
		return 110 + (size >> 12)
	case size>>15 <= 4:
		return 119 + (size >> 15)
	case size>>18 <= 2:
		return 124 + (size >> 18)
	default:
		return policy.NormalBinCount - 2
	}
}

func (policy heapBinPolicy) largeRange(index uint64) (uint64, uint64, bool) {
	if !policy.valid() || index < policy.SmallBinCount || index > policy.NormalBinCount-2 {
		return 0, 0, false
	}
	first := func(wanted uint64) uint64 {
		low, high := policy.SmallBinCount-policy.correction(), uint64(math.MaxUint64)/policy.Alignment
		for low < high {
			middle := low + (high-low)/2
			if policy.largeIndex(middle*policy.Alignment) >= wanted {
				high = middle
			} else {
				low = middle + 1
			}
		}
		return low * policy.Alignment
	}
	minimum := first(index)
	if index == policy.NormalBinCount-2 {
		return minimum, uint64(math.MaxUint64) &^ (policy.Alignment - 1), true
	}
	return minimum, first(index+1) - policy.Alignment, true
}

func (policy heapBinPolicy) fastSlotsValid(slots uint64) bool {
	return policy.valid() && policy.FastBinShift != 0 && slots != 0 &&
		slots <= (uint64(math.MaxUint32)>>policy.FastBinShift)-(policy.MinChunkSize>>policy.FastBinShift)+1
}

func (policy heapBinPolicy) fastIndex(size, slots uint64) (uint64, bool) {
	if !policy.fastSlotsValid(slots) || size < policy.MinChunkSize || size > math.MaxUint32 || size%policy.Alignment != 0 {
		return 0, false
	}
	index := (size >> policy.FastBinShift) - (policy.MinChunkSize >> policy.FastBinShift)
	if index >= slots {
		return 0, false
	}
	return index, true
}

func (policy heapBinPolicy) fastRange(index, slots uint64) (uint64, bool) {
	if !policy.fastSlotsValid(slots) || index >= slots {
		return 0, false
	}
	size := policy.MinChunkSize + index*(1<<policy.FastBinShift)
	return size, size%policy.Alignment == 0
}

func (policy heapBinPolicy) correction() uint64 {
	if policy.word() == 4 {
		return 1
	}
	return 0
}

func (policy heapBinPolicy) word() uint64 {
	if policy.Pointer == 0 {
		return 8
	}
	return policy.Pointer
}
