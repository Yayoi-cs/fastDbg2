package xstate

import (
	"errors"
	"testing"

	"fastdbg2/target"
)

func testLeaves() map[uint32][4]uint32 {
	return map[uint32][4]uint32{
		0: {0x207, 2696, 2696, 0},
		2: {256, 576, 0, 0},
		9: {8, 2688, 0, 0},
	}
}

func decodeLeaves(leaves map[uint32][4]uint32) (CPU, error) {
	return decode(func(leaf, subleaf uint32) (uint32, uint32, uint32, uint32) {
		value := leaves[subleaf]
		return value[0], value[1], value[2], value[3]
	}, CPU{Enabled: 0x207, MXCSRMask: 0xffff})
}

func TestCPUEnumeration(t *testing.T) {
	cpu, err := decodeLeaves(testLeaves())
	if err != nil || !cpu.XSave || cpu.Size != 2696 || cpu.Supported != 0x207 || cpu.Enabled != 0x207 || len(cpu.Components) != 2 {
		t.Fatalf("CPU=%+v err=%v", cpu, err)
	}
	if cpu.Components[0] != (Component{ID: 2, Offset: 576, Size: 256}) || cpu.Components[1] != (Component{ID: 9, Offset: 2688, Size: 8}) {
		t.Fatalf("components=%+v", cpu.Components)
	}
}

func TestCPUEnumerationRejectsInvalidLayout(t *testing.T) {
	for _, change := range []func(map[uint32][4]uint32){
		func(v map[uint32][4]uint32) { v[0] = [4]uint32{0x207, 568, 2696, 0} },
		func(v map[uint32][4]uint32) { v[0] = [4]uint32{0x207, 2697, 2704, 0} },
		func(v map[uint32][4]uint32) { v[0] = [4]uint32{0x207, 2696, 2695, 0} },
		func(v map[uint32][4]uint32) { v[0] = [4]uint32{0x203, 2696, 2696, 0} },
		func(v map[uint32][4]uint32) { v[0] = [4]uint32{0x207, 2696, 2696, 1 << 31} },
		func(v map[uint32][4]uint32) { v[2] = [4]uint32{0, 576, 0, 0} },
		func(v map[uint32][4]uint32) { v[2] = [4]uint32{256, 512, 0, 0} },
		func(v map[uint32][4]uint32) { v[2] = [4]uint32{256, 576, 1, 0} },
		func(v map[uint32][4]uint32) { v[9] = [4]uint32{8, 600, 0, 0} },
		func(v map[uint32][4]uint32) { v[9] = [4]uint32{9, 2688, 0, 0} },
	} {
		leaves := testLeaves()
		change(leaves)
		if _, err := decodeLeaves(leaves); !errors.Is(err, target.ErrUnsupported) {
			t.Fatalf("invalid leaves=%v err=%v", leaves, err)
		}
	}
}

func TestCPUEnumerationAllowsOffsetOrderDifferentFromFeatureOrder(t *testing.T) {
	leaves := testLeaves()
	leaves[2], leaves[9] = [4]uint32{256, 1024, 0, 0}, [4]uint32{8, 576, 0, 0}
	if _, err := decodeLeaves(leaves); err != nil {
		t.Fatal(err)
	}
}

func TestHostCPUEnumeration(t *testing.T) {
	cpu, err := Host()
	if errors.Is(err, target.ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil || cpu.Size < 512 || cpu.MXCSRMask == 0 {
		t.Fatalf("CPU=%+v err=%v", cpu, err)
	}
	t.Logf("XSAVE=%v size=%d supported=%#x enabled=%#x MXCSR_MASK=%#x components=%+v", cpu.XSave, cpu.Size, cpu.Supported, cpu.Enabled, cpu.MXCSRMask, cpu.Components)
}
