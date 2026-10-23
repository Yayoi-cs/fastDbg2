package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func TestRuntimeProcmapKernelABILayout(t *testing.T) {
	var query runtimeProcmapQuery
	if unsafe.Sizeof(query) != 104 || unsafe.Offsetof(query.QueryAddr) != 16 || unsafe.Offsetof(query.Inode) != 64 ||
		unsafe.Offsetof(query.DevMajor) != 72 || unsafe.Offsetof(query.BuildIDSize) != 84 || unsafe.Offsetof(query.BuildIDAddr) != 96 || procmapQueryIOCTL != 3<<30|104<<16|'f'<<8|17 {
		t.Fatalf("wrong Linux AMD64 PROCMAP_QUERY layout: size=%d query=%+v", unsafe.Sizeof(query), query)
	}
}

func runtimeProcmapTestPair() (procMap, runtimeProcmapQuery) {
	mapping := procMap{Start: 0x1000, End: 0x2000, Offset: 0x3000, Inode: 42, DevMajor: 1, DevMinor: 2, Read: true, Write: true, Execute: true, Private: true}
	query := runtimeProcmapQuery{Start: 0x1000, End: 0x2000, Offset: 0x3000, Inode: 42, DevMajor: 1, DevMinor: 2, Flags: 7, PageSize: 4096, BuildIDSize: 20}
	return mapping, query
}

func TestRuntimeProcmapRequiresExactMappingObservation(t *testing.T) {
	mapping, query := runtimeProcmapTestPair()
	if err := validateRuntimeProcmapQuery(mapping, query, 128); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*runtimeProcmapQuery){
		func(q *runtimeProcmapQuery) { q.Start++ }, func(q *runtimeProcmapQuery) { q.End++ },
		func(q *runtimeProcmapQuery) { q.Offset++ }, func(q *runtimeProcmapQuery) { q.Inode++ },
		func(q *runtimeProcmapQuery) { q.DevMajor++ }, func(q *runtimeProcmapQuery) { q.DevMinor++ },
		func(q *runtimeProcmapQuery) { q.Flags ^= 1 }, func(q *runtimeProcmapQuery) { q.Flags ^= 2 },
		func(q *runtimeProcmapQuery) { q.Flags ^= 4 }, func(q *runtimeProcmapQuery) { q.Flags ^= 8 },
		func(q *runtimeProcmapQuery) { q.Flags |= 16 },
	} {
		changed := query
		edit(&changed)
		if err := validateRuntimeProcmapQuery(mapping, changed, 128); !errors.Is(err, target.ErrStale) {
			t.Fatalf("query=%+v error=%v", changed, err)
		}
	}
	mapping.Private, query.Flags = false, 15
	if err := validateRuntimeProcmapQuery(mapping, query, 128); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeProcmapValidatesBuildIDBoundsAndPageSize(t *testing.T) {
	for _, test := range []struct {
		page     uint64
		size     uint32
		capacity int
		err      error
	}{
		{4096, 128, 128, nil}, {4096, 129, 128, target.ErrOverflow}, {4096, 1, -1, target.ErrOverflow},
		{4096, 0, 128, target.ErrUnavailable}, {0, 20, 128, target.ErrInvalidArgument}, {3, 20, 128, target.ErrInvalidArgument},
	} {
		mapping, query := runtimeProcmapTestPair()
		query.PageSize, query.BuildIDSize = test.page, test.size
		if err := validateRuntimeProcmapQuery(mapping, query, test.capacity); !errors.Is(err, test.err) {
			t.Fatalf("query=%+v capacity=%d error=%v", query, test.capacity, err)
		}
	}
}

func TestRuntimeProcmapRejectsUnobservedOrAnonymousMappings(t *testing.T) {
	dir := procTestDirectory(t)
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte("1000-2000 r--p 0 00:00 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	proc := &stoppedProc{ctx: context.Background(), dir: file}
	mappings, err := proc.maps()
	if err != nil {
		t.Fatal(err)
	}
	if id, err := proc.mappedBuildID(mappings[0]); id != nil || !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("id=%x error=%v", id, err)
	}
	wrong := mappings[0]
	wrong.Inode++
	if id, err := proc.mappedBuildID(wrong); id != nil || !errors.Is(err, target.ErrStale) {
		t.Fatalf("id=%x error=%v", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	proc.ctx = ctx
	if _, err := proc.mappedBuildID(mappings[0]); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRuntimeProcmapLiveAllBackingSegmentsAndFDFlags(t *testing.T) {
	fixture := newExpansionIntegration(t, true)
	fixture.breakpoint(t)
	snapshot, thread, err := fixture.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	err = fixture.controller.withStoppedProc(context.Background(), snapshot, thread, func(proc *stoppedProc) error {
		mappings, err := proc.maps()
		if err != nil {
			return err
		}
		view, err := fixture.controller.runtimeELFModules(context.Background(), snapshot, proc)
		if err != nil {
			return err
		}
		defer view.Memory.close()
		var image *runtimeELFModule
		for _, module := range view.Modules {
			if module.ID == "interpreter" {
				image = module
			}
		}
		if image == nil || image.BuildIDErr != nil || len(image.BuildID) == 0 {
			t.Fatalf("formal AT_BASE module has no complete build ID: %+v", image)
		}
		flags, err := unix.FcntlInt(proc.dir.Fd(), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		fdFlags, err := unix.FcntlInt(proc.dir.Fd(), unix.F_GETFD, 0)
		if err != nil {
			return err
		}
		if fdFlags&unix.FD_CLOEXEC == 0 {
			t.Fatal("procfs directory FD missing CLOEXEC")
		}
		checked, nonzeroOffset := 0, false
		for _, mapping := range mappings {
			intersects := false
			for _, load := range image.Loads {
				if mapping.Start < load.Address+target.Address(load.Size) && load.Address < mapping.End {
					intersects = true
				}
			}
			if !intersects || mapping.Inode == 0 {
				continue
			}
			id, err := proc.mappedBuildID(mapping)
			if errors.Is(err, target.ErrUnsupported) {
				t.Logf("kernel does not implement PROCMAP_QUERY: %v", err)
				return nil
			}
			if err != nil {
				return err
			}
			if !bytes.Equal(id, image.BuildID) {
				t.Fatalf("mapping=%+v id=%x runtime ELF note=%x", mapping, id, image.BuildID)
			}
			checked++
			nonzeroOffset = nonzeroOffset || mapping.Offset != 0
		}
		if checked < 3 || !nonzeroOffset {
			t.Fatalf("insufficient exact backed segments: count=%d nonzero=%t", checked, nonzeroOffset)
		}
		afterFlags, err := unix.FcntlInt(proc.dir.Fd(), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		afterFDFlags, err := unix.FcntlInt(proc.dir.Fd(), unix.F_GETFD, 0)
		if err != nil {
			return err
		}
		if flags != afterFlags || fdFlags != afterFDFlags {
			t.Fatal("build ID observation changed caller FD flags")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeProcmapLongBuildIDIsNeverTruncatedPrefix(t *testing.T) {
	for _, size := range []int{20, 64} {
		image := runtimeELFTestObject(t, 0x400000, true, 0)
		binary.LittleEndian.PutUint32(image.data[0x804:], uint32(size))
		binary.LittleEndian.PutUint64(image.data[64+4*56+32:], uint64(16+size))
		binary.LittleEndian.PutUint64(image.data[64+4*56+40:], uint64(16+size))
		for index := 0; index < size; index++ {
			image.data[0x810+index] = byte(index + 1)
		}
		path := filepath.Join(procTestDirectory(t), "build-id.elf")
		if err := os.WriteFile(path, image.data, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := unix.Mmap(int(file.Fd()), 0, len(image.data), unix.PROT_READ, unix.MAP_PRIVATE)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal(errors.Join(err, closeErr))
		}
		t.Cleanup(func() {
			if err := unix.Munmap(mapped); err != nil {
				t.Error(err)
			}
		})
		proc, err := openStoppedProc(context.Background(), os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = proc.dir.Close() })
		mappings, err := proc.maps()
		if err != nil {
			t.Fatal(err)
		}
		address := target.Address(uintptr(unsafe.Pointer(&mapped[0])))
		found := false
		for _, mapping := range mappings {
			if address < mapping.Start || address >= mapping.End {
				continue
			}
			found = true
			id, err := proc.mappedBuildID(mapping)
			if errors.Is(err, target.ErrUnsupported) {
				t.Logf("kernel does not implement PROCMAP_QUERY: %v", err)
				break
			}
			if size > 20 && errors.Is(err, target.ErrUnavailable) && id == nil {
				break
			}
			if err != nil || !bytes.Equal(id, image.data[0x810:0x810+size]) {
				t.Fatalf("size=%d returned ID=%x error=%v", size, id, err)
			}
		}
		if !found {
			t.Fatal("owned ELF mapping missing")
		}
	}
}
