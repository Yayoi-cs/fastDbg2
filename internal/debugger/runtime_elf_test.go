package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"fastdbg2/target"
)

type runtimeELFTestRegion struct {
	address target.Address
	data    []byte
}

func runtimeELFTestMemory(t *testing.T, regions ...runtimeELFTestRegion) *runtimeELFMemory {
	t.Helper()
	sort.Slice(regions, func(i, j int) bool { return regions[i].address < regions[j].address })
	var mappings []procMap
	for _, region := range regions {
		mappings = append(mappings, procMap{Start: region.address, End: region.address + target.Address(len(region.data)), Read: true, Private: true})
	}
	memory, err := newRuntimeELFMemory(context.Background(), mappings, func(address target.Address, data []byte) (int, error) {
		for _, region := range regions {
			if address >= region.address && uint64(address-region.address) < uint64(len(region.data)) {
				n := copy(data, region.data[uint64(address-region.address):])
				if n != len(data) {
					return n, io.ErrUnexpectedEOF
				}
				return n, nil
			}
		}
		return 0, target.ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(memory.close)
	return memory
}

func runtimeELFTestObject(t *testing.T, address target.Address, pie bool, rendezvous uint64) runtimeELFTestRegion {
	t.Helper()
	virtual := uint64(0)
	kind := elf.ET_DYN
	if !pie {
		virtual, kind = uint64(address), elf.ET_EXEC
	}
	programs := []elf.Prog64{
		{Type: uint32(elf.PT_PHDR), Flags: uint32(elf.PF_R), Off: 64, Vaddr: virtual + 64, Filesz: 5 * 56, Memsz: 5 * 56, Align: 8},
		{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W | elf.PF_X), Vaddr: virtual, Filesz: 0x2000, Memsz: 0x2000, Align: 0x1000},
		{Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R | elf.PF_W), Off: 0x500, Vaddr: virtual + 0x500, Filesz: 32, Memsz: 32, Align: 8},
		{Type: uint32(elf.PT_GNU_EH_FRAME), Flags: uint32(elf.PF_R), Off: 0x700, Vaddr: virtual + 0x700, Filesz: 16, Memsz: 16, Align: 4},
		{Type: uint32(elf.PT_NOTE), Flags: uint32(elf.PF_R), Off: 0x800, Vaddr: virtual + 0x800, Filesz: 20, Memsz: 20, Align: 4},
	}
	header := elf.Header64{Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Entry: virtual + 0x1000, Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: uint16(len(programs))}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS], header.Ident[elf.EI_DATA], header.Ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	var encoded bytes.Buffer
	for _, value := range []any{header, programs} {
		if err := binary.Write(&encoded, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	data := make([]byte, 0x2000)
	copy(data, encoded.Bytes())
	binary.LittleEndian.PutUint64(data[0x500:], uint64(elf.DT_DEBUG))
	binary.LittleEndian.PutUint64(data[0x508:], rendezvous)
	binary.LittleEndian.PutUint32(data[0x800:], 4)
	binary.LittleEndian.PutUint32(data[0x804:], 4)
	binary.LittleEndian.PutUint32(data[0x808:], 3)
	copy(data[0x80c:], "GNU\x00")
	copy(data[0x810:], []byte{1, 2, 3, byte(address >> 20)})
	return runtimeELFTestRegion{address, data}
}

func runtimeELFTestAuxiliary(entries ...uint64) []byte {
	data := make([]byte, len(entries)*8+16)
	for index, value := range entries {
		binary.LittleEndian.PutUint64(data[index*8:], value)
	}
	return data
}

type runtimeELFTestSetup struct {
	memory *runtimeELFMemory
	auxv   []byte
	main   []byte
	lib    []byte
	state  []byte
}

func runtimeELFTestLoader(t *testing.T, pie bool) runtimeELFTestSetup {
	t.Helper()
	main := runtimeELFTestObject(t, 0x400000, pie, 0x900000)
	interpreter := runtimeELFTestObject(t, 0x600000, true, 0)
	vdso := runtimeELFTestObject(t, 0x700000, true, 0)
	library := runtimeELFTestObject(t, 0x800000, true, 0)
	state := runtimeELFTestRegion{0x900000, make([]byte, 0x20000)}
	binary.LittleEndian.PutUint32(state.data, 1)
	binary.LittleEndian.PutUint64(state.data[8:], 0x900100)
	for index, image := range []runtimeELFTestRegion{main, interpreter, vdso, library} {
		offset := 0x100 + index*40
		bias := uint64(image.address)
		if index == 0 && !pie {
			bias = 0
		}
		binary.LittleEndian.PutUint64(state.data[offset:], bias)
		binary.LittleEndian.PutUint64(state.data[offset+8:], 0x902000+uint64(index*256))
		binary.LittleEndian.PutUint64(state.data[offset+16:], uint64(image.address)+0x500)
		if index < 3 {
			binary.LittleEndian.PutUint64(state.data[offset+24:], 0x900100+uint64((index+1)*40))
		}
		if index > 0 {
			binary.LittleEndian.PutUint64(state.data[offset+32:], 0x900100+uint64((index-1)*40))
			copy(state.data[0x2000+index*256:], fmt.Sprintf("module-%d", index))
		}
	}
	return runtimeELFTestSetup{
		memory: runtimeELFTestMemory(t, main, interpreter, vdso, library, state),
		auxv:   runtimeELFTestAuxiliary(3, 0x400040, 4, 56, 5, 5, 7, 0x600000, 33, 0x700000),
		main:   main.data, lib: library.data, state: state.data,
	}
}

func TestRuntimeELFDiscoversExactAuxiliaryAndLoaderAnchors(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			fixture := runtimeELFTestLoader(t, pie)
			view, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
			if err != nil || len(view.Modules) != 4 || !view.LoaderComplete || len(view.Loader) != 4 {
				t.Fatalf("view=%+v error=%v", view, err)
			}
			for index, module := range view.Modules {
				if module.Proof == "" || module.ID == "" || len(module.Programs) != 5 || len(module.Loads) != 1 || len(module.Links) != 1 || module.EHFrameHeader.Size != 16 || len(module.BuildID) != 4 || module.BuildIDErr != nil {
					t.Fatalf("module=%+v", module)
				}
				if module.EHFrameHeader.Address != module.Loads[0].Address+0x700 {
					t.Fatalf("EH_FRAME_HDR address=%#x", module.EHFrameHeader.Address)
				}
				if index == 0 && (!module.Main || (module.LoadBias != 0) != pie) {
					t.Fatalf("main=%+v PIE=%t", module, pie)
				}
				if index < 3 {
					tag := []uint64{3, 7, 33}[index]
					address := []target.Address{0x400040, 0x600000, 0x700000}[index]
					if module.AuxiliaryTag != tag || module.AuxiliaryAddress != address {
						t.Fatalf("wrong formal auxiliary anchor: module=%+v", module)
					}
				} else if module.AuxiliaryTag != 0 || module.AuxiliaryAddress != 0 {
					t.Fatalf("invented auxiliary anchor for loader module: %+v", module)
				}
			}
		})
	}
}

func TestRuntimeELFUnpublishedLoaderPreservesOnlyIndependentAnchors(t *testing.T) {
	for _, edit := range []func(runtimeELFTestSetup){
		func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.main[0x508:], 0) },
		func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint32(f.state[24:], 1) },
		func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.state[8:], 0) },
		func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.state[0x110:], 0x400501) },
	} {
		fixture := runtimeELFTestLoader(t, true)
		edit(fixture)
		view, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
		if !errors.Is(err, target.ErrUnavailable) || view == nil || len(view.Modules) != 3 || view.LoaderComplete || len(view.Loader) != 0 {
			t.Fatalf("view=%+v error=%v", view, err)
		}
	}
}

func TestRuntimeELFLoaderPendingRequiresPresentZeroDebugEntry(t *testing.T) {
	for _, test := range []struct {
		name    string
		edit    func(runtimeELFTestSetup)
		pending bool
	}{
		{"zero", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.main[0x508:], 0) }, true},
		{"absent", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.main[0x500:], 0) }, false},
		{"malformed", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.main[0x510:], uint64(elf.DT_DEBUG)) }, false},
		{"inconsistent", func(f runtimeELFTestSetup) { binary.LittleEndian.PutUint32(f.state[24:], 1) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := runtimeELFTestLoader(t, true)
			test.edit(fixture)
			_, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
			if err == nil || runtimeELFLoaderPending(err) != test.pending {
				t.Fatalf("pending=%t error=%v", runtimeELFLoaderPending(err), err)
			}
		})
	}
	for _, invalid := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		if runtimeELFLoaderPending(errors.Join(&runtimeLoaderPendingError{}, invalid)) {
			t.Fatalf("invalid proof classified pending: %v", invalid)
		}
	}
}

func TestRuntimeELFRejectsUnsupportedDSOWithoutScanningOtherHeaders(t *testing.T) {
	fixture := runtimeELFTestLoader(t, true)
	copy(fixture.lib[0x1000:], fixture.lib[:0x1000])
	fixture.lib[0] = 0
	view, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
	if !errors.Is(err, target.ErrUnsupported) || view == nil || len(view.Modules) != 3 || !view.LoaderComplete || len(view.Loader) != 4 {
		t.Fatalf("view=%+v error=%v", view, err)
	}
	for _, module := range view.Modules {
		if module.Header == 0x801000 {
			t.Fatal("scanned to a different ELF header")
		}
	}
}

func TestRuntimeELFMainRequiresUniqueExactPHDRRelation(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*runtimeELFTestSetup)
		err  error
	}{
		{"no PHDR", func(f *runtimeELFTestSetup) { binary.LittleEndian.PutUint32(f.main[64:], uint32(elf.PT_NULL)) }, target.ErrUnsupported},
		{"duplicate PHDR", func(f *runtimeELFTestSetup) { copy(f.main[64+4*56:], f.main[64:64+56]) }, target.ErrAmbiguous},
		{"wrong size", func(f *runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.main[64+32:], 1) }, target.ErrInvalidArgument},
		{"underflow", func(f *runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.main[64+16:], 0x500000) }, target.ErrInvalidArgument},
		{"wrong PHENT", func(f *runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.auxv[24:], 55) }, target.ErrUnavailable},
		{"large PHNUM", func(f *runtimeELFTestSetup) { binary.LittleEndian.PutUint64(f.auxv[40:], maxRuntimeELFPrograms+1) }, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := runtimeELFTestLoader(t, true)
			test.edit(&fixture)
			view, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
			if !errors.Is(err, test.err) || view == nil || len(view.Modules) != 2 || view.LoaderComplete {
				t.Fatalf("view=%+v error=%v", view, err)
			}
		})
	}
}

func runtimeELFTestPinnedMain(t *testing.T, image runtimeELFTestRegion, bias uint64) *mappedELF {
	t.Helper()
	path := filepath.Join(procTestDirectory(t), "main.elf")
	if err := os.WriteFile(path, image.data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	file, err := elf.NewFile(source)
	if err != nil {
		t.Fatal(err)
	}
	return &mappedELF{ID: "main", File: file, Source: source, Main: true, LoadBias: bias, Proof: "proc-exe+auxv"}
}

func TestRuntimeELFMainWithoutPHDRUsesExactPinnedMainCoordinates(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			image := runtimeELFTestObject(t, 0x400000, pie, 0)
			binary.LittleEndian.PutUint32(image.data[64:], uint32(elf.PT_NULL))
			bias := uint64(0)
			if pie {
				bias = 0x400000
			}
			source := runtimeELFTestPinnedMain(t, image, bias)
			memory := runtimeELFTestMemory(t, image)
			auxv := runtimeELFTestAuxiliary(3, 0x400040, 4, 56, 5, 5, 9, 0x401000)
			view, err := discoverRuntimeELFWithMain(memory, auxv, source)
			if err != nil || len(view.Modules) != 1 || view.LoaderComplete || view.Modules[0].LoadBias != bias || view.Modules[0].Proof != "proc-exe+auxv-AT_ENTRY+runtime-AT_PHDR" {
				t.Fatalf("view=%+v error=%v", view, err)
			}
		})
	}
}

func TestRuntimeELFMainPinnedFallbackRejectsMismatchedEvidence(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*testing.T, runtimeELFTestRegion, *mappedELF, map[uint64]uint64)
		err  error
	}{
		{"runtime program", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			binary.LittleEndian.PutUint32(image.data[64+56+4:], uint32(elf.PF_R))
		}, target.ErrStale},
		{"cached source program", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			source.File.Progs[1].Flags = elf.PF_R
		}, target.ErrStale},
		{"entry", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) { auxv[9]++ }, target.ErrStale},
		{"missing entry", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			delete(auxv, 9)
		}, target.ErrUnavailable},
		{"cached bias", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			source.LoadBias++
		}, target.ErrStale},
		{"source kind", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			source.Main = false
		}, target.ErrInvalidArgument},
		{"source proof", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			source.Proof = "kernel-vma-build-id-metadata"
		}, target.ErrInvalidArgument},
		{"different PHDR coordinate", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			copy(image.data[0xa00:], image.data[64:64+5*56])
			auxv[3] = 0x400a00
		}, target.ErrStale},
		{"source PHDR offset", func(t *testing.T, image runtimeELFTestRegion, source *mappedELF, auxv map[uint64]uint64) {
			copy(image.data[0xa00:], image.data[64:64+5*56])
			changed := slices.Clone(image.data)
			binary.LittleEndian.PutUint64(changed[32:], 0xa00)
			if _, err := source.Source.WriteAt(changed, 0); err != nil {
				t.Fatal(err)
			}
		}, target.ErrStale},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := runtimeELFTestObject(t, 0x400000, true, 0)
			binary.LittleEndian.PutUint32(image.data[64:], uint32(elf.PT_NULL))
			source := runtimeELFTestPinnedMain(t, image, 0x400000)
			auxv := map[uint64]uint64{3: 0x400040, 4: 56, 5: 5, 9: 0x401000}
			test.edit(t, image, source, auxv)
			if module, err := runtimeELFMainWithSource(runtimeELFTestMemory(t, image), auxv, source); module != nil || !errors.Is(err, test.err) {
				t.Fatalf("module=%+v error=%v", module, err)
			}
		})
	}
}

func TestRuntimeELFMainSourceDoesNotMaskMalformedPHDR(t *testing.T) {
	image := runtimeELFTestObject(t, 0x400000, true, 0)
	source := runtimeELFTestPinnedMain(t, image, 0x400000)
	binary.LittleEndian.PutUint64(image.data[64+32:], 1)
	if module, err := runtimeELFMainWithSource(runtimeELFTestMemory(t, image), map[uint64]uint64{3: 0x400040, 4: 56, 5: 5, 9: 0x401000}, source); module != nil || !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("module=%+v error=%v", module, err)
	}
}

func TestRuntimeELFNoInterpreterDoesNotHideInvalidOrExpectedRendezvous(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte)
		err  error
	}{
		{"absent debug tag", func(data []byte) { binary.LittleEndian.PutUint64(data[0x500:], 0) }, nil},
		{"interpreter declaration", func(data []byte) { binary.LittleEndian.PutUint32(data[64+4*56:], uint32(elf.PT_INTERP)) }, target.ErrUnavailable},
		{"malformed dynamic", func(data []byte) { binary.LittleEndian.PutUint64(data[0x510:], uint64(elf.DT_STRTAB)) }, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := runtimeELFTestObject(t, 0x400000, true, 0)
			binary.LittleEndian.PutUint32(image.data[64:], uint32(elf.PT_NULL))
			test.edit(image.data)
			source := runtimeELFTestPinnedMain(t, image, 0x400000)
			view, err := discoverRuntimeELFWithMain(runtimeELFTestMemory(t, image), runtimeELFTestAuxiliary(3, 0x400040, 4, 56, 5, 5, 9, 0x401000), source)
			if !errors.Is(err, test.err) || view == nil || len(view.Modules) != 1 || view.LoaderComplete {
				t.Fatalf("view=%+v error=%v", view, err)
			}
		})
	}
}

func TestRuntimeELFZeroOriginValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte)
		err  error
	}{
		{"machine", func(data []byte) { binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_AARCH64)) }, target.ErrUnsupported},
		{"exec", func(data []byte) { binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_EXEC)) }, target.ErrUnsupported},
		{"phoff overflow", func(data []byte) { binary.LittleEndian.PutUint64(data[32:], math.MaxUint64) }, target.ErrOverflow},
		{"nonzero origin", func(data []byte) { binary.LittleEndian.PutUint64(data[64+56+16:], 0x1000) }, target.ErrUnsupported},
		{"wrong load filesz", func(data []byte) { binary.LittleEndian.PutUint64(data[64+56+32:], 0x100) }, target.ErrUnsupported},
		{"memory size", func(data []byte) { binary.LittleEndian.PutUint64(data[64+56+40:], 1) }, target.ErrOverflow},
		{"bad alignment", func(data []byte) { binary.LittleEndian.PutUint64(data[64+56+48:], 3) }, target.ErrInvalidArgument},
		{"dynamic outside load", func(data []byte) { binary.LittleEndian.PutUint64(data[64+2*56+16:], 0x3000) }, target.ErrInvalidArgument},
		{"duplicate EH header", func(data []byte) { copy(data[64+4*56:], data[64+3*56:64+4*56]) }, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := runtimeELFTestObject(t, 0x400000, true, 0)
			test.edit(image.data)
			if _, err := runtimeELFZeroOrigin(runtimeELFTestMemory(t, image), image.address, nil); !errors.Is(err, test.err) {
				t.Fatal(err)
			}
		})
	}
	image := runtimeELFTestObject(t, 0x400000, true, 0)
	wrong := target.Address(0x400501)
	if _, err := runtimeELFZeroOrigin(runtimeELFTestMemory(t, image), image.address, &wrong); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestRuntimeELFLoaderListStructuralFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte)
		err  error
	}{
		{"version", func(data []byte) { binary.LittleEndian.PutUint32(data, 3) }, target.ErrUnsupported},
		{"state", func(data []byte) { binary.LittleEndian.PutUint32(data[24:], 2) }, target.ErrUnavailable},
		{"backlink", func(data []byte) { binary.LittleEndian.PutUint64(data[0x100+40+32:], 0) }, target.ErrInvalidArgument},
		{"cycle", func(data []byte) { binary.LittleEndian.PutUint64(data[0x100+3*40+24:], 0x900100) }, target.ErrInvalidArgument},
		{"null name", func(data []byte) { binary.LittleEndian.PutUint64(data[0x108:], 0) }, target.ErrInvalidArgument},
		{"unreadable name", func(data []byte) { binary.LittleEndian.PutUint64(data[0x108:], 0xdeadbeef) }, target.ErrUnavailable},
		{"namespace cycle", func(data []byte) {
			binary.LittleEndian.PutUint32(data, 2)
			binary.LittleEndian.PutUint64(data[40:], 0x900000)
		}, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := runtimeELFTestLoader(t, true)
			test.edit(fixture.state)
			if links, err := runtimeELFLinkMaps(fixture.memory, 0x900000); !errors.Is(err, test.err) || links != nil {
				t.Fatalf("links=%+v error=%v", links, err)
			}
		})
	}
}

func TestRuntimeELFExtendedNamespaceKeepsPhysicalImageAndLinkIdentities(t *testing.T) {
	fixture := runtimeELFTestLoader(t, true)
	binary.LittleEndian.PutUint32(fixture.state, 2)
	binary.LittleEndian.PutUint64(fixture.state[40:], 0x900800)
	binary.LittleEndian.PutUint32(fixture.state[0x800:], 2)
	binary.LittleEndian.PutUint64(fixture.state[0x808:], 0x900900)
	copy(fixture.state[0x900:], fixture.state[0x100+40:0x100+80])
	binary.LittleEndian.PutUint64(fixture.state[0x918:], 0)
	binary.LittleEndian.PutUint64(fixture.state[0x920:], 0)
	view, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
	if err != nil || len(view.Modules) != 4 || len(view.Loader) != 5 || len(view.Modules[1].Links) != 2 {
		t.Fatalf("view=%+v error=%v", view, err)
	}
	if view.Modules[1].Links[1].Namespace != 0x900800 || view.Modules[1].Links[1].Address != 0x900900 {
		t.Fatalf("links=%+v", view.Modules[1].Links)
	}
}

func TestRuntimeELFLoaderWitnessChangeInvalidatesAllDiscovery(t *testing.T) {
	fixture := runtimeELFTestLoader(t, true)
	read := fixture.memory.read
	reads := 0
	fixture.memory.read = func(address target.Address, data []byte) (int, error) {
		if address == 0x900000 {
			reads++
			if reads == 2 {
				binary.LittleEndian.PutUint32(fixture.state[24:], 1)
			}
		}
		return read(address, data)
	}
	if view, err := discoverRuntimeELF(fixture.memory, fixture.auxv); view != nil || !errors.Is(err, target.ErrStale) {
		t.Fatalf("view=%+v error=%v", view, err)
	}
}

func TestRuntimeELFBuildIDIsIndependentMetadataNotFileIdentity(t *testing.T) {
	image := runtimeELFTestObject(t, 0x400000, true, 0)
	module, err := runtimeELFZeroOrigin(runtimeELFTestMemory(t, image), image.address, nil)
	if err != nil || !bytes.Equal(module.BuildID, []byte{1, 2, 3, 4}) || module.BuildIDErr != nil {
		t.Fatalf("module=%+v error=%v", module, err)
	}
	image.data[0x810] = 5
	if module.BuildID[0] != 1 {
		t.Fatal("build ID aliases memory source")
	}
	binary.LittleEndian.PutUint32(image.data[0x804:], math.MaxUint32)
	module, err = runtimeELFZeroOrigin(runtimeELFTestMemory(t, image), image.address, nil)
	if err != nil || module.BuildID != nil || !errors.Is(module.BuildIDErr, target.ErrInvalidArgument) || module.EHFrameHeader.Address != 0x400700 {
		t.Fatalf("optional malformed note discarded independent EH metadata: module=%+v error=%v", module, err)
	}
}

func TestRuntimeELFAuxiliaryRejectsMalformedOrDuplicateInputs(t *testing.T) {
	for _, data := range [][]byte{
		nil, {0}, make([]byte, 15), runtimeELFTestAuxiliary(3, 1, 3, 1), runtimeELFTestAuxiliary(0, 1),
		append(make([]byte, 16), runtimeELFTestAuxiliary(3, 1)...), runtimeELFTestAuxiliary(3, 1)[:16],
	} {
		if _, err := runtimeAuxiliary(data); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("input=%x error=%v", data, err)
		}
	}
}

func TestRuntimeELFDebugTagValidation(t *testing.T) {
	for _, test := range []struct {
		entries []uint64
		err     error
	}{
		{[]uint64{21, 1, 0, 0}, nil},
		{[]uint64{21, 0, 0, 0}, target.ErrUnavailable},
		{[]uint64{0, 0}, target.ErrUnavailable},
		{[]uint64{21, 1, 21, 2, 0, 0}, target.ErrAmbiguous},
		{[]uint64{21, 1}, target.ErrInvalidArgument},
	} {
		data := runtimeELFTestAuxiliary(test.entries...)
		data = data[:len(test.entries)*8]
		memory := runtimeELFTestMemory(t, runtimeELFTestRegion{0x1000, data})
		address, err := runtimeELFDebugAddress(memory, runtimeELFSpan{0x1000, uint64(len(data))})
		if !errors.Is(err, test.err) || err == nil && address != 1 {
			t.Fatalf("entries=%v address=%#x error=%v", test.entries, address, err)
		}
	}
}

func TestRuntimeELFMemoryBoundsAndLifetime(t *testing.T) {
	region := runtimeELFTestRegion{0x1000, make([]byte, 0x100)}
	memory := runtimeELFTestMemory(t, region)
	for _, test := range []struct {
		address target.Address
		size    int
		err     error
	}{
		{0x1000, 256, nil}, {0x1001, 256, target.ErrUnavailable}, {0xfff, 1, target.ErrUnavailable},
		{math.MaxUint64, 2, target.ErrOverflow}, {0, 0, nil},
	} {
		if _, err := memory.Read(context.Background(), test.address, make([]byte, test.size)); !errors.Is(err, test.err) {
			t.Fatalf("address=%#x size=%d error=%v", test.address, test.size, err)
		}
	}
	memory.remaining = 1
	if _, err := memory.Read(context.Background(), 0x1000, make([]byte, 2)); !errors.Is(err, target.ErrOverflow) {
		t.Fatal(err)
	}
	memory.close()
	if _, err := memory.Read(context.Background(), 0x1000, make([]byte, 1)); !errors.Is(err, target.ErrInvalidState) {
		t.Fatal(err)
	}
}

func TestRuntimeELFMemoryRejectsGapsPermissionsAndBadReaders(t *testing.T) {
	for _, mappings := range [][]procMap{
		{{Start: 1, End: 1}}, {{Start: 2, End: 1}}, {{Start: 1, End: 3}, {Start: 2, End: 4}},
	} {
		if _, err := newRuntimeELFMemory(context.Background(), mappings, func(target.Address, []byte) (int, error) { return 0, nil }); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, mapping := range []procMap{{Start: 1, End: 4}, {Start: 3, End: 4, Read: true}} {
		memory, err := newRuntimeELFMemory(context.Background(), []procMap{mapping}, func(target.Address, []byte) (int, error) { t.Fatal("unreadable reader called"); return 0, nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := memory.Read(context.Background(), 1, make([]byte, 3)); !errors.Is(err, target.ErrUnavailable) {
			t.Fatal(err)
		}
	}
	for _, count := range []int{-1, 0, 2} {
		memory, err := newRuntimeELFMemory(context.Background(), []procMap{{Start: 1, End: 4, Read: true}}, func(target.Address, []byte) (int, error) { return count, nil })
		if err != nil {
			t.Fatal(err)
		}
		want := target.ErrInvalidArgument
		if count == 0 {
			want = io.ErrUnexpectedEOF
		}
		if _, err := memory.Read(context.Background(), 1, make([]byte, 1)); !errors.Is(err, want) {
			t.Fatalf("count=%d error=%v", count, err)
		}
	}
}

func TestRuntimeELFCancellationAndFatalPartialClassification(t *testing.T) {
	fixture := runtimeELFTestLoader(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.memory.Read(ctx, 0x400000, make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, err := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded} {
		if runtimeELFResultUsable(&runtimeELFPartialError{Err: err}) || runtimeELFResultUsable(errors.Join(&runtimeELFPartialError{Err: target.ErrUnavailable}, err)) {
			t.Fatalf("fatal result classified usable: %v", err)
		}
	}
	if !runtimeELFResultUsable(nil) || !runtimeELFResultUsable(&runtimeELFPartialError{Err: target.ErrUnavailable}) || runtimeELFResultUsable(target.ErrUnavailable) {
		t.Fatal("incorrect partial classification")
	}
}

func TestRuntimeELFLiveMainLibrariesAndReaderLifetime(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(fmt.Sprint(pie), func(t *testing.T) {
			fixture := newExpansionIntegration(t, pie)
			fixture.breakpoint(t)
			snapshot, thread, err := fixture.controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			var escaped *runtimeELFMemory
			err = fixture.controller.withRuntimeELFModules(context.Background(), snapshot, thread, func(view *runtimeELFView) error {
				escaped = view.Memory
				if len(view.Modules) < 4 || !view.LoaderComplete || len(view.Loader) < 4 {
					t.Fatalf("incomplete live runtime view: %+v", view)
				}
				for _, module := range view.Modules {
					if module.Proof == "" || len(module.Loads) == 0 || len(module.Links) == 0 {
						t.Fatalf("module=%+v", module)
					}
					if module.Main && ((module.LoadBias != 0) != pie) {
						t.Fatalf("PIE=%t main=%+v", pie, module)
					}
					if module.EHFrameHeader.Size > 0 {
						var header [4]byte
						if _, err := view.Memory.Read(context.Background(), module.EHFrameHeader.Address, header[:]); err != nil || header[0] != 1 {
							t.Fatalf("EH frame header=%x error=%v module=%+v", header, err, module)
						}
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := escaped.Read(context.Background(), 0, nil); !errors.Is(err, target.ErrInvalidState) {
				t.Fatalf("escaped runtime reader: %v", err)
			}
		})
	}
}

func TestRuntimeELFLiveInitialExecDoesNotGuessUnpublishedLoaderList(t *testing.T) {
	fixture := newExpansionIntegration(t, true)
	snapshot, thread, err := fixture.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	err = fixture.controller.withRuntimeELFModules(context.Background(), snapshot, thread, func(view *runtimeELFView) error {
		if view.LoaderComplete || len(view.Loader) != 0 || len(view.Modules) < 2 {
			t.Fatalf("initial view=%+v", view)
		}
		return nil
	})
	if !runtimeELFResultUsable(err) || !errors.Is(err, target.ErrUnavailable) || !errors.Is(err, target.ErrPartial) {
		t.Fatal(err)
	}
}

type runtimeELFChangingSnapshot struct {
	session
	changed bool
}

func (session *runtimeELFChangingSnapshot) Snapshot() (target.Snapshot, error) {
	snapshot, err := session.session.Snapshot()
	if session.changed {
		snapshot.Sequence++
	}
	return snapshot, err
}

func TestRuntimeELFLiveFinalProofFailureIsNotUsablePartial(t *testing.T) {
	fixture := newExpansionIntegration(t, true)
	fixture.breakpoint(t)
	snapshot, thread, err := fixture.controller.stopped()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &runtimeELFChangingSnapshot{session: fixture.controller.session}
	fixture.controller.session = wrapper
	err = fixture.controller.withRuntimeELFModules(context.Background(), snapshot, thread, func(view *runtimeELFView) error {
		if len(view.Modules) == 0 {
			t.Fatal("no confirmed modules")
		}
		wrapper.changed = true
		return nil
	})
	if !errors.Is(err, target.ErrStale) || runtimeELFResultUsable(err) {
		t.Fatal(err)
	}
}

func TestRuntimeELFReadOnlyNamesArePreservedWithoutPathIdentity(t *testing.T) {
	fixture := runtimeELFTestLoader(t, true)
	name := "relative/../target\n\x1b[31m.so"
	copy(fixture.state[0x2300:], append([]byte(name), 0))
	view, err := discoverRuntimeELF(fixture.memory, fixture.auxv)
	if err != nil || !slices.ContainsFunc(view.Modules, func(module *runtimeELFModule) bool {
		return module.Name == name && module.Proof == "link-map+runtime-zero-origin-elf"
	}) {
		t.Fatalf("view=%+v error=%v", view, err)
	}
}
