package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func mappedELFTestFile() *elf.File {
	return &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_DYN}, Progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0, Vaddr: 0, Filesz: 0x900, Memsz: 0x900, Align: 0x1000}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0x1000, Vaddr: 0x1000, Filesz: 0x900, Memsz: 0x900, Align: 0x1000}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0x2d00, Vaddr: 0x3d00, Filesz: 0x500, Memsz: 0x1900, Align: 0x1000}},
	}}
}

func mappedELFTestMaps(bias uint64) []procMap {
	return []procMap{
		{Start: target.Address(bias), End: target.Address(bias + 0x1000), Offset: 0},
		{Start: target.Address(bias + 0x1000), End: target.Address(bias + 0x2000), Offset: 0x1000},
		{Start: target.Address(bias + 0x3000), End: target.Address(bias + 0x4000), Offset: 0x2000},
		{Start: target.Address(bias + 0x4000), End: target.Address(bias + 0x5000), Offset: 0x3000},
	}
}

func TestMappedELFUniqueBiasFromEveryLoad(t *testing.T) {
	for _, bias := range []uint64{0, 0x400000, 0x7f1234500000} {
		got, err := mappedELFLoadBias(mappedELFTestFile(), mappedELFTestMaps(bias), 0x1000)
		if err != nil || got != bias {
			t.Fatalf("bias %#x: got %#x, %v", bias, got, err)
		}
	}
}

func TestMappedELFRejectsMissingOrWrongFileCoverage(t *testing.T) {
	for _, edit := range []func([]procMap) []procMap{
		func(m []procMap) []procMap { return m[:3] },
		func(m []procMap) []procMap { m[1].Offset = 0; return m },
		func(m []procMap) []procMap { m[2].End -= 1; return m },
		func(m []procMap) []procMap { m[0].Start++; return m },
		func(m []procMap) []procMap { m[3].Start += 0x200; return m },
	} {
		maps := edit(mappedELFTestMaps(0x700000))
		if _, err := mappedELFLoadBias(mappedELFTestFile(), maps, 0x1000); !errors.Is(err, target.ErrUnavailable) {
			t.Fatalf("maps=%+v error=%v", maps, err)
		}
	}
}

func TestMappedELFDoesNotChooseFirstCompleteCopy(t *testing.T) {
	maps := append(mappedELFTestMaps(0x700000), mappedELFTestMaps(0x800000)...)
	if _, err := mappedELFLoadBias(mappedELFTestFile(), maps, 0x1000); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
}

func TestMappedELFPartialExtraMappingDoesNotInventCopy(t *testing.T) {
	maps := append(mappedELFTestMaps(0x700000), procMap{Start: 0x900000, End: 0x901000})
	bias, err := mappedELFLoadBias(mappedELFTestFile(), maps, 0x1000)
	if err != nil || bias != 0x700000 {
		t.Fatalf("bias=%#x error=%v", bias, err)
	}
}

func TestMappedELFRejectsInvalidProgramRanges(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*elf.File)
		err  error
	}{
		{"filesz", func(f *elf.File) { f.Progs[0].Filesz = 0x1000 }, target.ErrOverflow},
		{"virtual overflow", func(f *elf.File) { f.Progs[0].Vaddr = math.MaxUint64 - 1 }, target.ErrOverflow},
		{"file overflow", func(f *elf.File) { f.Progs[0].Off = math.MaxUint64 - 1 }, target.ErrOverflow},
		{"congruence", func(f *elf.File) { f.Progs[0].Vaddr = 1 }, target.ErrInvalidArgument},
		{"alignment", func(f *elf.File) { f.Progs[0].Align = 3 }, target.ErrInvalidArgument},
		{"empty", func(f *elf.File) { f.Progs = nil }, target.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := mappedELFTestFile()
			test.edit(file)
			if _, err := mappedELFLoadBias(file, mappedELFTestMaps(0x700000), 0x1000); !errors.Is(err, test.err) {
				t.Fatal(err)
			}
		})
	}
	for _, page := range []uint64{0, 3, 4095} {
		if _, err := mappedELFLoadBias(mappedELFTestFile(), mappedELFTestMaps(0x700000), page); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
}

func TestMappedELFFixedExecutableRejectsBias(t *testing.T) {
	file := mappedELFTestFile()
	file.Type = elf.ET_EXEC
	if _, err := mappedELFLoadBias(file, mappedELFTestMaps(0x700000), 0x1000); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := validateELFLoadBias(file, mappedELFTestMaps(0), 0x1000, 0); err != nil {
		t.Fatal(err)
	}
}

func TestMappedELFSelectionIsExactAndUnambiguous(t *testing.T) {
	modules := []*mappedELF{
		{ID: "main", Path: "/a/main", Main: true},
		{ID: "one", Path: "/a/libtest.so"},
		{ID: "two", Path: "/b/libtest.so"},
	}
	for _, test := range []struct {
		selection elfModuleSelection
		count     int
		err       error
	}{
		{elfModuleSelection{}, 1, nil},
		{elfModuleSelection{Name: "main"}, 1, nil},
		{elfModuleSelection{Name: "/a/libtest.so"}, 1, nil},
		{elfModuleSelection{Name: "two"}, 1, nil},
		{elfModuleSelection{Name: "libtest.so"}, 0, target.ErrAmbiguous},
		{elfModuleSelection{Name: "libtest"}, 0, target.ErrNotFound},
		{elfModuleSelection{All: true}, 3, nil},
	} {
		got, err := selectELFModules(modules, test.selection)
		if !errors.Is(err, test.err) || len(got) != test.count {
			t.Fatalf("%+v: modules=%v error=%v", test.selection, got, err)
		}
	}
}

func TestMappedELFCommandArgumentGrammar(t *testing.T) {
	for _, args := range [][]string{{"--module"}, {"libc"}, {"all", "extra"}, {"--file", "x"}, {"--module", ""}, {"--module", "x\x00y"}} {
		if _, _, err := parseELFModuleArguments(args, false); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%q: %v", args, err)
		}
	}
	selection, path, err := parseELFModuleArguments([]string{"--file", "a b"}, true)
	if err != nil || selection != (elfModuleSelection{}) || path != "a b" {
		t.Fatalf("selection=%+v path=%q error=%v", selection, path, err)
	}
}

func TestMappedELFLiveMainAndLibraries(t *testing.T) {
	for _, pie := range []bool{false, true} {
		t.Run(map[bool]string{false: "exec", true: "pie"}[pie], func(t *testing.T) {
			fixture := newExpansionIntegration(t, pie)
			fixture.breakpoint(t)
			controller := fixture.controller
			snapshot, thread, err := controller.stopped()
			if err != nil {
				t.Fatal(err)
			}
			libraryUnavailable, metadataAvailable := mappedELFLiveLibraryProofUnavailable(t, controller, snapshot, thread)
			var count int
			var closed *mappedELF
			associated := false
			var runtimeID, runtimeName string
			err = controller.withELFModules(context.Background(), snapshot, thread, elfModuleSelection{All: true}, func(modules []*mappedELF) error {
				count = len(modules)
				for _, module := range modules {
					if module.ID == "" || module.Path == "" || module.Runtime == nil && (module.File == nil || module.Source == nil) || module.Runtime != nil && (module.File != nil || module.Source != nil || !module.Runtime.SymbolsComplete) {
						t.Fatalf("incomplete module: %+v", module)
					}
					if module.Main && ((module.LoadBias != 0) != pie) {
						t.Fatalf("PIE=%t main bias=%#x", pie, module.LoadBias)
					}
					if module.Source != nil {
						closed = module
					}
					associated = associated || module.Proof == kernelBuildIDMetadataProof
					if module.Runtime != nil {
						runtimeID, runtimeName = module.ID, module.Path
					}
				}
				return nil
			})
			valid := err == nil && count >= 4 && (!libraryUnavailable || associated)
			if !metadataAvailable {
				valid = count >= 1 && mappedELFResultUsable(err) && errors.Is(err, target.ErrPartial) && errors.Is(err, target.ErrUnavailable) && errors.Is(err, unix.EPERM) && !errors.Is(err, target.ErrStale)
			}
			if !valid {
				_ = controller.withStoppedProc(context.Background(), snapshot, thread, func(proc *stoppedProc) error {
					maps, mapErr := proc.maps()
					source, openErr := proc.openFile("exe")
					if openErr == nil {
						identity, identityErr := elfSourceIdentity(source)
						t.Logf("source identity=%+v error=%v maps=%+v map-error=%v", identity, identityErr, maps, mapErr)
						return source.Close()
					}
					return openErr
				})
				t.Fatalf("count=%d error=%v", count, err)
			}
			if _, err := closed.Source.Stat(); err == nil {
				t.Fatal("callback source remains open")
			}
			if metadataAvailable {
				for _, name := range []string{runtimeID, runtimeName} {
					if name == "" {
						t.Fatal("runtime metadata had no selectable identity")
					}
					err := controller.withELFModules(context.Background(), snapshot, thread, elfModuleSelection{Name: name}, func(modules []*mappedELF) error {
						if len(modules) != 1 || modules[0].ID != runtimeID || modules[0].File != nil || modules[0].Source != nil || modules[0].Runtime == nil {
							t.Fatalf("runtime selector %q: %+v", name, modules)
						}
						return nil
					})
					if err != nil {
						t.Fatalf("runtime selector %q: %v", name, err)
					}
				}
			}
			for _, command := range []func(context.Context, string) error{controller.showChecksec, controller.showGOT} {
				fixture.output.Reset()
				if err := command(context.Background(), ""); err != nil {
					t.Fatal(err)
				}
				if fixture.output.Len() == 0 || strings.ContainsRune(fixture.output.String(), '\x1b') {
					t.Fatalf("unexpected output %q", fixture.output.String())
				}
				if metadataAvailable {
					fixture.output.Reset()
					if err := command(context.Background(), "all"); err != nil || !strings.Contains(fixture.output.String(), "Runtime") {
						t.Fatalf("all metadata: error=%v output=%q", err, fixture.output.String())
					}
				}
			}
			fixture.output.Reset()
			stdioErr := controller.showStdio(context.Background(), "")
			if !metadataAvailable {
				if !errors.Is(stdioErr, target.ErrPartial) || !errors.Is(stdioErr, target.ErrUnavailable) || !errors.Is(stdioErr, unix.EPERM) || fixture.output.Len() != 0 {
					t.Fatalf("unproven stdio: error=%v output=%q", stdioErr, fixture.output.String())
				}
			} else if stdioErr != nil || !strings.Contains(fixture.output.String(), "[FILE->_wide_data->_wide_vtable]") {
				t.Fatalf("proven stdio: error=%v output=%q", stdioErr, fixture.output.String())
			}
		})
	}
}

func mappedELFLiveLibraryProofUnavailable(t *testing.T, controller *Controller, snapshot target.Snapshot, thread target.ThreadInfo) (bool, bool) {
	t.Helper()
	unavailable := false
	metadataAvailable := true
	checked := false
	err := controller.withStoppedProc(context.Background(), snapshot, thread, func(proc *stoppedProc) error {
		maps, err := proc.maps()
		if err != nil {
			return err
		}
		for _, mapping := range maps {
			if filepath.Base(mapping.Path) != "libc.so.6" {
				continue
			}
			checked = true
			source, pinErr := proc.openMappedFile(mapping)
			if pinErr == nil {
				return source.Close()
			}
			if !errors.Is(pinErr, unix.EPERM) || !errors.Is(pinErr, target.ErrUnavailable) || errors.Is(pinErr, target.ErrStale) {
				return pinErr
			}
			candidate, err := proc.openFile("root" + mapping.Path)
			if err != nil {
				return err
			}
			defer candidate.Close()
			identity, err := elfSourceIdentity(candidate)
			if err != nil {
				return err
			}
			var filesystem unix.Statfs_t
			if err := unix.Fstatfs(int(candidate.Fd()), &filesystem); err != nil {
				return err
			}
			major, minor, inode, err := proc.fileSuperblockMetadata(candidate)
			if err != nil {
				return err
			}
			if filesystem.Type != unix.BTRFS_SUPER_MAGIC || identity.inode != mapping.Inode || identity == elfMapIdentity(mapping) || major != mapping.DevMajor || minor != mapping.DevMinor || inode != mapping.Inode {
				t.Fatalf("unexpected library identity failure: filesystem=%#x identity=%+v map=%+v superblock=%x:%x/%d error=%v", filesystem.Type, identity, mapping, major, minor, inode, pinErr)
			}
			unavailable = true
			id, queryErr := proc.mappedBuildID(mapping)
			if queryErr != nil {
				if !errors.Is(queryErr, target.ErrUnsupported) && !errors.Is(queryErr, target.ErrUnavailable) {
					return queryErr
				}
				metadataAvailable = false
			} else if len(id) == 0 {
				t.Fatal("kernel query succeeded without a build ID")
			}
			return nil
		}
		return nil
	})
	if err != nil || !checked {
		t.Fatalf("library proof check: checked=%t error=%v", checked, err)
	}
	return unavailable, metadataAvailable
}
