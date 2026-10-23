package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func elfDebugLookupTestModule(t *testing.T, id []byte, name string, debugData []byte) *mappedELF {
	t.Helper()
	file, _ := elfCommandTestELF(t, nil, nil, nil)
	if id != nil {
		file, _ = elfBuildIDTestELF(t, id)
	}
	if name != "" {
		linkFile, data := elfCommandTestELF(t, nil, nil, nil)
		link := make([]byte, (len(name)+1+3)&^3+4)
		copy(link, name)
		binary.LittleEndian.PutUint32(link[len(link)-4:], crc32.ChecksumIEEE(debugData))
		section := linkFile.Sections[1]
		copy(data[section.Offset:], link)
		section.Name, section.Size = ".gnu_debuglink", uint64(len(link))
		file.Sections = append(file.Sections, section)
	}
	return &mappedELF{File: file}
}

func elfDebugLookupTestPaths(t *testing.T) elfDebugLookupPaths {
	t.Helper()
	directory := elfSourceTestDirectory(t)
	return elfDebugLookupPaths{
		local: filepath.Join(directory, "local"), system: filepath.Join(directory, "system"),
		clients: []string{filepath.Join(directory, "client")},
	}
}

func elfDebugLookupTestWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func elfDebugLookupTestBuildPath(root string, id []byte) string {
	encoded := hex.EncodeToString(id)
	return filepath.Join(root, ".build-id", encoded[:2], encoded[2:]+".debug")
}

func TestELFDebugLookupCandidatePathsAreExactAndDeduplicated(t *testing.T) {
	id := []byte{0x12, 0x34, 0xab, 0xcd}
	module := elfDebugLookupTestModule(t, id, "module.debug", nil)
	module.Path, module.MetadataPath = "/opt/lib/module.so", "/opt/lib/module.so"
	paths := elfDebugLookupPaths{local: "/work/cache", system: "/usr/lib/debug", clients: []string{"/client", "/client"}}
	candidates, err := elfDebugLookupCandidates(module, paths, true)
	want := []elfDebugLookupCandidate{
		{path: "/work/cache/.build-id/12/34abcd.debug"},
		{path: "/usr/lib/debug/.build-id/12/34abcd.debug"},
		{path: "/usr/lib/debug/.build-id/12/34abcd.debug", target: true},
		{path: "/client/1234abcd/debuginfo"},
		{path: "/opt/lib/module.debug"},
		{path: "/opt/lib/module.debug", target: true},
		{path: "/opt/lib/.debug/module.debug"},
		{path: "/opt/lib/.debug/module.debug", target: true},
		{path: "/usr/lib/debug/opt/lib/module.debug"},
		{path: "/usr/lib/debug/opt/lib/module.debug", target: true},
	}
	if err != nil || !slices.Equal(candidates, want) {
		t.Fatalf("candidates=%+v want=%+v error=%v", candidates, want, err)
	}
	module.Path, module.MetadataPath = "not-an-absolute-image", ""
	candidates, err = elfDebugLookupCandidates(module, paths, false)
	if err != nil || len(candidates) != 3 {
		t.Fatalf("relative image produced guessed paths: %+v error=%v", candidates, err)
	}
}

func TestELFDebugLookupUsesCompleteBuildIDAndBoundedPaths(t *testing.T) {
	for _, length := range []int{1, 125, 126, 127, 128} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			id := bytes.Repeat([]byte{0xab}, length)
			module := elfDebugLookupTestModule(t, id, "", nil)
			paths := elfDebugLookupPaths{local: "/cache", system: "/system", clients: []string{"/client"}}
			candidates, err := elfDebugLookupCandidates(module, paths, false)
			if length > 127 {
				if !errors.Is(err, target.ErrUnsupported) || len(candidates) != 0 {
					t.Fatalf("long build ID truncated: %+v error=%v", candidates, err)
				}
				return
			}
			want := 3
			if length > 125 {
				want = 1
			}
			if err != nil || len(candidates) != want {
				t.Fatalf("candidates=%+v error=%v", candidates, err)
			}
			if candidates[len(candidates)-1].path != filepath.Join("/client", hex.EncodeToString(id), "debuginfo") {
				t.Fatal(candidates)
			}
		})
	}
	module := elfDebugLookupTestModule(t, []byte{1, 2, 3}, "", nil)
	for _, paths := range []elfDebugLookupPaths{
		{local: "relative"},
		{local: "/" + strings.Repeat("x", 4096)},
		{local: "/invalid\x00path"},
	} {
		if _, err := elfDebugLookupCandidates(module, paths, false); err == nil {
			t.Fatalf("invalid paths accepted: %+v", paths)
		}
	}
	paths := elfDebugLookupPaths{}
	for index := 0; index <= maxDebugLookupCandidates; index++ {
		paths.clients = append(paths.clients, "/"+strings.Repeat("x", index+1))
	}
	if _, err := elfDebugLookupCandidates(module, paths, false); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("candidate count is unbounded: %v", err)
	}
}

func TestELFDebugLookupMissingIsDistinctFromRejectedMetadata(t *testing.T) {
	id := []byte{0x01, 0x12, 0x23, 0x34}
	module := elfDebugLookupTestModule(t, id, "", nil)
	paths := elfDebugLookupTestPaths(t)
	result, err := findELFDebugFileAt(context.Background(), module, paths, -1)
	if result != nil || !errors.Is(err, target.ErrUnavailable) || !elfDebugLookupMissing(err) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if elfDebugLookupMissing(errors.Join(err, context.Canceled)) || elfDebugLookupMissing(errors.Join(err, io.ErrClosedPipe)) {
		t.Fatal("joined errors are not an ordinary lookup miss")
	}
	_, wrong := elfBuildIDTestELF(t, []byte{0x01, 0x12, 0x23, 0x35})
	elfDebugLookupTestWrite(t, elfDebugLookupTestBuildPath(paths.local, id), wrong)
	result, err = findELFDebugFileAt(context.Background(), module, paths, -1)
	if result != nil || !errors.Is(err, target.ErrUnavailable) || elfDebugLookupMissing(err) || !strings.Contains(err.Error(), "build IDs differ") {
		t.Fatalf("mismatched candidate was absence: result=%+v error=%v", result, err)
	}
	_, correct := elfBuildIDTestELF(t, id)
	correctPath := elfDebugLookupTestBuildPath(paths.system, id)
	elfDebugLookupTestWrite(t, correctPath, correct)
	result, err = findELFDebugFileAt(context.Background(), module, paths, -1)
	if err != nil || result == nil || result.Path != correctPath || result.Proof != "gnu-build-id-metadata" || !bytes.Equal(result.BuildID, id) {
		t.Fatalf("exact candidate not selected: result=%+v error=%v", result, err)
	}
	if err := result.Source.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestELFDebugLookupDebuglinkLocationsRequireWholeFileCRC(t *testing.T) {
	_, debugData := elfCommandTestELF(t, nil, nil, nil)
	for _, location := range []string{"same", "dot-debug", "system"} {
		t.Run(location, func(t *testing.T) {
			paths := elfDebugLookupTestPaths(t)
			module := elfDebugLookupTestModule(t, nil, "declared.debug", debugData)
			module.Path = filepath.Join(filepath.Dir(paths.local), "module", "program")
			path := filepath.Join(filepath.Dir(module.Path), "declared.debug")
			if location == "dot-debug" {
				path = filepath.Join(filepath.Dir(module.Path), ".debug", "declared.debug")
			} else if location == "system" {
				path = filepath.Join(paths.system, strings.TrimPrefix(filepath.Dir(module.Path), "/"), "declared.debug")
			}
			elfDebugLookupTestWrite(t, path, debugData)
			association, err := findELFDebugFileAt(context.Background(), module, paths, -1)
			if err != nil || association == nil || association.Path != path || association.Proof != "gnu-debuglink-crc32-metadata" {
				t.Fatalf("association=%+v error=%v", association, err)
			}
			if err := association.Source.Close(); err != nil {
				t.Fatal(err)
			}
			changed := bytes.Clone(debugData)
			changed[0x900]++
			elfDebugLookupTestWrite(t, path, changed)
			association, err = findELFDebugFileAt(context.Background(), module, paths, -1)
			if association != nil || !errors.Is(err, target.ErrUnavailable) || elfDebugLookupMissing(err) || !strings.Contains(err.Error(), "CRC32") {
				t.Fatalf("changed content accepted: association=%+v error=%v", association, err)
			}
		})
	}
}

func TestELFDebugLookupIdenticalCopiesAndHardlinksAreNotAmbiguous(t *testing.T) {
	id := []byte{0x21, 0x43, 0x65, 0x87}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	for _, hardlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "copies", true: "hardlinks"}[hardlink], func(t *testing.T) {
			paths := elfDebugLookupTestPaths(t)
			local, system := elfDebugLookupTestBuildPath(paths.local, id), elfDebugLookupTestBuildPath(paths.system, id)
			elfDebugLookupTestWrite(t, local, data)
			if hardlink {
				if err := os.MkdirAll(filepath.Dir(system), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(local, system); err != nil {
					t.Fatal(err)
				}
			} else {
				elfDebugLookupTestWrite(t, system, data)
			}
			association, err := findELFDebugFileAt(context.Background(), module, paths, -1)
			if err != nil || association == nil || association.Path != local {
				t.Fatalf("association=%+v error=%v", association, err)
			}
			if err := association.Source.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestELFDebugLookupConflictingBuildIDCandidatesAreAmbiguous(t *testing.T) {
	id := []byte{0x10, 0x20, 0x30, 0x40}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	paths := elfDebugLookupTestPaths(t)
	elfDebugLookupTestWrite(t, elfDebugLookupTestBuildPath(paths.local, id), data)
	changed := bytes.Clone(data)
	changed[0x900]++
	elfDebugLookupTestWrite(t, elfDebugLookupTestBuildPath(paths.system, id), changed)
	association, err := findELFDebugFileAt(context.Background(), module, paths, -1)
	if association != nil || !errors.Is(err, target.ErrAmbiguous) || elfDebugLookupMissing(err) {
		t.Fatalf("conflicting associated files accepted: association=%+v error=%v", association, err)
	}
}

func TestELFDebugLookupReturnedSourceSurvivesPathReplacement(t *testing.T) {
	id := []byte{0x22, 0x33, 0x44, 0x55}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	paths := elfDebugLookupTestPaths(t)
	path := elfDebugLookupTestBuildPath(paths.local, id)
	elfDebugLookupTestWrite(t, path, data)
	association, err := findELFDebugFileAt(context.Background(), module, paths, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer association.Source.Close()
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(association.Source.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("source descriptor not private: flags=%#x error=%v", flags, err)
	}
	got, err := io.ReadAll(association.Source)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("replacement redirected source: error=%v", err)
	}
}

func TestELFDebugLookupTargetRootAbsoluteSymlinksStayInsideRoot(t *testing.T) {
	id := []byte{0x33, 0x44, 0x55, 0x66}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	directory := elfSourceTestDirectory(t)
	root := filepath.Join(directory, "target")
	paths := elfDebugLookupPaths{system: "/fastdbg-test-debug-root"}
	inside := filepath.Join(root, "objects", "debug")
	elfDebugLookupTestWrite(t, inside, data)
	candidate := filepath.Join(root, elfDebugLookupTestBuildPath(paths.system, id))
	if err := os.MkdirAll(filepath.Dir(candidate), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/objects/debug", candidate); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	association, err := findELFDebugFileAt(context.Background(), module, paths, fd)
	if err != nil || association == nil || association.Path != "target-root:"+elfDebugLookupTestBuildPath(paths.system, id) {
		t.Fatalf("association=%+v error=%v", association, err)
	}
	if err := association.Source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(candidate); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside")
	elfDebugLookupTestWrite(t, outside, data)
	if err := os.Symlink(outside, candidate); err != nil {
		t.Fatal(err)
	}
	association, err = findELFDebugFileAt(context.Background(), module, paths, fd)
	if association != nil || !elfDebugLookupMissing(err) {
		t.Fatalf("absolute symlink escaped target root: association=%+v error=%v", association, err)
	}
}

func TestELFDebugLookupReportsMalformedAndNonregularCandidates(t *testing.T) {
	id := []byte{0x44, 0x55, 0x66, 0x77}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, correct := elfBuildIDTestELF(t, id)
	for _, kind := range []string{"malformed", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			paths := elfDebugLookupTestPaths(t)
			badPath := elfDebugLookupTestBuildPath(paths.local, id)
			if err := os.MkdirAll(filepath.Dir(badPath), 0o700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "malformed":
				err = os.WriteFile(badPath, []byte("not ELF"), 0o600)
			case "fifo":
				err = unix.Mkfifo(badPath, 0o600)
			case "directory":
				err = os.Mkdir(badPath, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			elfDebugLookupTestWrite(t, elfDebugLookupTestBuildPath(paths.system, id), correct)
			association, err := findELFDebugFileAt(context.Background(), module, paths, -1)
			if association != nil || err == nil || elfDebugLookupMissing(err) || !strings.Contains(err.Error(), badPath) {
				t.Fatalf("malformed candidate silently hidden: association=%+v error=%v", association, err)
			}
		})
	}
}

func TestELFDebugLookupDefaultRootsUseOnlyLiteralConfiguredPaths(t *testing.T) {
	directory := elfSourceTestDirectory(t)
	t.Chdir(directory)
	t.Setenv("DEBUGINFOD_CACHE_PATH", "$HOME/literal-client")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(directory, "xdg"))
	paths, err := localELFDebugLookupPaths()
	if err != nil || paths.local != filepath.Join(directory, ".cache", "debug-info") || paths.system != "/usr/lib/debug" || !slices.Equal(paths.clients, []string{
		filepath.Join(directory, "$HOME", "literal-client"), filepath.Join(directory, "xdg", "debuginfod_client"),
	}) {
		t.Fatalf("paths=%+v error=%v", paths, err)
	}
	id := []byte{0xf1, 0xe2, 0xd3, 0xc4, 0xb5}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	path := filepath.Join(paths.clients[0], hex.EncodeToString(id), "debuginfo")
	elfDebugLookupTestWrite(t, path, data)
	association, err := findELFDebugFile(context.Background(), nil, module)
	if err != nil || association == nil || association.Path != path {
		t.Fatalf("configured client cache not read: association=%+v error=%v", association, err)
	}
	if err := association.Source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".cache")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lookup wrote cache state: %v", err)
	}
}

func TestELFDebugLookupCancellationAndMissingMetadata(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	module := elfDebugLookupTestModule(t, []byte{1, 2, 3}, "", nil)
	for _, run := range []func() (*associatedDebugELF, error){
		func() (*associatedDebugELF, error) { return findELFDebugFile(ctx, nil, module) },
		func() (*associatedDebugELF, error) { return findELFDebugFileAt(ctx, module, elfDebugLookupPaths{}, -1) },
	} {
		if association, err := run(); association != nil || !errors.Is(err, context.Canceled) || elfDebugLookupMissing(err) {
			t.Fatalf("cancellation lost: association=%+v error=%v", association, err)
		}
	}
	for _, module := range []*mappedELF{nil, {}} {
		if _, err := findELFDebugFileAt(context.Background(), module, elfDebugLookupPaths{}, -1); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	module = elfDebugLookupTestModule(t, nil, "", nil)
	if association, err := findELFDebugFileAt(context.Background(), module, elfDebugLookupPaths{}, -1); association != nil || !elfDebugLookupMissing(err) {
		t.Fatalf("metadata-free module guessed candidates: association=%+v error=%v", association, err)
	}
	module = elfDebugLookupTestModule(t, nil, "../escape", nil)
	if _, err := findELFDebugFileAt(context.Background(), module, elfDebugLookupPaths{}, -1); !errors.Is(err, target.ErrInvalidArgument) || elfDebugLookupMissing(err) {
		t.Fatalf("malformed debuglink ignored: %v", err)
	}
}

func TestELFDebugLookupUsesSuppliedProcRootCapability(t *testing.T) {
	directory := elfSourceTestDirectory(t)
	t.Chdir(directory)
	t.Setenv("DEBUGINFOD_CACHE_PATH", filepath.Join(directory, "client"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(directory, "xdg"))
	id := []byte{0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	root, procDirectory := filepath.Join(directory, "root"), filepath.Join(directory, "proc")
	path := elfDebugLookupTestBuildPath("/usr/lib/debug", id)
	elfDebugLookupTestWrite(t, filepath.Join(root, path), data)
	if err := os.Mkdir(procDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(procDirectory, "root")); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(procDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	association, err := findELFDebugFile(context.Background(), &stoppedProc{dir: dir}, module)
	if err != nil || association == nil || association.Path != "target-root:"+path {
		t.Fatalf("association=%+v error=%v", association, err)
	}
	if err := association.Source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.Stat(); err != nil {
		t.Fatalf("borrowed proc descriptor closed: %v", err)
	}
	if _, err := findELFDebugFile(context.Background(), &stoppedProc{}, module); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestELFDebugLookupByteComparisonBudgetAndCancellation(t *testing.T) {
	directory := elfSourceTestDirectory(t)
	paths := []string{filepath.Join(directory, "left"), filepath.Join(directory, "right")}
	data := bytes.Repeat([]byte{0, 1, 2, 3}, 20000)
	var files []*os.File
	for _, path := range paths {
		elfDebugLookupTestWrite(t, path, data)
		file, err := openRegularELFSource(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		files = append(files, file)
	}
	budget := int64(len(data) * 2)
	if equal, err := equalELFDebugSources(context.Background(), files[0], files[1], &budget); err != nil || !equal || budget != 0 {
		t.Fatalf("equal=%v budget=%d error=%v", equal, budget, err)
	}
	if equal, err := equalELFDebugSources(context.Background(), files[0], files[1], &budget); !errors.Is(err, target.ErrUnsupported) || equal {
		t.Fatalf("unbounded comparison: equal=%v error=%v", equal, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	budget = int64(len(data) * 2)
	if equal, err := equalELFDebugSources(ctx, files[0], files[1], &budget); !errors.Is(err, context.Canceled) || equal {
		t.Fatalf("canceled comparison: equal=%v error=%v", equal, err)
	}
	data[len(data)-1]++
	elfDebugLookupTestWrite(t, paths[1], data)
	if equal, err := equalELFDebugSources(context.Background(), files[0], files[1], &budget); err != nil || equal {
		t.Fatalf("different tail ignored: equal=%v error=%v", equal, err)
	}
}

func TestELFDebugSourceAssociationBorrowsCallerSource(t *testing.T) {
	id := []byte{1, 3, 5, 7}
	module := elfDebugLookupTestModule(t, id, "", nil)
	_, data := elfBuildIDTestELF(t, id)
	path := filepath.Join(elfSourceTestDirectory(t), "source")
	elfDebugLookupTestWrite(t, path, data)
	source, err := openRegularELFSource(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	association, err := associateELFDebugSource(context.Background(), module, source, "borrowed")
	if err != nil || association.Source != source || association.Path != "borrowed" {
		t.Fatalf("association=%+v error=%v", association, err)
	}
	module.File.Type = elf.ET_DYN
	if _, err := associateELFDebugSource(context.Background(), module, source, "wrong-type"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := source.Stat(); err != nil {
		t.Fatalf("borrowed source closed on failed association: %v", err)
	}
}

func BenchmarkELFDebugLookup(b *testing.B) {
	id := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	note := elfBuildIDTestNote(id, binary.LittleEndian)
	data := make([]byte, 12<<20)
	copy(data[0x100:], note)
	header := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: 1, Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS], header.Ident[elf.EI_DATA], header.Ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	program := elf.Prog64{Type: uint32(elf.PT_NOTE), Off: 0x100, Filesz: uint64(len(note)), Align: 4}
	var headers bytes.Buffer
	if err := binary.Write(&headers, binary.LittleEndian, header); err != nil {
		b.Fatal(err)
	}
	if err := binary.Write(&headers, binary.LittleEndian, program); err != nil {
		b.Fatal(err)
	}
	copy(data, headers.Bytes())
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		b.Fatal(err)
	}
	module := &mappedELF{File: file}
	root, err := filepath.Abs(filepath.Join("..", "..", ".cache", "deterministic-foundations", "debug-lookup", "bench"))
	if err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		b.Fatal(err)
	}
	for _, copies := range []int{1, 2} {
		b.Run(strconv.Itoa(copies)+"-candidate", func(b *testing.B) {
			directory, err := os.MkdirTemp(root, "lookup-")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := os.RemoveAll(directory); err != nil {
					b.Error(err)
				}
			})
			paths := elfDebugLookupPaths{local: filepath.Join(directory, "local"), system: filepath.Join(directory, "system")}
			for _, root := range []string{paths.local, paths.system}[:copies] {
				path := elfDebugLookupTestBuildPath(root, id)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					b.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				association, err := findELFDebugFileAt(context.Background(), module, paths, -1)
				if err != nil {
					b.Fatal(err)
				}
				if err := association.Source.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
