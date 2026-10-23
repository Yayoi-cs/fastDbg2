package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fastdbg2/target"
)

func elfBuildIDTestNote(id []byte, order binary.ByteOrder) []byte {
	data := make([]byte, 16+(len(id)+3)&^3)
	order.PutUint32(data[0:4], 4)
	order.PutUint32(data[4:8], uint32(len(id)))
	order.PutUint32(data[8:12], 3)
	copy(data[12:16], "GNU\x00")
	copy(data[16:], id)
	return data
}

func elfBuildIDTestELF(t *testing.T, id []byte) (*elf.File, []byte) {
	t.Helper()
	file, data := elfCommandTestELF(t, nil, nil, nil)
	note := elfBuildIDTestNote(id, binary.LittleEndian)
	copy(data[file.Sections[1].Offset:], note)
	sectionTable := binary.LittleEndian.Uint64(data[40:48])
	binary.LittleEndian.PutUint32(data[sectionTable+64+4:], uint32(elf.SHT_NOTE))
	binary.LittleEndian.PutUint64(data[sectionTable+64+32:], uint64(len(note)))
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return file, data
}

func TestELFGNUBuildIDExactNoteParsing(t *testing.T) {
	id := []byte{1, 2, 3, 0, 5, 6, 7}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		notes, err := elfGNUNotes(elfBuildIDTestNote(id, order), 0x1234, order)
		if err != nil || len(notes) != 1 || notes[0].offset != 0x1234 || !bytes.Equal(notes[0].id, id) {
			t.Fatalf("notes=%+v error=%v", notes, err)
		}
	}
	file, _ := elfBuildIDTestELF(t, id)
	got, err := elfGNUBuildID(file)
	if err != nil || !bytes.Equal(got, id) {
		t.Fatalf("ID=%x error=%v", got, err)
	}
	file.Sections = append(file.Sections, file.Sections[1])
	if _, err := elfGNUBuildID(file); err != nil {
		t.Fatalf("same file-offset note referenced twice: %v", err)
	}
	other := *file.Sections[1]
	other.Offset += 0x100
	file.Sections = append(file.Sections, &other)
	if _, err := elfGNUBuildID(file); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("two distinct GNU notes accepted: %v", err)
	}
}

func TestELFGNUBuildIDRejectsMalformedAndAbsentEvidence(t *testing.T) {
	for _, edit := range []func([]byte) []byte{
		func(data []byte) []byte { return data[:11] },
		func(data []byte) []byte { return data[:len(data)-1] },
		func(data []byte) []byte { binary.LittleEndian.PutUint32(data, 0xffffffff); return data },
		func(data []byte) []byte { binary.LittleEndian.PutUint32(data[4:], 0xffffffff); return data },
	} {
		if _, err := elfGNUNotes(edit(elfBuildIDTestNote([]byte{1, 2, 3}, binary.LittleEndian)), 0, binary.LittleEndian); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, id := range [][]byte{nil, make([]byte, 4097)} {
		if _, err := elfGNUNotes(elfBuildIDTestNote(id, binary.LittleEndian), 0, binary.LittleEndian); !errors.Is(err, target.ErrUnsupported) {
			t.Fatal(err)
		}
	}
	data := elfBuildIDTestNote([]byte{1, 2}, binary.LittleEndian)
	copy(data[12:], "GXX\x00")
	notes, err := elfGNUNotes(data, 0, binary.LittleEndian)
	if err != nil || len(notes) != 0 {
		t.Fatalf("unrelated note: %v %v", notes, err)
	}
	if _, err := uniqueELFBuildID(notes); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := uniqueELFBuildID([]elfBuildIDNote{{1, []byte{1}}, {1, []byte{2}}}); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatal(err)
	}
}

func TestELFKernelBuildIDRequiresEveryExactVMA(t *testing.T) {
	group := mappedELFTestMaps(0x700000)
	var calls int
	id, err := commonMappedBuildID(group, func(mapping procMap) ([]byte, error) {
		if mapping != group[calls] {
			t.Fatal("query changed map metadata")
		}
		calls++
		return []byte{1, 2, 3}, nil
	})
	if err != nil || calls != len(group) || !bytes.Equal(id, []byte{1, 2, 3}) {
		t.Fatalf("ID=%x calls=%d error=%v", id, calls, err)
	}
	for _, failure := range []error{target.ErrUnsupported, target.ErrUnavailable, target.ErrStale, context.Canceled} {
		if _, err := commonMappedBuildID(group, func(procMap) ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
	calls = 0
	if _, err := commonMappedBuildID(group, func(procMap) ([]byte, error) { calls++; return []byte{byte(calls)}, nil }); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("same map device/inode but different kernel IDs accepted: %v", err)
	}
	if _, err := commonMappedBuildID(group, func(procMap) ([]byte, error) { return nil, nil }); !errors.Is(err, target.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestELFBuildIDAssociationDoesNotClaimBackingFileIdentity(t *testing.T) {
	_, data := elfBuildIDTestELF(t, []byte{1, 2, 3, 4})
	path := filepath.Join(elfSourceTestDirectory(t), "metadata")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := openRegularELFSource(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	group := []procMap{{Start: 0x400000, End: 0x401000, DevMajor: 99, DevMinor: 77, Inode: 123, Path: "/mapped-original"}}
	module, err := associateMappedELFSource(source, path, group, elfMapIdentity(group[0]), 0x1000, []byte{1, 2, 3, 4})
	if err != nil || module.Proof != kernelBuildIDMetadataProof || module.MetadataPath != path || module.LoadBias != 0 {
		t.Fatalf("module=%+v error=%v", module, err)
	}
	if !strings.Contains(mappedELFSourceDescription(module), "backing-file identity is not established") {
		t.Fatal(mappedELFSourceDescription(module))
	}
	if _, err := associateMappedELFSource(source, path, group, elfMapIdentity(group[0]), 0x1000, []byte{1, 2, 3, 5}); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("different build ID accepted: %v", err)
	}
	group[0].End = 0x400900
	if _, err := associateMappedELFSource(source, path, group, elfMapIdentity(group[0]), 0x1000, []byte{1, 2, 3, 4}); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("missing PT_LOAD coverage accepted: %v", err)
	}
}

func TestELFBuildIDMetadataFallbackPreservesFatalErrors(t *testing.T) {
	for _, err := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded, errors.Join(target.ErrUnavailable, target.ErrStale), errors.Join(target.ErrUnavailable, context.Canceled)} {
		if mappedELFMetadataFallback(err) {
			t.Fatalf("fatal error permits metadata fallback: %v", err)
		}
	}
	if !mappedELFMetadataFallback(target.ErrUnavailable) {
		t.Fatal("ordinary proof unavailable cannot attempt separate metadata association")
	}
}

func TestELFSeparateDebugFileBuildIDAssociation(t *testing.T) {
	moduleFile, data := elfBuildIDTestELF(t, []byte{10, 20, 30, 40})
	path := filepath.Join(elfSourceTestDirectory(t), "renamed-debug")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	module := &mappedELF{File: moduleFile}
	debugFile, err := associateELFDebugFile(context.Background(), module, path)
	if err != nil || debugFile.Proof != "gnu-build-id-metadata" || !bytes.Equal(debugFile.BuildID, []byte{10, 20, 30, 40}) {
		t.Fatalf("result=%+v error=%v", debugFile, err)
	}
	if err := debugFile.Source.Close(); err != nil {
		t.Fatal(err)
	}
	_, other := elfBuildIDTestELF(t, []byte{10, 20, 30, 41})
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := associateELFDebugFile(context.Background(), module, path); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("debug ID mismatch accepted: %v", err)
	}
}

func TestELFSeparateDebugFileCRCIsWholeContentNotFilename(t *testing.T) {
	moduleFile, moduleData := elfCommandTestELF(t, nil, nil, nil)
	_, debugData := elfCommandTestELF(t, []elf.Symbol{{Name: "arena", Section: 1, Value: 0x400800, Size: 8}}, nil, nil)
	linkName := "declared.debug"
	link := make([]byte, (len(linkName)+1+3)&^3+4)
	copy(link, linkName)
	binary.LittleEndian.PutUint32(link[len(link)-4:], crc32.ChecksumIEEE(debugData))
	section := moduleFile.Sections[1]
	copy(moduleData[section.Offset:], link)
	section.Name, section.Size = ".gnu_debuglink", uint64(len(link))
	path := filepath.Join(elfSourceTestDirectory(t), "explicit-renamed-file")
	if err := os.WriteFile(path, debugData, 0o600); err != nil {
		t.Fatal(err)
	}
	module := &mappedELF{File: moduleFile}
	debugFile, err := associateELFDebugFile(context.Background(), module, path)
	if err != nil || debugFile.Proof != "gnu-debuglink-crc32-metadata" {
		t.Fatalf("result=%+v error=%v", debugFile, err)
	}
	if err := debugFile.Source.Close(); err != nil {
		t.Fatal(err)
	}
	debugData[0x900]++
	if err := os.WriteFile(path, debugData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := associateELFDebugFile(context.Background(), module, path); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("CRC mismatch accepted: %v", err)
	}
}
