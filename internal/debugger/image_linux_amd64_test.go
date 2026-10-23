package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestImagePreflightAMD64(t *testing.T) {
	for _, kind := range []elf.Type{elf.ET_EXEC, elf.ET_DYN} {
		path := imageTestELF(t, kind, nil)
		if err := preflightAMD64(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := preflightAMD64(""); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("empty path: %v", err)
	}
	if err := preflightAMD64(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing executable: %v", err)
	}
	path := imageTestELF(t, elf.ET_REL, nil)
	if err := preflightAMD64(path); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("relocatable executable: %v", err)
	}
	for _, pid := range []int{-1, 0} {
		if err := preflightAttachAMD64(pid); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("PID %d: %v", pid, err)
		}
	}
	if err := preflightAttachAMD64(os.Getpid()); err != nil {
		t.Fatal(err)
	}
}

func TestImageAMD64Validation(t *testing.T) {
	valid := elf.FileHeader{
		Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Data: elf.ELFDATA2LSB, Type: elf.ET_EXEC,
	}
	for _, test := range []struct {
		name string
		edit func(*elf.FileHeader)
	}{
		{"class", func(header *elf.FileHeader) { header.Class = elf.ELFCLASS32 }},
		{"machine", func(header *elf.FileHeader) { header.Machine = elf.EM_AARCH64 }},
		{"byte order", func(header *elf.FileHeader) { header.Data = elf.ELFDATA2MSB }},
		{"type", func(header *elf.FileHeader) { header.Type = elf.ET_CORE }},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := valid
			test.edit(&header)
			if err := validateAMD64ELF(&elf.File{FileHeader: header}); !errors.Is(err, target.ErrUnsupported) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := validateAMD64ELF(nil); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil ELF: %v", err)
	}
}

func TestImageAuxiliaryEntry(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want uint64
		err  error
	}{
		{"entry", imageTestAuxv(6, 4096, 9, 0x12345678, 0, 0), 0x12345678, nil},
		{"zero entry", imageTestAuxv(9, 0, 0, 0), 0, nil},
		{"zero padding", imageTestAuxv(9, 7, 0, 0, 0, 0), 7, nil},
		{"empty", nil, 0, target.ErrInvalidArgument},
		{"partial", []byte{9}, 0, target.ErrInvalidArgument},
		{"no terminator", imageTestAuxv(9, 1), 0, target.ErrInvalidArgument},
		{"missing entry", imageTestAuxv(6, 4096, 0, 0), 0, target.ErrUnavailable},
		{"duplicate", imageTestAuxv(9, 1, 9, 1, 0, 0), 0, target.ErrInvalidArgument},
		{"entry after terminator", imageTestAuxv(0, 0, 9, 1), 0, target.ErrInvalidArgument},
		{"nonzero terminator", imageTestAuxv(9, 1, 0, 1), 0, target.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := auxiliaryEntry(test.data)
			if got != test.want || !errors.Is(err, test.err) {
				t.Fatalf("got %#x, %v; want %#x, %v", got, err, test.want, test.err)
			}
		})
	}
}

func TestImageExactLoadBias(t *testing.T) {
	for _, test := range []struct {
		name  string
		kind  elf.Type
		entry uint64
		aux   uint64
		bias  uint64
		err   error
	}{
		{"executable", elf.ET_EXEC, 0x401000, 0x401000, 0, nil},
		{"PIE", elf.ET_DYN, 0x1020, 0x701020, 0x700000, nil},
		{"zero entry", elf.ET_DYN, 0, 0x700000, 0x700000, nil},
		{"exec mismatch", elf.ET_EXEC, 0x401000, 0x501000, 0, target.ErrStale},
		{"underflow", elf.ET_DYN, 0x1000, 1, 0, target.ErrOverflow},
		{"unsupported", elf.ET_REL, 0, 0, 0, target.ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			bias, err := imageLoadBias(test.kind, test.entry, imageTestAuxv(9, test.aux, 0, 0))
			if bias != test.bias || !errors.Is(err, test.err) {
				t.Fatalf("got %#x, %v; want %#x, %v", bias, err, test.bias, test.err)
			}
		})
	}
}

func TestImageStateCachesOnlyAddressSpaceIdentity(t *testing.T) {
	snapshot, thread := imageTestSnapshot()
	var state imageState
	var calls int
	read := func(ctx context.Context, tid int) (*loadedImage, error) {
		calls++
		if tid != thread.TID {
			t.Fatalf("read TID %d, want %d", tid, thread.TID)
		}
		return &loadedImage{path: fmt.Sprintf("image-%d", calls), symbolErr: target.ErrUnavailable}, nil
	}
	first, err := state.loadWith(context.Background(), snapshot, thread, read)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Memory.Revision++
	thread.Token.Registers++
	snapshot.Threads[0] = thread
	second, err := state.loadWith(context.Background(), snapshot, thread, read)
	if err != nil || second != first || calls != 1 {
		t.Fatalf("same address space reloaded: image=%p, calls=%d, error=%v", second, calls, err)
	}
	snapshot.Memory.Space.ID++
	third, err := state.loadWith(context.Background(), snapshot, thread, read)
	if err != nil || third == first || calls != 2 {
		t.Fatalf("new address space retained old image: image=%p, calls=%d, error=%v", third, calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := state.loadWith(ctx, snapshot, thread, read); !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatalf("canceled cache access: %v, calls=%d", err, calls)
	}
}

func TestImageStateDoesNotRetainFailedNewImage(t *testing.T) {
	snapshot, thread := imageTestSnapshot()
	oldSpace := snapshot.Memory.Space
	oldSpace.ID++
	state := imageState{space: oldSpace, image: &loadedImage{path: "old"}}
	failure := errors.New("image unavailable")
	if _, err := state.loadWith(context.Background(), snapshot, thread, func(context.Context, int) (*loadedImage, error) {
		return nil, failure
	}); !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
	if state.image != nil || state.space != (target.SpaceRef{}) {
		t.Fatal("failed new image retained old symbols")
	}
	image, err := state.loadWith(context.Background(), snapshot, thread, func(context.Context, int) (*loadedImage, error) {
		return &loadedImage{path: "new"}, nil
	})
	if err != nil || image.path != "new" {
		t.Fatalf("retry: image=%+v error=%v", image, err)
	}
}

func TestImageSnapshotValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*target.Snapshot, *target.ThreadInfo)
		want error
	}{
		{"architecture", func(s *target.Snapshot, _ *target.ThreadInfo) { s.Architecture = target.AArch64 }, target.ErrUnsupported},
		{"running", func(s *target.Snapshot, _ *target.ThreadInfo) { s.State = target.StateRunning }, target.ErrInvalidState},
		{"memory", func(s *target.Snapshot, _ *target.ThreadInfo) { s.Memory.Revision = 0 }, target.ErrUnavailable},
		{"foreign process", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.Process.ID++ }, target.ErrUnsupported},
		{"thread running", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.State = target.StateRunning }, target.ErrInvalidState},
		{"exiting", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.Exiting = true }, target.ErrInvalidState},
		{"listening", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.Listening = true }, target.ErrInvalidState},
		{"zero TID", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.TID = 0 }, target.ErrInvalidState},
		{"missing", func(s *target.Snapshot, _ *target.ThreadInfo) { s.Threads = nil }, target.ErrStale},
		{"stale token", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.Token.Registers++ }, target.ErrStale},
		{"zero token", func(_ *target.Snapshot, thread *target.ThreadInfo) { thread.Token.Stop = 0 }, target.ErrStale},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, thread := imageTestSnapshot()
			test.edit(&snapshot, &thread)
			var state imageState
			_, err := state.loadWith(context.Background(), snapshot, thread, func(context.Context, int) (*loadedImage, error) {
				t.Fatal("invalid snapshot read process files")
				return nil, nil
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestImageReadLiveExecutable(t *testing.T) {
	image, err := readLiveImage(context.Background(), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if image.path != fmt.Sprintf("/proc/%d/exe", os.Getpid()) {
		t.Fatalf("unexpected path: %q", image.path)
	}
	file, err := elf.Open(image.path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	auxv, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := auxiliaryEntry(auxv)
	if err != nil {
		t.Fatal(err)
	}
	if image.loadBias+file.Entry != entry {
		t.Fatalf("bias %#x + entry %#x differs from runtime entry %#x", image.loadBias, file.Entry, entry)
	}
}

func TestImageSymbolResolution(t *testing.T) {
	path := imageTestELF(t, elf.ET_DYN, []elf.Symbol{
		{Name: "main", Value: 0x1010, Size: 8, Info: byte(elf.STT_FUNC), Section: 1},
		{Name: "two  spaces.name", Value: 0x1020, Size: 8, Info: byte(elf.STT_FUNC), Section: 1},
		{Name: "alias", Value: 0x1030, Size: 8, Info: byte(elf.STT_FUNC), Section: 1},
		{Name: "alias", Value: 0x1040, Size: 8, Info: byte(elf.STT_FUNC), Section: 1},
	})
	symbols, err := inspect.LoadSymbols(context.Background(), []inspect.Module{{ID: "main", Path: path, LoadBias: 0x700000}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	image := &loadedImage{symbols: symbols}
	for name, want := range map[string]uint64{"main": 0x701010, "two  spaces.name": 0x701020} {
		if got, err := image.resolveSymbol(name); err != nil || got != want {
			t.Fatalf("%q: %#x, %v; want %#x", name, got, err, want)
		}
	}
	if _, err := image.resolveSymbol("missing"); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("missing symbol: %v", err)
	}
	if _, err := image.resolveSymbol("alias"); !errors.Is(err, target.ErrAmbiguous) {
		t.Fatalf("ambiguous symbol: %v", err)
	}
	if _, err := (*loadedImage)(nil).resolveSymbol("main"); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("no image: %v", err)
	}
	image.symbolErr = target.ErrUnavailable
	if _, err := image.resolveSymbol("main"); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("symbol load failure: %v", err)
	}
}

func imageTestSnapshot() (target.Snapshot, target.ThreadInfo) {
	process := target.ProcessRef{Session: 7, ID: 1}
	ref := target.ThreadRef{Session: 7, ID: 2}
	thread := target.ThreadInfo{
		Ref: ref, Process: process, TID: 1234, State: target.StateStopped,
		Token: target.ThreadToken{Thread: ref, Stop: 3, Registers: 4},
	}
	snapshot := target.Snapshot{
		Sequence: 5, State: target.StateStopped, Architecture: target.AMD64, Process: process,
		Threads: []target.ThreadInfo{thread},
		Memory:  target.MemoryToken{Space: target.SpaceRef{Session: 7, ID: 6}, Revision: 1},
	}
	return snapshot, thread
}

func imageTestAuxv(values ...uint64) []byte {
	data := make([]byte, len(values)*8)
	for i, value := range values {
		binary.LittleEndian.PutUint64(data[i*8:], value)
	}
	return data
}

func imageTestELF(t *testing.T, kind elf.Type, symbols []elf.Symbol) string {
	t.Helper()
	type section struct {
		header elf.Section64
		data   []byte
	}
	names := []byte("\x00.text\x00.strtab\x00.symtab\x00.shstrtab\x00")
	sections := []section{
		{},
		{header: elf.Section64{Name: 1, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x1000, Addralign: 16}, data: bytes.Repeat([]byte{0x90}, 128)},
	}
	if symbols != nil {
		strings := []byte{0}
		var table bytes.Buffer
		imageTestWrite(t, &table, elf.Sym64{})
		for _, symbol := range symbols {
			offset := len(strings)
			strings = append(strings, symbol.Name...)
			strings = append(strings, 0)
			imageTestWrite(t, &table, elf.Sym64{
				Name: uint32(offset), Info: symbol.Info, Shndx: uint16(symbol.Section), Value: symbol.Value, Size: symbol.Size,
			})
		}
		sections = append(sections,
			section{header: elf.Section64{Name: 7, Type: uint32(elf.SHT_STRTAB), Addralign: 1}, data: strings},
			section{header: elf.Section64{Name: 15, Type: uint32(elf.SHT_SYMTAB), Link: 2, Info: 1, Addralign: 8, Entsize: 24}, data: table.Bytes()},
		)
	}
	shstrndx := len(sections)
	sections = append(sections, section{header: elf.Section64{Name: 23, Type: uint32(elf.SHT_STRTAB), Addralign: 1}, data: names})
	var data bytes.Buffer
	data.Write(make([]byte, elf.EI_NIDENT+48))
	for i := 1; i < len(sections); i++ {
		for data.Len()%8 != 0 {
			data.WriteByte(0)
		}
		sections[i].header.Off = uint64(data.Len())
		sections[i].header.Size = uint64(len(sections[i].data))
		data.Write(sections[i].data)
	}
	for data.Len()%8 != 0 {
		data.WriteByte(0)
	}
	shoff := uint64(data.Len())
	for _, section := range sections {
		imageTestWrite(t, &data, section.header)
	}
	header := elf.Header64{
		Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Entry: 0x1010,
		Ehsize: 64, Shoff: shoff, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: uint16(shstrndx),
	}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	var encoded bytes.Buffer
	imageTestWrite(t, &encoded, header)
	copy(data.Bytes(), encoded.Bytes())
	path := filepath.Join(t.TempDir(), "fixture with spaces.elf")
	if err := os.WriteFile(path, data.Bytes(), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func imageTestWrite(t *testing.T, output *bytes.Buffer, value any) {
	t.Helper()
	if err := binary.Write(output, binary.LittleEndian, value); err != nil {
		t.Fatal(err)
	}
}
