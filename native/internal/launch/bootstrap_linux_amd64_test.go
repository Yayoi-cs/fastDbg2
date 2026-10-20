package launch

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func launchTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".cache", "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", root)
	return t.TempDir()
}

func TestBootstrapAssembly(t *testing.T) {
	dir := launchTempDir(t)
	object, binary := filepath.Join(dir, "bootstrap.o"), filepath.Join(dir, "bootstrap.bin")
	if out, err := exec.Command("as", "--64", "-o", object, "testdata/bootstrap.s").CombinedOutput(); err != nil {
		t.Fatalf("assemble: %v\n%s", err, out)
	}
	if out, err := exec.Command("objcopy", "-O", "binary", "--only-section=.text", object, binary).CombinedOutput(); err != nil {
		t.Fatalf("extract code: %v\n%s", err, out)
	}
	code, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(code, []byte(bootstrapCode)) {
		t.Fatalf("bootstrap code differs from assembly: got %x want %x", []byte(bootstrapCode), code)
	}
	f, err := elf.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, section := range f.Sections {
		if section.Type == elf.SHT_REL || section.Type == elf.SHT_RELA {
			t.Fatalf("bootstrap has unresolved relocation section %s", section.Name)
		}
	}
}

func TestBootstrapImage(t *testing.T) {
	image := bootstrapImage()
	f, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != elf.ET_DYN || f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		t.Fatalf("header=%+v", f.FileHeader)
	}
	if len(f.Progs) != 2 || len(f.Sections) != 0 {
		t.Fatalf("program headers=%d sections=%d", len(f.Progs), len(f.Sections))
	}
	load := f.Progs[0]
	if load.Type != elf.PT_LOAD || load.Flags != elf.PF_R|elf.PF_X || load.Off != 0 || load.Vaddr != 0 || load.Filesz != uint64(len(image)) || load.Memsz != load.Filesz || load.Align != 4096 {
		t.Fatalf("load=%+v", load.ProgHeader)
	}
	stack := f.Progs[1]
	if stack.Type != elf.PT_GNU_STACK || stack.Flags != elf.PF_R|elf.PF_W {
		t.Fatalf("stack=%+v", stack.ProgHeader)
	}
	if !bytes.Equal(image[f.Entry:], []byte(bootstrapCode)) {
		t.Fatal("entry does not point at bootstrap code")
	}
}

func TestBootstrapSeals(t *testing.T) {
	f, err := newBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0500 {
		t.Fatalf("permissions=%o", info.Mode().Perm())
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("descriptor flags=%x error=%v", flags, err)
	}
	required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_EXEC | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&required != required {
		t.Fatalf("seals=%x error=%v", seals, err)
	}
	if _, err := f.WriteAt([]byte{0}, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("sealed write: %v", err)
	}
	if err := f.Chmod(0600); !errors.Is(err, unix.EPERM) {
		t.Fatalf("sealed executable permission: %v", err)
	}
}
