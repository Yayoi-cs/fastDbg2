package launch

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const bootstrapCode = "\x48\x8b\x04\x24\x4c\x8d\x64\x24\x08\x4c\x8d\x6c\xc4\x10\x48\x83" +
	"\xec\x10\xb8\x48\x00\x00\x00\xbf\x05\x00\x00\x00\xbe\x02\x00\x00" +
	"\x00\xba\x01\x00\x00\x00\x0f\x05\x48\x85\xc0\x0f\x88\xb2\x00\x00" +
	"\x00\xb8\x48\x00\x00\x00\xbf\x03\x00\x00\x00\x0f\x05\x48\x85\xc0" +
	"\x0f\x88\x9d\x00\x00\x00\xb8\x03\x00\x00\x00\xbf\x06\x00\x00\x00" +
	"\x0f\x05\x48\x85\xc0\x0f\x88\x88\x00\x00\x00\xc7\x04\x24\x00\x00" +
	"\x00\x00\xb8\x01\x00\x00\x00\xbf\x05\x00\x00\x00\x48\x89\xe6\xba" +
	"\x04\x00\x00\x00\x0f\x05\x48\x83\xf8\xfc\x74\xe6\x48\x85\xc0\x78" +
	"\x62\x48\x83\xf8\x04\x0f\x85\x93\x00\x00\x00\x31\xc0\xbf\x04\x00" +
	"\x00\x00\x48\x89\xe6\xba\x01\x00\x00\x00\x0f\x05\x48\x83\xf8\xfc" +
	"\x74\xe9\x48\x85\xc0\x78\x3c\x48\x83\xf8\x01\x75\x63\x80\x3c\x24" +
	"\x01\x75\x64\xb8\x03\x00\x00\x00\xbf\x04\x00\x00\x00\x0f\x05\x48" +
	"\x85\xc0\x78\x1f\xb8\x42\x01\x00\x00\xbf\x03\x00\x00\x00\x48\x8d" +
	"\x35\x50\x00\x00\x00\x4c\x89\xe2\x4d\x89\xea\x41\xb8\x00\x10\x00" +
	"\x00\x0f\x05\xf7\xd8\x89\x04\x24\xb8\x01\x00\x00\x00\xbf\x05\x00" +
	"\x00\x00\x48\x89\xe6\xba\x04\x00\x00\x00\x0f\x05\x48\x83\xf8\xfc" +
	"\x74\xe6\xb8\x3c\x00\x00\x00\xbf\x7f\x00\x00\x00\x0f\x05\x0f\x0b" +
	"\xb8\x83\xff\xff\xff\xeb\xcc\xb8\xb9\xff\xff\xff\xeb\xc5\xb8\xfb" +
	"\xff\xff\xff\xeb\xbe\x00"

func bootstrapImage() []byte {
	const headerSize = 64
	const programHeaderSize = 56
	const entry = headerSize + 2*programHeaderSize
	image := make([]byte, entry+len(bootstrapCode))
	copy(image, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	put16 := func(offset int, value uint16) { binary.LittleEndian.PutUint16(image[offset:], value) }
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(image[offset:], value) }
	put64 := func(offset int, value uint64) { binary.LittleEndian.PutUint64(image[offset:], value) }
	put16(16, uint16(elf.ET_DYN))
	put16(18, uint16(elf.EM_X86_64))
	put32(20, uint32(elf.EV_CURRENT))
	put64(24, entry)
	put64(32, headerSize)
	put16(52, headerSize)
	put16(54, programHeaderSize)
	put16(56, 2)
	put32(64, uint32(elf.PT_LOAD))
	put32(68, uint32(elf.PF_R|elf.PF_X))
	put64(96, uint64(len(image)))
	put64(104, uint64(len(image)))
	put64(112, 4096)
	put32(120, uint32(elf.PT_GNU_STACK))
	put32(124, uint32(elf.PF_R|elf.PF_W))
	put64(168, 16)
	copy(image[entry:], bootstrapCode)
	return image
}

func newBootstrap() (_ *os.File, err error) {
	fd, err := unix.MemfdCreate("fastdbg2-launch", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		return nil, fmt.Errorf("launch memfd_create requires executable memfd support: %w", err)
	}
	f := os.NewFile(uintptr(fd), "fastdbg2-launch")
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	if _, err = f.Write(bootstrapImage()); err != nil {
		return nil, fmt.Errorf("write launch bootstrap: %w", err)
	}
	if err = f.Chmod(0500); err != nil {
		return nil, fmt.Errorf("chmod launch bootstrap: %w", err)
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_EXEC | unix.F_SEAL_SEAL
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, fmt.Errorf("seal launch bootstrap: %w", err)
	}
	return f, nil
}
