package debugger

import (
	"debug/elf"
	"fmt"
	"math"

	"fastdbg2/native/amd64"
	"fastdbg2/native/x86"
	"fastdbg2/target"
)

type commandABI struct {
	arch       target.Architecture
	word, bits int
	pc, sp, bp string
	maximum    uint64
}

func abiFor(arch target.Architecture) commandABI {
	if arch == target.X86 {
		return commandABI{target.X86, 4, 32, "eip", "esp", "ebp", math.MaxUint32}
	}
	return commandABI{target.AMD64, 8, 64, "rip", "rsp", "rbp", math.MaxUint64}
}

func (c *Controller) abi() commandABI         { return abiFor(c.arch) }
func (view contextOutput) abi() commandABI    { return abiFor(view.arch) }
func (walker *addressWalker) abi() commandABI { return abiFor(walker.arch) }

func nativeELFArchitecture(file *elf.File) (target.Architecture, error) {
	if file == nil {
		return "", target.ErrInvalidArgument
	}
	if file.Data != elf.ELFDATA2LSB {
		return "", target.ErrUnsupported
	}
	if file.Class == elf.ELFCLASS32 && file.Machine == elf.EM_386 {
		return target.X86, nil
	}
	if file.Class == elf.ELFCLASS64 && file.Machine == elf.EM_X86_64 {
		return target.AMD64, nil
	}
	return "", fmt.Errorf("native commands require ELF32 i386 or ELF64 amd64: %w", target.ErrUnsupported)
}

func validateNativeELF(file *elf.File) error {
	if _, err := nativeELFArchitecture(file); err != nil {
		return err
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return target.ErrUnsupported
	}
	return nil
}

func nativePathArchitecture(path string) (target.Architecture, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := validateNativeELF(file); err != nil {
		return "", err
	}
	return nativeELFArchitecture(file)
}

func nativeRegister(name string, architecture target.Architecture) bool {
	profile := amd64.Descriptor()
	if architecture == target.X86 {
		profile = x86.Descriptor()
	}
	_, ok := profile.Register(name)
	return ok
}

func (c *Controller) assemblyArchitecture() (target.Architecture, error) {
	if c.session != nil {
		snapshot, err := c.refresh()
		if err != nil {
			return "", err
		}
		return snapshot.Architecture, nil
	}
	if c.path != "" {
		return nativePathArchitecture(c.path)
	}
	return target.AMD64, nil
}
