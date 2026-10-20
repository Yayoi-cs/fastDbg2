package arch

import (
	"debug/elf"
	"fmt"
	"math"

	"fastdbg2/target"
)

type Register struct {
	Name   string
	Bits   int
	Offset int
}

type Descriptor struct {
	Architecture      target.Architecture
	ELFClass          elf.Class
	ELFMachine        elf.Machine
	AddressBits       int
	RegisterSetSize   int
	PCName            string
	Registers         []Register
	ValidateRegisters func([]byte) error
}

func (d Descriptor) Register(name string) (Register, bool) {
	for _, register := range d.Registers {
		if register.Name == name {
			return register, true
		}
	}
	return Register{}, false
}

func (d Descriptor) MaxAddress() (target.Address, error) {
	switch d.AddressBits {
	case 32:
		return target.Address(math.MaxUint32), nil
	case 64:
		return target.Address(math.MaxUint64), nil
	default:
		return 0, fmt.Errorf("address width %d: %w", d.AddressBits, target.ErrUnsupported)
	}
}

func (d Descriptor) ValidateRange(address target.Address, size int) error {
	if size < 0 {
		return fmt.Errorf("negative memory size: %w", target.ErrInvalidArgument)
	}
	maximum, err := d.MaxAddress()
	if err != nil {
		return err
	}
	if address > maximum || (size > 0 && uint64(size-1) > uint64(maximum-address)) {
		return fmt.Errorf("memory range at %#x of size %d exceeds %d-bit addresses: %w", address, size, d.AddressBits, target.ErrOverflow)
	}
	return nil
}
