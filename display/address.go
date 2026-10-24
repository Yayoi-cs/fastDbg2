package display

import (
	"fmt"
	"math"

	"fastdbg2/target"
)

type AddressKind uint8

const (
	AddressUnknown AddressKind = iota
	AddressCode
	AddressData
	AddressStack
	AddressHeap
)

func (r Renderer) Address(arch target.Architecture, address target.Address, kind AddressKind) (string, error) {
	var width int
	switch arch {
	case target.X86:
		width = 8
		if address > math.MaxUint32 {
			return "", fmt.Errorf("x86 address %#x: %w", address, target.ErrOverflow)
		}
	case target.AMD64, target.AArch64:
		width = 16
	default:
		return "", fmt.Errorf("architecture %q: %w", arch, target.ErrUnsupported)
	}
	var code string
	switch kind {
	case AddressUnknown:
	case AddressCode:
		code = codeColor
	case AddressData:
		code = "36"
	case AddressStack, AddressHeap:
		code = "36"
	default:
		return "", fmt.Errorf("address kind %d: %w", kind, target.ErrInvalidArgument)
	}
	return r.paint(code, fmt.Sprintf("0x%0*x", width, address)), nil
}
