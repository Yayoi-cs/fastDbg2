package arch

import "fastdbg2/target"

type Register struct {
	Name    string
	Bits    int
	Feature string
}

type Descriptor struct {
	Architecture           target.Architecture
	XMLArchitecture        string
	IsProgramCounter       func(Register) bool
	BreakpointKind         uint64
	BreakpointAlignment    uint64
	FixedRegisterByteOrder target.ByteOrder
	ValidateRegisters      func([]Register) error
}
