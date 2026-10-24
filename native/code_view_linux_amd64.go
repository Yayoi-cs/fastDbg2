package native

import (
	"fmt"
	"sort"

	"fastdbg2/target"
)

type CodeLocation struct {
	RawPC         target.Address
	InstructionPC target.Address
	Breakpoint    *target.Address
}

func (s *Session) ReadCodeLocation(token target.ThreadToken) (CodeLocation, error) {
	return call(s, func(e *engine) (CodeLocation, error) {
		return e.readCodeLocation(token)
	})
}

func (s *Session) ReadCodeMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	return call(s, func(e *engine) (int, error) {
		return e.readCodeMemory(token, address, dst)
	})
}

func (e *engine) readCodeLocation(token target.ThreadToken) (CodeLocation, error) {
	t, err := e.requireThread(token)
	if err != nil {
		return CodeLocation{}, err
	}
	if t.process.profile.Architecture != target.AMD64 && t.process.profile.Architecture != target.X86 {
		return CodeLocation{}, fmt.Errorf("code view requires native x86 or amd64: %w", target.ErrUnsupported)
	}
	space := t.process.space
	if space == nil {
		return CodeLocation{}, target.ErrUnavailable
	}
	memory := target.MemoryToken{Space: space.ref, Revision: space.revision}
	if _, _, err := e.requireMemory(memory); err != nil {
		return CodeLocation{}, err
	}
	rawPC, err := e.readPC(t.tid)
	if err != nil {
		return CodeLocation{}, err
	}
	location := CodeLocation{RawPC: rawPC, InstructionPC: rawPC}
	if t.hit == nil {
		return location, nil
	}
	if err := validateBreakpointHit(t); err != nil {
		return CodeLocation{}, err
	}
	hit := t.hit
	bp := hit.bp
	if err := validateCodeBreakpoint(space, bp.addr, bp); err != nil {
		return CodeLocation{}, err
	}
	if hit.rewinding {
		return CodeLocation{}, fmt.Errorf("breakpoint PC write is unconfirmed: %w", target.ErrStale)
	}
	expected := hit.rawPC
	if hit.rewound {
		expected = bp.addr
	}
	if rawPC != expected {
		return CodeLocation{}, fmt.Errorf("thread %d breakpoint PC changed: %w", t.tid, target.ErrStale)
	}
	value, err := e.readByte(t.tid, bp.addr)
	if err != nil {
		return CodeLocation{}, err
	}
	if err := validateCodeBreakpointByte(bp, value); err != nil {
		return CodeLocation{}, err
	}
	address := bp.addr
	location.InstructionPC, location.Breakpoint = address, &address
	return location, nil
}

func (e *engine) readCodeMemory(token target.MemoryToken, address target.Address, dst []byte) (int, error) {
	space, t, err := e.requireMemory(token)
	if err != nil {
		return 0, err
	}
	if t.process.profile.Architecture != target.AMD64 && t.process.profile.Architecture != target.X86 {
		return 0, fmt.Errorf("code view requires native x86 or amd64: %w", target.ErrUnsupported)
	}
	if err := validateMemoryRange(t.process.profile, address, len(dst)); err != nil {
		return 0, err
	}
	breakpoints, err := codeBreakpoints(space, address, len(dst))
	if err != nil {
		return 0, err
	}
	data := make([]byte, len(dst))
	n, readErr := e.readSpaceMemory(token, address, data)
	if n < 0 || n > len(data) {
		return 0, fmt.Errorf("code memory returned invalid count %d/%d: %w", n, len(data), target.ErrUnknown)
	}
	for _, bp := range breakpoints {
		if uint64(bp.addr-address) >= uint64(n) {
			break
		}
		if err := validateCodeBreakpointByte(bp, data[int(bp.addr-address)]); err != nil {
			return 0, err
		}
	}
	for _, bp := range breakpoints {
		if uint64(bp.addr-address) >= uint64(n) {
			break
		}
		if bp.armed {
			data[int(bp.addr-address)] = bp.original
		}
	}
	copy(dst, data[:n])
	return n, readErr
}

func codeBreakpoints(space *addressSpace, address target.Address, size int) ([]*breakpoint, error) {
	var addresses []target.Address
	for location := range space.breakpoints {
		if location >= address && uint64(location-address) < uint64(size) {
			addresses = append(addresses, location)
		}
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	breakpoints := make([]*breakpoint, 0, len(addresses))
	for _, location := range addresses {
		bp := space.breakpoints[location]
		if err := validateCodeBreakpoint(space, location, bp); err != nil {
			return nil, err
		}
		breakpoints = append(breakpoints, bp)
	}
	return breakpoints, nil
}

func validateCodeBreakpoint(space *addressSpace, address target.Address, bp *breakpoint) error {
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	if bp.space != space || bp.addr != address || bp.generation == 0 || bp.original == 0xcc {
		return fmt.Errorf("code breakpoint at %#x is inconsistent: %w", address, target.ErrStale)
	}
	if bp.pending != nil {
		return fmt.Errorf("breakpoint write at %#x is unconfirmed: %w", address, target.ErrStale)
	}
	return nil
}

func validateCodeBreakpointByte(bp *breakpoint, value byte) error {
	expected := bp.original
	if bp.armed {
		expected = 0xcc
	}
	if value != expected {
		return fmt.Errorf("breakpoint byte changed at %#x: %w", bp.addr, target.ErrStale)
	}
	return nil
}
