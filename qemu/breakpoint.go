package qemu

import (
	"fmt"

	"fastdbg2/target"
)

func (s *Session) AddBreakpoint(addr target.Address) error {
	if uint64(addr)%uint64(s.profile.BreakpointAlignment) != 0 {
		return fmt.Errorf("%w: breakpoint address must be aligned to %d bytes", target.ErrInvalidArgument, s.profile.BreakpointAlignment)
	}
	if !validRange(addr, int(s.profile.BreakpointKind)) {
		return target.ErrOverflow
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	if _, exists := s.breakpoints[addr]; exists {
		return nil
	}
	s.changed()
	if err := s.expectOK(fmt.Sprintf("Z0,%x,%x", addr, s.profile.BreakpointKind)); err != nil {
		return err
	}
	s.breakpoints[addr] = struct{}{}
	return nil
}

func (s *Session) RemoveBreakpoint(addr target.Address) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.removeBreakpoint(addr)
}

func (s *Session) removeBreakpoint(addr target.Address) error {
	if _, exists := s.breakpoints[addr]; !exists {
		return target.ErrNotFound
	}
	s.changed()
	if err := s.expectOK(fmt.Sprintf("z0,%x,%x", addr, s.profile.BreakpointKind)); err != nil {
		return err
	}
	delete(s.breakpoints, addr)
	return nil
}

type HardwarePoint struct {
	Kind    int
	Address target.Address
	Size    int
}

func (s *Session) AddHardwarePoint(point HardwarePoint) error {
	if point.Kind < 1 || point.Kind > 4 || point.Size < 1 || point.Size > 8 || point.Size&(point.Size-1) != 0 || !validRange(point.Address, point.Size) {
		return target.ErrInvalidArgument
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	if s.hardwarePoints[point] {
		return nil
	}
	s.changed()
	if err := s.expectOK(fmt.Sprintf("Z%d,%x,%x", point.Kind, point.Address, point.Size)); err != nil {
		return err
	}
	if s.hardwarePoints == nil {
		s.hardwarePoints = make(map[HardwarePoint]bool)
	}
	s.hardwarePoints[point] = true
	return nil
}
func (s *Session) RemoveHardwarePoint(point HardwarePoint) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.removeHardwarePoint(point)
}
func (s *Session) removeHardwarePoint(point HardwarePoint) error {
	if !s.hardwarePoints[point] {
		return target.ErrNotFound
	}
	s.changed()
	if err := s.expectOK(fmt.Sprintf("z%d,%x,%x", point.Kind, point.Address, point.Size)); err != nil {
		return err
	}
	delete(s.hardwarePoints, point)
	return nil
}
