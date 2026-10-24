package qemu

import (
	"encoding/hex"
	"fmt"
	"io"
	"math"

	"fastdbg2/target"
)

func validRange(addr target.Address, length int) bool {
	return length == 0 || uint64(length-1) <= math.MaxUint64-uint64(addr)
}

func (s *Session) ReadMemory(addr target.Address, dst []byte) (int, error) {
	if !validRange(addr, len(dst)) {
		return 0, target.ErrOverflow
	}
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.end()
	return s.readMemory(addr, dst)
}

func (s *Session) readMemory(addr target.Address, dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if err := s.selectThread(); err != nil {
		return 0, err
	}
	n := 0
	for n < len(dst) {
		length := min(len(dst)-n, s.packetSize/2, s.protocol.limit/2)
		if length == 0 {
			return n, &target.PartialError{Op: "read memory", Completed: n, Total: len(dst), Err: target.ErrUnsupported}
		}
		data, err := s.request(fmt.Sprintf("m%x,%x", uint64(addr)+uint64(n), length))
		if err == nil && len(data) == 0 {
			err = fmt.Errorf("%w: m packet", target.ErrUnsupported)
		}
		if err != nil {
			return n, &target.PartialError{Op: "read memory", Completed: n, Total: len(dst), Err: err}
		}
		if len(data)%2 != 0 || len(data)/2 > length {
			return n, &target.PartialError{Op: "read memory", Completed: n, Total: len(dst), Err: s.protocolError("invalid memory response length")}
		}
		decoded, err := hex.DecodeString(string(data))
		if err != nil {
			return n, &target.PartialError{Op: "read memory", Completed: n, Total: len(dst), Err: s.protocolError("invalid memory hex data")}
		}
		copy(dst[n:], decoded)
		n += len(decoded)
		if len(decoded) != length {
			return n, &target.PartialError{Op: "read memory", Completed: n, Total: len(dst), Err: io.ErrUnexpectedEOF}
		}
	}
	return n, nil
}

func (s *Session) WriteMemory(addr target.Address, src []byte) (int, error) {
	if !validRange(addr, len(src)) {
		return 0, target.ErrOverflow
	}
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.end()
	if len(src) == 0 {
		return 0, nil
	}
	for breakpoint := range s.breakpoints {
		overlaps := func() bool {
			if breakpoint >= addr {
				return uint64(breakpoint-addr) < uint64(len(src))
			}
			return uint64(addr-breakpoint) < uint64(s.profile.BreakpointKind)
		}()
		if overlaps {
			return 0, fmt.Errorf("%w: write overlaps breakpoint at %#x", target.ErrInvalidState, breakpoint)
		}
	}
	if err := s.selectThread(); err != nil {
		return 0, err
	}
	s.changed()
	n := 0
	for n < len(src) {
		length := min(len(src)-n, s.packetSize/2)
		var header string
		for {
			header = fmt.Sprintf("M%x,%x:", uint64(addr)+uint64(n), length)
			if len(header)+2*length <= s.packetSize {
				break
			}
			length = (s.packetSize - len(header)) / 2
			if length <= 0 {
				return n, &target.PartialError{Op: "write memory", Completed: n, Total: len(src), Err: target.ErrUnsupported}
			}
		}
		if length == 0 {
			return n, &target.PartialError{Op: "write memory", Completed: n, Total: len(src), Err: target.ErrUnsupported}
		}
		if err := s.expectOK(header + hex.EncodeToString(src[n:n+length])); err != nil {
			return n, &target.PartialError{Op: "write memory", Completed: n, Total: len(src), Err: err}
		}
		n += length
	}
	return n, nil
}
