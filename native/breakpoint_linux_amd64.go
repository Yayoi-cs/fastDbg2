package native

import (
	"errors"
	"fastdbg2/target"
	"fmt"
	"sort"
)

type breakpoint struct {
	addr     target.Address
	original byte
	armed    bool
	restored map[int]bool
}

type taskError struct {
	pid int
	err error
}

func (e *taskError) Error() string { return fmt.Sprintf("task %d: %v", e.pid, e.err) }

func (e *taskError) Unwrap() error { return e.err }

func (s *Session) AddBreakpoint(addr target.Address) error {
	return command(s, func(e *engine) error {
		if err := e.requireStopped(); err != nil {
			return err
		}
		if err := e.checkBreakpointAddress(addr); err != nil {
			return err
		}
		if _, ok := e.breakpoints[addr]; ok {
			return fmt.Errorf("breakpoint already exists: %w", target.ErrInvalidState)
		}
		value, err := e.readByte(e.s.pid, addr)
		if err != nil {
			return err
		}
		if value == 0xcc {
			return fmt.Errorf("address already contains INT3: %w", target.ErrUnsupported)
		}
		bp := &breakpoint{addr: addr, original: value}
		if err := e.arm(bp); err != nil {
			return err
		}
		e.breakpoints[addr] = bp
		return nil
	})
}

func (s *Session) RemoveBreakpoint(addr target.Address) error {
	return command(s, func(e *engine) error {
		if err := e.requireStopped(); err != nil {
			return err
		}
		if err := e.checkBreakpointAddress(addr); err != nil {
			return err
		}
		bp, ok := e.breakpoints[addr]
		if !ok {
			return target.ErrNotFound
		}
		resetPC := false
		if e.hit != nil && *e.hit == addr {
			pc, err := e.readPC(e.s.pid)
			if err != nil {
				return err
			}
			resetPC = pc == addr+1
		}
		if err := e.disarm(bp); err != nil {
			return err
		}
		if resetPC {
			if err := e.writePC(e.s.pid, addr); err != nil {
				return errors.Join(err, e.arm(bp))
			}
			e.hit = nil
		}
		delete(e.breakpoints, addr)
		if e.suspended == bp {
			e.suspended = nil
		}
		return nil
	})
}

func (e *engine) checkBreakpointAddress(addr target.Address) error {
	if e.profile == nil {
		return target.ErrUnknown
	}
	max, err := e.profile.MaxAddress()
	if err != nil {
		return err
	}
	if addr >= max {
		return fmt.Errorf("breakpoint successor exceeds address width: %w", target.ErrOverflow)
	}
	return nil
}

func (e *engine) arm(bp *breakpoint) error {
	if bp.armed {
		return nil
	}
	value, err := e.readByte(e.s.pid, bp.addr)
	if err != nil {
		return err
	}
	if value != bp.original {
		return fmt.Errorf("instruction changed at 0x%x: %w", bp.addr, target.ErrStale)
	}
	if err := e.writeByte(e.s.pid, bp.addr, 0xcc); err != nil {
		return err
	}
	bp.armed = true
	return nil
}

func (e *engine) disarm(bp *breakpoint) error {
	if !bp.armed {
		return nil
	}
	value, err := e.readByte(e.s.pid, bp.addr)
	if err != nil {
		return err
	}
	if value != 0xcc {
		return fmt.Errorf("breakpoint byte changed at 0x%x: %w", bp.addr, target.ErrStale)
	}
	if err := e.writeByte(e.s.pid, bp.addr, bp.original); err != nil {
		return err
	}
	bp.armed = false
	return nil
}

func (e *engine) restoreBreakpoints() error {
	pids := []int{e.s.pid}
	var other []int
	for pid := range e.groups {
		if pid != e.s.pid {
			other = append(other, pid)
		}
	}
	sort.Ints(other)
	pids = append(pids, other...)
	for _, pid := range pids {
		if t := e.tasks[pid]; t == nil || t.exited {
			continue
		}
		for _, bp := range e.breakpoints {
			if !bp.armed {
				continue
			}
			value, err := e.readByte(pid, bp.addr)
			if err != nil {
				return &taskError{pid, err}
			}
			if value == bp.original && (pid != e.s.pid || bp.restored[pid]) {
				continue
			}
			if value != 0xcc {
				return fmt.Errorf("breakpoint byte changed at 0x%x: %w", bp.addr, target.ErrStale)
			}
			if err := e.writeByte(pid, bp.addr, bp.original); err != nil {
				return &taskError{pid, err}
			}
			if bp.restored == nil {
				bp.restored = make(map[int]bool)
			}
			bp.restored[pid] = true
		}
	}
	if e.hit != nil {
		pc, err := e.readPC(e.s.pid)
		if err != nil {
			return &taskError{e.s.pid, err}
		}
		if pc == *e.hit+1 {
			if err := e.writePC(e.s.pid, *e.hit); err != nil {
				return &taskError{e.s.pid, err}
			}
		}
	}
	e.breakpoints = make(map[target.Address]*breakpoint)
	e.hit = nil
	e.suspended = nil
	return nil
}
