package native

import (
	"fastdbg2/target"
	"sort"
)

func (e *engine) installExecBoundary(t *thread, address target.Address) (*breakpoint, error) {
	if err := e.requireAllStopped(); err != nil {
		return nil, err
	}
	if t == nil || t.process == nil || t.process.space == nil || t.state != target.StateStopped || t.listening || t.exiting {
		return nil, target.ErrInvalidState
	}
	if t.hit != nil || t.suspended != nil || t.process.space.stepping != nil {
		return nil, target.ErrBusy
	}
	if _, err := e.breakpointThread(t.process.space); err != nil {
		return nil, err
	}
	if err := checkBreakpointAddress(t.process.profile, address); err != nil {
		return nil, err
	}
	pc, err := e.readPC(t.tid)
	if err != nil {
		return nil, err
	}
	if pc != address {
		return nil, target.ErrStale
	}
	space := t.process.space
	if bp := space.breakpoints[address]; bp != nil {
		if bp.boundary != nil {
			return nil, target.ErrBusy
		}
		return nil, nil
	}
	value, err := e.readByte(t.tid, address)
	if err != nil {
		return nil, err
	}
	if value == 0xcc {
		return nil, nil
	}
	return e.insertBreakpoint(space, address, value, t)
}

func (e *engine) consumeExecBoundary(t *thread, bp *breakpoint) error {
	if !e.allStopped() {
		return target.ErrRunning
	}
	if t == nil || t.state != target.StateStopped || t.listening || t.exiting || bp == nil || bp.boundary != t || t.hit == nil || t.hit.bp != bp {
		return target.ErrStale
	}
	if err := validateBreakpointHit(t); err != nil {
		return err
	}
	return e.removeBreakpoint(bp)
}

func (e *engine) cancelExecBoundary(bp *breakpoint) error {
	if !e.allStopped() {
		return target.ErrRunning
	}
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	if bp.boundary == nil {
		return target.ErrInvalidArgument
	}
	if !e.breakpointSpaceAlive(bp.space) {
		for _, t := range e.threads {
			if t.hit != nil && t.hit.bp == bp {
				t.hit = nil
			}
			if t.suspended == bp {
				t.suspended = nil
				if bp.space.stepping == t {
					bp.space.stepping = nil
				}
			}
		}
		delete(bp.space.breakpoints, bp.addr)
		return nil
	}
	return e.removeBreakpoint(bp)
}

func (e *engine) cancelExecBoundaries() error {
	if !e.allStopped() {
		return target.ErrRunning
	}
	seen := make(map[*addressSpace]bool)
	var spaces []*addressSpace
	for _, p := range e.processes {
		if p.space != nil && !seen[p.space] {
			seen[p.space] = true
			spaces = append(spaces, p.space)
		}
	}
	for _, t := range e.threads {
		if t.process != nil && t.process.space != nil && !seen[t.process.space] {
			seen[t.process.space] = true
			spaces = append(spaces, t.process.space)
		}
	}
	sort.Slice(spaces, func(i, j int) bool { return spaces[i].ref.ID < spaces[j].ref.ID })
	for _, space := range spaces {
		var addresses []target.Address
		for addr, bp := range space.breakpoints {
			if bp.boundary != nil {
				addresses = append(addresses, addr)
			}
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
		for _, addr := range addresses {
			if err := e.cancelExecBoundary(space.breakpoints[addr]); err != nil {
				return err
			}
		}
	}
	return nil
}
