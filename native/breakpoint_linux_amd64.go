package native

import (
	"errors"
	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
	"fmt"
	"sort"
)

type breakpoint struct {
	addr       target.Address
	original   byte
	armed      bool
	space      *addressSpace
	spaceRef   target.SpaceRef
	generation uint64
	pending    *breakpointWrite
	boundary   *thread
}

type breakpointWrite struct {
	before byte
	after  byte
}

type breakpointHit struct {
	bp         *breakpoint
	generation uint64
	rawPC      target.Address
	rewound    bool
	rewinding  bool
}

type taskError struct {
	pid int
	err error
}

func (e *taskError) Error() string { return fmt.Sprintf("task %d: %v", e.pid, e.err) }

func (e *taskError) Unwrap() error { return e.err }

func (s *Session) AddBreakpoint(addr target.Address) error {
	return command(s, func(e *engine) error {
		token, err := e.primaryMemory()
		if err != nil {
			return err
		}
		space, t, err := e.requireMemory(token)
		if err != nil {
			return err
		}
		if err := checkBreakpointAddress(t.process.profile, addr); err != nil {
			return err
		}
		if _, ok := space.breakpoints[addr]; ok {
			return fmt.Errorf("breakpoint already exists: %w", target.ErrInvalidState)
		}
		value, err := e.readByte(t.tid, addr)
		if err != nil {
			return err
		}
		if value == 0xcc {
			return fmt.Errorf("address already contains INT3: %w", target.ErrUnsupported)
		}
		_, err = e.insertBreakpoint(space, addr, value, nil)
		return err
	})
}

func (e *engine) insertBreakpoint(space *addressSpace, addr target.Address, original byte, boundary *thread) (*breakpoint, error) {
	if space.nextBreakpoint == ^uint64(0) {
		return nil, target.ErrOverflow
	}
	space.nextBreakpoint++
	bp := &breakpoint{
		addr: addr, original: original, space: space, spaceRef: space.ref,
		generation: space.nextBreakpoint, boundary: boundary,
	}
	if space.breakpoints == nil {
		space.breakpoints = make(map[target.Address]*breakpoint)
	}
	space.breakpoints[addr] = bp
	if err := e.arm(bp); err != nil {
		restoreErr := e.disarm(bp)
		if restoreErr == nil {
			delete(space.breakpoints, addr)
			return nil, err
		}
		e.unsupported = errors.Join(e.unsupported, err, restoreErr)
		return bp, errors.Join(err, restoreErr)
	}
	return bp, nil
}

func (s *Session) RemoveBreakpoint(addr target.Address) error {
	return command(s, func(e *engine) error {
		token, err := e.primaryMemory()
		if err != nil {
			return err
		}
		space, t, err := e.requireMemory(token)
		if err != nil {
			return err
		}
		if err := checkBreakpointAddress(t.process.profile, addr); err != nil {
			return err
		}
		bp, ok := space.breakpoints[addr]
		if !ok {
			return target.ErrNotFound
		}
		return e.removeBreakpoint(bp)
	})
}

func (e *engine) checkBreakpointAddress(addr target.Address) error {
	if e.primary == nil {
		return target.ErrUnknown
	}
	return checkBreakpointAddress(e.primary.profile, addr)
}

func checkBreakpointAddress(profile *arch.Descriptor, addr target.Address) error {
	if profile == nil {
		return target.ErrUnknown
	}
	max, err := profile.MaxAddress()
	if err != nil {
		return err
	}
	if addr >= max {
		return fmt.Errorf("breakpoint successor exceeds address width: %w", target.ErrOverflow)
	}
	return nil
}

func (e *engine) breakpointThread(space *addressSpace) (*thread, error) {
	if space == nil || space.unknown {
		return nil, target.ErrUnavailable
	}
	if !e.spaceStopped(space) {
		return nil, target.ErrRunning
	}
	var selected *thread
	for _, t := range e.threads {
		if t.process == nil || t.process.space != space || t.state != target.StateStopped || t.exiting || t.listening {
			continue
		}
		if selected == nil || t.tid < selected.tid {
			selected = t
		}
	}
	if selected == nil {
		return nil, target.ErrExited
	}
	return selected, nil
}

func validateBreakpoint(bp *breakpoint) error {
	if bp == nil || bp.space == nil || bp.spaceRef != bp.space.ref || bp.space.breakpoints[bp.addr] != bp {
		return target.ErrStale
	}
	return nil
}

func validateBreakpointHit(t *thread) error {
	if t == nil || t.hit == nil || t.process == nil {
		return target.ErrInvalidState
	}
	hit := t.hit
	if err := validateBreakpoint(hit.bp); err != nil {
		return err
	}
	if t.process.space != hit.bp.space || hit.generation != hit.bp.generation || hit.rawPC != hit.bp.addr+1 {
		return target.ErrStale
	}
	return nil
}

func (e *engine) arm(bp *breakpoint) error { return e.setBreakpointByte(bp, true) }

func (e *engine) disarm(bp *breakpoint) error { return e.setBreakpointByte(bp, false) }

func (e *engine) setBreakpointByte(bp *breakpoint, armed bool) error {
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	t, err := e.breakpointThread(bp.space)
	if err != nil {
		return err
	}
	value, err := e.readByte(t.tid, bp.addr)
	if err != nil {
		return &taskError{t.tid, err}
	}
	if bp.pending != nil {
		if err := bp.confirmWrite(value); err != nil {
			return err
		}
	}
	expected := bp.original
	if bp.armed {
		expected = 0xcc
	}
	if value != expected {
		return fmt.Errorf("breakpoint byte changed at %#x: %w", bp.addr, target.ErrStale)
	}
	if bp.armed == armed {
		return nil
	}
	next := bp.original
	if armed {
		next = 0xcc
	}
	bp.pending = &breakpointWrite{before: expected, after: next}
	writeErr := e.writeByte(t.tid, bp.addr, next)
	value, readErr := e.readByte(t.tid, bp.addr)
	if readErr != nil {
		return &taskError{t.tid, errors.Join(writeErr, readErr)}
	}
	confirmErr := bp.confirmWrite(value)
	if confirmErr == nil && bp.armed != armed && writeErr == nil {
		confirmErr = fmt.Errorf("breakpoint write did not change %#x: %w", bp.addr, target.ErrPartial)
	}
	if err := errors.Join(writeErr, confirmErr); err != nil {
		return &taskError{t.tid, err}
	}
	return nil
}

func (bp *breakpoint) confirmWrite(value byte) error {
	if bp.pending == nil {
		return target.ErrInvalidState
	}
	if value != bp.pending.before && value != bp.pending.after {
		return fmt.Errorf("breakpoint write at %#x cannot be confirmed: %w", bp.addr, target.ErrStale)
	}
	bp.armed = value == 0xcc
	bp.pending = nil
	return nil
}

func (e *engine) recordBreakpointHit(t *thread, addr, rawPC target.Address) error {
	if t == nil || t.process == nil || t.process.space == nil || t.state != target.StateStopped {
		return target.ErrInvalidState
	}
	bp := t.process.space.breakpoints[addr]
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	if !bp.armed || bp.pending != nil || rawPC != addr+1 {
		return target.ErrStale
	}
	value, err := e.readByte(t.tid, addr)
	if err != nil {
		return err
	}
	if value != 0xcc {
		return fmt.Errorf("breakpoint byte changed at %#x: %w", addr, target.ErrStale)
	}
	t.hit = &breakpointHit{bp: bp, generation: bp.generation, rawPC: rawPC}
	t.pendingSignal = 0
	return nil
}

func (e *engine) rewindBreakpointHit(t *thread) error {
	if err := validateBreakpointHit(t); err != nil {
		return err
	}
	hit := t.hit
	pc, err := e.readPC(t.tid)
	if err != nil {
		return &taskError{t.tid, err}
	}
	if hit.rewinding {
		if pc != hit.rawPC && pc != hit.bp.addr {
			return fmt.Errorf("thread %d breakpoint PC write cannot be confirmed: %w", t.tid, target.ErrStale)
		}
		hit.rewound, hit.rewinding = pc == hit.bp.addr, false
	}
	expected := hit.rawPC
	if hit.rewound {
		expected = hit.bp.addr
	}
	if pc != expected {
		return fmt.Errorf("thread %d breakpoint PC changed: %w", t.tid, target.ErrStale)
	}
	if !hit.rewound {
		hit.rewinding = true
		if err := e.writePC(t.tid, hit.bp.addr); err != nil {
			t.hit = hit
			return &taskError{t.tid, err}
		}
		confirmed, err := e.readPC(t.tid)
		if err != nil {
			return &taskError{t.tid, err}
		}
		if confirmed != hit.bp.addr {
			return fmt.Errorf("thread %d breakpoint PC write cannot be confirmed: %w", t.tid, target.ErrStale)
		}
		hit.rewound, hit.rewinding = true, false
	}
	return nil
}

func (e *engine) breakpointThreads(bp *breakpoint) []*thread {
	var threads []*thread
	for _, t := range e.threads {
		if t.process != nil && t.process.space == bp.space && t.state == target.StateStopped && !t.exiting {
			threads = append(threads, t)
		}
	}
	sort.Slice(threads, func(i, j int) bool { return threads[i].tid < threads[j].tid })
	return threads
}

func (e *engine) removeBreakpoint(bp *breakpoint) error {
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	threads := e.breakpointThreads(bp)
	for _, t := range threads {
		if t.hit != nil && t.hit.bp == bp {
			if err := validateBreakpointHit(t); err != nil {
				return err
			}
		}
	}
	if err := e.disarm(bp); err != nil {
		return e.restoreArmedBreakpoint(bp, err)
	}
	for _, t := range threads {
		if t.hit != nil && t.hit.bp == bp {
			if err := e.rewindBreakpointHit(t); err != nil {
				return e.restoreArmedBreakpoint(bp, err)
			}
		}
	}
	for _, t := range threads {
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

func (e *engine) restoreArmedBreakpoint(bp *breakpoint, cause error) error {
	err := e.arm(bp)
	if err != nil {
		e.unsupported = errors.Join(e.unsupported, cause, err)
	}
	return errors.Join(cause, err)
}

func (e *engine) prepareBreakpointStep(t *thread) (*breakpoint, error) {
	if t == nil || t.process == nil || t.process.space == nil || t.state != target.StateStopped {
		return nil, target.ErrInvalidState
	}
	if !e.allStopped() {
		return nil, target.ErrRunning
	}
	space := t.process.space
	if space.stepping != nil && space.stepping != t {
		return nil, target.ErrBusy
	}
	if bp := t.suspended; bp != nil {
		if err := validateBreakpoint(bp); err != nil || bp.space != space {
			return nil, errors.Join(err, target.ErrStale)
		}
		pc, err := e.readPC(t.tid)
		if err != nil {
			return nil, err
		}
		if pc != bp.addr {
			return nil, fmt.Errorf("interrupted breakpoint step completion is not confirmed; remove the breakpoint before resuming: %w", target.ErrUnsupported)
		}
		if err := e.disarm(bp); err != nil {
			return nil, err
		}
		space.stepping = t
		return bp, nil
	}
	if t.hit == nil {
		return nil, nil
	}
	if err := validateBreakpointHit(t); err != nil {
		return nil, err
	}
	bp := t.hit.bp
	if err := e.disarm(bp); err != nil {
		return nil, e.restoreArmedBreakpoint(bp, err)
	}
	if err := e.rewindBreakpointHit(t); err != nil {
		return nil, e.restoreArmedBreakpoint(bp, err)
	}
	t.hit, t.suspended = nil, bp
	space.stepping = t
	return bp, nil
}

func (e *engine) finishBreakpointStep(t *thread, bp *breakpoint, completed bool) error {
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	if t == nil || t.process == nil || t.process.space != bp.space || bp.space.stepping != t || t.suspended != bp {
		return target.ErrStale
	}
	if !completed {
		t.suspended = bp
		return nil
	}
	if err := e.arm(bp); err != nil {
		return err
	}
	t.suspended = nil
	bp.space.stepping = nil
	return nil
}

func (e *engine) abandonBreakpointStep(t *thread) error {
	if t == nil {
		return target.ErrInvalidArgument
	}
	t.hit = nil
	bp := t.suspended
	if bp == nil {
		return nil
	}
	if err := validateBreakpoint(bp); err != nil {
		return err
	}
	if e.breakpointSpaceAlive(bp.space) {
		if err := e.arm(bp); err != nil {
			return err
		}
	} else {
		bp.space.breakpoints = make(map[target.Address]*breakpoint)
	}
	t.suspended = nil
	if bp.space.stepping == t {
		bp.space.stepping = nil
	}
	return nil
}

func (e *engine) breakpointSpaceAlive(space *addressSpace) bool {
	for _, t := range e.threads {
		if t.process != nil && t.process.space == space && t.state != target.StateExited && t.state != target.StateDetached && !t.exiting {
			return true
		}
	}
	return false
}

func (e *engine) copyBreakpoints(from, to *addressSpace) error {
	if from == nil || to == nil || from == to || from.unknown || to.unknown || len(to.breakpoints) != 0 {
		return target.ErrInvalidState
	}
	for _, bp := range from.breakpoints {
		if err := validateBreakpoint(bp); err != nil {
			return err
		}
		if bp.pending != nil {
			return target.ErrStale
		}
	}
	copy := make(map[target.Address]*breakpoint, len(from.breakpoints))
	for addr, bp := range from.breakpoints {
		copy[addr] = &breakpoint{
			addr: addr, original: bp.original, armed: bp.armed,
			space: to, spaceRef: to.ref, generation: bp.generation,
		}
	}
	to.breakpoints, to.nextBreakpoint = copy, from.nextBreakpoint
	return nil
}

func (e *engine) restoreBreakpoints() error {
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
		if t.suspended != nil && !seen[t.suspended.space] {
			seen[t.suspended.space] = true
			spaces = append(spaces, t.suspended.space)
		}
	}
	sort.Slice(spaces, func(i, j int) bool { return spaces[i].ref.ID < spaces[j].ref.ID })
	for _, space := range spaces {
		if !e.breakpointSpaceAlive(space) {
			space.breakpoints = make(map[target.Address]*breakpoint)
			space.stepping = nil
			for _, t := range e.threads {
				if t.hit != nil && t.hit.bp.space == space {
					t.hit = nil
				}
				if t.suspended != nil && t.suspended.space == space {
					t.suspended = nil
				}
			}
			continue
		}
		var addresses []target.Address
		for addr := range space.breakpoints {
			addresses = append(addresses, addr)
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
		for _, addr := range addresses {
			if err := e.disarm(space.breakpoints[addr]); err != nil {
				return err
			}
		}
		for _, addr := range addresses {
			bp := space.breakpoints[addr]
			for _, t := range e.breakpointThreads(bp) {
				if t.hit != nil && t.hit.bp == bp {
					if err := e.rewindBreakpointHit(t); err != nil {
						return err
					}
				}
			}
		}
		for _, t := range e.threads {
			if t.process != nil && t.process.space == space {
				t.hit, t.suspended = nil, nil
			}
		}
		space.breakpoints = make(map[target.Address]*breakpoint)
		space.stepping = nil
	}
	return nil
}
