package debugger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"syscall"

	"fastdbg2/target"
)

type loaderBreakpointState struct {
	space     target.SpaceRef
	address   target.Address
	installed bool
	attempted bool
	err       error
	arrivals  map[target.ThreadRef]target.ThreadToken
	before    *target.Snapshot
}

func isPendingBreakpointError(err error) bool {
	return isSymbolPending(err) && onlyLoaderPublicationPending(err)
}

func (c *Controller) writeBreakpointPending(bp *breakpoint) error {
	return c.writef("Breakpoint %d pending %s: %q\n", bp.id, bp.expressionDescription(), bp.err.Error())
}

func (c *Controller) hasPendingBreakpoints() bool {
	for _, bp := range c.breakpoints {
		if bp.enabled && !bp.attempted && !bp.installed && isPendingBreakpointError(bp.err) {
			return true
		}
	}
	return false
}

func (c *Controller) loaderBreakpointAt(space target.SpaceRef, address target.Address) bool {
	bp := c.loaderBreakpoint
	return bp != nil && bp.space == space && bp.address == address && bp.attempted
}

func (c *Controller) userBreakpointAt(space target.SpaceRef, address target.Address) *breakpoint {
	for _, bp := range c.breakpoints {
		if bp.space == space && bp.address == address && bp.attempted {
			return bp
		}
	}
	return nil
}

func (c *Controller) retryUninstalledBreakpoints(ctx context.Context, pending bool) error {
	var failures []error
	for _, bp := range c.breakpoints {
		if !bp.enabled || bp.installed || bp.attempted || (bp.err != nil && !pending) || pending && !isPendingBreakpointError(bp.err) {
			continue
		}
		if err := contextReady(ctx); err != nil {
			return errors.Join(append(failures, err)...)
		}
		previousError := bp.err
		err := c.installBreakpoint(ctx, bp)
		if pending && ctx.Err() != nil && !bp.attempted {
			bp.err = previousError
			return errors.Join(append(failures, err, ctx.Err())...)
		}
		if isPendingBreakpointError(err) {
			if !pending {
				if err := c.writeBreakpointPending(bp); err != nil {
					return errors.Join(append(failures, err)...)
				}
			}
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("breakpoint %d %s: %w", bp.id, bp.expressionDescription(), err))
			continue
		}
		if err := c.writef("Breakpoint %d installed address=%#x %s\n", bp.id, bp.address, bp.expressionDescription()); err != nil {
			return errors.Join(append(failures, err)...)
		}
	}
	return errors.Join(failures...)
}

func (c *Controller) prepareLoaderBreakpoints(ctx context.Context) error {
	if len(c.breakpoints) != 0 || c.loaderBreakpoint != nil {
		if _, _, err := c.stopped(); err != nil {
			return err
		}
	}
	if _, err := c.processLoaderArrivals(ctx); err != nil {
		return err
	}
	if err := c.retryUninstalledBreakpoints(ctx, false); err != nil {
		return err
	}
	if !c.hasPendingBreakpoints() {
		return c.releaseUnneededLoaderBreakpoint()
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	info, err := c.loaderRendezvous(ctx, snapshot, thread)
	if err != nil {
		return fmt.Errorf("pending breakpoints require a proven loader rendezvous: %w", err)
	}
	if c.loaderBreakpoint != nil && (c.loaderBreakpoint.space != info.Space || c.loaderBreakpoint.address != info.Hook) {
		return fmt.Errorf("loader rendezvous differs from the retained internal breakpoint: %w", target.ErrStale)
	}
	return c.armLoaderBreakpoint(info)
}

func (c *Controller) armLoaderBreakpoint(info loaderRendezvousInfo) error {
	snapshot, _, err := c.stopped()
	if err != nil {
		return err
	}
	if info.Space != snapshot.Memory.Space || info.Hook == 0 {
		return fmt.Errorf("loader rendezvous does not match the stopped address space: %w", target.ErrStale)
	}
	if previous := c.loaderBreakpoint; previous != nil {
		if previous.space != info.Space || previous.address != info.Hook {
			return fmt.Errorf("loader breakpoint address changed: %w", target.ErrStale)
		}
		if previous.installed && previous.err == nil {
			return nil
		}
		if err := c.removeLoaderBreakpoint(); err != nil {
			return err
		}
	}
	state := &loaderBreakpointState{space: info.Space, address: info.Hook}
	if user := c.userBreakpointAt(info.Space, info.Hook); user != nil {
		if !user.installed || user.err != nil {
			return fmt.Errorf("user breakpoint %d owns an unconfirmed loader address: %w", user.id, target.ErrBusy)
		}
		state.attempted, state.installed = true, true
		c.loaderBreakpoint = state
		return nil
	}
	state.attempted = true
	c.loaderBreakpoint = state
	err = c.session.AddBreakpoint(info.Hook)
	if err == nil {
		state.installed = true
	}
	_, snapshotErr := c.refresh()
	state.err = errors.Join(err, snapshotErr)
	if state.err != nil {
		return fmt.Errorf("install internal loader breakpoint at %#x: %w", info.Hook, state.err)
	}
	if c.loaderBreakpoint != state {
		return fmt.Errorf("loader breakpoint address space changed during installation: %w", target.ErrStale)
	}
	return nil
}

func (c *Controller) releaseUnneededLoaderBreakpoint() error {
	if c.hasPendingBreakpoints() {
		return nil
	}
	return c.removeLoaderBreakpoint()
}

func (c *Controller) removeLoaderBreakpoint() error {
	state := c.loaderBreakpoint
	if state == nil {
		return nil
	}
	if c.session == nil {
		c.loaderBreakpoint = nil
		return nil
	}
	snapshot, err := c.refresh()
	if err != nil {
		return err
	}
	if c.loaderBreakpoint != state || state.space != snapshot.Memory.Space {
		return nil
	}
	if user := c.userBreakpointAt(state.space, state.address); user != nil {
		if !user.installed || user.err != nil {
			return fmt.Errorf("user breakpoint %d has unconfirmed shared loader ownership: %w", user.id, target.ErrBusy)
		}
		c.loaderBreakpoint = nil
		return nil
	}
	if _, _, err := c.stopped(); err != nil {
		return err
	}
	err = c.session.RemoveBreakpoint(state.address)
	if err != nil && !(err == target.ErrNotFound && !state.installed) {
		_, snapshotErr := c.refresh()
		state.err = errors.Join(err, snapshotErr)
		return fmt.Errorf("remove internal loader breakpoint at %#x: %w", state.address, state.err)
	}
	c.loaderBreakpoint = nil
	_, err = c.refresh()
	return err
}

func (c *Controller) loaderBreakpointHit(thread target.ThreadInfo, address target.Address) (bool, error) {
	stop := thread.Stop
	if stop.Reason != target.StopBreakpoint || stop.Breakpoint == nil || *stop.Breakpoint != address || stop.RawPC == nil ||
		len(stop.Watchpoints) != 0 || len(stop.HardwareBreakpoints) != 0 || !loaderDebuggerSignal(stop.Signal) {
		return false, nil
	}
	location, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil {
		return false, err
	}
	return location.Breakpoint != nil && *location.Breakpoint == address && location.InstructionPC == address && location.RawPC == *stop.RawPC, nil
}

func (c *Controller) ownsLoaderStop(result target.RunResult) (bool, error) {
	state := c.loaderBreakpoint
	if state == nil || !state.installed || state.err != nil || result.Stop.RawPC == nil || !loaderDebuggerSignal(result.Stop.Signal) ||
		len(result.Stop.Watchpoints) != 0 || len(result.Stop.HardwareBreakpoints) != 0 {
		return false, nil
	}
	stepped := result.Stop.Reason == target.StopStep && result.Stop.StepCompleted
	if !stepped && (result.Stop.Reason != target.StopBreakpoint || result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != state.address) {
		return false, nil
	}
	snapshot, err := c.refresh()
	if err != nil {
		return false, err
	}
	if c.loaderBreakpoint != state || snapshot.State != target.StateStopped || snapshot.Memory.Space != state.space {
		return false, nil
	}
	for _, thread := range snapshot.Threads {
		if thread.Ref == result.Thread {
			if !primaryInspectableThread(snapshot, thread) || thread.GroupStopped || thread.Token != result.Token ||
				thread.Stop.RawPC == nil || *thread.Stop.RawPC != *result.Stop.RawPC {
				return false, nil
			}
			if stepped {
				if thread.Stop.Reason != target.StopStep || !thread.Stop.StepCompleted || len(thread.Stop.Watchpoints) != 0 || len(thread.Stop.HardwareBreakpoints) != 0 || !loaderDebuggerSignal(thread.Stop.Signal) {
					return false, nil
				}
				location, err := c.session.ReadCodeLocation(thread.Token)
				if err != nil {
					return false, err
				}
				if location.RawPC != *result.Stop.RawPC || location.InstructionPC != state.address || location.RawPC != state.address || location.Breakpoint != nil {
					return false, nil
				}
				var logical [1]byte
				n, err := c.session.ReadCodeMemory(snapshot.Memory, state.address, logical[:])
				if err != nil || n != len(logical) {
					return false, errors.Join(err, io.ErrUnexpectedEOF)
				}
				var raw [1]byte
				n, err = c.session.ReadSpaceMemory(snapshot.Memory, state.address, raw[:])
				if err != nil || n != len(raw) {
					return false, errors.Join(err, io.ErrUnexpectedEOF)
				}
				if raw[0] != 0xcc || logical[0] == 0xcc {
					return false, fmt.Errorf("stepped loader entry lacks the confirmed native breakpoint overlay: %w", target.ErrStale)
				}
				return true, nil
			}
			return c.loaderBreakpointHit(thread, state.address)
		}
	}
	return false, nil
}

func (c *Controller) loaderStopMatches(before target.Snapshot, result target.RunResult) (bool, error) {
	state := c.loaderBreakpoint
	if state == nil || !state.installed || state.err != nil || result.Stop.Reason != target.StopBreakpoint ||
		result.Stop.Breakpoint == nil || *result.Stop.Breakpoint != state.address || result.Stop.RawPC == nil ||
		result.Stop.StepCompleted || len(result.Stop.Watchpoints) != 0 || len(result.Stop.HardwareBreakpoints) != 0 || !loaderDebuggerSignal(result.Stop.Signal) {
		return false, nil
	}
	snapshot, err := c.refresh()
	if err != nil {
		return false, err
	}
	if snapshot.State != target.StateStopped || snapshot.Process != before.Process || snapshot.Memory.Space != state.space || c.loaderBreakpoint != state {
		return false, nil
	}
	previous := make(map[target.ThreadRef]target.ThreadInfo, len(before.Threads))
	for _, thread := range before.Threads {
		previous[thread.Ref] = thread
	}
	seen := make(map[target.ThreadRef]bool, len(snapshot.Threads))
	found := false
	for _, thread := range snapshot.Threads {
		seen[thread.Ref] = true
		old, existed := previous[thread.Ref]
		if !existed {
			return false, nil
		}
		if thread.Ref != result.Thread && old.Token.Stop == thread.Token.Stop {
			continue
		}
		if !primaryInspectableThread(snapshot, thread) || thread.GroupStopped {
			return false, nil
		}
		if thread.Stop.StepCompleted {
			return false, nil
		}
		if thread.Ref == result.Thread {
			if result.Token != thread.Token || thread.Stop.RawPC == nil || *result.Stop.RawPC != *thread.Stop.RawPC {
				return false, nil
			}
			found = true
		} else if thread.Stop.Reason == target.StopInterrupt && !thread.Stop.StepCompleted && len(thread.Stop.Watchpoints) == 0 && len(thread.Stop.HardwareBreakpoints) == 0 && loaderDebuggerSignal(thread.Stop.Signal) {
			continue
		}
		matches, err := c.loaderBreakpointHit(thread, state.address)
		if err != nil || !matches {
			return false, err
		}
	}
	for _, thread := range before.Threads {
		if !seen[thread.Ref] {
			return false, nil
		}
	}
	return found, nil
}

func loaderDebuggerSignal(signal target.Signal) bool {
	return signal.Domain == target.SignalNone && signal.Number == 0 || signal.Domain == target.SignalLinux && signal.Number == uint32(syscall.SIGTRAP)
}

func (c *Controller) beginLoaderOperation(snapshot target.Snapshot) {
	if c.loaderBreakpoint == nil {
		return
	}
	snapshot.Threads = append([]target.ThreadInfo(nil), snapshot.Threads...)
	c.loaderBreakpoint.before = &snapshot
}

func (c *Controller) captureLoaderArrivals() error {
	state := c.loaderBreakpoint
	if state == nil || state.before == nil {
		return nil
	}
	snapshot, err := c.refresh()
	if err != nil {
		return err
	}
	if c.loaderBreakpoint != state || snapshot.State != target.StateStopped || snapshot.Memory.Space != state.space {
		return nil
	}
	previous := make(map[target.ThreadRef]uint64, len(state.before.Threads))
	for _, thread := range state.before.Threads {
		previous[thread.Ref] = thread.Token.Stop
	}
	state.before = nil
	for _, thread := range snapshot.Threads {
		if previous[thread.Ref] == thread.Token.Stop || !primaryInspectableThread(snapshot, thread) || thread.GroupStopped || !loaderDebuggerSignal(thread.Stop.Signal) || len(thread.Stop.Watchpoints) != 0 || len(thread.Stop.HardwareBreakpoints) != 0 {
			continue
		}
		stop := thread.Stop
		if stop.RawPC == nil {
			continue
		}
		breakpoint := stop.Reason == target.StopBreakpoint && stop.Breakpoint != nil && *stop.Breakpoint == state.address
		step := stop.Reason == target.StopStep && stop.StepCompleted && *stop.RawPC == state.address
		if !breakpoint && !step {
			continue
		}
		if state.arrivals == nil {
			state.arrivals = make(map[target.ThreadRef]target.ThreadToken)
		}
		state.arrivals[thread.Ref] = thread.Token
	}
	return nil
}

func (c *Controller) processLoaderArrivals(ctx context.Context) (bool, error) {
	state := c.loaderBreakpoint
	if state == nil || len(state.arrivals) == 0 {
		return false, nil
	}
	if err := contextReady(ctx); err != nil {
		return false, err
	}
	snapshot, err := c.refresh()
	if err != nil {
		return false, err
	}
	if c.loaderBreakpoint != state || snapshot.Memory.Space != state.space {
		return false, fmt.Errorf("loader arrival address space changed: %w", target.ErrStale)
	}
	var selected target.ThreadInfo
	for ref, token := range state.arrivals {
		found := false
		for _, thread := range snapshot.Threads {
			if thread.Ref != ref {
				continue
			}
			found = true
			if thread.Token != token {
				return false, fmt.Errorf("loader arrival thread token changed: %w", target.ErrStale)
			}
			owned, err := c.ownsLoaderStop(target.RunResult{Thread: ref, Token: token, Stop: thread.Stop})
			if err != nil || !owned {
				return false, errors.Join(fmt.Errorf("loader arrival cannot be confirmed: %w", target.ErrStale), err)
			}
			if selected.Ref == (target.ThreadRef{}) || thread.Ref.ID < selected.Ref.ID {
				selected = thread
			}
		}
		if !found {
			return false, fmt.Errorf("loader arrival thread disappeared: %w", target.ErrStale)
		}
	}
	info, err := c.loaderRendezvous(ctx, snapshot, selected)
	if err != nil {
		return false, err
	}
	if !info.Published || info.Space != state.space || info.Hook != state.address {
		return false, fmt.Errorf("loader hook hit did not confirm the published rendezvous: %w", target.ErrStale)
	}
	previousSelection := c.selected
	c.selected = selected.Ref
	defer func() { c.selected = previousSelection }()
	var resolveErr error
	if info.Consistent {
		resolveErr = c.retryUninstalledBreakpoints(ctx, true)
		if resolveErr == nil && c.hasPendingBreakpoints() {
			resolveErr = fmt.Errorf("symbols remain pending at RT_CONSISTENT: %w", target.ErrUnavailable)
		}
	}
	if !info.Consistent || !c.hasPendingBreakpoints() {
		state.arrivals = nil
	}
	cleanupErr := c.releaseUnneededLoaderBreakpoint()
	if resolveErr != nil || cleanupErr != nil {
		return false, errors.Join(resolveErr, cleanupErr)
	}
	return true, nil
}

func (c *Controller) handleLoaderStop(ctx context.Context, before target.Snapshot, result target.RunResult) (bool, error) {
	state := c.loaderBreakpoint
	if state == nil {
		return false, nil
	}
	consumable, err := c.loaderStopMatches(before, result)
	if err != nil {
		return false, err
	}
	processed, err := c.processLoaderArrivals(ctx)
	if err != nil {
		return false, err
	}
	visible := c.userBreakpointAt(state.space, state.address) != nil
	return processed && consumable && !visible, nil
}
