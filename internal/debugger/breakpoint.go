package debugger

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/target"
)

type breakpointKind uint8

const (
	breakpointAbsolute breakpointKind = iota
	breakpointPIE
)

func (bp *breakpoint) expressionDescription() string {
	description := fmt.Sprintf("expression=%q", bp.expression)
	if bp.kind == breakpointPIE {
		description += " kind=pie"
	}
	return description
}

func (c *Controller) invalidateBreakpoints() {
	c.loaderBreakpoint = nil
	for _, bp := range c.breakpoints {
		clearBreakpointInstallation(bp)
	}
}

func clearBreakpointInstallation(bp *breakpoint) {
	bp.address, bp.space = 0, target.SpaceRef{}
	bp.installed, bp.attempted, bp.err = false, false, nil
}

func (c *Controller) addBreakpoint(ctx context.Context, expression string) error {
	return c.addBreakpointKind(ctx, expression, breakpointAbsolute)
}

func (c *Controller) addPIEBreakpoint(ctx context.Context, expression string) error {
	return c.addBreakpointKind(ctx, expression, breakpointPIE)
}

func (c *Controller) addBreakpointKind(ctx context.Context, expression string, kind breakpointKind) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; kill or detach for cleanup: %w", target.ErrBusy)
	}
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return fmt.Errorf("usage: break EXPR | pie OFFSET | list: %w", target.ErrInvalidArgument)
	}
	if c.nextBreakpoint == math.MaxUint64 {
		return target.ErrOverflow
	}
	if c.session != nil && c.session.State() != target.StateExited {
		if _, _, err := c.stopped(); err != nil {
			return err
		}
	}
	c.nextBreakpoint++
	bp := &breakpoint{id: c.nextBreakpoint, expression: expression, kind: kind, enabled: true}
	c.breakpoints = append(c.breakpoints, bp)
	if c.session == nil || c.session.State() == target.StateExited {
		return c.writef("Breakpoint %d pending %s\n", bp.id, bp.expressionDescription())
	}
	if err := c.installBreakpoint(ctx, bp); err != nil {
		if isPendingBreakpointError(err) {
			return c.writeBreakpointPending(bp)
		}
		return fmt.Errorf("breakpoint %d %s: %w", bp.id, bp.expressionDescription(), err)
	}
	return c.writef("Breakpoint %d installed address=%s %s\n", bp.id, c.renderer.Text(display.StyleCyan, fmt.Sprintf("%#x", bp.address)), bp.expressionDescription())
}

func (c *Controller) breakpointAddress(ctx context.Context, bp *breakpoint, snapshot target.Snapshot, thread target.ThreadInfo) (target.Address, error) {
	if bp.kind != breakpointAbsolute && bp.kind != breakpointPIE {
		return 0, fmt.Errorf("unknown breakpoint kind %d: %w", bp.kind, target.ErrInvalidArgument)
	}
	address, err := c.evaluate(ctx, bp.expression, snapshot, thread)
	if err != nil || bp.kind == breakpointAbsolute {
		return address, err
	}
	if remote, ok := c.session.(*qemuSession); ok {
		if remote.image == nil {
			return 0, target.ErrUnavailable
		}
		if uint64(address) > math.MaxUint64-remote.image.slide {
			return 0, target.ErrOverflow
		}
		return target.Address(remote.image.slide + uint64(address)), nil
	}
	image, err := c.image.load(ctx, snapshot, thread)
	if err != nil {
		return 0, fmt.Errorf("main executable load bias: %w", err)
	}
	if uint64(address) > math.MaxUint64-image.loadBias {
		return 0, fmt.Errorf("main executable load bias %#x plus offset %#x: %w", image.loadBias, address, target.ErrOverflow)
	}
	return target.Address(image.loadBias + uint64(address)), nil
}

func (c *Controller) installBreakpoint(ctx context.Context, bp *breakpoint) (err error) {
	defer func() { bp.err = err }()
	if !bp.enabled {
		return nil
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if bp.attempted || bp.installed {
		return fmt.Errorf("breakpoint %d has an existing native installation; disable it before reinstalling: %w", bp.id, target.ErrInvalidState)
	}
	bp.address, bp.space = 0, target.SpaceRef{}
	address, err := c.breakpointAddress(ctx, bp, snapshot, thread)
	if err != nil {
		if isPendingBreakpointError(err) {
			if _, syntaxErr := inspect.ParseSymbolExpression(bp.expression); syntaxErr != nil {
				return fmt.Errorf("deferred breakpoints require a single symbol; register-dependent and compound expressions must resolve at the current stop: %w", syntaxErr)
			}
		}
		return err
	}
	bp.address, bp.space = address, snapshot.Memory.Space
	for _, other := range c.breakpoints {
		if other != bp && other.space == bp.space && other.address == address && (other.installed || other.attempted) {
			return fmt.Errorf("address %#x duplicates breakpoint %d: %w", address, other.id, target.ErrInvalidArgument)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bp.attempted = true
	if c.loaderBreakpointAt(bp.space, address) {
		if !c.loaderBreakpoint.installed || c.loaderBreakpoint.err != nil {
			bp.attempted = false
			return fmt.Errorf("loader breakpoint ownership at %#x is unconfirmed: %w", address, target.ErrBusy)
		}
		bp.installed = true
		return nil
	}
	if err := c.session.AddBreakpoint(address); err != nil {
		_, snapshotErr := c.refresh()
		return errors.Join(err, snapshotErr)
	}
	bp.installed = true
	if _, err := c.refresh(); err != nil {
		return err
	}
	if !bp.installed || bp.space != snapshot.Memory.Space {
		return fmt.Errorf("breakpoint address space changed after installation: %w", target.ErrStale)
	}
	return nil
}

func (c *Controller) installBreakpoints(ctx context.Context) error {
	var failures []error
	for _, bp := range c.breakpoints {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if !bp.enabled {
			continue
		}
		if err := c.installBreakpoint(ctx, bp); err != nil {
			if isPendingBreakpointError(err) {
				if err := c.writeBreakpointPending(bp); err != nil {
					return errors.Join(append(failures, err)...)
				}
				continue
			}
			failures = append(failures, fmt.Errorf("breakpoint %d %s: %w", bp.id, bp.expressionDescription(), err))
			continue
		}
		if err := c.writef("Breakpoint %d installed address=%s %s\n", bp.id, c.renderer.Text(display.StyleCyan, fmt.Sprintf("%#x", bp.address)), bp.expressionDescription()); err != nil {
			return errors.Join(append(failures, err)...)
		}
	}
	return errors.Join(failures...)
}

func (c *Controller) listBreakpoints() error {
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; kill or detach for cleanup: %w", target.ErrBusy)
	}
	if c.session != nil {
		if _, err := c.refresh(); err != nil {
			return err
		}
	}
	if len(c.breakpoints) == 0 {
		return c.writef("No breakpoints.\n")
	}
	if err := c.writef("%s\n", c.renderer.Section("breakpoints", display.OutputWidth(c.out))); err != nil {
		return err
	}
	if err := c.writef("%s\n", c.renderer.Text(display.StyleHeading, fmt.Sprintf("%-4s %-13s %-3s %-18s %-12s %s", "Num", "Type", "Enb", "Address", "State", "What"))); err != nil {
		return err
	}
	for _, bp := range c.breakpoints {
		state := "pending"
		address := "<pending>"
		enabled := "n"
		if bp.enabled {
			enabled = "y"
		}
		if bp.installed {
			state = "installed"
			address = fmt.Sprintf("0x%0*x", c.abi().word*2, bp.address)
		}
		if bp.attempted {
			address = fmt.Sprintf("0x%0*x", c.abi().word*2, bp.address)
			if !bp.installed || bp.err != nil {
				state = "unconfirmed"
			}
		}
		if bp.err != nil && !bp.attempted && !isPendingBreakpointError(bp.err) {
			state = "error"
			if bp.installed {
				state = "error/installed"
			}
		}
		what := fmt.Sprintf("%q", bp.expression)
		if bp.kind == breakpointPIE {
			what += " (PIE offset)"
		}
		if bp.installed || bp.attempted {
			address = c.renderer.Text(display.StyleCyan, address)
		}
		if err := c.writef("%-4d %-13s %-3s %s %-12s %s\n", bp.id, "breakpoint", enabled, display.Pad(address, 18), state, what); err != nil {
			return err
		}
		if bp.err != nil {
			label := "Error"
			if isPendingBreakpointError(bp.err) {
				label = "Pending"
			}
			if err := c.writef("     %s: %q\n", label, bp.err.Error()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) deleteBreakpoint(id uint64) error {
	return c.deleteBreakpoints(context.Background(), strconv.FormatUint(id, 10))
}

func (c *Controller) selectedBreakpoints(rawArgs string, allowAll bool) ([]*breakpoint, error) {
	args := strings.Fields(rawArgs)
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one breakpoint ID is required: %w", target.ErrInvalidArgument)
	}
	if allowAll && len(args) == 1 && args[0] == "all" {
		return append([]*breakpoint(nil), c.breakpoints...), nil
	}
	selected := make([]*breakpoint, 0, len(args))
	seen := make(map[uint64]bool, len(args))
	for _, arg := range args {
		for _, b := range []byte(arg) {
			if b < '0' || b > '9' {
				return nil, fmt.Errorf("breakpoint ID %q must be a positive decimal integer: %w", arg, target.ErrInvalidArgument)
			}
		}
		id, err := strconv.ParseUint(arg, 10, 64)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid breakpoint ID %q: %w", arg, errors.Join(target.ErrInvalidArgument, err))
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate breakpoint ID %d: %w", id, target.ErrInvalidArgument)
		}
		seen[id] = true
		var found *breakpoint
		for _, bp := range c.breakpoints {
			if bp.id == id {
				found = bp
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("breakpoint %d: %w", id, target.ErrNotFound)
		}
		selected = append(selected, found)
	}
	return selected, nil
}

func breakpointBatchError(action string, completed, total int, id uint64, err error) error {
	err = fmt.Errorf("%s breakpoint %d: %w", action, id, err)
	if total > 1 {
		return &target.PartialError{Op: action + " breakpoints", Completed: completed, Total: total, Err: err}
	}
	return err
}

func (c *Controller) setBreakpointsEnabled(ctx context.Context, rawArgs string, enabled bool) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; kill or detach for cleanup: %w", target.ErrBusy)
	}
	selected, err := c.selectedBreakpoints(rawArgs, false)
	if err != nil {
		return err
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	completed := 0
	for _, bp := range selected {
		if err := ctx.Err(); err != nil {
			return breakpointBatchError(action, completed, len(selected), bp.id, err)
		}
		done, err := c.setBreakpointEnabled(ctx, bp, enabled)
		if done {
			completed++
		}
		if err != nil {
			return breakpointBatchError(action, completed, len(selected), bp.id, err)
		}
		if err := c.writef("Breakpoint %d enabled=%t\n", bp.id, bp.enabled); err != nil {
			return breakpointBatchError(action, completed, len(selected), bp.id, err)
		}
	}
	return c.releaseUnneededLoaderBreakpoint()
}

func (c *Controller) setBreakpointEnabled(ctx context.Context, bp *breakpoint, enabled bool) (bool, error) {
	if !enabled {
		done, err := c.uninstallBreakpoint(bp)
		if done {
			bp.enabled = false
		}
		return done, err
	}
	if c.session != nil {
		if _, err := c.refresh(); err != nil {
			return false, err
		}
	}
	if c.session == nil || c.session.State() == target.StateExited {
		bp.enabled, bp.err = true, nil
		return true, nil
	}
	if _, _, err := c.stopped(); err != nil {
		return false, err
	}
	if bp.enabled && !bp.attempted && !bp.installed && isPendingBreakpointError(bp.err) {
		return true, nil
	}
	if bp.installed && bp.err == nil {
		bp.enabled = true
		return true, nil
	}
	if bp.attempted {
		if _, err := c.uninstallBreakpoint(bp); err != nil {
			return false, err
		}
	}
	bp.enabled = true
	err := c.installBreakpoint(ctx, bp)
	if isPendingBreakpointError(err) {
		return true, c.writeBreakpointPending(bp)
	}
	return bp.installed, err
}

func (c *Controller) deleteBreakpoints(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; kill or detach for cleanup: %w", target.ErrBusy)
	}
	selected, err := c.selectedBreakpoints(rawArgs, true)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		if err := c.releaseUnneededLoaderBreakpoint(); err != nil {
			return err
		}
		return c.writef("No breakpoints.\n")
	}
	completed := 0
	for _, bp := range selected {
		if err := ctx.Err(); err != nil {
			return breakpointBatchError("delete", completed, len(selected), bp.id, err)
		}
		done, err := c.uninstallBreakpoint(bp)
		if done {
			for i, current := range c.breakpoints {
				if current == bp {
					c.breakpoints = append(c.breakpoints[:i], c.breakpoints[i+1:]...)
					break
				}
			}
			completed++
		}
		if err != nil {
			return breakpointBatchError("delete", completed, len(selected), bp.id, err)
		}
		if err := c.writef("Deleted breakpoint %d\n", bp.id); err != nil {
			return breakpointBatchError("delete", completed, len(selected), bp.id, err)
		}
	}
	return c.releaseUnneededLoaderBreakpoint()
}

func (c *Controller) uninstallBreakpoint(bp *breakpoint) (bool, error) {
	if c.session == nil {
		clearBreakpointInstallation(bp)
		return true, nil
	}
	if _, err := c.refresh(); err != nil {
		return false, err
	}
	if !bp.attempted {
		clearBreakpointInstallation(bp)
		return true, nil
	}
	snapshot, _, err := c.stopped()
	if err != nil {
		return false, err
	}
	if !bp.attempted || bp.space != snapshot.Memory.Space {
		clearBreakpointInstallation(bp)
		return true, nil
	}
	if c.loaderBreakpointAt(bp.space, bp.address) {
		if !c.loaderBreakpoint.installed || c.loaderBreakpoint.err != nil {
			return false, fmt.Errorf("loader breakpoint ownership at %#x is unconfirmed: %w", bp.address, target.ErrBusy)
		}
		clearBreakpointInstallation(bp)
		return true, nil
	}
	err = c.session.RemoveBreakpoint(bp.address)
	if err != nil && !(err == target.ErrNotFound && !bp.installed) {
		_, snapshotErr := c.refresh()
		err = errors.Join(err, snapshotErr)
		if bp.attempted {
			bp.err = err
		}
		return false, err
	}
	clearBreakpointInstallation(bp)
	_, err = c.refresh()
	if err != nil {
		bp.err = err
	}
	return true, err
}
