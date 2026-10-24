package debugger

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

type watchpointSession interface {
	SetWatchpoint(target.ThreadToken, target.WatchpointRequest) (target.WatchpointResult, error)
	ClearWatchpoint(target.ThreadToken, target.WatchpointRef) (target.ThreadToken, error)
}

type watchRecord struct {
	thread    target.ThreadRef
	space     target.SpaceRef
	request   target.WatchpointRequest
	ref       target.WatchpointRef
	installed bool
	attempted bool
	expired   bool
	err       error
}

func (c *Controller) reconcileWatchpoints(snapshot target.Snapshot) {
	for _, point := range c.watchpoints {
		if point.expired {
			continue
		}
		if c.session == nil || snapshot.State == target.StateExited || snapshot.State == target.StateDetached || snapshot.State == target.StateClosed {
			point.expired = true
			continue
		}
		if snapshot.Memory.Space != (target.SpaceRef{}) && point.space != snapshot.Memory.Space {
			point.expired = true
			continue
		}
		if snapshot.State != target.StateStopped || snapshot.Memory.Space == (target.SpaceRef{}) {
			continue
		}
		found := false
		for _, thread := range snapshot.Threads {
			if thread.Ref == point.thread && thread.Process == snapshot.Process && thread.State != target.StateExited && thread.State != target.StateDetached && thread.State != target.StateClosed {
				found = true
				break
			}
		}
		point.expired = !found
	}
}

func watchpointArguments(args []string) (string, target.WatchpointRequest, error) {
	request := target.WatchpointRequest{Size: 1, Access: target.WatchReadWrite}
	var expression string
	seen := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--size" || arg == "--access" {
			if seen[arg] || index+1 == len(args) {
				return "", target.WatchpointRequest{}, fmt.Errorf("wp option %s requires one value and may appear once: %w", arg, target.ErrInvalidArgument)
			}
			seen[arg] = true
			index++
			value := args[index]
			if arg == "--size" {
				switch value {
				case "1", "2", "4", "8":
					request.Size = int(value[0] - '0')
				default:
					return "", target.WatchpointRequest{}, fmt.Errorf("wp size must be 1, 2, 4 or 8: %w", target.ErrInvalidArgument)
				}
			} else {
				switch value {
				case "write":
					request.Access = target.WatchWrite
				case "read-write":
					request.Access = target.WatchReadWrite
				default:
					return "", target.WatchpointRequest{}, fmt.Errorf("wp access must be write or read-write: %w", target.ErrInvalidArgument)
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "--") || expression != "" || strings.TrimSpace(arg) == "" {
			return "", target.WatchpointRequest{}, fmt.Errorf("wp requires one address expression and optional --size/--access; quote expressions containing spaces: %w", target.ErrInvalidArgument)
		}
		expression = arg
	}
	if expression == "" {
		return "", target.WatchpointRequest{}, fmt.Errorf("wp requires an address expression: %w", target.ErrInvalidArgument)
	}
	return expression, request, nil
}

func (c *Controller) commandWatch(ctx context.Context, rawArgs string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: wp EXPR [--size N] [--access write|read-write], wp list, or wp d SLOT: %w", target.ErrInvalidArgument)
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("wp list takes no arguments: %w", target.ErrInvalidArgument)
		}
		return c.listWatchpoints()
	case "d":
		if len(args) != 2 || strings.HasPrefix(args[1], "+") || strings.HasPrefix(args[1], "-") {
			return fmt.Errorf("wp d requires a slot from 0 through 3: %w", target.ErrInvalidArgument)
		}
		slot, err := strconv.ParseUint(args[1], 0, 8)
		if err != nil || slot > 3 {
			return fmt.Errorf("wp d requires a slot from 0 through 3: %w", target.ErrInvalidArgument)
		}
		return c.deleteWatchpoint(ctx, int(slot))
	default:
		expression, request, err := watchpointArguments(args)
		if err != nil {
			return err
		}
		return c.addWatchpoint(ctx, expression, request)
	}
}

func (c *Controller) addWatchpoint(ctx context.Context, expression string, request target.WatchpointRequest) error {
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	if snapshot.Architecture == target.X86 && request.Size == 8 {
		return fmt.Errorf("x86 watchpoints support 1, 2 or 4 bytes: %w", target.ErrUnsupported)
	}
	backend, ok := c.session.(watchpointSession)
	if !ok {
		return fmt.Errorf("hardware watchpoints: %w", target.ErrUnsupported)
	}
	c.reconcileWatchpoints(snapshot)
	var used [4]bool
	for _, point := range c.watchpoints {
		if point.expired || point.thread != thread.Ref && !c.qemuMode() || point.space != snapshot.Memory.Space {
			continue
		}
		if point.attempted && (!point.installed || point.err != nil) {
			return fmt.Errorf("thread %d has an unconfirmed watchpoint operation; remove its known handle or release the session: %w", thread.Ref.ID, errors.Join(target.ErrUnavailable, point.err))
		}
		used[point.request.Slot] = true
	}
	request.Slot = -1
	for slot, occupied := range used {
		if !occupied {
			request.Slot = slot
			break
		}
	}
	if request.Slot < 0 {
		if c.qemuMode() {
			return fmt.Errorf("all four remote watchpoint handles are owned: %w", target.ErrBusy)
		}
		return fmt.Errorf("all four thread-local hardware slots are owned: %w", target.ErrBusy)
	}
	resolver, err := c.mutationResolver(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	address, err := inspect.EvalExpression(expression, resolver)
	if err != nil {
		return err
	}
	request.Address = target.Address(address)
	if err := mutationRange(request.Address, request.Size); err != nil {
		return err
	}
	if address > c.abi().maximum || uint64(request.Size-1) > c.abi().maximum-address {
		return target.ErrOverflow
	}
	if uint64(request.Address)%uint64(request.Size) != 0 {
		return fmt.Errorf("watchpoint address must be aligned to its %d-byte size: %w", request.Size, target.ErrInvalidArgument)
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	point := &watchRecord{thread: thread.Ref, space: snapshot.Memory.Space, request: request, attempted: true}
	c.watchpoints = append(c.watchpoints, point)
	result, installErr := backend.SetWatchpoint(thread.Token, request)
	if installErr == nil {
		if result.Ref.Thread != thread.Ref || result.Ref.Slot != request.Slot || result.Ref.Generation == 0 || result.Token.Thread != thread.Ref || result.Token.Stop != thread.Token.Stop || result.Token.Registers == 0 {
			installErr = fmt.Errorf("watchpoint installation returned an inconsistent identity: %w", target.ErrUnknown)
		} else {
			point.ref, point.installed = result.Ref, true
		}
	}
	snapshotErr := c.refreshAfterMutation(snapshot, thread)
	if snapshotErr == nil {
		c.reconcileWatchpoints(c.snapshot)
	}
	point.err = errors.Join(installErr, snapshotErr, ctx.Err())
	if point.err != nil {
		return fmt.Errorf("watchpoint thread=%d slot=%d installation is retained for cleanup: %w", thread.Ref.ID, request.Slot, point.err)
	}
	if c.qemuMode() {
		return c.writef("Watchpoint all-vCPUs slot=%d address=%s size=%d access=%s\n", point.ref.Slot, c.renderer.Text(display.StyleCyan, fmt.Sprintf("%#x", request.Address)), request.Size, request.Access)
	}
	return c.writef("Watchpoint thread=%d tid=%d slot=%d address=%s size=%d access=%s\n",
		thread.Ref.ID, thread.TID, point.ref.Slot, c.renderer.Text(display.StyleCyan, fmt.Sprintf("%#x", request.Address)), request.Size, request.Access)
}

func (c *Controller) deleteWatchpoint(ctx context.Context, slot int) error {
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	backend, ok := c.session.(watchpointSession)
	if !ok {
		return fmt.Errorf("hardware watchpoints: %w", target.ErrUnsupported)
	}
	c.reconcileWatchpoints(snapshot)
	var point *watchRecord
	var index int
	for i, candidate := range c.watchpoints {
		if !candidate.expired && (candidate.thread == thread.Ref || c.qemuMode()) && candidate.space == snapshot.Memory.Space && candidate.request.Slot == slot {
			point, index = candidate, i
			break
		}
	}
	if point == nil {
		return fmt.Errorf("thread %d watchpoint slot %d: %w", thread.Ref.ID, slot, target.ErrNotFound)
	}
	if !point.installed || point.ref.Thread != thread.Ref && !c.qemuMode() || point.ref.Generation == 0 || point.ref.Slot != slot {
		return fmt.Errorf("watchpoint installation has no confirmed handle; release the session for cleanup: %w", errors.Join(target.ErrUnavailable, point.err))
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	token, clearErr := backend.ClearWatchpoint(thread.Token, point.ref)
	if clearErr == nil && (token.Thread != thread.Ref || token.Stop != thread.Token.Stop || token.Registers == 0) {
		clearErr = fmt.Errorf("watchpoint removal returned an inconsistent identity: %w", target.ErrUnknown)
	}
	snapshotErr := c.refreshAfterMutation(snapshot, thread)
	if clearErr == nil {
		c.watchpoints = append(c.watchpoints[:index], c.watchpoints[index+1:]...)
	} else {
		point.err = errors.Join(clearErr, snapshotErr, ctx.Err())
	}
	if err := errors.Join(clearErr, snapshotErr, ctx.Err()); err != nil {
		return fmt.Errorf("remove watchpoint thread=%d slot=%d generation=%d: %w", thread.Ref.ID, slot, point.ref.Generation, err)
	}
	if c.qemuMode() {
		return c.writef("Removed watchpoint all-vCPUs slot=%d\n", slot)
	}
	return c.writef("Removed watchpoint thread=%d slot=%d\n", thread.Ref.ID, slot)
}

func (c *Controller) listWatchpoints() error {
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; interrupt, kill or detach for cleanup: %w", target.ErrBusy)
	}
	var snapshot target.Snapshot
	if c.session != nil {
		var err error
		snapshot, err = c.refresh()
		if err != nil {
			return err
		}
	}
	c.reconcileWatchpoints(snapshot)
	if len(c.watchpoints) == 0 {
		return c.writef("No watchpoints configured by this controller.\n")
	}
	if err := c.writef("%s\n", c.renderer.Section("watchpoints", display.OutputWidth(c.out))); err != nil {
		return err
	}
	if err := c.writef("%s\n", c.renderer.Text(display.StyleHeading, fmt.Sprintf("%-8s %-5s %-11s %-5s %-18s %s", "Thread", "Slot", "Access", "Size", "Address", "State"))); err != nil {
		return err
	}
	for _, point := range c.watchpoints {
		state := "unconfirmed"
		if point.installed && point.err == nil {
			state = "installed"
		}
		if point.expired {
			state = "invalidated"
		}
		if err := c.writef("%-8s %-5d %-11s %-5d %s %s\n",
			watchThreadLabel(point.thread, c.qemuMode()), point.request.Slot, point.request.Access, point.request.Size,
			c.renderer.Text(display.StyleCyan, fmt.Sprintf("0x%0*x", c.abi().word*2, point.request.Address)), state); err != nil {
			return err
		}
		if point.err != nil {
			if err := c.writef("  Error: %q\n", point.err.Error()); err != nil {
				return err
			}
		}
	}
	return nil
}

func watchThreadLabel(ref target.ThreadRef, remote bool) string {
	if remote {
		return "all"
	}
	return fmt.Sprintf("#%d", ref.ID)
}
