package debugger

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

type threadDisplayOptions struct {
	renderer display.Renderer
	width    int
}

func writeThreadSnapshot(writef func(string, ...any) error, snapshot target.Snapshot, selected target.ThreadRef, options ...threadDisplayOptions) error {
	var view threadDisplayOptions
	if len(options) > 0 {
		view = options[0]
	}
	if err := writef("%s\n", view.renderer.Section("threads", view.width)); err != nil {
		return err
	}
	if err := writef("  %-5s %-8s %-8s %-20s %-10s %s\n", "Id", "TID", "Process", "Name", "State", "Reason"); err != nil {
		return err
	}
	for _, thread := range snapshot.Threads {
		marker := " "
		if thread.Ref == selected {
			marker = view.renderer.Text(display.StyleCurrent, "*")
		}
		state := thread.State.String()
		if thread.Exiting {
			state += "/exiting"
		}
		if thread.Listening {
			state += "/listening"
		}
		reason := thread.Stop.Reason.String()
		if thread.Stop.Reason == target.StopSignal && thread.Stop.Signal.Number != 0 {
			reason += fmt.Sprintf(" (%s:%d)", contextEscapedText(string(thread.Stop.Signal.Domain)), thread.Stop.Signal.Number)
		}
		if err := writef("%s %-5d %-8d %-8d %s %-10s %s\n", marker, thread.Ref.ID, thread.TID, thread.Process.ID, display.Pad(fmt.Sprintf("%q", thread.Name), 20), state, reason); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) showThreads() error {
	snapshot, err := c.refresh()
	if err != nil {
		return err
	}
	return writeThreadSnapshot(c.writef, snapshot, c.selected, threadDisplayOptions{c.renderer, display.OutputWidth(c.out)})
}

func (c *Controller) threadSnapshot() (target.Snapshot, error) {
	if c.active != nil {
		return target.Snapshot{}, fmt.Errorf("operation completion is unconfirmed; interrupt, kill or detach for cleanup: %w", target.ErrBusy)
	}
	snapshot, err := c.refresh()
	if err != nil {
		return snapshot, err
	}
	if snapshot.State != target.StateStopped {
		return snapshot, fmt.Errorf("target is %s: %w", snapshot.State, target.ErrInvalidState)
	}
	return snapshot, nil
}

func primaryInspectableThread(snapshot target.Snapshot, thread target.ThreadInfo) bool {
	return thread.Process == snapshot.Process && thread.State == target.StateStopped && !thread.Exiting && !thread.Listening
}

func validateSelectedThread(snapshot target.Snapshot, thread target.ThreadInfo) error {
	if thread.Process != snapshot.Process {
		return fmt.Errorf("thread ID %d is not in the primary process: %w", thread.Ref.ID, target.ErrUnsupported)
	}
	if !primaryInspectableThread(snapshot, thread) {
		return fmt.Errorf("thread ID %d (TID %d) is not stopped and inspectable: %w", thread.Ref.ID, thread.TID, target.ErrInvalidState)
	}
	return nil
}

func (c *Controller) selectThreadInfo(snapshot target.Snapshot, thread target.ThreadInfo) error {
	if err := validateSelectedThread(snapshot, thread); err != nil {
		return err
	}
	c.selected = thread.Ref
	return c.writef("Selected thread tid=%d thread=%d\n", thread.TID, thread.Ref.ID)
}

func (c *Controller) selectThread(tid int) error {
	snapshot, err := c.threadSnapshot()
	if err != nil {
		return err
	}
	for _, thread := range snapshot.Threads {
		if thread.TID == tid {
			return c.selectThreadInfo(snapshot, thread)
		}
	}
	return fmt.Errorf("thread TID %d: %w", tid, target.ErrNotFound)
}

func (c *Controller) selectThreadID(id uint64) error {
	snapshot, err := c.threadSnapshot()
	if err != nil {
		return err
	}
	for _, thread := range snapshot.Threads {
		if thread.Ref.ID == id {
			return c.selectThreadInfo(snapshot, thread)
		}
	}
	return fmt.Errorf("thread ID %d: %w", id, target.ErrNotFound)
}

func positiveThreadID(input string) (uint64, error) {
	if input == "" || strings.IndexFunc(input, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("thread ID must be a positive decimal integer: %w", target.ErrInvalidArgument)
	}
	id, err := strconv.ParseUint(input, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid thread ID %q: %w", input, errors.Join(target.ErrInvalidArgument, err))
	}
	return id, nil
}

func (c *Controller) commandThread(ctx context.Context, rawArgs string) error {
	selector, rest := cli.SplitCommand(strings.TrimSpace(rawArgs))
	switch selector {
	case "":
		_, thread, err := c.stopped()
		if err != nil {
			return err
		}
		return c.writef("Current thread tid=%d thread=%d state=%s\n", thread.TID, thread.Ref.ID, thread.State)
	case "tid":
		tid, err := positiveInt(rest, "TID")
		if err != nil {
			return err
		}
		return c.selectThread(tid)
	case "apply":
		return c.applyThreads(ctx, rest)
	default:
		id, err := positiveThreadID(strings.TrimSpace(rawArgs))
		if err != nil {
			return err
		}
		return c.selectThreadID(id)
	}
}

type threadApplyArguments struct {
	all       bool
	ascending bool
	keepGoing bool
	ids       []uint64
	command   string
	arguments string
}

func parseThreadApply(rawArgs string) (threadApplyArguments, error) {
	var request threadApplyArguments
	word, rest := cli.SplitCommand(strings.TrimSpace(rawArgs))
	if word == "all" {
		request.all = true
		word, rest = cli.SplitCommand(rest)
	} else {
		seen := make(map[uint64]bool)
		for word != "" && strings.IndexFunc(word, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			id, err := positiveThreadID(word)
			if err != nil {
				return threadApplyArguments{}, err
			}
			if seen[id] {
				return threadApplyArguments{}, fmt.Errorf("duplicate thread ID %d: %w", id, target.ErrInvalidArgument)
			}
			seen[id] = true
			request.ids = append(request.ids, id)
			word, rest = cli.SplitCommand(rest)
		}
		if len(request.ids) == 0 {
			return threadApplyArguments{}, fmt.Errorf("thread apply requires all or positive decimal thread IDs: %w", target.ErrInvalidArgument)
		}
	}
	for strings.HasPrefix(word, "-") {
		switch word {
		case "-ascending":
			if !request.all || request.ascending {
				return threadApplyArguments{}, fmt.Errorf("-ascending is accepted once, with thread apply all only: %w", target.ErrInvalidArgument)
			}
			request.ascending = true
		case "-c":
			if request.keepGoing {
				return threadApplyArguments{}, fmt.Errorf("duplicate thread apply -c: %w", target.ErrInvalidArgument)
			}
			request.keepGoing = true
		default:
			return threadApplyArguments{}, fmt.Errorf("unsupported thread apply option %q: %w", word, target.ErrInvalidArgument)
		}
		word, rest = cli.SplitCommand(rest)
	}
	if word == "" {
		return threadApplyArguments{}, fmt.Errorf("thread apply requires a read-only command: %w", target.ErrInvalidArgument)
	}
	request.command, request.arguments = word, rest
	if err := threadApplyReadOnly(word, rest); err != nil {
		return threadApplyArguments{}, err
	}
	return request, nil
}

func threadApplyReadOnly(name, rawArgs string) error {
	command, ok := canonicalCommand(name)
	if ok {
		switch command.name {
		case "regs", "memory", "print", "x", "disassemble", "stack", "hexdump", "db", "dw", "dd", "dq", "backtrace", "stackframe", "arena", "bins":
			return nil
		case "vmmap", "proc-info", "fd", "sym", "got", "checksec", "stdio", "fs_base", "gs_base", "telescope", "simd", "xmm", "ymm", "search-string", "search-value", "findruction", "xxd", "chunk", "visual-heap":
			return nil
		case "wp":
			if strings.TrimSpace(rawArgs) == "list" {
				return nil
			}
		case "context":
			for _, pane := range strings.Fields(rawArgs) {
				switch pane {
				case "regs", "registers", "code", "stack", "threads":
				default:
					return fmt.Errorf("thread apply context accepts read-only panes, not %q: %w", pane, target.ErrInvalidArgument)
				}
			}
			return nil
		case "thread", "threads":
			if strings.TrimSpace(rawArgs) == "" {
				return nil
			}
		case "info":
			subcommand, _ := cli.SplitCommand(strings.TrimSpace(rawArgs))
			switch subcommand {
			case "threads", "registers", "breakpoints":
				return nil
			}
		}
	}
	return fmt.Errorf("thread apply does not permit command %q; use a supported read-only command: %w", name, target.ErrUnsupported)
}

func threadApplyTargets(snapshot target.Snapshot, request threadApplyArguments) ([]target.ThreadInfo, error) {
	var threads []target.ThreadInfo
	if request.all {
		for _, thread := range snapshot.Threads {
			if thread.Process != snapshot.Process || thread.State == target.StateExited || thread.State == target.StateDetached || thread.State == target.StateClosed {
				continue
			}
			if err := validateSelectedThread(snapshot, thread); err != nil {
				return nil, err
			}
			threads = append(threads, thread)
		}
		slices.SortFunc(threads, func(a, b target.ThreadInfo) int {
			if request.ascending {
				return cmp.Compare(a.Ref.ID, b.Ref.ID)
			}
			return cmp.Compare(b.Ref.ID, a.Ref.ID)
		})
	} else {
		for _, id := range request.ids {
			found := false
			for _, thread := range snapshot.Threads {
				if thread.Ref.ID != id {
					continue
				}
				if err := validateSelectedThread(snapshot, thread); err != nil {
					return nil, err
				}
				threads = append(threads, thread)
				found = true
				break
			}
			if !found {
				return nil, fmt.Errorf("thread ID %d: %w", id, target.ErrNotFound)
			}
		}
	}
	if len(threads) == 0 {
		return nil, fmt.Errorf("no stopped primary-process threads: %w", target.ErrNotFound)
	}
	return threads, nil
}

func (c *Controller) applyThreads(ctx context.Context, rawArgs string) error {
	request, err := parseThreadApply(rawArgs)
	if err != nil {
		return err
	}
	snapshot, err := c.threadSnapshot()
	if err != nil {
		return err
	}
	threads, err := threadApplyTargets(snapshot, request)
	if err != nil {
		return err
	}
	selected := c.selected
	defer func() { c.selected = selected }()
	var errs []error
	for _, thread := range threads {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		c.selected = thread.Ref
		if err := c.writef("\nThread %d (tid=%d name=%q):\n", thread.Ref.ID, thread.TID, thread.Name); err != nil {
			return errors.Join(append(errs, err)...)
		}
		_, err := c.Execute(ctx, request.command, request.arguments)
		if err == nil {
			continue
		}
		errs = append(errs, fmt.Errorf("thread ID %d: %w", thread.Ref.ID, err))
		var outputErr *OutputError
		if !request.keepGoing || errors.As(err, &outputErr) || ctx.Err() != nil {
			return errors.Join(errs...)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) schedulerMode() string {
	if c.schedulerLocking == "" {
		return "replay"
	}
	return c.schedulerLocking
}

func (c *Controller) setSchedulerLocking(rawArgs string) error {
	mode := strings.TrimSpace(rawArgs)
	switch mode {
	case "off", "on", "step", "replay":
	default:
		return fmt.Errorf("scheduler-locking requires off, on, step or replay: %w", target.ErrInvalidArgument)
	}
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; interrupt, kill or detach for cleanup: %w", target.ErrBusy)
	}
	c.schedulerLocking = mode
	return nil
}

func (c *Controller) showSchedulerLocking() error {
	return c.writef("Mode for locking scheduler during execution is %q.\n", c.schedulerMode())
}

func (c *Controller) resumePeers(step bool) (bool, error) {
	switch c.schedulerMode() {
	case "off", "replay":
		return true, nil
	case "on":
		return false, nil
	case "step":
		return !step, nil
	default:
		return false, fmt.Errorf("invalid scheduler-locking mode %q: %w", c.schedulerLocking, target.ErrInvalidArgument)
	}
}

func (c *Controller) interruptActive(ctx context.Context) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if c.session == nil || c.active == nil {
		return fmt.Errorf("no unconfirmed operation to interrupt; foreground execution is interrupted with Ctrl-C: %w", target.ErrInvalidState)
	}
	snapshot, err := c.refresh()
	if err != nil {
		return err
	}
	op := c.active
	interruptErr := c.session.Interrupt(target.InterruptRequest{
		Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process},
	})
	waitCtx := ctx
	if interruptErr != nil {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithCancel(ctx)
		cancel()
	}
	result, waitErr := op.Wait(waitCtx)
	if waitCtx.Err() != nil && errors.Is(waitErr, waitCtx.Err()) {
		_, snapshotErr := c.refresh()
		return errors.Join(fmt.Errorf("operation completion remains unconfirmed; session is retained: %w", waitErr), interruptErr, snapshotErr)
	}
	c.active = nil
	return errors.Join(interruptErr, waitErr, c.captureLoaderArrivals(), c.showStop(context.WithoutCancel(ctx), result.Stop, result.Thread))
}
