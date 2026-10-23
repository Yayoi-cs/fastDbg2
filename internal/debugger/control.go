package debugger

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"

	"fastdbg2/display"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func (c *Controller) start(ctx context.Context, rawArgs string, run bool) error {
	if c.path == "" {
		return fmt.Errorf("configure an executable with file PATH first: %w", target.ErrInvalidState)
	}
	if c.session != nil && !c.owned {
		return fmt.Errorf("cannot restart an attached process; detach or kill it first: %w", target.ErrInvalidState)
	}
	args := slices.Clone(c.args)
	if strings.TrimSpace(rawArgs) != "" {
		var err error
		args, err = cli.ParseArgs(rawArgs)
		if err != nil {
			return err
		}
	}
	if err := preflightAMD64(c.path); err != nil {
		return err
	}
	if err := c.Close(); err != nil {
		return fmt.Errorf("previous session was not released; restart canceled: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.args = args
	s, err := c.launch(c.path, slices.Clone(args))
	if s != nil {
		c.session, c.owned = s, true
	}
	if err != nil {
		return fmt.Errorf("launch %q: %w", c.path, err)
	}
	if s == nil {
		return fmt.Errorf("launch returned no session: %w", target.ErrUnknown)
	}
	if err := c.initializeSelection(); err != nil {
		if errors.Is(err, target.ErrUnsupported) {
			return errors.Join(err, c.Close())
		}
		return err
	}
	if err := c.writef("Started native amd64 pid=%d executable=%q arguments=%q\n", s.PID(), c.path, c.args); err != nil {
		return err
	}
	breakpointErr := c.installBreakpoints(ctx)
	if breakpointErr != nil || !run || ctx.Err() != nil {
		displayErr := c.showStop(context.WithoutCancel(ctx), s.LastStop(), target.ThreadRef{})
		return errors.Join(breakpointErr, displayErr)
	}
	return c.resume(ctx, "", false)
}

func (c *Controller) attachProcess(ctx context.Context, pid int) error {
	if c.session != nil {
		return fmt.Errorf("release the current session before attaching: %w", target.ErrInvalidState)
	}
	if err := preflightAttachAMD64(pid); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := c.attach(pid)
	if s != nil {
		c.session, c.owned = s, false
	}
	if err != nil {
		return fmt.Errorf("attach PID %d: %w", pid, err)
	}
	if s == nil {
		return fmt.Errorf("attach returned no session: %w", target.ErrUnknown)
	}
	if err := c.initializeSelection(); err != nil {
		if errors.Is(err, target.ErrUnsupported) {
			return errors.Join(err, c.Close())
		}
		return err
	}
	if err := c.writef("Attached native amd64 pid=%d\n", s.PID()); err != nil {
		return err
	}
	breakpointErr := c.installBreakpoints(ctx)
	return errors.Join(breakpointErr, c.showStop(context.WithoutCancel(ctx), s.LastStop(), target.ThreadRef{}))
}

func (c *Controller) initializeSelection() error {
	snapshot, err := c.refresh()
	if err != nil {
		return err
	}
	for _, thread := range snapshot.Threads {
		if thread.TID == c.session.PID() && thread.Process == snapshot.Process && thread.State == target.StateStopped && !thread.Exiting && !thread.Listening {
			c.selected = thread.Ref
			return nil
		}
	}
	return fmt.Errorf("primary leader is not inspectable; select a stopped thread with thread ID: %w", target.ErrUnavailable)
}

func signalDecisions(rawArgs string, threads []target.ThreadInfo) ([]target.ThreadSignal, error) {
	option := strings.TrimSpace(rawArgs)
	if option != "" && option != "--deliver" && option != "--suppress" {
		return nil, fmt.Errorf("expected --deliver or --suppress: %w", target.ErrInvalidArgument)
	}
	var decisions []target.ThreadSignal
	var pending []int
	for _, thread := range threads {
		if thread.Stop.Reason != target.StopSignal {
			continue
		}
		pending = append(pending, thread.TID)
		if option == "" {
			continue
		}
		signal := target.Signal{}
		if option == "--deliver" {
			signal = thread.Stop.Signal
			if signal.Domain != target.SignalLinux || signal.Number == 0 || signal.Number > 64 {
				return nil, fmt.Errorf("thread %d has an invalid pending signal: %w", thread.TID, target.ErrUnknown)
			}
		}
		decisions = append(decisions, target.ThreadSignal{Thread: thread.Ref, Stop: thread.Token.Stop, Signal: signal})
	}
	if len(pending) > 0 && option == "" {
		return nil, fmt.Errorf("pending signals on TIDs %v require --deliver or --suppress: %w", pending, target.ErrInvalidArgument)
	}
	return decisions, nil
}

func (c *Controller) resume(ctx context.Context, rawArgs string, step bool) error {
	if c.active != nil {
		return fmt.Errorf("previous operation has not completed; kill or detach for cleanup: %w", target.ErrBusy)
	}
	if _, err := signalDecisions(rawArgs, nil); err != nil {
		return err
	}
	for {
		if err := c.prepareLoaderBreakpoints(ctx); err != nil {
			return err
		}
		snapshot, selected, err := c.stopped()
		if err != nil {
			return err
		}
		peers, err := c.resumePeers(step)
		if err != nil {
			return err
		}
		set := target.ThreadSet{Threads: []target.ThreadRef{selected.Ref}}
		threads := []target.ThreadInfo{selected}
		if peers {
			set = target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process}
			threads = nil
			for _, thread := range snapshot.Threads {
				if thread.Process == snapshot.Process && thread.State != target.StateExited && thread.State != target.StateDetached && !thread.Exiting {
					if err := validateSelectedThread(snapshot, thread); err != nil {
						return err
					}
					threads = append(threads, thread)
				}
			}
		}
		signals, err := signalDecisions(rawArgs, threads)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var op operation
		if step {
			request := target.StepRequest{Thread: selected.Ref, Signals: signals}
			if peers {
				request.Continue = set
			}
			op, err = c.session.StepInstruction(request)
		} else {
			op, err = c.session.Run(target.RunRequest{
				Threads: set,
				Signals: signals,
			})
		}
		if err != nil {
			_, snapshotErr := c.refresh()
			return errors.Join(err, snapshotErr)
		}
		if op == nil {
			return fmt.Errorf("resume returned no operation: %w", target.ErrUnknown)
		}
		c.active = op
		c.beginLoaderOperation(snapshot)
		result, waitErr := op.Wait(ctx)
		if ctx.Err() != nil && errors.Is(waitErr, ctx.Err()) {
			interruptErr := c.session.Interrupt(target.InterruptRequest{
				Threads: target.ThreadSet{Scope: target.ProcessThreads, Process: snapshot.Process},
			})
			if interruptErr != nil {
				result, waitErr = op.Wait(ctx)
				if errors.Is(waitErr, ctx.Err()) {
					_, snapshotErr := c.refresh()
					return errors.Join(fmt.Errorf("interrupt failed; target stop is not confirmed and session is retained: %w", interruptErr), snapshotErr)
				}
				waitErr = errors.Join(waitErr, interruptErr)
			} else {
				result, waitErr = op.Wait(context.Background())
			}
		}
		c.active = nil
		if arrivalErr := c.captureLoaderArrivals(); arrivalErr != nil {
			return errors.Join(waitErr, arrivalErr, c.showStop(context.WithoutCancel(ctx), result.Stop, result.Thread))
		}
		if waitErr == nil && ctx.Err() == nil {
			consumed, loaderErr := c.handleLoaderStop(ctx, snapshot, result)
			if loaderErr != nil {
				return errors.Join(loaderErr, c.showStop(context.WithoutCancel(ctx), result.Stop, result.Thread))
			}
			if consumed && !step {
				rawArgs = ""
				continue
			}
		}
		return errors.Join(waitErr, c.showStop(context.WithoutCancel(ctx), result.Stop, result.Thread))
	}
}
func (c *Controller) showStop(ctx context.Context, stop target.Stop, ref target.ThreadRef) error {
	snapshot, err := c.refresh()
	if err != nil {
		return err
	}
	if snapshot.State == target.StateStopped && ref != (target.ThreadRef{}) {
		for _, thread := range snapshot.Threads {
			if thread.Ref == ref && primaryInspectableThread(snapshot, thread) {
				c.selected = ref
				break
			}
		}
	}
	writeStatus := c.writeStatus
	var prefix strings.Builder
	buffered := c.stoppedContextScreen(snapshot)
	if buffered {
		writeStatus = func(style display.Style, format string, args ...any) error {
			prefix.WriteString(c.statusText(style, format, args...))
			return nil
		}
	}
	if err := writeStatus(display.StyleHeading, "%s\n", statusStopSummary(snapshot, stop, ref, c.session.PID())); err != nil {
		return err
	}
	if stop.RawPC != nil && (snapshot.State != target.StateStopped || stop.Reason == target.StopExited || stop.Reason == target.StopSignaled || c.contextDisabled && stop.Reason == target.StopBreakpoint && stop.Breakpoint != nil && *stop.Breakpoint != *stop.RawPC) {
		if err := writeStatus(display.StylePlain, "  Raw PC: 0x%016x\n", *stop.RawPC); err != nil {
			return err
		}
	}
	if stop.Breakpoint != nil && (stop.Reason != target.StopBreakpoint || snapshot.State != target.StateStopped) {
		if err := writeStatus(display.StylePlain, "  Breakpoint address: 0x%016x\n", *stop.Breakpoint); err != nil {
			return err
		}
	}
	signalShown := snapshot.State == target.StateStopped && stop.Reason == target.StopSignal || (snapshot.State == target.StateStopped || snapshot.State == target.StateExited) && stop.Reason == target.StopSignaled
	if stop.Signal.Number != 0 && !signalShown && !statusDebuggerTrap(stop) {
		if err := writeStatus(display.StylePlain, "  Signal: %s\n", statusSignal(stop.Signal)); err != nil {
			return err
		}
	}
	exitCodeShown := snapshot.State == target.StateExited && stop.Reason != target.StopSignaled || snapshot.State == target.StateStopped && stop.Reason == target.StopExited
	if stop.ExitCode != nil && !exitCodeShown {
		if err := writeStatus(display.StylePlain, "  Exit code: %d\n", *stop.ExitCode); err != nil {
			return err
		}
	}
	if stop.StepCompleted {
		if err := writeStatus(display.StylePlain, "  Instruction step completed.\n"); err != nil {
			return err
		}
	}
	for _, hit := range stop.Watchpoints {
		if err := writeStatus(display.StylePlain, "  Watchpoint: thread #%d, slot %d, generation %d; %s %d byte(s) at 0x%016x (session %d).\n",
			hit.Ref.Thread.ID, hit.Ref.Slot, hit.Ref.Generation, hit.Access, hit.Size, hit.Address, hit.Ref.Thread.Session); err != nil {
			return err
		}
	}
	for _, hit := range stop.HardwareBreakpoints {
		if err := writeStatus(display.StylePlain, "  Hardware breakpoint: thread #%d, slot %d, generation %d; execution at 0x%016x (session %d).\n",
			hit.Ref.Thread.ID, hit.Ref.Slot, hit.Ref.Generation, hit.Address, hit.Ref.Thread.Session); err != nil {
			return err
		}
	}
	if snapshot.State == target.StateStopped && !c.contextDisabled {
		if buffered {
			return c.showContextWithPrefix(ctx, prefix.String(), &snapshot)
		}
		return c.showContext(ctx)
	}
	return nil
}

func (c *Controller) writeStatus(style display.Style, format string, args ...any) error {
	return c.writef("%s", c.statusText(style, format, args...))
}

func (c *Controller) statusText(style display.Style, format string, args ...any) string {
	text := fmt.Sprintf(format, args...)
	newline := strings.HasSuffix(text, "\n")
	text = c.renderer.Text(style, strings.TrimSuffix(text, "\n"))
	if newline {
		text += "\n"
	}
	return display.Wrap(text, display.OutputWidth(c.out), 2)
}

func statusDebuggerTrap(stop target.Stop) bool {
	if stop.Signal.Domain != target.SignalLinux || stop.Signal.Number != uint32(unix.SIGTRAP) {
		return false
	}
	switch stop.Reason {
	case target.StopBreakpoint, target.StopStep, target.StopInterrupt, target.StopExec,
		target.StopClone, target.StopFork, target.StopVFork, target.StopAttach,
		target.StopWatchpoint, target.StopHardwareBreakpoint:
		return true
	default:
		return false
	}
}

func statusSignal(signal target.Signal) string {
	if signal.Domain == target.SignalLinux && signal.Number != 0 {
		if name := unix.SignalName(syscall.Signal(signal.Number)); name != "" {
			return fmt.Sprintf("%s (%d)", name, signal.Number)
		}
		return fmt.Sprintf("Linux signal %d", signal.Number)
	}
	if signal.Domain == target.SignalNone && signal.Number == 0 {
		return "an unknown signal"
	}
	return fmt.Sprintf("%q signal %d", signal.Domain, signal.Number)
}

func statusStopSubject(snapshot target.Snapshot, stop target.Stop, ref target.ThreadRef, pid int) string {
	tid := "unknown"
	if stop.ThreadID != nil {
		tid = fmt.Sprintf("%d", *stop.ThreadID)
	} else if ref != (target.ThreadRef{}) {
		for _, thread := range snapshot.Threads {
			if thread.Ref == ref {
				tid = fmt.Sprintf("%d", thread.TID)
				break
			}
		}
	}
	if ref.ID != 0 {
		return fmt.Sprintf("Thread #%d (TID %s)", ref.ID, tid)
	}
	if stop.ThreadID != nil {
		return fmt.Sprintf("Thread (TID %s)", tid)
	}
	return fmt.Sprintf("Process %d", pid)
}

func statusStopSummary(snapshot target.Snapshot, stop target.Stop, ref target.ThreadRef, pid int) string {
	exit := "code unknown"
	if stop.ExitCode != nil {
		exit = fmt.Sprintf("code %d", *stop.ExitCode)
	}
	if stop.Reason == target.StopSignaled {
		exit = statusSignal(stop.Signal)
	}
	if snapshot.State == target.StateExited {
		return fmt.Sprintf("Process %d exited (%s).", pid, exit)
	}
	if snapshot.State != target.StateStopped {
		return fmt.Sprintf("Process %d is %s; last stop reason: %s.", pid, snapshot.State, stop.Reason)
	}
	subject := statusStopSubject(snapshot, stop, ref, pid)
	if stop.Reason == target.StopExited || stop.Reason == target.StopSignaled {
		if ref.ID == 0 && stop.ThreadID == nil {
			subject = "A thread"
		}
		return fmt.Sprintf("%s exited (%s); process %d remains stopped.", subject, exit, pid)
	}
	location := ""
	pc := stop.RawPC
	if stop.Reason == target.StopBreakpoint && stop.Breakpoint != nil {
		pc = stop.Breakpoint
	}
	if pc != nil {
		location = fmt.Sprintf(" at 0x%016x", *pc)
	}
	if stop.Reason == target.StopSignal {
		return fmt.Sprintf("%s stopped by %s%s.", subject, statusSignal(stop.Signal), location)
	}
	reason := stop.Reason.String()
	switch stop.Reason {
	case target.StopStep:
		reason = "instruction step"
	case target.StopGroupStop:
		reason = "group stop"
	case target.StopHardwareBreakpoint:
		reason = "hardware execution breakpoint"
	case target.StopWatchpoint:
		reason = "hardware watchpoint"
	case target.StopUnknown:
		reason = "unknown stop reason"
	}
	return fmt.Sprintf("%s stopped%s (%s).", subject, location, reason)
}

func (c *Controller) releaseTarget(kill bool) error {
	if c.session == nil {
		return fmt.Errorf("no target: %w", target.ErrInvalidState)
	}
	pid := c.session.PID()
	var err error
	action := "Detached"
	if kill {
		action = "Killed"
		err = c.session.Kill()
	} else {
		err = c.session.Detach()
	}
	if err != nil {
		_, snapshotErr := c.refresh()
		return errors.Join(err, snapshotErr)
	}
	if err := c.Close(); err != nil {
		return err
	}
	return c.writef("%s pid=%d\n", action, pid)
}

func (c *Controller) Close() error {
	if c.session == nil {
		return nil
	}
	if err := c.session.Close(); err != nil {
		return fmt.Errorf("session remains retained for cleanup: %w", err)
	}
	c.session = nil
	c.snapshot = target.Snapshot{}
	c.selected = target.ThreadRef{}
	c.owned = false
	c.active = nil
	c.image = imageState{}
	c.invalidateBreakpoints()
	return nil
}
