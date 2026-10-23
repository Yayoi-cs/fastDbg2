package debugger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"fastdbg2/internal/shellcmd"
	"fastdbg2/target"
)

func (c *Controller) commandShell(ctx context.Context, raw string) error {
	if c.active != nil {
		return fmt.Errorf("operation completion is unconfirmed; cleanup is required: %w", target.ErrBusy)
	}
	if ctx == nil || strings.TrimSpace(raw) == "" || strings.IndexByte(raw, 0) >= 0 {
		return fmt.Errorf("usage: !SHELL_COMMAND: %w", target.ErrInvalidArgument)
	}
	if c.out == nil {
		return &OutputError{Err: fmt.Errorf("output writer is required: %w", target.ErrInvalidArgument)}
	}
	input := os.Stdin
	terminal, err := shellcmd.TerminalInput(input)
	if err != nil {
		return fmt.Errorf("shell input: %w", err)
	}
	if !terminal {
		input, err = os.Open(os.DevNull)
		if err != nil {
			return err
		}
		defer input.Close()
	}
	err = shellcmd.Run(ctx, raw, input, c.out)
	var outputErr *shellcmd.OutputError
	if errors.As(err, &outputErr) {
		return &OutputError{Err: err}
	}
	return err
}
