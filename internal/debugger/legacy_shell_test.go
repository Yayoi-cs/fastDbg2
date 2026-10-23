package debugger

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"fastdbg2/internal/shellcmd"
	"fastdbg2/target"
)

func TestMain(m *testing.M) {
	if code, handled := shellcmd.Helper(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestLegacyShellRejectsUnconfirmedTargetOperation(t *testing.T) {
	c := &Controller{out: io.Discard, active: controllerTestOperation(func(context.Context) (target.RunResult, error) {
		t.Fatal("shell waited on target operation")
		return target.RunResult{}, nil
	})}
	if err := c.commandShell(context.Background(), "printf unexpected"); !errors.Is(err, target.ErrBusy) {
		t.Fatalf("active operation shell: %v", err)
	}
}

func TestLegacyShellRejectsInvalidInputBeforeLaunch(t *testing.T) {
	c := &Controller{out: io.Discard}
	for _, raw := range []string{"", " \t\n", "printf a\x00printf b"} {
		if err := c.commandShell(context.Background(), raw); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("invalid shell input %q: %v", raw, err)
		}
	}
	if err := c.commandShell(nil, "printf x"); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("nil context: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.commandShell(ctx, "printf x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled shell: %v", err)
	}
	c.out = nil
	var output *OutputError
	if err := c.commandShell(context.Background(), "printf x"); !errors.As(err, &output) {
		t.Fatalf("nil output: %v", err)
	}
}
