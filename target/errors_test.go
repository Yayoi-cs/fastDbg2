package target_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"fastdbg2/target"
)

func TestPartialError(t *testing.T) {
	for _, cause := range []error{nil, target.ErrUnknown} {
		err := &target.PartialError{Op: "write registers", Completed: 1, Total: 3, Err: cause}
		wrapped := fmt.Errorf("target operation: %w", err)
		if !errors.Is(wrapped, target.ErrPartial) {
			t.Fatal("partial error classification was lost")
		}
		if cause != nil && !errors.Is(wrapped, cause) {
			t.Fatal("original cause was lost")
		}
		if errors.Is(wrapped, target.ErrClosed) {
			t.Fatal("partial error matched an unrelated cause")
		}
		var partial *target.PartialError
		if !errors.As(wrapped, &partial) || partial.Completed != 1 || partial.Total != 3 {
			t.Fatal("partial error details were lost")
		}
		if !strings.Contains(err.Error(), "1 of 3 confirmed") {
			t.Fatalf("error must describe only the confirmed progress: %q", err)
		}
	}
}
