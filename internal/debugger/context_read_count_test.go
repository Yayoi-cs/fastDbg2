package debugger

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestConfirmedContextInvalidCountRetainsBackendCauses(t *testing.T) {
	for _, count := range []int{-1, 5} {
		for _, cause := range []error{nil, target.ErrStale, context.Canceled, context.DeadlineExceeded, target.ErrUnavailable, errors.Join(target.ErrUnavailable, target.ErrStale)} {
			data, err := confirmedContextBytes([]byte{1, 2, 3, 4}, count, cause)
			if data != nil || !errors.Is(err, target.ErrUnknown) || cause != nil && !errors.Is(err, cause) {
				t.Fatalf("count=%d cause=%v prefix=%x error=%v", count, cause, data, err)
			}
		}
	}
}

func TestAddressTextInvalidCountCannotHideFatalReads(t *testing.T) {
	for _, optional := range []bool{false, true} {
		for _, over := range []bool{false, true} {
			for _, cause := range []error{target.ErrStale, context.Canceled, context.DeadlineExceeded, target.ErrUnavailable} {
				t.Run(fmt.Sprintf("optional=%t/over=%t/cause=%v", optional, over, cause), func(t *testing.T) {
					_, fixture, _ := newAddressWalkTestController()
					fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
						if optional && address == 0x1000 {
							copy(data, "ABCDEFGH")
							return len(data), nil
						}
						if over {
							return len(data) + 1, cause
						}
						return -1, cause
					}
					walker := addressWalkTestView(t, fixture, display.Renderer{})
					text, err := walker.Rows(context.Background(), 0x1000, 1, 4)
					switch {
					case addressWalkFatal(cause):
						if text != "" || !errors.Is(err, cause) || !errors.Is(err, target.ErrUnknown) {
							t.Fatalf("fatal count published: %q %v", text, err)
						}
					case optional:
						if err != nil || !strings.Contains(text, "0x4847464544434241") || strings.Contains(text, "'") {
							t.Fatalf("optional invalid count changed raw word: %q %v", text, err)
						}
					default:
						if !errors.Is(err, cause) || !errors.Is(err, target.ErrUnknown) || strings.Contains(text, "0x0000000000000000") {
							t.Fatalf("required count lost cause or invented value: %q %v", text, err)
						}
					}
					reads := len(fixture.stackCalls)
					repeated, repeatErr := walker.Rows(context.Background(), 0x1000, 1, 4)
					if len(fixture.stackCalls) != reads || addressWalkFatal(cause) && (repeated != "" || !errors.Is(repeatErr, cause)) {
						t.Fatalf("invalid count cache reused or retried: text=%q err=%v calls=%+v", repeated, repeatErr, fixture.stackCalls)
					}
				})
			}
		}
	}
}

func TestAddressTextInvalidCountAndCallbackCancelRetainAllCauses(t *testing.T) {
	for _, count := range []int{-1, 33} {
		controller, fixture, output := newAddressWalkTestController()
		ctx, cancel := context.WithCancel(context.Background())
		fixture.readRaw = func(_ target.MemoryToken, address target.Address, data []byte) (int, error) {
			if address == 0x1000 {
				copy(data, "ABCDEFGH")
				return len(data), nil
			}
			cancel()
			return count, target.ErrUnavailable
		}
		err := controller.showTelescope(ctx, "0x1000 1")
		cancel()
		if output.Len() != 0 || !errors.Is(err, target.ErrUnknown) || !errors.Is(err, target.ErrUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("callback count=%d published or hid cause: %q %v", count, output.String(), err)
		}
	}
}
