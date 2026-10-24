package debugger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

var vmmapTestSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func vmmapTestMappings() []procMap {
	return []procMap{
		{Start: 0x400000, End: 0x401000, Read: true, Execute: true, Private: true, DevMajor: 8, DevMinor: 1, Inode: 42, Path: "/code"},
		{Start: 0x401000, End: 0x402000, Offset: 0x1000, Read: true, Write: true, Private: true, Path: ""},
		{Start: 0x402000, End: 0x403000, Offset: 0x2000, Read: true, Private: true, DevMajor: 8, DevMinor: 1, Inode: 42, Path: "/readonly"},
		{Start: 0x403000, End: 0x404000, Read: true, Write: true, Execute: true, Path: "/rwx"},
		{Start: 0x404000, End: 0x405000, Write: true, Path: "/write"},
		{Start: 0x405000, End: 0x406000, Path: "/none"},
	}
}

func TestVMMapUIPermissionColorCoversEveryRowAndContinuation(t *testing.T) {
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	for index, mapping := range vmmapTestMappings() {
		t.Run(mapping.permissions(), func(t *testing.T) {
			mapping.Path += strings.Repeat("/long-component", 12)
			text, err := renderVMMap(context.Background(), []procMap{mapping}, "", 80, renderer)
			if err != nil {
				t.Fatal(err)
			}
			codes := []string{"35", "36", "34", "33", "32", ""}
			lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			data := false
			for _, line := range lines {
				plain := vmmapTestSGR.ReplaceAllString(line, "")
				data = data || strings.HasPrefix(plain, "0x")
				if data && ((codes[index] == "" && line != plain) || (codes[index] != "" && (!strings.HasPrefix(line, "\x1b["+codes[index]+"m") || !strings.HasSuffix(line, "\x1b[0m")))) {
					t.Fatalf("row fragment lacks full permission color: %q", line)
				}
				if display.VisibleWidth(line) > 80 {
					t.Fatalf("row exceeds viewport width: %q", line)
				}
			}
			if !data {
				t.Fatal("no mapping rows")
			}
		})
	}
}

func TestVMMapUICompactColumnsRetainExactWideValues(t *testing.T) {
	mappings := vmmapTestMappings()
	for _, width := range []int{80, 120} {
		text, err := renderVMMap(context.Background(), mappings, "", width, display.Renderer{})
		if err != nil {
			t.Fatal(err)
		}
		for _, mapping := range mappings {
			want := fmt.Sprintf("0x%016x 0x%016x 0x%08x 0x%08x %s", mapping.Start, mapping.End, mapping.End-mapping.Start, mapping.Offset, mapping.permissions())
			if !strings.Contains(text, want) {
				t.Fatalf("numeric mapping facts lost at width %d: %q\n%s", width, want, text)
			}
		}
		if width == 120 && len(strings.Split(strings.TrimSuffix(text, "\n"), "\n")) != len(mappings)+2 {
			t.Fatalf("short paths needlessly expanded to multiple rows:\n%s", text)
		}
		for _, line := range strings.Split(text, "\n") {
			if display.VisibleWidth(line) > width {
				t.Fatalf("line exceeds %d: %q", width, line)
			}
		}
	}
	wide := procMap{Start: 0x1000, End: target.Address(math.MaxUint64), Offset: 0x123456789abcdef0, Inode: math.MaxUint64, DevMajor: math.MaxUint32, DevMinor: math.MaxUint32}
	text, err := renderVMMap(context.Background(), []procMap{wide}, "", 120, display.Renderer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"0xffffffffffffffff", "0xffffffffffffefff", "0x123456789abcdef0", "ffffffff:ffffffff", "18446744073709551615"} {
		if !strings.Contains(text, want) {
			t.Fatalf("large value was truncated: %q\n%s", want, text)
		}
	}
}

func TestVMMapUILongPathsAreEscapedAndLosslesslyContinued(t *testing.T) {
	path := strings.Repeat("/long\"\\測試 component", 12) + "\x1b]0;unsafe\a\n\t\u202e tail"
	quoted := strconv.QuoteToGraphic(path)
	for _, width := range []int{80, 120} {
		prefix := "    8:1 42 "
		lines := vmmapQuotedLines(prefix, quoted, width)
		var recovered strings.Builder
		for index, line := range lines {
			if display.VisibleWidth(line) > width {
				t.Fatalf("path exceeds %d columns: %q", width, line)
			}
			if strings.ContainsAny(line, "\x1b\a\r\n\t\u202e") {
				t.Fatalf("path controls reached output: %q", line)
			}
			if index == 0 {
				recovered.WriteString(strings.TrimPrefix(line, prefix))
			} else {
				recovered.WriteString(strings.TrimPrefix(line, strings.Repeat(" ", len(prefix))))
			}
		}
		if recovered.String() != quoted {
			t.Fatalf("path bytes lost or altered: %q want %q", recovered.String(), quoted)
		}
		decoded, err := strconv.Unquote(recovered.String())
		if err != nil || decoded != path {
			t.Fatalf("escaped path cannot round-trip: %v %q", err, decoded)
		}
	}
}

func TestVMMapUIFilterColorPolicyAndInvalidInputs(t *testing.T) {
	for _, options := range []display.Options{
		{Mode: display.ColorNever, IsTerminal: true},
		{Mode: display.ColorAuto, IsTerminal: false, Term: "xterm-256color"},
		{Mode: display.ColorAuto, IsTerminal: true, Term: "xterm-256color", NoColor: "1"},
	} {
		renderer, err := display.NewRenderer(options)
		if err != nil {
			t.Fatal(err)
		}
		text, err := renderVMMap(context.Background(), vmmapTestMappings(), "readonly", 120, renderer)
		if err != nil || strings.ContainsRune(text, '\x1b') || !strings.Contains(text, `"/readonly"`) || strings.Contains(text, `"/code"`) || strings.Contains(text, `"/rwx"`) {
			t.Fatalf("filter/plain policy: %v %q", err, text)
		}
	}
	text, err := renderVMMap(context.Background(), vmmapTestMappings(), "no-such-map", 80, display.Renderer{})
	if err != nil || strings.Contains(text, "0x") || !strings.Contains(text, "[vmmap]") || !strings.Contains(text, "Start") {
		t.Fatalf("empty filter result: %v %q", err, text)
	}
	for _, mapping := range []procMap{{Start: 1, End: 1}, {Start: 2, End: 1}} {
		if text, err := renderVMMap(context.Background(), []procMap{mapping}, "", 80, display.Renderer{}); !errors.Is(err, target.ErrInvalidArgument) || text != "" {
			t.Fatalf("invalid mapping rendered: %v %q", err, text)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if text, err := renderVMMap(ctx, vmmapTestMappings(), "", 80, display.Renderer{}); !errors.Is(err, context.Canceled) || text != "" {
		t.Fatalf("cancelled view rendered: %v %q", err, text)
	}
}

func TestVMMapUIPublishValidatesSnapshotBeforeAnyOutput(t *testing.T) {
	for _, mode := range []string{"current", "stale", "register-error", "cancel-during-validation", "output-error"} {
		t.Run(mode, func(t *testing.T) {
			fixture, snapshot, thread := newContextFixture()
			var output bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			controller := &Controller{session: fixture, selected: thread.Ref, out: &output}
			var want error
			writes := 0
			switch mode {
			case "stale":
				fixture.snapshot.Sequence++
				want = target.ErrStale
			case "register-error":
				fixture.registerErr = target.ErrUnavailable
				want = target.ErrUnavailable
			case "cancel-during-validation":
				fixture.onReadRegisters = cancel
				want = context.Canceled
			case "output-error":
				want = errors.New("output failed")
				controller.out = controllerTestWriter(func([]byte) (int, error) { writes++; return 0, want })
			}
			err := controller.publishVMMap(ctx, snapshot, thread, "confirmed view\n")
			if want == nil {
				if err != nil || output.String() != "confirmed view\n" {
					t.Fatalf("valid publish: %v %q", err, output.String())
				}
			} else if !errors.Is(err, want) || output.Len() != 0 || mode == "output-error" && writes != 1 {
				t.Fatalf("invalid/failed publish: %v %q writes=%d", err, output.String(), writes)
			}
			if len(fixture.registerTokens) != 1 || fixture.registerTokens[0] != thread.Token {
				t.Fatalf("final validation did not use exact selected token: %+v", fixture.registerTokens)
			}
		})
	}
}
