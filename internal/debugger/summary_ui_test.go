package debugger

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestSummaryUISearchHeadingRetainsScopePatternCountsAndStatus(t *testing.T) {
	for _, partial := range []bool{false, true} {
		var output bytes.Buffer
		renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
		if err != nil {
			t.Fatal(err)
		}
		controller := &Controller{out: &output, renderer: renderer}
		var readErr error
		if partial {
			readErr = target.ErrPartial
		}
		if err := controller.searchHeading("live-raw", "readable mappings intersect [0x404060, 0x4040a0)", []byte("SHELL="), searchResult{addresses: []target.Address{0x404060}, bytesRead: 64}, readErr); err != nil {
			t.Fatal(err)
		}
		plain := vmmapTestSGR.ReplaceAllString(output.String(), "")
		for _, want := range []string{"Source     : live-raw", "Scope      : readable mappings intersect [0x404060, 0x4040a0)", "Pattern    : 5348454c4c3d (6 bytes)", "Matches    : 1 confirmed byte match(es)", "Bytes read : 64"} {
			if !strings.Contains(plain, want) {
				t.Fatalf("search fact changed %q: %s", want, plain)
			}
		}
		status, code := "complete", "1;32"
		if partial {
			status, code = "partial", "33"
		}
		if !strings.Contains(output.String(), "\x1b["+code+"m"+status+"\x1b[0m") {
			t.Fatalf("incorrect search completeness style: %q", output.String())
		}
	}
}

func TestSummaryUIHeapTitlePreservesExplicitInterpretationAndOutputErrors(t *testing.T) {
	var output bytes.Buffer
	controller := &Controller{out: &output}
	if err := controller.heapLayoutTitle("chunk"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[chunk]", "Layout     : glibc-amd64 (user-selected)", "allocation ownership and state are not determined"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("explicit-layout interpretation missing: %q\n%s", want, output.String())
		}
	}
	want := errors.New("summary output")
	controller.out = controllerTestWriter(func([]byte) (int, error) { return 0, want })
	if err := controller.heapLayoutTitle("visual-heap"); !errors.Is(err, want) {
		t.Fatalf("output failure hidden: %v", err)
	}
}
