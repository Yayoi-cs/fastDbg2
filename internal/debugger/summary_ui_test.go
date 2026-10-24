package debugger

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestSummaryUISearchHeadingShowsResultsAndPartialStatus(t *testing.T) {
	for _, partial := range []bool{false, true} {
		var output bytes.Buffer
		renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
		if err != nil {
			t.Fatal(err)
		}
		controller := &Controller{out: &output, renderer: renderer}
		var readErr error
		want := "Found 1 match(es)\n"
		if partial {
			readErr = target.ErrPartial
			want = "Found 1 match(es) (partial)\n"
		}
		if err := controller.searchHeading("live-raw", "readable mappings intersect [0x404060, 0x4040a0)", []byte("SHELL="), searchResult{addresses: []target.Address{0x404060}, bytesRead: 64}, readErr); err != nil {
			t.Fatal(err)
		}
		if vmmapTestSGR.ReplaceAllString(output.String(), "") != want || !strings.Contains(output.String(), "\x1b[36m1\x1b[0m") {
			t.Fatal(output.String())
		}
	}
}

func TestSummaryUIHeapTitlePreservesExplicitInterpretationAndOutputErrors(t *testing.T) {
	var output bytes.Buffer
	controller := &Controller{out: &output}
	if err := controller.heapLayoutTitle("chunk"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[chunk]"} {
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
