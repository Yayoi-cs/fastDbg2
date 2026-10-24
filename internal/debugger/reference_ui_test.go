package debugger

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
)

func TestFastDbgVisualPaletteAndPermissionColors(t *testing.T) {
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	palette := []string{"31", "32", "33", "34", "35", "36"}
	for index := 0; index < 18; index++ {
		want := "\x1b[" + palette[index%6] + "mchunk\x1b[0m"
		if got := renderer.Text(heapVisualChunkStyle(index), "chunk"); got != want {
			t.Fatalf("chunk %d: %q want %q", index, got, want)
		}
	}
	for _, test := range []struct {
		read, write, execute bool
		color                string
	}{
		{false, false, false, ""}, {true, false, false, "34"}, {false, true, false, "32"},
		{true, true, false, "36"}, {false, false, true, "35"}, {true, false, true, "35"},
		{false, true, true, "35"}, {true, true, true, "33"},
	} {
		want := "address"
		if test.color != "" {
			want = "\x1b[" + test.color + "maddress\x1b[0m"
		}
		if got := renderer.PermissionText("address", test.read, test.write, test.execute); got != want {
			t.Fatalf("permissions %+v: %q want %q", test, got, want)
		}
	}
}

func TestNormalViewsDoNotPrintInternalVerification(t *testing.T) {
	var output bytes.Buffer
	controller := New(&output, display.Renderer{})
	view := controller.metadataView()
	view.module("got", &mappedELF{ID: "main", Path: "/target", MetadataPath: "/debug", Proof: "INTERNAL_PROOF", Scope: "INTERNAL_SCOPE", BuildID: []byte{1, 2, 3}})
	output.WriteString(view.output.String())
	if err := controller.renderSymbolFacts(legacyFunctionFacts(), ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.searchHeading("INTERNAL_SOURCE", "INTERNAL_SCOPE", []byte("INTERNAL_PATTERN"), searchResult{addresses: []target.Address{0x401000}, bytesRead: 16384}, nil); err != nil {
		t.Fatal(err)
	}
	if err := controller.showColorLegend(); err != nil {
		t.Fatal(err)
	}
	if err := controller.heapLayoutTitle("chunk"); err != nil {
		t.Fatal(err)
	}
	_, seed, result, _ := unwindUIFixture()
	seed.abiExplicit = false
	output.WriteString(controller.backtraceText(seed, result))
	for _, forbidden := range []string{"INTERNAL_", "Source proof", "Metadata file", "Build ID", "not inferred", "ownership", "names are literal", "ABI:", "Raw RIP:", "End of stack", "bytesRead"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("normal display leaked %q:\n%s", forbidden, output.String())
		}
	}
	for _, present := range []string{"/target", "work", "Found 1 match(es)", "[chunk]", "[*#0] 0x0000000000401000"} {
		if !strings.Contains(output.String(), present) {
			t.Fatalf("removed useful result %q:\n%s", present, output.String())
		}
	}
}

func TestTelescopeAddressColorIsSeparateFromPointerPermissions(t *testing.T) {
	controller, fixture, output := newAddressWalkTestController()
	controller.renderer, _ = display.NewRenderer(display.Options{Mode: display.ColorAlways})
	fixture.mappings = []procMap{{Start: 0x70000000, End: 0x70000010, Read: true, Write: true}}
	addressWalkTestWords(fixture, map[target.Address]uint64{0x70000000: 0x70000008, 0x70000008: 0})
	if err := controller.showTelescope(context.Background(), "$rsp 1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "\x1b[34m0x0000000070000000\x1b[0m") || !strings.Contains(output.String(), "\x1b[36m0x0000000070000008\x1b[0m") || strings.Contains(output.String(), "[telescope]") {
		t.Fatal(output.String())
	}
	if len(fixture.stackCalls) != 2 || fixture.stackCalls[0].token != fixture.snapshot.Memory {
		t.Fatal(fmt.Sprint(fixture.stackCalls))
	}
}
