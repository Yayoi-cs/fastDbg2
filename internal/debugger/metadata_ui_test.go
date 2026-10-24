package debugger

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"fastdbg2/display"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
)

func metadataJoinedField(output, label string) string {
	lines := strings.Split(output, "\n")
	for index, line := range lines {
		if !strings.HasPrefix(line, label) {
			continue
		}
		colon := strings.Index(line, ": ")
		if colon < len(label) {
			continue
		}
		prefix := colon + 2
		text := line[prefix:]
		indent := strings.Repeat(" ", prefix)
		for _, next := range lines[index+1:] {
			if !strings.HasPrefix(next, indent) {
				break
			}
			text += strings.TrimPrefix(next, indent)
		}
		return text
	}
	return ""
}

func TestMetadataUIViewCapturesActualOutputWidthBeforeBuffering(t *testing.T) {
	master, slave := pagerTestPTY(t)
	before := [2][2]int{pagerTestFlags(t, master), pagerTestFlags(t, slave)}
	connection, err := slave.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for _, width := range []uint16{80, 120} {
		var resizeErr error
		if err := connection.Control(func(fd uintptr) {
			resizeErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: 30, Col: width})
		}); err != nil || resizeErr != nil {
			t.Fatal(errors.Join(err, resizeErr))
		}
		controller := &Controller{out: slave}
		view := controller.metadataView()
		var other bytes.Buffer
		controller.out = &other
		view.heading("checksec")
		if view.width != int(width) || display.VisibleWidth(strings.TrimSuffix(view.output.String(), "\n")) != int(width) {
			t.Fatalf("TTY width fell back after buffering: width=%d text=%q", view.width, view.output.String())
		}
	}
	if after := [2][2]int{pagerTestFlags(t, master), pagerTestFlags(t, slave)}; after != before {
		t.Fatalf("width query altered caller fd flags: before=%v after=%v", before, after)
	}
}

func TestMetadataUISecurityUsesDeclaredAbsentAndUnknownStates(t *testing.T) {
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		facts elfSecurityFacts
		text  string
		color string
	}{
		{"nx-declared", elfSecurityFacts{kind: elf.ET_DYN, stackKnown: true}, "Enabled", "32"},
		{"nx-absent", elfSecurityFacts{kind: elf.ET_DYN, stackKnown: true, stackExec: true}, "Disabled", "31"},
		{"nx-unknown", elfSecurityFacts{kind: elf.ET_DYN}, "Unknown (no PT_GNU_STACK)", "33"},
		{"relro-partial", elfSecurityFacts{kind: elf.ET_DYN, relro: true}, "Partial", "33"},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := &metadataView{width: 120, renderer: renderer}
			view.security(test.facts)
			want := test.text
			if test.color != "" {
				want = "\x1b[" + test.color + "m" + test.text + "\x1b[0m"
			}
			if !strings.Contains(view.output.String(), want) {
				t.Fatalf("fact state lacks its semantic style: %q", view.output.String())
			}
			if strings.Contains(view.output.String(), "Symbol presence does not establish instrumentation") || strings.Contains(view.output.String(), "Canary: Enabled") {
				t.Fatal("symbol presence was promoted to protection")
			}
		})
	}
}

func TestMetadataUIPathsAndProofsRemainLosslessWithoutDiagnosticWalls(t *testing.T) {
	path := "/" + strings.Repeat("long_日本語_component/", 12) + "quote\"\n\x1b]0;BAD\a"
	for _, width := range []int{80, 120} {
		view := &metadataView{width: width}
		view.module("got", &mappedELF{ID: "main", Path: path, MetadataPath: path, Proof: "proc-exe+auxv", Scope: "executable"})
		view.field("FD 4", strconv.QuoteToGraphic(path)+` flags="0100002"`, metadataPlain)
		text := view.output.String()
		for _, line := range strings.Split(text, "\n") {
			if display.VisibleWidth(line) > width || strings.ContainsAny(line, "\x1b\a\r") {
				t.Fatalf("unsafe or overflowing metadata line: %q", line)
			}
		}
		if metadataJoinedField(text, "File") != strconv.QuoteToGraphic(path) || !strings.Contains(metadataJoinedField(text, "FD 4"), strconv.QuoteToGraphic(path)) {
			t.Fatalf("wrapped source/descriptor identity lost:\n%s", text)
		}
		for _, want := range []string{`Source proof: "proc-exe+auxv"`, `Scope      : "executable"`, "Metadata   : ELF file shown above"} {
			if strings.Contains(text, want) {
				t.Fatalf("internal proof leaked %q:\n%s", want, text)
			}
		}
	}
}

func TestMetadataUIGOTUsesOnlyConfirmedMappingPermissions(t *testing.T) {
	renderer, err := display.NewRenderer(display.Options{Mode: display.ColorAlways})
	if err != nil {
		t.Fatal(err)
	}
	view := &metadataView{width: 80, renderer: renderer}
	mappings := []procMap{{Start: 0x400000, End: 0x401000, Read: true, Execute: true}, {Start: 0x500000, End: 0x501000, Read: true, Write: true}}
	relocation := elfPointerRelocation{address: 0x500008, kind: elf.R_X86_64_JMP_SLOT, symbol: "puts", section: ".rela.plt"}
	view.relocation(relocation, 0x400100, true, mappings)
	view.relocation(relocation, 0, true, mappings)
	view.relocation(relocation, 0, false, mappings)
	text := view.output.String()
	for _, want := range []string{"\x1b[36m0x0000000000500008\x1b[0m", "\x1b[35m0x0000000000400100\x1b[0m", "0x0000000000000000", "<unavailable>", `"puts" / ".rela.plt"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("confirmed slot/value facts missing %q: %q", want, text)
		}
	}
	if strings.Contains(text, "m0x0000000000000000") || strings.Contains(text, "unresolved") || strings.Contains(text, "PLT stub") {
		t.Fatalf("unknown pointer permissions/binding were inferred: %q", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if display.VisibleWidth(line) > 80 {
			t.Fatalf("GOT row overflow: %q", line)
		}
	}
}

func TestMetadataUIPublishDropsStaleCancellationAndPreservesPartialErrors(t *testing.T) {
	for _, mode := range []string{"stale-scope", "stale-detail", "cancelled", "partial", "output"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			controller := &Controller{out: &output}
			view := controller.metadataView()
			view.field("Confirmed", "value", metadataPlain)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var scanErr, detailErr, want error
			switch mode {
			case "stale-scope":
				scanErr, want = target.ErrStale, target.ErrStale
			case "stale-detail":
				detailErr, want = target.ErrStale, target.ErrStale
			case "cancelled":
				cancel()
				want = context.Canceled
			case "partial":
				scanErr = &mappedELFPartialError{Err: target.ErrUnavailable}
				want = target.ErrUnavailable
			case "output":
				want = errors.New("output")
				controller.out = controllerTestWriter(func([]byte) (int, error) { return 0, want })
			}
			err := controller.publishMetadata(ctx, view, scanErr, detailErr)
			if !errors.Is(err, want) {
				t.Fatalf("error cause lost: %v want %v", err, want)
			}
			if mode == "partial" {
				if !strings.Contains(output.String(), "Confirmed") || !strings.Contains(output.String(), "Scope") || !strings.Contains(output.String(), "unavailable") {
					t.Fatal(output.String())
				}
			} else if output.Len() != 0 {
				t.Fatalf("unproven view published: %q", output.String())
			}
		})
	}
}

func TestMetadataUIProcPublicationRevalidatesBeforeWriting(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			fixture, snapshot, thread := newContextFixture()
			if stale {
				fixture.snapshot.Memory.Revision++
			}
			var output bytes.Buffer
			controller := &Controller{session: fixture, out: &output}
			missing := errors.New("field unavailable")
			err := controller.publishProcSections(context.Background(), snapshot, thread, []procSection{{name: "File Descriptors", fields: []procField{{label: "FD 0", value: `"/dev/null"`}, {label: "FD 1", err: missing}}}})
			if !errors.Is(err, missing) || stale != errors.Is(err, target.ErrStale) || stale && output.Len() != 0 || !stale && !strings.Contains(output.String(), `"/dev/null"`) {
				t.Fatalf("proc facts/final proof: %v %q", err, output.String())
			}
		})
	}
}

func TestMetadataUIModuleHeaderCopiesTypedSourceFacts(t *testing.T) {
	module := &mappedELF{ID: "lib", Path: "/target/lib", MetadataPath: "/debug/lib", Scope: "loader", Proof: kernelBuildIDMetadataProof, BuildID: []byte{1, 2, 3}}
	header := newMetadataModuleHeader(module)
	module.Path, module.Proof, module.BuildID[0] = "/changed", "changed", 9
	view := &metadataView{width: 80}
	view.moduleHeader("symbols", header)
	text := view.output.String()
	for _, want := range []string{`"/target/lib"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("typed source facts mutated or disappeared: %q\n%s", want, text)
		}
	}
	if header.metadataPath != "/debug/lib" || header.proof != kernelBuildIDMetadataProof || header.buildID != "010203" || strings.Contains(text, "Source proof") || !header.present || newMetadataModuleHeader(nil).present || strings.Contains(text, "/changed") {
		t.Fatal("source header retained mutable metadata or fabricated presence")
	}
	fieldsOnly := &metadataView{width: 80}
	fieldsOnly.moduleHeader("", header)
	if !strings.HasPrefix(fieldsOnly.output.String(), "File") || strings.Contains(fieldsOnly.output.String(), "[]") {
		t.Fatal("empty title emitted another heading")
	}
}
