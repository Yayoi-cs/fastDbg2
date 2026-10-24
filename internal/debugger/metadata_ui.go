package debugger

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"fastdbg2/display"
	"fastdbg2/target"
)

type metadataState uint8

const (
	metadataPlain metadataState = iota
	metadataPresent
	metadataPartial
	metadataAbsent
	metadataUnknown
)

type metadataView struct {
	arch     target.Architecture
	width    int
	renderer display.Renderer
	output   strings.Builder
}

type metadataModuleHeader struct {
	present      bool
	id           string
	path         string
	metadataPath string
	proof        string
	scope        string
	runtime      bool
	buildID      string
}

func newMetadataModuleHeader(module *mappedELF) metadataModuleHeader {
	if module == nil {
		return metadataModuleHeader{}
	}
	return metadataModuleHeader{
		present: true, id: module.ID, path: module.Path, metadataPath: module.MetadataPath,
		proof: module.Proof, scope: module.Scope, runtime: module.Runtime != nil, buildID: fmt.Sprintf("%x", module.BuildID),
	}
}

func (c *Controller) metadataView() *metadataView {
	return &metadataView{arch: c.abi().arch, width: display.OutputWidth(c.out), renderer: c.renderer}
}

func metadataStyle(state metadataState) display.Style {
	switch state {
	case metadataPresent:
		return display.StyleFlagSet
	case metadataPartial:
		return display.StyleString
	case metadataAbsent:
		return display.StyleError
	case metadataUnknown:
		return display.StyleYellow
	default:
		return display.StyleCyan
	}
}

func (view *metadataView) heading(name string) {
	view.output.WriteString(view.renderer.Section(name, view.width) + "\n")
}

func metadataLines(text string, width, indent int) []string {
	var result []string
	for _, line := range strings.Split(display.Wrap(text, width, indent), "\n") {
		if display.VisibleWidth(line) <= width {
			result = append(result, line)
			continue
		}
		leading := len(line) - len(strings.TrimLeft(line, " "))
		prefixEnd := leading
		if leading == 0 {
			columns := 0
			for index, char := range line {
				if columns >= min(indent, width/2) {
					break
				}
				columns += display.VisibleWidth(string(char))
				prefixEnd = index + utf8.RuneLen(char)
			}
		}
		result = append(result, vmmapQuotedLines(line[:prefixEnd], line[prefixEnd:], width)...)
	}
	return result
}

func (view *metadataView) field(label, value string, state metadataState) {
	prefix := display.Pad(contextEscapedText(label), 11) + ": "
	for index, line := range metadataLines(prefix+value, view.width, len(prefix)) {
		if index == 0 && strings.HasPrefix(line, prefix) {
			view.output.WriteString(prefix)
			view.output.WriteString(view.renderer.Text(metadataStyle(state), line[len(prefix):]) + "\n")
		} else {
			view.output.WriteString(view.renderer.Text(metadataStyle(state), line) + "\n")
		}
	}
}

func (view *metadataView) note(text string, state metadataState) {
	for _, line := range metadataLines(text, view.width, 4) {
		view.output.WriteString(view.renderer.Text(metadataStyle(state), line) + "\n")
	}
}

func (view *metadataView) unavailable(label string, err error) {
	view.field(label, "unavailable: "+strconv.QuoteToGraphic(err.Error()), metadataAbsent)
}

func (view *metadataView) module(title string, module *mappedELF) {
	view.moduleHeader(title, newMetadataModuleHeader(module))
}

func (view *metadataView) moduleHeader(title string, module metadataModuleHeader) {
	if title != "" {
		view.heading(title)
	}
	label := "File"
	if module.runtime {
		label = "Runtime"
	}
	view.field(label, strconv.QuoteToGraphic(module.path), metadataPlain)
}

func (view *metadataView) security(facts elfSecurityFacts) {
	view.field("Type", facts.kind.String(), metadataPlain)
	pie, pieState := "Unknown", metadataUnknown
	if facts.pieFlag {
		pie, pieState = "Enabled", metadataPresent
	}
	if facts.kind == elf.ET_EXEC {
		pie, pieState = "Disabled", metadataAbsent
		if facts.pieFlag {
			pie, pieState = "Inconsistent ELF flags", metadataPartial
		}
	}
	view.field("PIE", pie, pieState)
	nx, nxState := "Unknown (no PT_GNU_STACK)", metadataUnknown
	if facts.stackKnown {
		nx, nxState = "Enabled", metadataPresent
		if facts.stackExec {
			nx, nxState = "Disabled", metadataAbsent
		}
	}
	view.field("NX", nx, nxState)
	relro, relroState := "None", metadataAbsent
	if facts.relro {
		relro, relroState = "Partial", metadataPartial
		if facts.bindNow {
			relro, relroState = "Full", metadataPresent
		}
	}
	view.field("RELRO", relro, relroState)
	stripped, strippedState := "No", metadataPresent
	if !facts.staticKnown {
		stripped, strippedState = "Unknown", metadataUnknown
	} else if !facts.static {
		stripped, strippedState = "Yes", metadataPartial
	}
	view.field("Stripped", stripped, strippedState)
	for _, row := range []struct {
		label string
		names []string
	}{{"Canary", facts.canary}, {"Fortify", facts.fortify}} {
		text, state := "Not found", metadataAbsent
		if !facts.symbols {
			text = "Unknown (no symbols)"
		} else if len(row.names) != 0 {
			text, state = "Found", metadataPresent
		}
		view.field(row.label, text, state)
	}
	if len(facts.rwx) == 0 {
		view.field("RWX", "none", metadataPresent)
	}
	for _, interval := range facts.rwx {
		view.field("RWX", fmt.Sprintf("[%#x, %#x)", interval[0], interval[1]), metadataAbsent)
	}
}

func (view *metadataView) address(address target.Address, mappings []procMap) string {
	text := fmt.Sprintf("0x%0*x", abiFor(view.arch).word*2, address)
	index := sort.Search(len(mappings), func(index int) bool { return mappings[index].End > address })
	if index < len(mappings) && mappings[index].Start <= address {
		mapping := mappings[index]
		return view.renderer.PermissionText(text, mapping.Read, mapping.Write, mapping.Execute)
	}
	return text
}

func (view *metadataView) relocation(relocation elfPointerRelocation, value uint64, known bool, mappings []procMap) {
	slot := view.address(relocation.address, mappings)
	raw := view.renderer.Text(display.StyleMuted, "<unavailable>")
	if known {
		raw = view.address(target.Address(value), mappings)
	}
	kind := relocation.kind.String()
	if view.arch == target.X86 {
		kind = elf.R_386(relocation.kind).String()
	}
	prefix := slot + " " + display.Pad(raw, abiFor(view.arch).word*2+2) + " " + display.Pad(kind, 22)
	suffix := strconv.QuoteToGraphic(relocation.symbol) + " / " + strconv.QuoteToGraphic(relocation.section)
	if display.VisibleWidth(prefix+" "+suffix) <= view.width {
		view.output.WriteString(prefix + " " + view.renderer.Text(display.StyleSymbol, suffix) + "\n")
		return
	}
	view.output.WriteString(strings.TrimRight(prefix, " ") + "\n")
	for _, line := range metadataLines("    "+suffix, view.width, 4) {
		view.output.WriteString(view.renderer.Text(display.StyleSymbol, line) + "\n")
	}
}

func (c *Controller) publishMetadata(ctx context.Context, view *metadataView, scanErr, detailErr error) error {
	if !mappedELFResultUsable(scanErr) || uiDisplayFatal(detailErr) || contextReady(ctx) != nil {
		return errors.Join(scanErr, detailErr, contextReady(ctx))
	}
	if scanErr != nil {
		view.unavailable("Scope", scanErr)
	}
	return errors.Join(c.writef("%s", view.output.String()), scanErr, detailErr)
}

func (view *metadataView) procSections(ctx context.Context, sections []procSection) error {
	var failures []error
	for _, section := range sections {
		if err := contextReady(ctx); err != nil {
			return errors.Join(append(failures, err)...)
		}
		view.heading(section.name)
		for _, field := range section.fields {
			if err := contextReady(ctx); err != nil {
				return errors.Join(append(failures, err)...)
			}
			if field.err != nil {
				failures = append(failures, fmt.Errorf("%s / %s: %w", section.name, field.label, field.err))
				view.unavailable(field.label, field.err)
			} else {
				view.field(field.label, field.value, metadataPlain)
			}
		}
	}
	return errors.Join(failures...)
}

func (c *Controller) publishProcSections(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, sections []procSection) error {
	view := c.metadataView()
	detailErr := view.procSections(ctx, sections)
	if err := contextReady(ctx); err != nil {
		return errors.Join(detailErr, err)
	}
	if err := errors.Join(c.verifyProcSnapshot(snapshot, thread), ctx.Err()); err != nil {
		return errors.Join(detailErr, err)
	}
	return errors.Join(detailErr, c.writef("%s", view.output.String()))
}
