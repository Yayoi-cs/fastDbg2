package debugger

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"fastdbg2/display"
	"fastdbg2/target"
)

func (c *Controller) publishVMMap(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, text string) error {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if err := errors.Join(c.verifyProcSnapshot(snapshot, thread), ctx.Err()); err != nil {
		return err
	}
	return c.writef("%s", text)
}

func renderVMMap(ctx context.Context, mappings []procMap, filter string, width int, renderer display.Renderer, architectures ...target.Architecture) (string, error) {
	if err := contextReady(ctx); err != nil {
		return "", err
	}
	if width <= 0 {
		width = display.DefaultWidth
	}
	width = min(width, 512)
	arch := target.AMD64
	if len(architectures) > 0 {
		arch = architectures[0]
	}
	digits := abiFor(arch).word * 2
	var selected []procMap
	sizeWidth, offsetWidth := 8, 8
	deviceWidth, inodeWidth := len("Dev"), len("Inode")
	for _, mapping := range mappings {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		if mapping.Start >= mapping.End {
			return "", fmt.Errorf("mapping range is invalid: %w", target.ErrInvalidArgument)
		}
		if !strings.Contains(mapping.Path, filter) {
			continue
		}
		selected = append(selected, mapping)
		sizeWidth = max(sizeWidth, len(strconv.FormatUint(uint64(mapping.End-mapping.Start), 16)))
		offsetWidth = max(offsetWidth, len(strconv.FormatUint(mapping.Offset, 16)))
		deviceWidth = max(deviceWidth, len(fmt.Sprintf("%x:%x", mapping.DevMajor, mapping.DevMinor)))
		inodeWidth = max(inodeWidth, len(strconv.FormatUint(mapping.Inode, 10)))
	}
	var output strings.Builder
	output.WriteString(renderer.Section("vmmap", width) + "\n")
	heading := fmt.Sprintf("%-*s %-*s %-*s %-*s %-4s %-*s %-*s Path", digits+2, "Start", digits+2, "End", sizeWidth+2, "Size", offsetWidth+2, "Offset", "Perm", deviceWidth, "Dev", inodeWidth, "Inode")
	output.WriteString(renderer.Text(display.StyleHeading, display.Wrap(heading, width, 4)) + "\n")
	for _, mapping := range selected {
		if err := contextReady(ctx); err != nil {
			return "", err
		}
		base := fmt.Sprintf("0x%0*x 0x%0*x 0x%0*x 0x%0*x %s", digits, mapping.Start, digits, mapping.End, sizeWidth, mapping.End-mapping.Start, offsetWidth, mapping.Offset, mapping.permissions())
		metadata := fmt.Sprintf("%-*s %-*d ", deviceWidth, fmt.Sprintf("%x:%x", mapping.DevMajor, mapping.DevMinor), inodeWidth, mapping.Inode)
		path := strconv.QuoteToGraphic(mapping.Path)
		var lines []string
		if display.VisibleWidth(base+" "+metadata+path) <= width {
			lines = []string{base + " " + metadata + path}
		} else if display.VisibleWidth(base+" "+strings.TrimRight(metadata, " ")) <= width {
			lines = []string{base + " " + strings.TrimRight(metadata, " ")}
			lines = append(lines, vmmapQuotedLines("    ", path, width)...)
		} else {
			lines = strings.Split(display.Wrap(base, width, 4), "\n")
			lines = append(lines, vmmapQuotedLines("    "+metadata, path, width)...)
		}
		for _, line := range lines {
			output.WriteString(renderer.PermissionText(line, mapping.Read, mapping.Write, mapping.Execute) + "\n")
		}
	}
	if err := contextReady(ctx); err != nil {
		return "", err
	}
	return output.String(), nil
}

func vmmapQuotedLines(prefix, quoted string, width int) []string {
	indent := strings.Repeat(" ", min(display.VisibleWidth(prefix), max(0, width/2)))
	var lines []string
	line, columns := prefix, display.VisibleWidth(prefix)
	for len(quoted) != 0 {
		_, length := utf8.DecodeRuneInString(quoted)
		if quoted[0] == '\\' && len(quoted) > 1 {
			length = 2
			switch quoted[1] {
			case 'x':
				length = 4
			case 'u':
				length = 6
			case 'U':
				length = 10
			}
			length = min(length, len(quoted))
		}
		part := quoted[:length]
		partWidth := display.VisibleWidth(part)
		if columns+partWidth > width && columns > len(indent) {
			lines = append(lines, line)
			line, columns = indent, len(indent)
		}
		line += part
		columns += partWidth
		quoted = quoted[length:]
	}
	return append(lines, line)
}
