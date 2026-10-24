package debugger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"fastdbg2/display"
	"fastdbg2/target"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type findructionUI struct {
	groups                                  []findructionGroup
	pattern                                 []byte
	partial                                 bool
	focus, group, match, scroll, horizontal int
}

func (u *findructionUI) current() *findructionMatch {
	if u.group < 0 || u.group >= len(u.groups) || u.match < 0 || u.match >= len(u.groups[u.group].matches) {
		return nil
	}
	return &u.groups[u.group].matches[u.match]
}

func (u *findructionUI) move(delta int) {
	switch u.focus {
	case 0:
		next := max(0, min(len(u.groups)-1, u.group+delta))
		if next != u.group {
			u.group, u.match, u.scroll, u.horizontal = next, 0, 0, 0
		}
	case 1:
		next := max(0, min(len(u.groups[u.group].matches)-1, u.match+delta))
		if next != u.match {
			u.match, u.scroll, u.horizontal = next, 0, 0
		}
	case 2:
		limit := 0
		if m := u.current(); m != nil {
			limit = len(m.instructions) + 3
		}
		u.scroll = max(0, min(limit, u.scroll+delta))
	}
}

func (u *findructionUI) key(key string, height int) bool {
	switch key {
	case "q", "\x1b", "\x03", "\x04":
		return true
	case "\t":
		u.focus = (u.focus + 1) % 3
		u.horizontal = 0
	case "\x1b[Z":
		u.focus = (u.focus + 2) % 3
		u.horizontal = 0
	case "j", "\x1b[B", "\x1bOB":
		u.move(1)
	case "k", "\x1b[A", "\x1bOA":
		u.move(-1)
	case "\x1b[6~", "\x06":
		u.move(max(1, height-5))
	case "\x1b[5~", "\x02":
		u.move(-max(1, height-5))
	case "g", "\x1b[H", "\x1bOH", "\x1b[1~":
		u.move(-searchMaximumMatches)
	case "G", "\x1b[F", "\x1bOF", "\x1b[4~":
		u.move(searchMaximumMatches)
	case "l", "\x1b[C", "\x1bOC":
		u.horizontal = min(4096, u.horizontal+8)
	case "h", "\x1b[D", "\x1bOD":
		u.horizontal = max(0, u.horizontal-8)
	case "\r", "\n":
		u.focus = (u.focus + 1) % 3
		u.horizontal = 0
	}
	if m := u.current(); m != nil {
		count := len(m.instructions) + 2
		if u.groups[u.group].file {
			count++
		}
		if m.readErr != nil {
			count++
		}
		if len(m.instructions) == 0 {
			count++
		}
		u.scroll = min(u.scroll, max(0, count-max(1, height-5)))
	}
	return false
}

func findructionClip(text string, skip, width int) string {
	if width <= 0 {
		return ""
	}
	var out strings.Builder
	columns, shown := 0, 0
	colored := false
	for len(text) > 0 {
		if strings.HasPrefix(text, "\x1b[") {
			end := strings.IndexByte(text, 'm')
			if end >= 0 {
				out.WriteString(text[:end+1])
				colored = true
				text = text[end+1:]
				continue
			}
		}
		r, n := utf8.DecodeRuneInString(text)
		text = text[n:]
		w := display.VisibleWidth(string(r))
		if columns < skip {
			columns += w
			continue
		}
		if shown+w > width {
			break
		}
		out.WriteRune(r)
		shown += w
	}
	if colored {
		out.WriteString("\x1b[0m")
	}
	return display.Pad(out.String(), width)
}

func (u *findructionUI) frame(renderer display.Renderer, width, height int) string {
	width = max(1, min(width, 512))
	height = max(1, min(height, 256))
	rows := make([]string, height)
	status := ""
	if u.partial {
		status = " (partial)"
	}
	rows[0] = renderer.Text(display.StyleGreen, "findruction") + fmt.Sprintf("  pattern=%x  %d match(es) / %d groups%s", u.pattern, findructionTotal(u.groups), len(u.groups), status)
	if height < 6 || width < 50 {
		if height > 1 {
			rows[1] = "Resize terminal (50x6 minimum); q quits"
		}
	} else {
		g := u.groups[u.group]
		rows[1] = contextEscapedText(g.label) + fmt.Sprintf(" [0x%x-0x%x)", g.start, g.end)
		widths := [3]int{max(12, width/4), 24, 0}
		widths[2] = width - widths[0] - widths[1] - 2
		titles := []string{fmt.Sprintf("libraries (%d)", len(u.groups)), fmt.Sprintf("matches (%d)", len(g.matches)), "disassembly"}
		for i := range titles {
			prefix := "  "
			if i == u.focus {
				prefix = "> "
			}
			titles[i] = findructionClip(renderer.Text(display.StyleYellow, prefix+titles[i]), 0, widths[i])
		}
		rows[2] = strings.Join(titles, "|")
		available := height - 5
		groupStart := max(0, u.group-available+1)
		matchStart := max(0, u.match-available+1)
		var code []string
		if m := u.current(); m != nil {
			field := "vaddr"
			if g.file {
				field = "elf-vaddr"
			}
			code = append(code, fmt.Sprintf("%s=0x%0*x", field, abiFor(g.arch).word*2, m.address))
			if g.file {
				code = append(code, fmt.Sprintf("file-offset=0x%x", m.offset))
			}
			code = append(code, "")
			for _, in := range m.instructions {
				code = append(code, findructionInsn(renderer, in, g.arch))
			}
			if len(m.instructions) == 0 {
				code = append(code, "<unable to disassemble>")
			}
			if m.readErr != nil {
				code = append(code, "<context unreadable or partial>")
			}
		}
		for row := 0; row < available; row++ {
			cells := make([]string, 3)
			if i := groupStart + row; i < len(u.groups) {
				group := u.groups[i]
				label := fmt.Sprintf("%s (%d)", filepath.Base(group.label), len(group.matches))
				prefix := "  "
				if i == u.group {
					prefix = "> "
					label = renderer.Text(display.StyleGreen, contextEscapedText(label))
				} else {
					label = contextEscapedText(label)
				}
				cells[0] = prefix + label
			}
			if i := matchStart + row; i < len(g.matches) {
				label := fmt.Sprintf("0x%0*x", abiFor(g.arch).word*2, g.matches[i].address)
				prefix := "  "
				if i == u.match {
					prefix = "> "
					label = renderer.Text(display.StyleGreen, label)
				} else {
					label = renderer.Text(display.StyleCyan, label)
				}
				cells[1] = prefix + label
			}
			if i := u.scroll + row; i < len(code) {
				cells[2] = code[i]
			}
			for i := range cells {
				offset := 0
				if i == u.focus {
					offset = u.horizontal
				}
				cells[i] = findructionClip(cells[i], offset, widths[i])
			}
			rows[row+3] = strings.Join(cells, "|")
		}
		rows[height-2] = "Tab/Shift-Tab focus  Up/Down j/k select  PgUp/PgDn scroll"
		rows[height-1] = "Left/Right h/l pan  Home/End g/G  q/Esc/Ctrl-C quit"
	}
	var out strings.Builder
	for i, row := range rows {
		fmt.Fprintf(&out, "\x1b[%d;1H\x1b[2K%s", i+1, findructionClip(row, 0, width))
	}
	return out.String()
}

func findructionKey(input []byte) (string, int) {
	if len(input) == 0 {
		return "", 0
	}
	if input[0] != 27 {
		return string(input[:1]), 1
	}
	if len(input) == 1 {
		return "", 0
	}
	if input[1] != '[' && input[1] != 'O' {
		return "\x1b", 1
	}
	for i := 2; i < len(input); i++ {
		if input[i] >= 0x40 && input[i] <= 0x7e {
			return string(input[:i+1]), i + 1
		}
	}
	if len(input) > 32 {
		return "ignored", len(input)
	}
	return "", 0
}

func findructionFD(file *os.File) (int, error) {
	connection, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	err = connection.Control(func(value uintptr) { fd = int(value) })
	return fd, err
}

func (c *Controller) findructionTUI(ctx context.Context, groups []findructionGroup, pattern []byte, partial bool) (err error) {
	if err := contextReady(ctx); err != nil {
		return err
	}
	if c.pager == nil || c.pager.input == nil || c.pager.output == nil || len(groups) == 0 {
		return target.ErrInvalidArgument
	}
	input, err := findructionFD(c.pager.input)
	if err != nil {
		return err
	}
	output, err := findructionFD(c.pager.output)
	if err != nil {
		return err
	}
	state, err := term.MakeRaw(input)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, term.Restore(input, state)) }()
	defer func() { err = errors.Join(err, c.writef("\x1b[?25h\x1b[?1049l")) }()
	if err := c.writef("\x1b[?1049h\x1b[?25l\x1b[2J"); err != nil {
		return err
	}
	ui := findructionUI{groups: groups, pattern: pattern, partial: partial}
	for i, g := range groups {
		if len(g.matches) > 0 {
			ui.group = i
			break
		}
	}
	width, height := 0, 0
	dirty := true
	var pending []byte
	var escapeAt time.Time
	for {
		if err := contextReady(ctx); err != nil {
			return err
		}
		w, h, sizeErr := term.GetSize(output)
		if sizeErr != nil {
			return sizeErr
		}
		w, h = max(1, min(w, 512)), max(1, min(h, 256))
		if w != width || h != height {
			width, height = w, h
			dirty = true
			if err := c.writef("\x1b[2J"); err != nil {
				return err
			}
		}
		if dirty {
			if err := c.writef("%s", ui.frame(c.renderer, width, height)); err != nil {
				return err
			}
			dirty = false
		}
		fds := []unix.PollFd{{Fd: int32(input), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 50)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL|unix.POLLHUP) != 0 {
			return io.EOF
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			var buffer [128]byte
			n, err := unix.Read(input, buffer[:])
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return io.EOF
			}
			pending = append(pending, buffer[:n]...)
		}
		for len(pending) > 0 {
			key, n := findructionKey(pending)
			if n == 0 {
				if escapeAt.IsZero() {
					escapeAt = time.Now()
				}
				if time.Since(escapeAt) < 150*time.Millisecond {
					break
				}
				key, n = "\x1b", len(pending)
			}
			escapeAt = time.Time{}
			pending = pending[n:]
			if ui.key(key, height) {
				return nil
			}
			dirty = true
		}
	}
}
