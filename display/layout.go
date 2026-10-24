package display

import (
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"fastdbg2/target"
	"golang.org/x/term"
	"golang.org/x/text/width"
)

const DefaultWidth = 100

var layoutSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func Pad(text string, columns int) string {
	return text + strings.Repeat(" ", max(0, columns-VisibleWidth(text)))
}

func layoutTokenEnd(text string, start int) int {
	first := start
	for first < len(text) {
		index := layoutSGR.FindStringIndex(text[first:])
		if index == nil || index[0] != 0 {
			break
		}
		first += index[1]
	}
	var closing byte
	if first < len(text) {
		switch text[first] {
		case '[':
			closing = ']'
		case '<':
			closing = '>'
		case '"':
			closing = '"'
		case '\'':
			closing = '\''
		}
	}
	if closing != 0 {
		for end := first + 1; end < len(text); end++ {
			if text[end] == '\x1b' {
				if index := layoutSGR.FindStringIndex(text[end:]); index != nil && index[0] == 0 {
					end += index[1] - 1
					continue
				}
			}
			if (closing == '"' || closing == '\'') && text[end] == '\\' {
				end++
				continue
			}
			if text[end] == closing {
				end++
				if closing == '\'' && strings.HasPrefix(text[end:], "...") {
					end += 3
				}
				for end < len(text) {
					index := layoutSGR.FindStringIndex(text[end:])
					if index == nil || index[0] != 0 {
						break
					}
					end += index[1]
				}
				return end
			}
		}
	}
	end := start
	for end < len(text) && text[end] != ' ' && text[end] != '\t' {
		end++
	}
	return end
}

func VisibleWidth(text string) int {
	columns := 0
	for _, char := range layoutSGR.ReplaceAllString(text, "") {
		if unicode.Is(unicode.Mn, char) || unicode.Is(unicode.Me, char) || unicode.Is(unicode.Cf, char) {
			continue
		}
		switch width.LookupRune(char).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			columns += 2
		default:
			columns++
		}
	}
	return columns
}

func Wrap(text string, width, indent int) string {
	if width <= 0 {
		width = DefaultWidth
	}
	width = min(width, 512)
	indent = max(0, min(indent, width/2))
	var output strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		body := strings.TrimSuffix(line, "\n")
		if VisibleWidth(body) <= width {
			output.WriteString(line)
			continue
		}
		column := 0
		for len(body) != 0 {
			spaceEnd := 0
			for spaceEnd < len(body) && (body[spaceEnd] == ' ' || body[spaceEnd] == '\t') {
				spaceEnd++
			}
			end := layoutTokenEnd(body, spaceEnd)
			spaces, word := body[:spaceEnd], body[spaceEnd:end]
			columns := VisibleWidth(spaces) + VisibleWidth(word)
			if column > indent && column+columns > width {
				output.WriteByte('\n')
				output.WriteString(strings.Repeat(" ", indent))
				column, spaces = indent, ""
			}
			output.WriteString(spaces)
			output.WriteString(word)
			column += VisibleWidth(spaces) + VisibleWidth(word)
			body = body[end:]
		}
		if strings.HasSuffix(line, "\n") {
			output.WriteByte('\n')
		}
	}
	return output.String()
}

func OutputWidth(output io.Writer) int {
	file, ok := output.(*os.File)
	if !ok {
		return DefaultWidth
	}
	connection, err := file.SyscallConn()
	if err != nil {
		return DefaultWidth
	}
	width := DefaultWidth
	err = connection.Control(func(fd uintptr) {
		if columns, _, sizeErr := term.GetSize(int(fd)); sizeErr == nil && columns > 0 {
			width = columns
		}
	})
	if err != nil {
		return DefaultWidth
	}
	return min(width, 512)
}

func (r Renderer) Section(name string, width int) string {
	if width <= 0 {
		width = DefaultWidth
	}
	width = min(width, 512)
	quoted := strconv.QuoteToGraphic(name)
	label := "[" + quoted[1:len(quoted)-1] + "]"
	padding := max(0, width-VisibleWidth(label))
	left := padding / 2
	return r.Text(StyleMuted, strings.Repeat("-", left)) + r.Text(StyleHeading, label) + r.Text(StyleMuted, strings.Repeat("-", padding-left))
}

func (r Renderer) AddressPermissions(arch target.Architecture, address target.Address, read, write, execute bool) (string, error) {
	value, err := (Renderer{}).Address(arch, address, AddressUnknown)
	if err != nil {
		return "", err
	}
	return r.PermissionText(value, read, write, execute), nil
}

func (r Renderer) PermissionText(text string, read, write, execute bool) string {
	code := ""
	switch {
	case read && write && execute:
		code = "33"
	case execute:
		code = codeColor
	case read && write:
		code = "36"
	case read:
		code = "34"
	case write:
		code = "32"
	}
	return r.paint(code, text)
}
