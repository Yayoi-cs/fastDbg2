package display

import (
	"fmt"

	"fastdbg2/target"
)

const codeColor = "31"

type ColorMode uint8

const (
	ColorAuto ColorMode = iota
	ColorNever
	ColorAlways
)

type Options struct {
	Mode       ColorMode
	IsTerminal bool
	Term       string
	NoColor    string
}

type Style uint8

const (
	StylePlain Style = iota
	StyleHeading
	StyleError
	StyleMuted
	StyleRegister
	StyleChanged
	StyleCurrent
	StyleSymbol
	StyleFlagSet
	StyleString
)

type Renderer struct {
	color bool
}

func NewRenderer(options Options) (Renderer, error) {
	switch options.Mode {
	case ColorAuto:
		return Renderer{color: options.IsTerminal && options.Term != "dumb" && options.NoColor == ""}, nil
	case ColorNever:
		return Renderer{}, nil
	case ColorAlways:
		return Renderer{color: true}, nil
	default:
		return Renderer{}, fmt.Errorf("color mode %d: %w", options.Mode, target.ErrInvalidArgument)
	}
}

func (r Renderer) Text(style Style, text string) string {
	var code string
	switch style {
	case StyleHeading:
		code = "1"
	case StyleError:
		code = "31"
	case StyleMuted:
		code = "2"
	case StyleRegister:
		code = "1;34"
	case StyleChanged:
		code = "1;31"
	case StyleCurrent:
		code = "1;32"
	case StyleSymbol:
		code = "36"
	case StyleFlagSet:
		code = "1;32"
	case StyleString:
		code = "33"
	}
	return r.paint(code, text)
}

func (r Renderer) paint(code, text string) string {
	if !r.color || code == "" || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}
