package display

import (
	"fmt"

	"fastdbg2/target"
)

const codeColor = "35"

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
	StyleRed
	StyleGreen
	StyleYellow
	StyleBlue
	StylePurple
	StyleCyan
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
	case StyleError:
		code = "31"
	case StyleChanged:
		code = "31"
	case StyleCurrent:
		code = "32"
	case StyleSymbol:
		code = "36"
	case StyleFlagSet:
		code = "32"
	case StyleString, StyleYellow:
		code = "33"
	case StyleRed:
		code = "31"
	case StyleGreen:
		code = "32"
	case StyleBlue:
		code = "34"
	case StylePurple:
		code = "35"
	case StyleCyan:
		code = "36"
	}
	return r.paint(code, text)
}

func (r Renderer) paint(code, text string) string {
	if !r.color || code == "" || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}
