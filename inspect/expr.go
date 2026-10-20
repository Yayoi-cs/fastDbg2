package inspect

import (
	"fmt"
	"go/token"
	"math"
	"math/bits"
	"strconv"
	"strings"

	"fastdbg2/target"
)

type ExpressionResolver interface {
	ResolveRegister(name string) (uint64, error)
	ResolveSymbol(name string) (uint64, error)
}

const (
	maxExpressionBytes = 64 << 10
	maxExpressionDepth = 256
)

type expressionToken struct {
	kind     token.Token
	text     string
	position int
	register bool
}

type expressionParser struct {
	input    string
	position int
	depth    int
	current  expressionToken
	resolver ExpressionResolver
}

func EvalExpression(expression string, resolver ExpressionResolver) (uint64, error) {
	if len(expression) > maxExpressionBytes {
		return 0, fmt.Errorf("%w: expression exceeds %d bytes", target.ErrInvalidArgument, maxExpressionBytes)
	}
	p := expressionParser{input: expression, resolver: resolver}
	if err := p.next(); err != nil {
		return 0, err
	}
	value, err := p.parse(1)
	if err != nil {
		return 0, err
	}
	if p.current.kind != token.EOF {
		return 0, p.invalid("unexpected token %q", p.current.text)
	}
	return value, nil
}

func (p *expressionParser) invalid(format string, args ...any) error {
	return fmt.Errorf("%w at byte %d: %s", target.ErrInvalidArgument, p.current.position, fmt.Sprintf(format, args...))
}

func (p *expressionParser) next() error {
	for p.position < len(p.input) && strings.ContainsRune(" \t\r\n\v\f", rune(p.input[p.position])) {
		p.position++
	}
	start := p.position
	p.current = expressionToken{kind: token.EOF, position: start}
	if start == len(p.input) {
		return nil
	}
	c := p.input[p.position]
	p.position++
	switch {
	case c >= '0' && c <= '9':
		for p.position < len(p.input) && expressionNameByte(p.input[p.position], false) {
			p.position++
		}
		p.current.kind = token.INT
	case expressionNameByte(c, true) || c == '$':
		p.current.kind = token.IDENT
		p.current.register = c == '$'
		if c == '$' {
			if p.position == len(p.input) || !expressionNameByte(p.input[p.position], true) {
				return p.invalid("expected a register name after $")
			}
			start++
			p.position++
		}
		for p.position < len(p.input) && expressionNameByte(p.input[p.position], false) {
			p.position++
		}
	case c == '`':
		end := strings.IndexByte(p.input[p.position:], '`')
		if end < 0 {
			return p.invalid("unterminated symbol name")
		}
		if end == 0 {
			return p.invalid("empty symbol name")
		}
		p.current.kind = token.STRING
		p.current.text = p.input[p.position : p.position+end]
		p.position += end + 1
		return nil
	default:
		switch c {
		case '+':
			p.current.kind = token.ADD
		case '-':
			p.current.kind = token.SUB
		case '*':
			p.current.kind = token.MUL
		case '/':
			p.current.kind = token.QUO
		case '%':
			p.current.kind = token.REM
		case '&':
			p.current.kind = token.AND
		case '|':
			p.current.kind = token.OR
		case '^':
			p.current.kind = token.XOR
		case '(':
			p.current.kind = token.LPAREN
		case ')':
			p.current.kind = token.RPAREN
		case '<', '>':
			if p.position == len(p.input) || p.input[p.position] != c {
				return p.invalid("expected %c%c", c, c)
			}
			p.position++
			p.current.kind = token.SHL
			if c == '>' {
				p.current.kind = token.SHR
			}
		default:
			return p.invalid("unexpected byte %q", c)
		}
	}
	p.current.text = p.input[start:p.position]
	return nil
}

func expressionNameByte(c byte, first bool) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || !first && c >= '0' && c <= '9'
}

func (p *expressionParser) parse(precedence int) (uint64, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxExpressionDepth {
		return 0, p.invalid("expression exceeds depth %d", maxExpressionDepth)
	}
	left, err := p.value()
	if err != nil {
		return 0, err
	}
	for p.current.kind.Precedence() >= precedence {
		op := p.current
		if err := p.next(); err != nil {
			return 0, err
		}
		right, err := p.parse(op.kind.Precedence() + 1)
		if err != nil {
			return 0, err
		}
		left, err = expressionBinary(op.kind, left, right)
		if err != nil {
			return 0, fmt.Errorf("operator %s at byte %d: %w", op.kind, op.position, err)
		}
	}
	return left, nil
}

func (p *expressionParser) value() (uint64, error) {
	t := p.current
	switch t.kind {
	case token.INT:
		if err := p.next(); err != nil {
			return 0, err
		}
		base, digits := 10, t.text
		if len(digits) >= 2 && digits[0] == '0' {
			switch digits[1] {
			case 'x', 'X':
				base, digits = 16, digits[2:]
			case 'b', 'B':
				base, digits = 2, digits[2:]
			case 'o', 'O':
				base, digits = 8, digits[2:]
			}
		}
		value, err := strconv.ParseUint(digits, base, 64)
		if err != nil {
			kind := target.ErrInvalidArgument
			if number, ok := err.(*strconv.NumError); ok && number.Err == strconv.ErrRange {
				kind = target.ErrOverflow
			}
			return 0, fmt.Errorf("%w at byte %d: invalid integer %q", kind, t.position, t.text)
		}
		return value, nil
	case token.IDENT, token.STRING:
		if err := p.next(); err != nil {
			return 0, err
		}
		if p.resolver == nil {
			return 0, fmt.Errorf("%w: resolver required for %q", target.ErrUnavailable, t.text)
		}
		if t.register {
			value, err := p.resolver.ResolveRegister(t.text)
			if err != nil {
				return 0, fmt.Errorf("register %q: %w", t.text, err)
			}
			return value, nil
		}
		value, err := p.resolver.ResolveSymbol(t.text)
		if err != nil {
			return 0, fmt.Errorf("symbol %q: %w", t.text, err)
		}
		return value, nil
	case token.LPAREN:
		if err := p.next(); err != nil {
			return 0, err
		}
		value, err := p.parse(1)
		if err != nil {
			return 0, err
		}
		if p.current.kind != token.RPAREN {
			return 0, p.invalid("expected closing parenthesis")
		}
		return value, p.next()
	case token.ADD:
		if err := p.next(); err != nil {
			return 0, err
		}
		return p.parse(token.UnaryPrec)
	case token.SUB:
		return 0, p.invalid("negative values are not supported")
	default:
		return 0, p.invalid("expected an integer, register, symbol, or parenthesized expression")
	}
}

func expressionBinary(op token.Token, left, right uint64) (uint64, error) {
	switch op {
	case token.ADD:
		value, carry := bits.Add64(left, right, 0)
		if carry != 0 {
			return 0, target.ErrOverflow
		}
		return value, nil
	case token.SUB:
		if right > left {
			return 0, target.ErrOverflow
		}
		return left - right, nil
	case token.MUL:
		hi, lo := bits.Mul64(left, right)
		if hi != 0 {
			return 0, target.ErrOverflow
		}
		return lo, nil
	case token.QUO, token.REM:
		if right == 0 {
			return 0, fmt.Errorf("%w: division by zero", target.ErrInvalidArgument)
		}
		if op == token.REM {
			return left % right, nil
		}
		return left / right, nil
	case token.SHL, token.SHR:
		if right >= 64 {
			return 0, fmt.Errorf("%w: shift count must be less than 64", target.ErrInvalidArgument)
		}
		if op == token.SHR {
			return left >> right, nil
		}
		if left > math.MaxUint64>>right {
			return 0, target.ErrOverflow
		}
		return left << right, nil
	case token.AND:
		return left & right, nil
	case token.OR:
		return left | right, nil
	case token.XOR:
		return left ^ right, nil
	default:
		return 0, fmt.Errorf("%w: unsupported operator %s", target.ErrInvalidArgument, op)
	}
}
