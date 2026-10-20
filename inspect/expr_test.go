package inspect

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"fastdbg2/target"
)

func TestEvalExpression(t *testing.T) {
	tests := []struct {
		expression string
		want       uint64
	}{
		{"0", 0},
		{" 42\t\n", 42},
		{"010", 10},
		{"08", 8},
		{"0xFf", 255},
		{"0XFF", 255},
		{"0b10101", 21},
		{"0B10101", 21},
		{"0o17", 15},
		{"0O17", 15},
		{"18446744073709551615", math.MaxUint64},
		{"0xffffffffffffffff", math.MaxUint64},
		{"1 + 2 * 3", 7},
		{"(1 + 2) * 3", 9},
		{"20 / 3", 6},
		{"20 % 3", 2},
		{"20 - 3 - 2", 15},
		{"32 / 2 / 4", 4},
		{"1 << 3 + 1", 9},
		{"1 + 2 << 3", 17},
		{"64 >> 2", 16},
		{"255 & 0x7f", 127},
		{"1 | 2 ^ 3", 0},
		{"1 | (2 ^ 3)", 1},
		{"7 ^ 3", 4},
		{"1 << 63", 1 << 63},
		{"0xffffffffffffffff >> 63", 1},
		{"+++7", 7},
		{"+(1 + 2) * +3", 9},
	}
	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			got, err := EvalExpression(tt.expression, nil)
			if err != nil || got != tt.want {
				t.Fatalf("EvalExpression(%q) = %d, %v; want %d", tt.expression, got, err, tt.want)
			}
		})
	}
}

func TestEvalExpressionInvalid(t *testing.T) {
	for _, expression := range []string{
		"", " ", "()", "(1", "1)", "1 2", "1 +", "*1", "1**2", "1//2", "1/*2*/3",
		"0x", "0o8", "0b2", "1_000", "0x_ff", "123name", "1.5", "1e3", "1;2", "1,2",
		"-1", "-0", "1+-2", "~1", "^1", "1 && 2", "1 || 2", "1 &^ 2", "1 < 2", "1 >>> 2",
		"1 / 0", "1 % 0", "0 << 64", "1 >> 64", "1 << 18446744073709551615",
		"$", "$1", "$`rip`", "`", "``", "'x'", "\"name\"", "1[0]", "1=2", "1==2",
	} {
		t.Run(expression, func(t *testing.T) {
			if got, err := EvalExpression(expression, nil); !errors.Is(err, target.ErrInvalidArgument) {
				t.Fatalf("EvalExpression(%q) = %d, %v; want ErrInvalidArgument", expression, got, err)
			}
		})
	}
}

func TestEvalExpressionOverflow(t *testing.T) {
	for _, expression := range []string{
		"18446744073709551616", "0x10000000000000000", "18446744073709551615+1",
		"18446744073709551615*2", "0-1", "(0-1)+1", "2<<63", "0xffffffffffffffff<<1",
	} {
		t.Run(expression, func(t *testing.T) {
			if got, err := EvalExpression(expression, nil); !errors.Is(err, target.ErrOverflow) {
				t.Fatalf("EvalExpression(%q) = %d, %v; want ErrOverflow", expression, got, err)
			}
		})
	}
}

type testExpressionResolver struct {
	registers map[string]uint64
	symbols   map[string]uint64
	lookupErr error
	calls     []string
}

func (r *testExpressionResolver) ResolveRegister(name string) (uint64, error) {
	r.calls = append(r.calls, "register:"+name)
	if value, ok := r.registers[name]; ok {
		return value, nil
	}
	return 0, r.lookupErr
}

func (r *testExpressionResolver) ResolveSymbol(name string) (uint64, error) {
	r.calls = append(r.calls, "symbol:"+name)
	if value, ok := r.symbols[name]; ok {
		return value, nil
	}
	return 0, r.lookupErr
}

func TestEvalExpressionExplicitNamespaces(t *testing.T) {
	r := &testExpressionResolver{
		registers: map[string]uint64{"rip": 0x100},
		symbols:   map[string]uint64{"rip": 0x20, "main.main": 0x10, "a+b@version": 2},
		lookupErr: target.ErrNotFound,
	}
	got, err := EvalExpression("$rip + rip + `main.main` + `a+b@version`", r)
	wantCalls := []string{"register:rip", "symbol:rip", "symbol:main.main", "symbol:a+b@version"}
	if err != nil || got != 0x132 || !reflect.DeepEqual(r.calls, wantCalls) {
		t.Fatalf("got %#x, %v, %v; want %#x, nil, %v", got, err, r.calls, 0x132, wantCalls)
	}
}

func TestEvalExpressionDoesNotFallBack(t *testing.T) {
	for _, lookupErr := range []error{target.ErrNotFound, target.ErrUnavailable, target.ErrAmbiguous, errors.New("read failed")} {
		for _, expression := range []string{"$symbol_only", "register_only"} {
			r := &testExpressionResolver{
				registers: map[string]uint64{"register_only": 1},
				symbols:   map[string]uint64{"symbol_only": 2},
				lookupErr: lookupErr,
			}
			if _, err := EvalExpression(expression, r); !errors.Is(err, lookupErr) || len(r.calls) != 1 {
				t.Fatalf("EvalExpression(%q) = %v, calls %v; want %v and one lookup", expression, err, r.calls, lookupErr)
			}
		}
	}
}

func TestEvalExpressionRequiresResolver(t *testing.T) {
	for _, expression := range []string{"$rip", "main", "`main.main`"} {
		if _, err := EvalExpression(expression, nil); !errors.Is(err, target.ErrUnavailable) {
			t.Fatalf("EvalExpression(%q) = %v; want ErrUnavailable", expression, err)
		}
	}
}

func TestEvalExpressionRejectsCallsAndSelectors(t *testing.T) {
	r := &testExpressionResolver{symbols: map[string]uint64{"f": 1, "main": 2}, lookupErr: target.ErrNotFound}
	for _, expression := range []string{"f()", "f(1)", "main.main", "f[0]"} {
		if _, err := EvalExpression(expression, r); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("EvalExpression(%q) = %v; want ErrInvalidArgument", expression, err)
		}
	}
}

func TestEvalExpressionResourceLimits(t *testing.T) {
	for _, expression := range []string{
		strings.Repeat(" ", maxExpressionBytes) + "1",
		strings.Repeat("(", maxExpressionDepth) + "1" + strings.Repeat(")", maxExpressionDepth),
		strings.Repeat("+", maxExpressionDepth) + "1",
	} {
		if _, err := EvalExpression(expression, nil); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("EvalExpression with %d bytes = %v; want ErrInvalidArgument", len(expression), err)
		}
	}
	expression := strings.Repeat("1+", 10_000) + "1"
	if value, err := EvalExpression(expression, nil); err != nil || value != 10_001 {
		t.Fatalf("long flat expression = %d, %v; want 10001", value, err)
	}
}

func FuzzEvalExpression(f *testing.F) {
	for _, seed := range []string{"1+2*3", "$rip", "`main.main`+0xff", "((1))", "0xffffffffffffffff << 64", "1_000"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		EvalExpression(expression, nil)
	})
}
