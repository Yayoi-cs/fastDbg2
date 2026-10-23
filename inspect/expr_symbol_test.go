package inspect

import (
	"errors"
	"strings"
	"testing"

	"fastdbg2/target"
)

func TestParseSymbolExpressionNeverEvaluatesOrDefersOtherSyntax(t *testing.T) {
	for _, test := range []struct {
		expression string
		name       string
	}{
		{"malloc", "malloc"}, {" \t_free32 \n", "_free32"},
		{"`libc.so.6!malloc@GLIBC_2.2.5`", "libc.so.6!malloc@GLIBC_2.2.5"},
		{"`name with spaces`", "name with spaces"},
	} {
		name, err := ParseSymbolExpression(test.expression)
		if err != nil || name != test.name {
			t.Fatalf("%q: name=%q error=%v", test.expression, name, err)
		}
	}
	for _, expression := range []string{"", "1", "$rax", "malloc+$rax", "$rax+malloc", "malloc + 1", "malloc +", "(malloc)", "malloc free", "`malloc` + 1", "`malloc", "``", "malloc\x00", strings.Repeat("a", maxExpressionBytes+1)} {
		name, err := ParseSymbolExpression(expression)
		if name != "" || err == nil || !errors.Is(err, target.ErrUnsupported) && !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("unsupported deferred expression %q: name=%q error=%v", expression, name, err)
		}
	}
}
