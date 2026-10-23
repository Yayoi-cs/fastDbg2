package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

func TestExpressionResolverRegisters(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, 0x8070605040302010)
	resolver := expressionResolver{registers: []target.Register{
		{Name: "rip", Bits: 64, Data: data, Available: true},
		{Name: "small", Bits: 16, Data: []byte{0x34, 0x12}, Available: true},
		{Name: "unavailable", Bits: 64},
		{Name: "bad-width", Bits: 65, Available: true},
		{Name: "short", Bits: 64, Data: []byte{1}, Available: true},
		{Name: "duplicate", Bits: 8, Data: []byte{1}, Available: true},
		{Name: "duplicate", Bits: 8, Data: []byte{2}, Available: true},
	}}
	for _, test := range []struct {
		name string
		want uint64
		err  error
	}{
		{"rip", 0x8070605040302010, nil},
		{"small", 0x1234, nil},
		{"RIP", 0, target.ErrNotFound},
		{"pc", 0, target.ErrNotFound},
		{"unavailable", 0, target.ErrUnavailable},
		{"bad-width", 0, target.ErrUnsupported},
		{"short", 0, target.ErrInvalidArgument},
		{"duplicate", 0, target.ErrAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := resolver.ResolveRegister(test.name)
			if value != test.want || !errors.Is(err, test.err) {
				t.Fatalf("got %#x, %v; want %#x, %v", value, err, test.want, test.err)
			}
		})
	}
}

func TestExpressionResolverPreservesNamesAndSyntax(t *testing.T) {
	var names []string
	resolver := expressionResolver{
		registers: []target.Register{{Name: "rip", Bits: 64, Data: []byte{0x10, 0, 0, 0, 0, 0, 0, 0}, Available: true}},
		symbols: func(name string) (uint64, error) {
			names = append(names, name)
			if name == "two  spaces.name" {
				return 0x1000, nil
			}
			return 0, target.ErrNotFound
		},
	}
	value, err := inspect.EvalExpression("`two  spaces.name` + ($rip << 1)", resolver)
	if err != nil || value != 0x1020 {
		t.Fatalf("got %#x, %v", value, err)
	}
	if len(names) != 1 || names[0] != "two  spaces.name" {
		t.Fatalf("symbol spelling changed: %q", names)
	}
	for _, expression := range []string{"'main'", "\"main\"", "$(echo main)", "~main", "${rip}"} {
		if _, err := inspect.EvalExpression(expression, resolver); !errors.Is(err, target.ErrInvalidArgument) {
			t.Fatalf("%q: %v", expression, err)
		}
	}
}

func TestExpressionResolverLoadsSymbolsOnlyWhenRequired(t *testing.T) {
	var calls int
	resolver := expressionResolver{
		registers: []target.Register{{Name: "rsp", Bits: 64, Data: []byte{0x10, 0, 0, 0, 0, 0, 0, 0}, Available: true}},
		symbols: func(string) (uint64, error) {
			calls++
			return 0, target.ErrUnavailable
		},
	}
	for _, expression := range []string{"0x10 + 8", "$rsp + 8"} {
		if value, err := inspect.EvalExpression(expression, resolver); value != 24 || err != nil {
			t.Fatalf("%q: %#x, %v", expression, value, err)
		}
	}
	if calls != 0 {
		t.Fatal("register or numeric expression loaded symbols")
	}
	if _, err := inspect.EvalExpression("main", resolver); !errors.Is(err, target.ErrUnavailable) || calls != 1 {
		t.Fatalf("symbol expression: %v, calls=%d", err, calls)
	}
	if _, err := (expressionResolver{}).ResolveSymbol("main"); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("missing symbol source: %v", err)
	}
}

func TestExpressionResolverDoesNotMaskArithmeticErrors(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, math.MaxUint64)
	resolver := expressionResolver{registers: []target.Register{{Name: "rax", Bits: 64, Data: data, Available: true}}}
	if _, err := inspect.EvalExpression("$rax + 1", resolver); !errors.Is(err, target.ErrOverflow) {
		t.Fatalf("overflow: %v", err)
	}
	if _, err := inspect.EvalExpression("$rax / 0", resolver); !errors.Is(err, target.ErrInvalidArgument) {
		t.Fatalf("division by zero: %v", err)
	}
}

func TestEvaluateUsesSuppliedSnapshotToken(t *testing.T) {
	snapshot, thread := imageTestSnapshot()
	backend := &expressionTestSession{registers: []target.Register{
		{Name: "rip", Bits: 64, Data: []byte{0x10, 0, 0, 0, 0, 0, 0, 0}, Available: true},
	}}
	controller := &Controller{session: backend}
	value, err := controller.evaluate(context.Background(), "$rip + 0x10", snapshot, thread)
	if err != nil || value != 0x20 || backend.token != thread.Token || backend.reads != 1 {
		t.Fatalf("value=%#x, error=%v, token=%+v, reads=%d", value, err, backend.token, backend.reads)
	}
	if controller.image.image != nil {
		t.Fatal("register expression loaded an image")
	}
	backend.err = target.ErrStale
	if _, err := controller.evaluate(context.Background(), "0x10", snapshot, thread); !errors.Is(err, target.ErrStale) {
		t.Fatalf("stale registers: %v", err)
	}
	if backend.reads != 2 {
		t.Fatalf("stale token retried or refreshed: %d reads", backend.reads)
	}
}

func TestEvaluateSymbolFailureKeepsSession(t *testing.T) {
	snapshot, thread := imageTestSnapshot()
	backend := &expressionTestSession{}
	controller := &Controller{session: backend}
	symbols := &stoppedSymbolResolver{
		ctx:  context.Background(),
		load: func() (*stoppedSymbolScope, error) { return nil, target.ErrUnavailable },
	}
	if _, err := inspect.EvalExpression("missing", expressionResolver{symbols: symbols.Resolve}); !errors.Is(err, target.ErrUnavailable) {
		t.Fatalf("symbol failure: %v", err)
	}
	if controller.session != backend {
		t.Fatal("symbol error discarded session")
	}
	if value, err := controller.evaluate(context.Background(), "0x10", snapshot, thread); err != nil || value != 16 {
		t.Fatalf("numeric expression after symbol failure: %#x, %v", value, err)
	}
}

func TestEvaluateRejectsInvalidStateBeforeReading(t *testing.T) {
	snapshot, thread := imageTestSnapshot()
	backend := &expressionTestSession{}
	controller := &Controller{session: backend}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.evaluate(ctx, "0x10", snapshot, thread); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled evaluation: %v", err)
	}
	snapshot.Architecture = target.AArch64
	if _, err := controller.evaluate(context.Background(), "0x10", snapshot, thread); !errors.Is(err, target.ErrUnsupported) {
		t.Fatalf("unsupported target: %v", err)
	}
	if backend.reads != 0 {
		t.Fatalf("invalid evaluation read registers %d times", backend.reads)
	}
	if _, err := (*Controller)(nil).evaluate(context.Background(), "0", snapshot, thread); !errors.Is(err, target.ErrInvalidState) {
		t.Fatalf("missing controller: %v", err)
	}
}

type expressionTestSession struct {
	session
	registers []target.Register
	token     target.ThreadToken
	reads     int
	err       error
}

func (s *expressionTestSession) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	s.token = token
	s.reads++
	return s.registers, s.err
}
