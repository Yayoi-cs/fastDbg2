package debugger

import (
	"context"
	"fmt"

	"fastdbg2/inspect"
	"fastdbg2/target"
)

type expressionResolver struct {
	registers []target.Register
	symbols   func(string) (uint64, error)
}

func (resolver expressionResolver) ResolveRegister(name string) (uint64, error) {
	var register *target.Register
	for i := range resolver.registers {
		if resolver.registers[i].Name == name {
			if register != nil {
				return 0, fmt.Errorf("register %q: %w", name, target.ErrAmbiguous)
			}
			register = &resolver.registers[i]
		}
	}
	if register == nil {
		return 0, fmt.Errorf("register %q: %w", name, target.ErrNotFound)
	}
	if !register.Available {
		return 0, fmt.Errorf("register %q: %w", name, target.ErrUnavailable)
	}
	if register.Bits <= 0 || register.Bits > 64 || register.Bits%8 != 0 {
		return 0, fmt.Errorf("register %q has %d bits: %w", name, register.Bits, target.ErrUnsupported)
	}
	if len(register.Data) != register.Bits/8 {
		return 0, fmt.Errorf("register %q has %d bytes for %d bits: %w", name, len(register.Data), register.Bits, target.ErrInvalidArgument)
	}
	var value uint64
	for i, b := range register.Data {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func (resolver expressionResolver) ResolveSymbol(name string) (uint64, error) {
	if resolver.symbols == nil {
		return 0, fmt.Errorf("symbol %q: %w", name, target.ErrUnavailable)
	}
	return resolver.symbols(name)
}

func (c *Controller) evaluate(ctx context.Context, expression string, snapshot target.Snapshot, thread target.ThreadInfo) (target.Address, error) {
	if c == nil || c.session == nil {
		return 0, target.ErrInvalidState
	}
	if ctx == nil {
		return 0, target.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := validateImageSnapshot(snapshot, thread); err != nil {
		return 0, err
	}
	registers, err := c.session.ReadThreadRegisters(thread.Token)
	if err != nil {
		return 0, fmt.Errorf("read selected thread registers: %w", err)
	}
	symbols := c.newStoppedSymbolResolver(ctx, snapshot, thread)
	resolver := expressionResolver{
		registers: registers,
		symbols:   symbols.Resolve,
	}
	value, err := inspect.EvalExpression(expression, resolver)
	if err == nil && value > abiFor(snapshot.Architecture).maximum {
		return 0, target.ErrOverflow
	}
	return target.Address(value), err
}
