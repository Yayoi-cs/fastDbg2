package debugger

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"fastdbg2/inspect"
	"fastdbg2/internal/cli"
	"fastdbg2/target"
)

type threadRegisterWriter interface {
	WriteThreadRegisters(target.ThreadToken, []target.Register) error
}

type spaceMemoryWriter interface {
	WriteSpaceMemory(target.MemoryToken, target.Address, []byte) (int, error)
}

func mutationArguments(rawArgs, command string, assignment bool) (string, string, error) {
	args, err := cli.ParseArgs(rawArgs)
	if err != nil {
		return "", "", err
	}
	if assignment && len(args) == 3 && args[1] == "=" {
		args = []string{args[0], args[2]}
	}
	if len(args) != 2 || strings.TrimSpace(args[0]) == "" || strings.TrimSpace(args[1]) == "" {
		return "", "", fmt.Errorf("%s requires DEST VALUE; quote each expression containing spaces: %w", command, target.ErrInvalidArgument)
	}
	return strings.TrimSpace(args[0]), strings.TrimSpace(args[1]), nil
}

func (c *Controller) mutationResolver(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) (expressionResolver, error) {
	if err := contextReady(ctx); err != nil {
		return expressionResolver{}, err
	}
	if err := validateImageSnapshot(snapshot, thread); err != nil {
		return expressionResolver{}, err
	}
	registers, err := c.session.ReadThreadRegisters(thread.Token)
	if err != nil {
		return expressionResolver{}, err
	}
	symbols := c.newStoppedSymbolResolver(ctx, snapshot, thread)
	return expressionResolver{
		registers: registers,
		symbols:   symbols.Resolve,
	}, nil
}

func mutationRegister(destination string, registers []target.Register) (*target.Register, error) {
	name := strings.ToLower(strings.TrimPrefix(destination, "$"))
	var selected *target.Register
	for i := range registers {
		if registers[i].Name != name {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("register %q: %w", name, target.ErrAmbiguous)
		}
		selected = &registers[i]
	}
	if selected != nil {
		if _, err := (expressionResolver{registers: registers}).ResolveRegister(name); err != nil {
			return nil, err
		}
		return selected, nil
	}
	if strings.HasPrefix(destination, "$") && name != "" && strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	}) < 0 {
		return nil, fmt.Errorf("register %q: %w", name, target.ErrNotFound)
	}
	return nil, nil
}

func mutationBytes(value uint64, bits int) ([]byte, error) {
	if bits != 8 && bits != 16 && bits != 32 && bits != 64 {
		return nil, fmt.Errorf("unsupported write width %d: %w", bits, target.ErrUnsupported)
	}
	if bits < 64 && value >= uint64(1)<<bits {
		return nil, fmt.Errorf("value %#x does not fit in %d bits: %w", value, bits, target.ErrOverflow)
	}
	data := make([]byte, bits/8)
	for i := range data {
		data[i] = byte(value >> (8 * i))
	}
	return data, nil
}

func mutationRange(address target.Address, size int) error {
	if size <= 0 {
		return target.ErrInvalidArgument
	}
	if uint64(size-1) > math.MaxUint64-uint64(address) {
		return fmt.Errorf("write range at %#x with %d bytes: %w", address, size, target.ErrOverflow)
	}
	return nil
}

func (c *Controller) refreshAfterMutation(before target.Snapshot, thread target.ThreadInfo) error {
	after, err := c.refresh()
	if err != nil {
		return err
	}
	if after.Memory.Space != before.Memory.Space || after.Process != before.Process || after.State != target.StateStopped {
		return fmt.Errorf("target image or state changed after mutation: %w", target.ErrStale)
	}
	for _, current := range after.Threads {
		if current.Ref == thread.Ref && primaryInspectableThread(after, current) {
			return nil
		}
	}
	return fmt.Errorf("selected thread changed after mutation: %w", target.ErrStale)
}

func (c *Controller) writeMutationMemory(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo, address target.Address, data []byte) error {
	writer, ok := c.session.(spaceMemoryWriter)
	if !ok {
		return fmt.Errorf("memory writes: %w", target.ErrUnsupported)
	}
	if err := mutationRange(address, len(data)); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	n, writeErr := writer.WriteSpaceMemory(snapshot.Memory, address, data)
	snapshotErr := c.refreshAfterMutation(snapshot, thread)
	if n < 0 || n > len(data) {
		return errors.Join(fmt.Errorf("write memory returned invalid count %d/%d: %w", n, len(data), target.ErrUnknown), writeErr, snapshotErr, ctx.Err())
	}
	if n != len(data) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
		if n > 0 {
			writeErr = &target.PartialError{Op: "write memory", Completed: n, Total: len(data), Err: writeErr}
		}
	}
	if err := errors.Join(writeErr, snapshotErr, ctx.Err()); err != nil {
		return fmt.Errorf("write memory at %#x: %d/%d bytes confirmed: %w", address, n, len(data), err)
	}
	return nil
}

func (c *Controller) commandSet(ctx context.Context, rawArgs string, bits int) error {
	destination, expression, err := mutationArguments(rawArgs, "set", true)
	if err != nil {
		return err
	}
	if _, err := mutationBytes(0, bits); err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	resolver, err := c.mutationResolver(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	var register *target.Register
	if bits == 64 {
		register, err = mutationRegister(destination, resolver.registers)
		if err != nil {
			return err
		}
	}
	value, err := inspect.EvalExpression(expression, resolver)
	if err != nil {
		return err
	}
	if register != nil {
		writer, ok := c.session.(threadRegisterWriter)
		if !ok {
			return fmt.Errorf("register writes: %w", target.ErrUnsupported)
		}
		data, err := mutationBytes(value, register.Bits)
		if err != nil {
			return err
		}
		if err := contextReady(ctx); err != nil {
			return err
		}
		writeErr := writer.WriteThreadRegisters(thread.Token, []target.Register{{Name: register.Name, Bits: register.Bits, Data: data, Available: true}})
		snapshotErr := c.refreshAfterMutation(snapshot, thread)
		if err := errors.Join(writeErr, snapshotErr, ctx.Err()); err != nil {
			return fmt.Errorf("write thread %d register %q: %w", thread.Ref.ID, register.Name, err)
		}
		return c.writef("Register write accepted thread=%d tid=%d $%s requested=%#x\n", thread.Ref.ID, thread.TID, register.Name, value)
	}
	address, err := inspect.EvalExpression(destination, resolver)
	if err != nil {
		return err
	}
	data, err := mutationBytes(value, bits)
	if err != nil {
		return err
	}
	if err := c.writeMutationMemory(ctx, snapshot, thread, target.Address(address), data); err != nil {
		return err
	}
	return c.writef("Set memory address=%#x bytes=%d value=%#x\n", address, len(data), value)
}

func (c *Controller) commandXor(ctx context.Context, rawArgs string) error {
	destination, expression, err := mutationArguments(rawArgs, "xor", false)
	if err != nil {
		return err
	}
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	resolver, err := c.mutationResolver(ctx, snapshot, thread)
	if err != nil {
		return err
	}
	address, err := inspect.EvalExpression(destination, resolver)
	if err != nil {
		return err
	}
	key, err := inspect.EvalExpression(expression, resolver)
	if err != nil {
		return err
	}
	if err := mutationRange(target.Address(address), 8); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	var data [8]byte
	n, readErr := c.session.ReadSpaceMemory(snapshot.Memory, target.Address(address), data[:])
	if n < 0 || n > len(data) {
		return errors.Join(fmt.Errorf("xor read returned invalid count %d/8: %w", n, target.ErrUnknown), readErr)
	}
	if readErr != nil || n != len(data) {
		if n != len(data) {
			readErr = errors.Join(readErr, io.ErrUnexpectedEOF)
		}
		return fmt.Errorf("xor requires an exact 8-byte read: %d/8 bytes read: %w", n, readErr)
	}
	before := binary.LittleEndian.Uint64(data[:])
	value := before ^ key
	binary.LittleEndian.PutUint64(data[:], value)
	if err := c.writeMutationMemory(ctx, snapshot, thread, target.Address(address), data[:]); err != nil {
		return err
	}
	return c.writef("XOR address=%#x bytes=8: %#x ^ %#x = %#x\n", address, before, key, value)
}
