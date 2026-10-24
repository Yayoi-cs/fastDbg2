package debugger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"fastdbg2/target"
)

type segmentBaseReader interface {
	ReadThreadSegmentBase(target.ThreadToken, string) (target.Address, error)
}

func (c *Controller) selectedSegmentBase(snapshot target.Snapshot, thread target.ThreadInfo, name string) (target.Address, error) {
	reader, ok := c.session.(segmentBaseReader)
	if !ok {
		return 0, target.ErrUnsupported
	}
	return reader.ReadThreadSegmentBase(thread.Token, name)
}

func (c *Controller) allocatorRegisters(snapshot target.Snapshot, thread target.ThreadInfo) ([]target.Register, error) {
	registers, err := c.session.ReadThreadRegisters(thread.Token)
	if err != nil {
		return nil, err
	}
	if snapshot.Architecture != target.X86 {
		return registers, nil
	}
	base, err := c.selectedSegmentBase(snapshot, thread, "gs")
	if err != nil {
		return nil, err
	}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(base))
	return append(registers, target.Register{Name: "gs_base", Bits: 32, Data: data, Available: true}), nil
}

func (c *Controller) showSegmentBase(ctx context.Context, name string) error {
	snapshot, thread, err := c.stopped()
	if err != nil {
		return err
	}
	base, err := c.selectedSegmentBase(snapshot, thread, name)
	if err != nil {
		return err
	}
	if uint64(base) > c.abi().maximum {
		return target.ErrOverflow
	}
	var data []byte
	var readErr error
	if base != 0 {
		data = make([]byte, 128)
		n, err := c.session.ReadSpaceMemory(snapshot.Memory, base, data)
		data, readErr = inspectionConfirmedBytes(data, n, err)
	}
	if uiDisplayFatal(readErr) {
		return readErr
	}
	if err := c.displaySnapshotCurrent(ctx, snapshot, thread); err != nil {
		return err
	}
	var buffer bytes.Buffer
	view := *c
	view.out = &buffer
	if err := view.writef("%s_base = 0x%0*x\n", name, c.abi().word*2, base); err != nil {
		return err
	}
	if err := view.hexRows(base, data, c.abi().word); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	return errors.Join(readErr, c.writef("%s", buffer.String()))
}
