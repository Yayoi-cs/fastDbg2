package debugger

import (
	"fmt"

	"fastdbg2/display"
)

func (c *Controller) Prompt() string {
	const unknown = "[fastDbg2]$ "
	snapshot, thread, err := c.stopped()
	if err != nil || validateImageSnapshot(snapshot, thread) != nil {
		return unknown
	}
	location, err := c.session.ReadCodeLocation(thread.Token)
	if err != nil {
		return unknown
	}
	current, err := c.session.Snapshot()
	if err != nil || current.Sequence != snapshot.Sequence || current.State != snapshot.State || current.Process != snapshot.Process ||
		current.Memory != snapshot.Memory || current.Architecture != snapshot.Architecture || validateImageSnapshot(current, thread) != nil {
		return unknown
	}
	return "[" + c.renderer.Text(display.StyleSymbol, "fastDbg2") + ":" + c.renderer.Text(display.StyleSymbol, fmt.Sprintf("0x%x", location.InstructionPC)) + "]$ "
}
