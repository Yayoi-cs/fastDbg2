package debugger

import (
	"os"

	"fastdbg2/target"
)

func (c *Controller) EnableContextScreen(enabled bool) {
	c.contextScreen = false
	output, ok := c.out.(*os.File)
	if enabled && ok && pagerTerminal(output) {
		c.contextScreen = true
	}
}

func (c *Controller) publishContext(text string, clear bool) error {
	if clear && c.contextScreen {
		text = "\x1b[H\x1b[2J" + text
	}
	return c.writef("%s", text)
}

func (c *Controller) stoppedContextScreen(snapshot target.Snapshot) bool {
	if !c.contextScreen || c.contextDisabled || c.active != nil || snapshot.State != target.StateStopped {
		return false
	}
	for _, thread := range snapshot.Threads {
		if thread.Ref == c.selected {
			return primaryInspectableThread(snapshot, thread)
		}
	}
	return false
}

func sameContextSnapshot(left, right target.Snapshot) bool {
	return left.Sequence == right.Sequence && left.State == right.State && left.Process == right.Process &&
		left.Memory == right.Memory && left.Architecture == right.Architecture
}
