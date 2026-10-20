package native

import (
	"errors"
	"fastdbg2/target"
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

type waitResult struct {
	pid    int
	status unix.WaitStatus
	err    error
}

func waitTask(tid int) (waitResult, bool) {
	if tid <= 0 {
		return waitResult{pid: tid, err: target.ErrInvalidArgument}, true
	}
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(tid, &status, unix.WALL|unix.WNOTHREAD|unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return waitResult{pid: tid, err: err}, true
		}
		return waitResult{pid: pid, status: status}, pid != 0
	}
}

func (e *engine) waitTIDs() []int {
	tids := make([]int, 0, len(e.threads))
	for tid, t := range e.threads {
		if t.state != target.StateExited && t.state != target.StateDetached && (t.seized || t.process != nil && t.process.owned) && e.life.lost[tid] == nil && (e.life.missing[tid] == nil || e.life.missing[tid] != t) {
			tids = append(tids, tid)
		}
	}
	for tid, p := range e.life.aliases {
		if !e.processLive(p) || processTerminated(p) {
			delete(e.life.aliases, tid)
			continue
		}
		found := false
		for _, existing := range tids {
			found = found || existing == tid
		}
		if !found {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	return tids
}

func (e *engine) drainWaits() {
	for {
		progress := false
		failed := make(map[*thread]waitResult)
		for _, tid := range e.waitTIDs() {
			t := e.threads[tid]
			if t == nil || (t.state == target.StateExited || t.state == target.StateDetached) && e.life.aliases[tid] == nil {
				continue
			}
			w, ready := waitTask(tid)
			if !ready {
				continue
			}
			if w.err != nil {
				if errors.Is(w.err, unix.ECHILD) && e.life.aliases[tid] != nil {
					continue
				}
				failed[t] = w
				continue
			}
			progress = true
			e.handleWait(w)
		}
		for t, w := range failed {
			if e.threads[w.pid] != t || t.state == target.StateExited || t.state == target.StateDetached {
				continue
			}
			if errors.Is(w.err, unix.ECHILD) && t.process != nil && t.tid != t.process.tgid {
				if e.life.missing == nil {
					e.life.missing = make(map[int]*thread)
				}
				e.life.missing[w.pid] = t
				e.updateState()
				continue
			}
			err := fmt.Errorf("wait TID %d lost ownership: %w", w.pid, w.err)
			e.life.lost[w.pid] = err
			e.updateState()
			e.unsupported = errors.Join(e.unsupported, err)
			if e.life.initializing {
				e.failInitialization(err)
			} else {
				e.failRun(err)
			}
		}
		if !progress || e.life.finished {
			return
		}
		select {
		case req := <-e.s.requests:
			req(e)
		default:
		}
	}
}
