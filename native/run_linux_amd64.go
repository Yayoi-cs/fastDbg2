package native

import (
	"context"
	"sync"

	"fastdbg2/target"
)

type Run struct {
	id     uint64
	done   chan struct{}
	once   sync.Once
	result target.RunResult
	err    error
}

func newRun(id uint64) *Run {
	return &Run{id: id, done: make(chan struct{})}
}

func (run *Run) ID() uint64 {
	if run == nil {
		return 0
	}
	return run.id
}

func (run *Run) Wait(ctx context.Context) (target.RunResult, error) {
	if run == nil || ctx == nil {
		return target.RunResult{}, target.ErrInvalidArgument
	}
	select {
	case <-run.done:
		return copyRunResult(run.result), run.err
	default:
	}
	select {
	case <-run.done:
		return copyRunResult(run.result), run.err
	case <-ctx.Done():
		return target.RunResult{}, ctx.Err()
	}
}

func (run *Run) complete(result target.RunResult, err error) {
	run.once.Do(func() {
		run.result = copyRunResult(result)
		run.err = err
		close(run.done)
	})
}

func copyRunResult(result target.RunResult) target.RunResult {
	result.Stop = copyStop(result.Stop)
	return result
}
