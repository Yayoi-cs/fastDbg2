package debugger

import (
	"context"
	"fastdbg2/display"
	"fastdbg2/inspect"
	"fastdbg2/native"
	"fastdbg2/target"
	"io"
)

func (s *nativeSession) addressWalkMaps(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) ([]procMap, error) {
	return (&Controller{session: s}).readProcessMaps(ctx, snapshot, thread)
}

func (s *nativeSession) addressWalkSymbols(ctx context.Context, snapshot target.Snapshot, thread target.ThreadInfo) ([]inspect.Symbol, error) {
	c := &Controller{session: s}
	return s.uiSymbols.read(ctx, newUISymbolCacheKey(snapshot, thread),
		func() error { return c.verifyProcSnapshot(snapshot, thread) },
		func() (*stoppedSymbolScope, error) { return c.loadStoppedSymbolDisplayScope(ctx, snapshot, thread) })
}

type nativeSession struct {
	*native.Session
	uiSymbols uiSymbolCache
}

func (s *nativeSession) Run(request target.RunRequest) (operation, error) {
	return s.Session.Run(request)
}

func (s *nativeSession) StepInstruction(request target.StepRequest) (operation, error) {
	return s.Session.StepInstruction(request)
}

func (s *nativeSession) Interrupt(request target.InterruptRequest) error {
	return s.Session.Interrupt(request)
}

func New(output io.Writer, renderer display.Renderer) *Controller {
	return &Controller{
		out: output, renderer: renderer,
		schedulerLocking: "replay",
		launch: func(path string, args []string) (session, error) {
			s, err := native.Launch(path, args...)
			if s == nil {
				return nil, err
			}
			return &nativeSession{Session: s}, err
		},
		attach: func(pid int) (session, error) {
			s, err := native.Attach(pid)
			if s == nil {
				return nil, err
			}
			return &nativeSession{Session: s}, err
		},
	}
}
