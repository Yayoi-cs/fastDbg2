package native

import (
	"fastdbg2/native/internal/arch"
	"fastdbg2/target"
	"os"
	"sort"
)

type engine struct {
	s           *Session
	life        lifecycleState
	threads     map[int]*thread
	processes   map[int]*process
	primary     *process
	nextThread  uint64
	nextProcess uint64
	nextSpace   uint64
	nextRun     uint64
	last        target.Stop
	sequence    uint64
	run         *runOperation
	barrier     *stopBarrier
	unsupported error
}

type process struct {
	ref       target.ProcessRef
	tgid      int
	pidfd     int
	owned     bool
	osProcess *os.Process
	profile   *arch.Descriptor
	exeInfo   os.FileInfo
	space     *addressSpace
}

type thread struct {
	ref                target.ThreadRef
	tid                int
	process            *process
	state              target.State
	name               string
	stop               target.Stop
	stopEpoch          uint64
	registerRevision   uint64
	pendingSignal      int
	interruptRequested bool
	internalStepTrap   bool
	needsUserBoundary  bool
	seized             bool
	exiting            bool
	exitComplete       bool
	groupStopped       bool
	listening          bool
	hit                *breakpointHit
	suspended          *breakpoint
	watchpoints        *watchpointState
	fault              error
}

type addressSpace struct {
	ref            target.SpaceRef
	revision       uint64
	breakpoints    map[target.Address]*breakpoint
	nextBreakpoint uint64
	stepping       *thread
	unknown        bool
	fault          error
}

type resumeAction struct {
	thread    *thread
	step      bool
	signal    int
	started   bool
	resumed   bool
	cloneStep bool
}

type runOperation struct {
	handle      *Run
	actions     map[target.ThreadRef]*resumeAction
	inherit     map[target.ProcessRef]bool
	step        target.ThreadRef
	legacy      bool
	overThread  *thread
	over        *breakpoint
	overPaused  bool
	entryThread *thread
	entry       *breakpoint
	entryHit    bool
	resumeCount int
}

type stopBarrier struct {
	thread *thread
	stop   target.Stop
	err    error
}

func (e *engine) newSpace() *addressSpace {
	e.nextSpace++
	return &addressSpace{
		ref: target.SpaceRef{Session: e.s.id, ID: e.nextSpace}, revision: 1,
		breakpoints: make(map[target.Address]*breakpoint),
	}
}

func (e *engine) newProcess(tgid, pidfd int, owned bool) *process {
	if e.processes == nil {
		e.processes = make(map[int]*process)
	}
	if p := e.processes[tgid]; p != nil {
		return p
	}
	e.nextProcess++
	p := &process{
		ref:  target.ProcessRef{Session: e.s.id, ID: e.nextProcess},
		tgid: tgid, pidfd: pidfd, owned: owned, space: e.newSpace(),
	}
	e.processes[tgid] = p
	return p
}

func (e *engine) newThread(p *process, tid int, seized bool) *thread {
	if e.threads == nil {
		e.threads = make(map[int]*thread)
	}
	if t := e.threads[tid]; t != nil && t.live() {
		if t.process == nil {
			t.process = p
		}
		return t
	}
	e.nextThread++
	t := &thread{
		ref: target.ThreadRef{Session: e.s.id, ID: e.nextThread},
		tid: tid, process: p, state: target.StateUnknown,
		registerRevision: 1, seized: seized,
	}
	e.threads[tid] = t
	return t
}

func (t *thread) live() bool {
	return t.state != target.StateExited && t.state != target.StateDetached
}

func (t *thread) token() target.ThreadToken {
	return target.ThreadToken{Thread: t.ref, Stop: t.stopEpoch, Registers: t.registerRevision}
}

func (e *engine) findThread(ref target.ThreadRef) (*thread, error) {
	if ref.Session != e.s.id || ref.ID == 0 {
		return nil, target.ErrInvalidArgument
	}
	for _, t := range e.threads {
		if t.ref == ref {
			if !t.live() {
				return nil, target.ErrExited
			}
			return t, nil
		}
	}
	return nil, target.ErrStale
}

func (e *engine) findProcess(ref target.ProcessRef) (*process, error) {
	if ref.Session != e.s.id || ref.ID == 0 {
		return nil, target.ErrInvalidArgument
	}
	for _, p := range e.processes {
		if p.ref == ref {
			return p, nil
		}
	}
	return nil, target.ErrStale
}

func (e *engine) findSpace(ref target.SpaceRef) (*addressSpace, error) {
	if ref.Session != e.s.id || ref.ID == 0 {
		return nil, target.ErrInvalidArgument
	}
	for _, p := range e.processes {
		if p.space != nil && p.space.ref == ref {
			return p.space, nil
		}
	}
	return nil, target.ErrStale
}

func (e *engine) ownershipError() error {
	if len(e.life.lost) != 0 {
		return target.ErrUnavailable
	}
	if len(e.life.missing) != 0 || len(e.life.births) != 0 {
		return target.ErrBusy
	}
	return nil
}

func (e *engine) requireThread(token target.ThreadToken) (*thread, error) {
	if err := e.lifecycleError(); err != nil {
		return nil, err
	}
	if e.unsupported != nil {
		return nil, e.unsupported
	}
	if err := e.ownershipError(); err != nil {
		return nil, err
	}
	t, err := e.findThread(token.Thread)
	if err != nil {
		return nil, err
	}
	if t.fault != nil {
		return nil, t.fault
	}
	if t.state != target.StateStopped || t.listening || t.exiting {
		return nil, target.ErrRunning
	}
	if token.Stop == 0 || token.Stop != t.stopEpoch || token.Registers != t.registerRevision {
		return nil, target.ErrStale
	}
	if t.process == nil || t.process.profile == nil {
		return nil, target.ErrUnavailable
	}
	return t, nil
}

func (e *engine) requireMemory(token target.MemoryToken) (*addressSpace, *thread, error) {
	if err := e.lifecycleError(); err != nil {
		return nil, nil, err
	}
	if e.unsupported != nil {
		return nil, nil, e.unsupported
	}
	if err := e.ownershipError(); err != nil {
		return nil, nil, err
	}
	if e.barrier != nil {
		return nil, nil, target.ErrBusy
	}
	space, err := e.findSpace(token.Space)
	if err != nil {
		return nil, nil, err
	}
	if space.fault != nil {
		return nil, nil, space.fault
	}
	if space.unknown {
		return nil, nil, target.ErrUnknown
	}
	if token.Revision != space.revision {
		return nil, nil, target.ErrStale
	}
	if !e.spaceStopped(space) {
		return nil, nil, target.ErrRunning
	}
	for _, t := range e.sortedThreads() {
		if t.process != nil && t.process.space == space && t.state == target.StateStopped && !t.exiting && !t.listening && t.fault == nil {
			if t.process.profile == nil {
				return nil, nil, target.ErrUnavailable
			}
			return space, t, nil
		}
	}
	return nil, nil, target.ErrUnavailable
}

func (e *engine) allStopped() bool {
	if e.ownershipError() != nil {
		return false
	}
	for _, t := range e.threads {
		if t.live() && !(t.exiting && t.exitComplete) && (t.state != target.StateStopped || t.listening || t.process == nil) {
			return false
		}
	}
	return true
}

func (e *engine) allExited() bool {
	if e.ownershipError() != nil {
		return false
	}
	for _, t := range e.threads {
		if t.live() {
			return false
		}
	}
	return true
}

func (e *engine) spaceStopped(space *addressSpace) bool {
	if space == nil || space.unknown || space.fault != nil || e.ownershipError() != nil {
		return false
	}
	found := false
	for _, t := range e.threads {
		if !t.live() || t.exiting && t.exitComplete {
			continue
		}
		if t.process == nil {
			return false
		}
		if t.process.space == space {
			if t.state != target.StateStopped || t.listening {
				return false
			}
			found = true
		}
	}
	return found
}

func (e *engine) requireAllStopped() error {
	if err := e.lifecycleError(); err != nil {
		return err
	}
	if e.unsupported != nil {
		return e.unsupported
	}
	if err := e.ownershipError(); err != nil {
		return err
	}
	if len(e.threads) == 0 {
		return target.ErrInvalidState
	}
	for _, t := range e.threads {
		if t.live() && (t.state == target.StateUnknown || t.process == nil) {
			return target.ErrBusy
		}
	}
	if e.barrier != nil || !e.allStopped() {
		return target.ErrRunning
	}
	return nil
}

func (e *engine) singleStoppedThread() (*thread, error) {
	if err := e.requireAllStopped(); err != nil {
		return nil, err
	}
	var result *thread
	for _, t := range e.threads {
		if !t.live() || t.exiting && t.exitComplete {
			continue
		}
		if result != nil {
			return nil, target.ErrAmbiguous
		}
		result = t
	}
	if result == nil {
		return nil, target.ErrExited
	}
	return result, nil
}

func (e *engine) requireStopped() error {
	_, err := e.singleStoppedThread()
	return err
}

func (e *engine) primaryMemory() (target.MemoryToken, error) {
	if err := e.requireAllStopped(); err != nil {
		return target.MemoryToken{}, err
	}
	var space *addressSpace
	for _, t := range e.threads {
		if !t.live() || t.exiting && t.exitComplete {
			continue
		}
		if t.process == nil || t.process.space == nil {
			return target.MemoryToken{}, target.ErrUnavailable
		}
		if space != nil && space != t.process.space {
			return target.MemoryToken{}, target.ErrAmbiguous
		}
		space = t.process.space
	}
	if space == nil {
		return target.MemoryToken{}, target.ErrExited
	}
	return target.MemoryToken{Space: space.ref, Revision: space.revision}, nil
}

func (e *engine) registersChanged(t *thread) { t.registerRevision++ }

func (e *engine) memoryChanged(space *addressSpace) { space.revision++ }

func (e *engine) sortedThreads() []*thread {
	result := make([]*thread, 0, len(e.threads))
	for _, t := range e.threads {
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ref.ID < result[j].ref.ID })
	return result
}

func (e *engine) actualState() target.State {
	if e.life.terminal != target.StateUnknown {
		return e.life.terminal
	}
	if len(e.threads) == 0 {
		return target.StateUnknown
	}
	if e.ownershipError() != nil {
		return target.StateUnknown
	}
	if e.life.awaitProcessExit {
		return target.StateRunning
	}
	if e.allExited() {
		return target.StateExited
	}
	for _, t := range e.threads {
		if t.live() && t.process != nil && t.process.space != nil && (t.process.space.unknown || t.process.space.fault != nil) {
			return target.StateUnknown
		}
	}
	if e.run != nil || e.barrier != nil || len(e.life.births) != 0 || !e.allStopped() {
		return target.StateRunning
	}
	return target.StateStopped
}

func (e *engine) setState(state target.State) { e.s.state.Store(uint32(state)) }

func (e *engine) updateState() { e.setState(e.actualState()) }

func (e *engine) publish(stop target.Stop) {
	stop.Generation = e.sequence
	e.last = copyStop(stop)
	value := copyStop(stop)
	e.s.last.Store(&value)
	e.updateState()
}

func (e *engine) emit(kind target.EventKind, t *thread, runID uint64, stop target.Stop) uint64 {
	event := target.Event{Kind: kind, RunID: runID, Stop: copyStop(stop)}
	if t != nil {
		event.Thread = t.ref
	}
	e.sequence = e.s.publishEvent(event)
	return e.sequence
}

func (e *engine) snapshot() target.Snapshot {
	result := target.Snapshot{Sequence: e.sequence, State: e.actualState()}
	if e.primary != nil {
		result.Process = e.primary.ref
		if e.primary.profile != nil {
			result.Architecture = e.primary.profile.Architecture
		}
		if space := e.primary.space; space != nil {
			result.Memory.Space = space.ref
			if e.barrier == nil && len(e.life.births) == 0 && !e.life.initializing && e.spaceStopped(space) {
				result.Memory.Revision = space.revision
			}
		}
	}
	for _, t := range e.sortedThreads() {
		info := target.ThreadInfo{
			Ref: t.ref, TID: t.tid, Name: t.name, State: t.state, Exiting: t.exiting,
			Listening: t.listening, GroupStopped: t.groupStopped,
			Token: t.token(), Stop: copyStop(t.stop),
		}
		if t.process != nil {
			info.Process = t.process.ref
		}
		result.Threads = append(result.Threads, info)
	}
	return result
}
