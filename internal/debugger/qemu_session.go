package debugger

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"fastdbg2/native"
	"fastdbg2/qemu"
	"fastdbg2/target"
)

var qemuSessionID atomic.Uint64

type qemuSession struct {
	stopRevision                  uint64
	watchGeneration               uint64
	watches                       map[int]target.WatchpointHit
	interruptRequested            bool
	remote                        *qemu.Session
	mu                            sync.Mutex
	id, cpu, revision, generation uint64
	cpus                          []uint64
	stop                          target.Stop
	active                        bool
	image                         *kernelImage
	points                        map[target.Address]bool
	mapRevision                   uint64
	maps                          []procMap
}

func newQemuSession(remote *qemu.Session, image *kernelImage) (*qemuSession, error) {
	if remote.Architecture() != target.AMD64 {
		return nil, target.ErrUnsupported
	}
	if err := remote.UseVirtualMemory(); err != nil {
		return nil, err
	}
	cpus, err := remote.Threads()
	if err != nil {
		return nil, err
	}
	cpu := cpus[0]
	stop := remote.LastStop()
	if stop.ThreadID != nil {
		cpu = *stop.ThreadID
	}
	if !slices.Contains(cpus, cpu) {
		return nil, target.ErrStale
	}
	stop.Reason = target.StopAttach
	return &qemuSession{remote: remote, id: qemuSessionID.Add(1) | (1 << 63), cpu: cpu, revision: 1, stopRevision: 1, watches: make(map[int]target.WatchpointHit), generation: remote.Generation(), cpus: cpus, stop: stop, image: image, points: make(map[target.Address]bool)}, nil
}

func (s *qemuSession) PID() int            { return 0 }
func (s *qemuSession) State() target.State { return s.remote.State() }
func (s *qemuSession) syncRevision() {
	if generation := s.remote.Generation(); generation != s.generation {
		s.generation = generation
		s.revision++
	}
}
func (s *qemuSession) token(id uint64) target.ThreadToken {
	return target.ThreadToken{Thread: target.ThreadRef{Session: s.id, ID: id}, Stop: s.stopRevision, Registers: s.revision}
}
func (s *qemuSession) memory() target.MemoryToken {
	return target.MemoryToken{Space: target.SpaceRef{Session: s.id, ID: 1}, Revision: s.revision}
}
func (s *qemuSession) SelectInspection(ref target.ThreadRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncRevision()
	if ref.Session != s.id || !slices.Contains(s.cpus, ref.ID) {
		return target.ErrStale
	}
	if s.active {
		return target.ErrRunning
	}
	if s.cpu != ref.ID {
		s.cpu = ref.ID
		s.revision++
	}
	return nil
}
func (s *qemuSession) Snapshot() (target.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncRevision()
	state := s.remote.State()
	if s.active {
		state = target.StateRunning
	}
	process := target.ProcessRef{Session: s.id, ID: 1}
	snapshot := target.Snapshot{Sequence: s.revision, State: state, Architecture: target.AMD64, Process: process, Memory: s.memory()}
	for _, id := range s.cpus {
		stop := target.Stop{Reason: target.StopInterrupt}
		if s.stop.ThreadID != nil && *s.stop.ThreadID == id {
			stop = s.stop
		}
		snapshot.Threads = append(snapshot.Threads, target.ThreadInfo{Ref: target.ThreadRef{Session: s.id, ID: id}, Process: process, TID: int(id), Name: fmt.Sprintf("vCPU %d", id), State: state, Token: s.token(id), Stop: stop})
	}
	return snapshot, nil
}
func (s *qemuSession) LastStop() target.Stop { s.mu.Lock(); defer s.mu.Unlock(); return s.stop }
func (s *qemuSession) require(token target.ThreadToken) error {
	s.syncRevision()
	if s.active || s.remote.State() != target.StateStopped {
		return target.ErrInvalidState
	}
	if token != s.token(token.Thread.ID) || !slices.Contains(s.cpus, token.Thread.ID) {
		return target.ErrStale
	}
	return s.remote.SelectThread(token.Thread.ID)
}
func (s *qemuSession) requireMemory(token target.MemoryToken) error {
	s.syncRevision()
	if s.active || s.remote.State() != target.StateStopped {
		return target.ErrInvalidState
	}
	if token != s.memory() {
		return target.ErrStale
	}
	return s.remote.SelectThread(s.cpu)
}
func (s *qemuSession) ReadThreadRegisters(token target.ThreadToken) ([]target.Register, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.require(token); err != nil {
		return nil, err
	}
	registers, err := s.remote.ReadRegisters()
	if err != nil {
		return nil, err
	}
	filtered := registers[:0]
	for _, register := range registers {
		if nativeRegister(register.Name, target.AMD64) || strings.HasPrefix(register.Name, "cr") || register.Name == "efer" || register.Name == "k_gs_base" {
			filtered = append(filtered, register)
		}
	}
	return filtered, nil
}
func (s *qemuSession) WriteThreadRegisters(token target.ThreadToken, registers []target.Register) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.require(token); err != nil {
		return err
	}
	defer s.syncRevision()
	return s.remote.WriteRegisters(registers)
}
func (s *qemuSession) ReadSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireMemory(token); err != nil {
		return 0, err
	}
	return s.remote.ReadMemory(address, data)
}
func (s *qemuSession) ReadCodeMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireMemory(token); err != nil {
		return 0, err
	}
	registers, err := s.remote.ReadRegisters()
	if err != nil {
		return 0, err
	}
	if err := kernelCodeMode(registers); err != nil {
		return 0, err
	}
	return s.remote.ReadMemory(address, data)
}
func (s *qemuSession) WriteSpaceMemory(token target.MemoryToken, address target.Address, data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireMemory(token); err != nil {
		return 0, err
	}
	defer s.syncRevision()
	return s.remote.WriteMemory(address, data)
}
func (s *qemuSession) ReadCodeLocation(token target.ThreadToken) (native.CodeLocation, error) {
	registers, err := s.ReadThreadRegisters(token)
	if err != nil {
		return native.CodeLocation{}, err
	}
	if err := kernelCodeMode(registers); err != nil {
		return native.CodeLocation{}, err
	}
	value, err := contextRegisterValue(registers, "rip")
	if err != nil {
		return native.CodeLocation{}, err
	}
	location := native.CodeLocation{RawPC: target.Address(value), InstructionPC: target.Address(value)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop.Reason == target.StopBreakpoint && s.stop.ThreadID != nil && *s.stop.ThreadID == token.Thread.ID && s.points[location.RawPC] {
		p := location.RawPC
		location.Breakpoint = &p
	}
	return location, nil
}
func (s *qemuSession) AddBreakpoint(address target.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return target.ErrRunning
	}
	err := s.remote.AddBreakpoint(address)
	s.syncRevision()
	if err == nil {
		s.points[address] = true
	}
	return err
}
func (s *qemuSession) RemoveBreakpoint(address target.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return target.ErrRunning
	}
	err := s.remote.RemoveBreakpoint(address)
	s.syncRevision()
	if err == nil {
		delete(s.points, address)
	}
	return err
}

type qemuOperation struct {
	done   chan struct{}
	result target.RunResult
	err    error
}

func (op *qemuOperation) Wait(ctx context.Context) (target.RunResult, error) {
	select {
	case <-op.done:
		return op.result, op.err
	default:
	}
	select {
	case <-op.done:
		return op.result, op.err
	case <-ctx.Done():
		return target.RunResult{}, ctx.Err()
	}
}
func (s *qemuSession) startCPU(cpu uint64, step, peers bool) (operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return nil, target.ErrBusy
	}
	if cpu == 0 {
		cpu = s.cpu
	}
	if !slices.Contains(s.cpus, cpu) {
		return nil, target.ErrNotFound
	}

	if err := s.remote.SelectThread(cpu); err != nil {
		return nil, err
	}
	registers, err := s.remote.ReadRegisters()
	if err != nil {
		return nil, err
	}
	pc, err := contextRegisterValue(registers, "rip")
	if err != nil {
		return nil, err
	}
	displaced := s.points[target.Address(pc)]
	if displaced {
		if err := s.remote.RemoveBreakpoint(target.Address(pc)); err != nil {
			return nil, err
		}
	}
	remote, err := s.remote.StartCPU(cpu, step || displaced, peers && !displaced)
	if err != nil {
		if displaced {
			err = errors.Join(err, s.remote.AddBreakpoint(target.Address(pc)))
		}
		s.syncRevision()
		return nil, err
	}
	s.active = true
	s.interruptRequested = false
	s.syncRevision()
	op := &qemuOperation{done: make(chan struct{})}
	go func() {

		stop, err := remote.Wait(context.Background())
		if displaced {
			s.mu.Lock()
			if s.remote.State() == target.StateStopped {
				err = errors.Join(err, s.remote.AddBreakpoint(target.Address(pc)))
			} else {
				err = errors.Join(err, fmt.Errorf("breakpoint restoration requires a confirmed stop: %w", target.ErrInvalidState))
			}
			var next *qemu.Execution
			atBreakpoint := false
			if err == nil && stop.ThreadID != nil && *stop.ThreadID == cpu && stop.Signal.Number == 5 && stop.Reason == target.StopSignal {
				registers, readErr := s.remote.ReadRegisters()
				err = readErr
				if err == nil {
					value, readErr := contextRegisterValue(registers, "rip")
					err = readErr
					atBreakpoint = s.points[target.Address(value)]
				}
			}
			if err == nil && !step && !s.interruptRequested && !atBreakpoint && stop.Reason == target.StopSignal && stop.Signal.Number == 5 && stop.ThreadID != nil && *stop.ThreadID == cpu {
				next, err = s.remote.StartCPU(cpu, false, peers)
			}
			interrupted := s.interruptRequested
			s.mu.Unlock()
			if next != nil && err == nil {
				stop, err = next.Wait(context.Background())
			} else if interrupted && err == nil {
				stop.Reason = target.StopInterrupt
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		defer close(op.done)
		s.active = false
		s.stopRevision++
		s.syncRevision()
		if err == nil && s.remote.State() == target.StateStopped {
			if stop.ThreadID == nil {
				err = fmt.Errorf("remote stop has no CPU identity: %w", target.ErrUnavailable)
			} else {
				id := *stop.ThreadID
				cpus, readErr := s.remote.Threads()
				if readErr != nil {
					err = readErr
				} else {
					s.cpus = cpus
				}
				if err == nil {
					err = s.remote.SelectThread(id)
				}
				if err == nil {
					regs, readErr := s.remote.ReadRegisters()
					err = readErr
					if err == nil {
						value, readErr := contextRegisterValue(regs, "rip")
						err = readErr
						pc := target.Address(value)
						stop.RawPC = &pc
						if stop.Signal.Number == 5 && s.points[pc] && (stop.Reason == target.StopSignal || stop.Reason == target.StopBreakpoint) {
							stop.Reason = target.StopBreakpoint
							stop.Breakpoint = &pc
						} else if step && stop.Signal.Number == 5 && id == cpu && stop.Reason != target.StopWatchpoint {
							stop.Reason = target.StopStep
							stop.StepCompleted = true
						} else if stop.Signal.Number == 2 {
							stop.Reason = target.StopInterrupt
						}
					}
				}
				s.cpu = id
			}
		}

		if stop.Reason == target.StopWatchpoint {
			var hits []target.WatchpointHit
			for _, reported := range stop.Watchpoints {
				for _, owned := range s.watches {
					if reported.Address >= owned.Address && uint64(reported.Address-owned.Address) < uint64(owned.Size) {
						hits = append(hits, owned)
					}
				}
			}
			slices.SortFunc(hits, func(a, b target.WatchpointHit) int { return a.Ref.Slot - b.Ref.Slot })
			stop.Watchpoints = hits
		}
		s.stop = stop
		op.err = err
		id := cpu
		if stop.ThreadID != nil {
			id = *stop.ThreadID
		}
		op.result = target.RunResult{Stop: stop, Thread: target.ThreadRef{Session: s.id, ID: id}, Token: s.token(id), Sequence: s.revision}
	}()
	return op, nil
}
func (s *qemuSession) Run(request target.RunRequest) (operation, error) {
	if slices.ContainsFunc(request.Signals, func(signal target.ThreadSignal) bool { return signal.Signal != (target.Signal{}) }) {
		return nil, fmt.Errorf("guest exceptions cannot be delivered as host signals: %w", target.ErrUnsupported)
	}
	if request.Threads.Scope == target.ProcessThreads {
		if request.Threads.Process != (target.ProcessRef{Session: s.id, ID: 1}) {
			return nil, target.ErrStale
		}
		return s.startCPU(0, false, true)
	}
	if len(request.Threads.Threads) != 1 || request.Threads.Threads[0].Session != s.id {
		return nil, target.ErrInvalidArgument
	}
	return s.startCPU(request.Threads.Threads[0].ID, false, false)
}
func (s *qemuSession) StepInstruction(request target.StepRequest) (operation, error) {
	if request.Thread.Session != s.id {
		return nil, target.ErrStale
	}
	if slices.ContainsFunc(request.Signals, func(signal target.ThreadSignal) bool { return signal.Signal != (target.Signal{}) }) {
		return nil, target.ErrUnsupported
	}
	peers := request.Continue.Scope == target.ProcessThreads
	if peers && request.Continue.Process != (target.ProcessRef{Session: s.id, ID: 1}) {
		return nil, target.ErrStale
	}
	if !peers && len(request.Continue.Threads) != 0 {
		return nil, target.ErrUnsupported
	}
	return s.startCPU(request.Thread.ID, true, peers)
}
func (s *qemuSession) Interrupt(request target.InterruptRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Threads.Scope != target.ProcessThreads || request.Threads.Process != (target.ProcessRef{Session: s.id, ID: 1}) {
		return target.ErrInvalidArgument
	}
	if !s.active {
		if s.remote.State() == target.StateStopped {
			return nil
		}
		return target.ErrInvalidState
	}
	s.interruptRequested = true
	if s.remote.State() == target.StateStopped {
		return nil
	}
	return s.remote.Interrupt()
}
func (s *qemuSession) Kill() error {
	return fmt.Errorf("kill is a native-process operation; use detach for QEMU: %w", target.ErrUnsupported)
}
func (s *qemuSession) Detach() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return target.ErrRunning
	}
	return s.remote.Detach()
}
func (s *qemuSession) Close() error {
	s.mu.Lock()
	active := s.active
	state := s.remote.State()
	s.mu.Unlock()
	if active {
		return target.ErrBusy
	}
	if state == target.StateStopped {
		if err := s.Detach(); err != nil {
			return err
		}
	}
	var imageErr error
	if s.image != nil {
		imageErr = s.image.Close()
		s.image = nil
	}
	return errors.Join(imageErr, s.remote.Close())
}

func (s *qemuSession) ReadThreadSegmentBase(token target.ThreadToken, name string) (target.Address, error) {
	if name != "fs" && name != "gs" {
		return 0, target.ErrInvalidArgument
	}
	registers, err := s.ReadThreadRegisters(token)
	if err != nil {
		return 0, err
	}
	value, err := contextRegisterValue(registers, name+"_base")
	return target.Address(value), err
}

func (s *qemuSession) SetWatchpoint(token target.ThreadToken, request target.WatchpointRequest) (target.WatchpointResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.require(token); err != nil {
		return target.WatchpointResult{}, err
	}
	if request.Slot < 0 || request.Slot > 3 {
		return target.WatchpointResult{}, target.ErrInvalidArgument
	}
	if _, ok := s.watches[request.Slot]; ok {
		return target.WatchpointResult{}, target.ErrBusy
	}
	kind := 2
	if request.Access == target.WatchReadWrite {
		kind = 4
	} else if request.Access != target.WatchWrite {
		return target.WatchpointResult{}, target.ErrInvalidArgument
	}
	err := s.remote.AddHardwarePoint(qemu.HardwarePoint{Kind: kind, Address: request.Address, Size: request.Size})
	s.syncRevision()
	if err != nil {
		return target.WatchpointResult{}, err
	}
	s.watchGeneration++
	ref := target.WatchpointRef{Thread: token.Thread, Slot: request.Slot, Generation: s.watchGeneration}
	s.watches[request.Slot] = target.WatchpointHit{Ref: ref, Address: request.Address, Size: request.Size, Access: request.Access}
	return target.WatchpointResult{Ref: ref, Token: s.token(token.Thread.ID)}, nil
}
func (s *qemuSession) ClearWatchpoint(token target.ThreadToken, ref target.WatchpointRef) (target.ThreadToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.require(token); err != nil {
		return target.ThreadToken{}, err
	}
	point, ok := s.watches[ref.Slot]
	if !ok || point.Ref != ref {
		return target.ThreadToken{}, target.ErrStale
	}
	kind := 2
	if point.Access == target.WatchReadWrite {
		kind = 4
	}
	err := s.remote.RemoveHardwarePoint(qemu.HardwarePoint{Kind: kind, Address: point.Address, Size: point.Size})
	s.syncRevision()
	if err != nil {
		return target.ThreadToken{}, err
	}
	delete(s.watches, ref.Slot)
	return s.token(token.Thread.ID), nil
}

func kernelCodeMode(registers []target.Register) error {
	efer, err := contextRegisterValue(registers, "efer")
	if err != nil {
		return err
	}
	if efer&(1<<10) == 0 {
		return fmt.Errorf("amd64 disassembly requires an active long-mode vCPU: %w", target.ErrUnsupported)
	}
	return nil
}
