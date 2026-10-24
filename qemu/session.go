package qemu

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fastdbg2/qemu/internal/arch"
	"fastdbg2/target"
)

type Options struct {
	Timeout           time.Duration
	PacketSize        int
	MaxPacketSize     int
	MaxConsoleSize    int
	RegisterByteOrder target.ByteOrder
}

type Session struct {
	hardwarePoints    map[HardwarePoint]bool
	protocol          *protocol
	operation         chan struct{}
	mu                sync.Mutex
	state             target.State
	stop              target.Stop
	generation        uint64
	registers         []registerDefinition
	profile           arch.Descriptor
	registerByteOrder target.ByteOrder
	features          map[string]string
	actions           map[string]bool
	breakpoints       map[target.Address]struct{}
	packetSize        int
	noAck             bool
	selected          *uint64
	inspectionThread  *uint64
	outputMu          sync.Mutex
	output            []byte
	outputLimit       int
}

func Connect(address string, options ...Options) (*Session, error) {
	optionsValue, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", address, optionsValue.Timeout)
	if err != nil {
		return nil, err
	}
	return connect(conn, optionsValue)
}

func normalizeOptions(options []Options) (Options, error) {
	if len(options) > 1 {
		return Options{}, fmt.Errorf("%w: at most one options value", target.ErrInvalidArgument)
	}
	var value Options
	if len(options) == 1 {
		value = options[0]
	}
	if value.Timeout == 0 {
		value.Timeout = 5 * time.Second
	}
	if value.MaxPacketSize == 0 {
		value.MaxPacketSize = 1 << 20
	}
	if value.MaxConsoleSize == 0 {
		value.MaxConsoleSize = 1 << 20
	}
	if value.Timeout < 0 || value.PacketSize < 0 || value.MaxPacketSize < 128 || value.MaxConsoleSize < 0 || value.RegisterByteOrder > target.BigEndian {
		return Options{}, fmt.Errorf("%w: invalid transport limits", target.ErrInvalidArgument)
	}
	return value, nil
}

func connect(conn net.Conn, options Options) (*Session, error) {
	s := &Session{
		protocol:  newProtocol(conn, options.Timeout, options.MaxPacketSize),
		operation: make(chan struct{}, 1), state: target.StateUnknown,
		features: make(map[string]string), actions: make(map[string]bool),
		breakpoints: make(map[target.Address]struct{}), packetSize: options.PacketSize,
		outputLimit: options.MaxConsoleSize, registerByteOrder: options.RegisterByteOrder,
	}
	s.operation <- struct{}{}
	if err := s.initialize(options); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) initialize(options Options) error {
	data, err := s.request("qSupported:swbreak+;hwbreak+;xmlRegisters=i386,aarch64")
	if err != nil {
		return err
	}
	for _, feature := range strings.Split(string(data), ";") {
		if feature == "" {
			continue
		}
		name, value, found := strings.Cut(feature, "=")
		if !found {
			if len(feature) < 2 || !strings.ContainsRune("+-?", rune(feature[len(feature)-1])) {
				return s.protocolError("invalid qSupported feature")
			}
			name, value = feature[:len(feature)-1], feature[len(feature)-1:]
		}
		if _, exists := s.features[name]; exists {
			return s.protocolError("duplicate qSupported feature")
		}
		s.features[name] = value
	}
	if value, exists := s.features["PacketSize"]; exists {
		n, err := strconv.ParseUint(value, 16, 31)
		if err != nil || n == 0 {
			return s.protocolError("invalid PacketSize")
		}
		s.packetSize = int(n)
		if options.PacketSize > 0 {
			s.packetSize = min(s.packetSize, options.PacketSize)
		}
	}
	if s.packetSize == 0 {
		return fmt.Errorf("%w: remote PacketSize is required", target.ErrUnknown)
	}
	if s.features["QStartNoAckMode"] == "+" {
		if err := s.expectOK("QStartNoAckMode"); err != nil {
			return err
		}
		s.noAck = true
	}
	if s.features["qXfer:features:read"] != "+" {
		return fmt.Errorf("%w: target XML is required", target.ErrUnsupported)
	}
	if err := s.loadRegisters(); err != nil {
		return err
	}
	data, err = s.request("vCont?")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(data), "vCont;") {
		return fmt.Errorf("%w: vCont is required", target.ErrUnsupported)
	}
	for _, action := range strings.Split(string(data[6:]), ";") {
		if action == "" || s.actions[action] {
			return s.protocolError("invalid vCont action list")
		}
		s.actions[action] = true
	}
	if !s.actions["c"] {
		return fmt.Errorf("%w: vCont continue", target.ErrUnsupported)
	}
	data, err = s.request("?")
	if err != nil {
		return err
	}
	stop, err := s.parseStop(data)
	if err != nil {
		return err
	}
	s.generation = 1
	s.recordStop(stop)
	return nil
}

func (s *Session) Architecture() target.Architecture {
	return s.profile.Architecture
}

func (s *Session) RegisterByteOrder() target.ByteOrder {
	return s.registerByteOrder
}

func (s *Session) State() target.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateLocked()
}

func (s *Session) stateLocked() target.State {
	if s.state == target.StateExited || s.state == target.StateDetached {
		return s.state
	}
	select {
	case <-s.protocol.done:
		return target.StateClosed
	default:
		return s.state
	}
}

func (s *Session) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func copyStop(stop target.Stop) target.Stop {
	stop.Watchpoints = slices.Clone(stop.Watchpoints)
	stop.HardwareBreakpoints = slices.Clone(stop.HardwareBreakpoints)
	if stop.ThreadID != nil {
		value := *stop.ThreadID
		stop.ThreadID = &value
	}
	if stop.RawPC != nil {
		value := *stop.RawPC
		stop.RawPC = &value
	}
	if stop.ExitCode != nil {
		value := *stop.ExitCode
		stop.ExitCode = &value
	}
	if stop.Breakpoint != nil {
		value := *stop.Breakpoint
		stop.Breakpoint = &value
	}
	return stop
}

func (s *Session) LastStop() target.Stop {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyStop(s.stop)
}

func (s *Session) begin() error {
	if err := s.checkStopped(); err != nil {
		return err
	}
	select {
	case <-s.operation:
	default:
		return target.ErrBusy
	}
	if err := s.checkStopped(); err != nil {
		s.end()
		return err
	}
	return nil
}

func (s *Session) end() {
	s.operation <- struct{}{}
}

func (s *Session) checkStopped() error {
	switch s.State() {
	case target.StateStopped:
		return nil
	case target.StateRunning:
		return target.ErrRunning
	case target.StateClosed:
		return target.ErrClosed
	case target.StateExited:
		return target.ErrExited
	case target.StateDetached:
		return target.ErrDetached
	default:
		return target.ErrInvalidState
	}
}

func (s *Session) changed() {
	s.mu.Lock()
	s.generation++
	s.mu.Unlock()
}

func (s *Session) protocolError(message string) error {
	err := fmt.Errorf("%w: %s", ErrProtocol, message)
	s.protocol.close(err)
	return err
}

func (s *Session) request(command string) ([]byte, error) {
	if s.packetSize > 0 && len(encodePacket([]byte(command)))-4 > s.packetSize {
		return nil, fmt.Errorf("%w: command exceeds remote PacketSize", target.ErrUnsupported)
	}
	if err := s.protocol.send(command, s.noAck); err != nil {
		return nil, err
	}
	data, err := s.protocol.reply(s.noAck, false, s.appendOutput)
	if err != nil {
		return nil, err
	}
	return data, remoteError(command, data)
}

func remoteError(command string, data []byte) error {
	if len(data) == 3 && data[0] == 'E' {
		code, err := hex.DecodeString(string(data[1:]))
		if err != nil {
			return fmt.Errorf("%w: malformed remote error", ErrProtocol)
		}
		return &RemoteError{Command: command, Code: code[0]}
	}
	return nil
}

func (s *Session) expectOK(command string) error {
	data, err := s.request(command)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: %s", target.ErrUnsupported, command)
	}
	if string(data) != "OK" {
		return s.protocolError("expected OK for " + command)
	}
	return nil
}

func (s *Session) appendOutput(data []byte) error {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	if len(data) > s.outputLimit-len(s.output) {
		return fmt.Errorf("%w: remote console buffer full", target.ErrOverflow)
	}
	s.output = append(s.output, data...)
	return nil
}

func (s *Session) TakeOutput() []byte {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	data := s.output
	s.output = nil
	return data
}

func (s *Session) currentThread() (uint64, error) {
	s.mu.Lock()
	known := s.stop.ThreadID
	s.mu.Unlock()
	if known != nil {
		return *known, nil
	}
	data, err := s.request("qC")
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(string(data), "QC") {
		return 0, fmt.Errorf("%w: current thread is not reported", target.ErrUnknown)
	}
	tid, err := parseThread(string(data[2:]))
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.stop.ThreadID = &tid
	s.mu.Unlock()
	return tid, nil
}

func parseThread(value string) (uint64, error) {
	if strings.HasPrefix(value, "p") {
		return 0, fmt.Errorf("%w: multiprocess thread ID", target.ErrUnsupported)
	}
	tid, err := strconv.ParseUint(value, 16, 32)
	if err != nil || tid == 0 {
		return 0, fmt.Errorf("%w: invalid thread ID", ErrProtocol)
	}
	return tid, nil
}

func (s *Session) selectThread() error {
	tid, err := s.currentThread()
	if s.inspectionThread != nil {
		tid, err = *s.inspectionThread, nil
	}
	if err != nil {
		return err
	}
	if s.selected != nil && *s.selected == tid {
		return nil
	}
	if err := s.expectOK(fmt.Sprintf("Hg%x", tid)); err != nil {
		return err
	}
	s.selected = &tid
	return nil
}

func (s *Session) Continue(signal target.Signal) (target.Stop, error) {
	return s.resume(false, signal)
}

func (s *Session) Step(signal target.Signal) (target.Stop, error) {
	return s.resume(true, signal)
}

func (s *Session) resume(step bool, signal target.Signal) (target.Stop, error) {
	return s.resumeCPU(step, signal, nil, !step, nil)
}

func (s *Session) resumeCPU(step bool, signal target.Signal, cpu *uint64, peers bool, started chan<- error) (result target.Stop, resultErr error) {
	defer func() {
		if started != nil {
			started <- resultErr
		}
	}()
	if signal.Domain != target.SignalGDB && signal != (target.Signal{}) {
		return target.Stop{}, fmt.Errorf("%w: expected GDB signal", target.ErrUnsupported)
	}
	if signal.Number > 255 {
		return target.Stop{}, fmt.Errorf("%w: GDB signal exceeds one byte", target.ErrInvalidArgument)
	}
	if err := s.begin(); err != nil {
		return target.Stop{}, err
	}
	defer s.end()
	action := "c"
	if step {
		action = "s"
	}
	if signal.Number != 0 {
		action = strings.ToUpper(action)
	}
	if !s.actions[action] {
		return target.Stop{}, fmt.Errorf("%w: vCont %s", target.ErrUnsupported, action)
	}
	command := "vCont;" + action
	if signal.Number != 0 {
		command += fmt.Sprintf("%02x", signal.Number)
	}
	if step || signal.Number != 0 || cpu != nil && !peers {
		tid, err := s.currentThread()
		if cpu != nil {
			tid, err = *cpu, nil
		}
		if err != nil {
			return target.Stop{}, err
		}
		command += fmt.Sprintf(":%x", tid)
		if peers {
			command += ";c"
		}
	}
	if len(command) > s.packetSize {
		return target.Stop{}, fmt.Errorf("%w: vCont exceeds PacketSize", target.ErrUnsupported)
	}
	s.mu.Lock()
	s.generation++
	err := s.protocol.send(command, s.noAck)
	if err == nil {
		s.state = target.StateRunning
	} else {
		s.state = target.StateUnknown
	}
	s.mu.Unlock()
	if err != nil {
		return target.Stop{}, err
	}
	if started != nil {
		started <- nil
		started = nil
	}
	data, err := s.protocol.reply(s.noAck, true, s.appendOutput)
	if err != nil {
		return target.Stop{}, err
	}
	if err := remoteError(command, data); err != nil {
		s.protocol.close(err)
		return target.Stop{}, err
	}
	stop, err := s.parseStop(data)
	if err != nil {
		s.protocol.close(err)
		return target.Stop{}, err
	}
	s.recordStop(stop)
	return s.LastStop(), nil
}

func (s *Session) recordStop(stop target.Stop) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stop.Generation = s.generation
	s.stop = copyStop(stop)
	s.selected = nil
	if stop.Reason == target.StopExited || stop.Reason == target.StopSignaled {
		s.state = target.StateExited
	} else {
		s.state = target.StateStopped
	}
}

func (s *Session) Interrupt() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateLocked() != target.StateRunning {
		return target.ErrInvalidState
	}
	return s.protocol.write([]byte{3})
}

func (s *Session) Detach() error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	addresses := make([]target.Address, 0, len(s.breakpoints))
	for addr := range s.breakpoints {
		addresses = append(addresses, addr)
	}
	slices.Sort(addresses)
	for _, addr := range addresses {
		if err := s.removeBreakpoint(addr); err != nil {
			return err
		}
	}

	points := make([]HardwarePoint, 0, len(s.hardwarePoints))
	for point := range s.hardwarePoints {
		points = append(points, point)
	}
	slices.SortFunc(points, func(a, b HardwarePoint) int {
		if a.Kind != b.Kind {
			return a.Kind - b.Kind
		}
		if a.Address < b.Address {
			return -1
		}
		if a.Address > b.Address {
			return 1
		}
		return a.Size - b.Size
	})
	for _, point := range points {
		if err := s.removeHardwarePoint(point); err != nil {
			return err
		}
	}
	s.changed()
	if err := s.expectOK("D"); err != nil {
		return err
	}
	s.protocol.close(target.ErrDetached)
	<-s.protocol.readerDone
	s.mu.Lock()
	s.state = target.StateDetached
	s.mu.Unlock()
	return nil
}

func (s *Session) Close() error {
	s.protocol.close(target.ErrClosed)
	<-s.protocol.readerDone
	s.mu.Lock()
	s.state = target.StateClosed
	s.mu.Unlock()
	return nil
}

func (s *Session) parseStop(data []byte) (target.Stop, error) {
	stop := target.Stop{Raw: string(data)}
	if len(data) == 0 {
		return stop, fmt.Errorf("%w: stop reply", target.ErrUnsupported)
	}
	if len(data) < 3 {
		return stop, fmt.Errorf("%w: incomplete stop reply", ErrProtocol)
	}
	number, err := strconv.ParseUint(string(data[1:3]), 16, 8)
	if err != nil {
		return stop, fmt.Errorf("%w: invalid stop code", ErrProtocol)
	}
	switch data[0] {
	case 'W':
		if len(data) != 3 {
			return stop, fmt.Errorf("%w: extended exit reply", target.ErrUnsupported)
		}
		code := int(number)
		stop.Reason, stop.ExitCode = target.StopExited, &code
	case 'X':
		if len(data) != 3 {
			return stop, fmt.Errorf("%w: extended signal-exit reply", target.ErrUnsupported)
		}
		stop.Reason = target.StopSignaled
		stop.Signal = target.Signal{Domain: target.SignalGDB, Number: uint32(number)}
	case 'S', 'T':
		stop.Reason = target.StopSignal
		stop.Signal = target.Signal{Domain: target.SignalGDB, Number: uint32(number)}
		if data[0] == 'S' && len(data) != 3 {
			return stop, fmt.Errorf("%w: extra signal reply data", ErrProtocol)
		}
		if len(data) == 3 {
			return stop, nil
		}
		if data[len(data)-1] != ';' {
			return stop, fmt.Errorf("%w: unterminated stop field", ErrProtocol)
		}
		seen := make(map[string]bool)
		reasons := 0
		for _, field := range strings.Split(string(data[3:len(data)-1]), ";") {
			key, value, ok := strings.Cut(field, ":")
			if !ok || key == "" || seen[key] {
				return stop, fmt.Errorf("%w: invalid stop field", ErrProtocol)
			}
			seen[key] = true
			switch key {
			case "thread":
				tid, err := parseThread(value)
				if err != nil {
					return stop, err
				}
				stop.ThreadID = &tid
			case "swbreak", "hwbreak":
				if value != "" || number != 5 || s.features[key] != "+" {
					return stop, fmt.Errorf("%w: invalid breakpoint stop", ErrProtocol)
				}
				reasons++
				stop.Reason = target.StopBreakpoint
				if key == "hwbreak" {
					stop.Reason = target.StopHardwareBreakpoint
				}
			case "watch", "rwatch", "awatch":
				address, err := strconv.ParseUint(value, 16, 64)
				if err != nil || number != 5 {
					return stop, fmt.Errorf("%w: invalid watchpoint stop", ErrProtocol)
				}
				reasons++
				stop.Reason = target.StopWatchpoint
				access := target.WatchReadWrite
				if key == "watch" {
					access = target.WatchWrite
				}
				stop.Watchpoints = []target.WatchpointHit{{Address: target.Address(address), Access: access}}
			case "syscall_entry", "syscall_return", "library", "replaylog", "fork", "vfork", "vforkdone", "exec", "clone", "create":
				reasons++
				stop.Reason = target.StopUnknown
			default:
				regnum, err := strconv.ParseUint(key, 16, 32)
				if err != nil {
					continue
				}
				for _, reg := range s.registers {
					if reg.number != uint32(regnum) {
						continue
					}
					valueBytes, available, err := decodeRegister(value, reg.bits)
					if err != nil {
						return stop, err
					}
					if available && s.profile.IsProgramCounter(arch.Register{Name: reg.name, Bits: reg.bits, Feature: reg.feature}) {
						var pc target.Address
						switch s.registerByteOrder {
						case target.LittleEndian:
							pc = target.Address(binary.LittleEndian.Uint64(valueBytes))
						case target.BigEndian:
							pc = target.Address(binary.BigEndian.Uint64(valueBytes))
						default:
							return stop, fmt.Errorf("%w: register byte order", target.ErrUnknown)
						}
						stop.RawPC = &pc
					}
				}
			}
		}
		if reasons > 1 {
			return stop, fmt.Errorf("%w: multiple stop reasons", ErrProtocol)
		}
		if (stop.Reason == target.StopBreakpoint || stop.Reason == target.StopHardwareBreakpoint) && stop.RawPC != nil {
			pc := *stop.RawPC
			stop.Breakpoint = &pc
		}
	default:
		return stop, fmt.Errorf("%w: stop reply %q", target.ErrUnsupported, data[0])
	}
	return stop, nil
}

type Execution struct {
	done chan struct{}
	stop target.Stop
	err  error
}

func (op *Execution) Wait(ctx context.Context) (target.Stop, error) {
	select {
	case <-op.done:
		return copyStop(op.stop), op.err
	default:
	}
	select {
	case <-op.done:
		return copyStop(op.stop), op.err
	case <-ctx.Done():
		return target.Stop{}, ctx.Err()
	}
}

func (s *Session) StartCPU(cpu uint64, step, peers bool) (*Execution, error) {
	if cpu == 0 {
		return nil, target.ErrInvalidArgument
	}
	op := &Execution{done: make(chan struct{})}
	started := make(chan error, 1)
	go func() { op.stop, op.err = s.resumeCPU(step, target.Signal{}, &cpu, peers, started); close(op.done) }()
	if err := <-started; err != nil {
		<-op.done
		return nil, err
	}
	return op, nil
}
