package target

type Address uint64

type Architecture string

const (
	X86     Architecture = "x86"
	AMD64   Architecture = "amd64"
	AArch64 Architecture = "aarch64"
)

type ByteOrder uint8

const (
	ByteOrderUnknown ByteOrder = iota
	LittleEndian
	BigEndian
)

func (b ByteOrder) String() string {
	switch b {
	case LittleEndian:
		return "little-endian"
	case BigEndian:
		return "big-endian"
	default:
		return "unknown"
	}
}

type State uint8

const (
	StateUnknown State = iota
	StateStopped
	StateRunning
	StateExited
	StateDetached
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateRunning:
		return "running"
	case StateExited:
		return "exited"
	case StateDetached:
		return "detached"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type SignalDomain string

const (
	SignalNone  SignalDomain = ""
	SignalLinux SignalDomain = "linux"
	SignalGDB   SignalDomain = "gdb"
)

type Signal struct {
	Domain SignalDomain
	Number uint32
}

type StopReason uint8

const (
	StopUnknown StopReason = iota
	StopSignal
	StopBreakpoint
	StopStep
	StopInterrupt
	StopExited
	StopSignaled
	StopExec
	StopClone
	StopFork
	StopVFork
	StopAttach
	StopGroupStop
	StopWatchpoint
	StopHardwareBreakpoint
)

func (r StopReason) String() string {
	switch r {
	case StopSignal:
		return "signal"
	case StopBreakpoint:
		return "breakpoint"
	case StopStep:
		return "step"
	case StopInterrupt:
		return "interrupt"
	case StopExited:
		return "exited"
	case StopSignaled:
		return "signaled"
	case StopExec:
		return "exec"
	case StopClone:
		return "clone"
	case StopFork:
		return "fork"
	case StopVFork:
		return "vfork"
	case StopAttach:
		return "attach"
	case StopGroupStop:
		return "group-stop"
	case StopWatchpoint:
		return "watchpoint"
	case StopHardwareBreakpoint:
		return "hardware-breakpoint"
	default:
		return "unknown"
	}
}

type Stop struct {
	Reason              StopReason
	ThreadID            *uint64
	RawPC               *Address
	Signal              Signal
	ExitCode            *int
	Breakpoint          *Address
	Generation          uint64
	Raw                 string
	Watchpoints         []WatchpointHit
	StepCompleted       bool
	RawDR6              *uint64
	HardwareBreakpoints []HardwareBreakpointHit
}

type Register struct {
	Name      string
	Bits      int
	Data      []byte
	Available bool
}
