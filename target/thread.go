package target

type ThreadRef struct {
	Session uint64
	ID      uint64
}

type ProcessRef struct {
	Session uint64
	ID      uint64
}

type SpaceRef struct {
	Session uint64
	ID      uint64
}

type ThreadToken struct {
	Thread    ThreadRef
	Stop      uint64
	Registers uint64
}

type MemoryToken struct {
	Space    SpaceRef
	Revision uint64
}

type ThreadInfo struct {
	Ref          ThreadRef
	Process      ProcessRef
	TID          int
	Name         string
	State        State
	Exiting      bool
	Listening    bool
	GroupStopped bool
	Token        ThreadToken
	Stop         Stop
}

type Snapshot struct {
	Sequence     uint64
	State        State
	Architecture Architecture
	Process      ProcessRef
	Threads      []ThreadInfo
	Memory       MemoryToken
}

type ThreadScope uint8

const (
	ExactThreads ThreadScope = iota
	ProcessThreads
)

type ThreadSet struct {
	Scope   ThreadScope
	Process ProcessRef
	Threads []ThreadRef
}

type ThreadSignal struct {
	Thread ThreadRef
	Stop   uint64
	Signal Signal
}

type RunRequest struct {
	Threads ThreadSet
	Signals []ThreadSignal
}

type StepRequest struct {
	Thread   ThreadRef
	Continue ThreadSet
	Signals  []ThreadSignal
}

type InterruptRequest struct {
	Threads ThreadSet
}

type RunResult struct {
	Stop     Stop
	Thread   ThreadRef
	Token    ThreadToken
	Sequence uint64
}

type ExecutionMode uint8

const (
	ExecutionUnknown ExecutionMode = iota
	AllStop
	NonStop
)

type Capabilities struct {
	Modes                    []ExecutionMode
	ThreadControl            bool
	InstructionStep          bool
	SoftwareBreakpoints      bool
	HardwareWatchpoints      bool
	WatchpointSlotsPerThread int
	WatchpointSizes          []int
}
