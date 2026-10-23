package target

type HardwareBreakpointRequest struct {
	Slot    int
	Address Address
}

type HardwareBreakpointRef struct {
	Thread     ThreadRef
	Slot       int
	Generation uint64
}

type HardwareBreakpointResult struct {
	Ref   HardwareBreakpointRef
	Token ThreadToken
}

type HardwareBreakpointHit struct {
	Ref     HardwareBreakpointRef
	Address Address
}
