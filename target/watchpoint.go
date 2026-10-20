package target

type WatchAccess uint8

const (
	WatchUnknown WatchAccess = iota
	WatchWrite
	WatchReadWrite
)

func (access WatchAccess) String() string {
	switch access {
	case WatchWrite:
		return "write"
	case WatchReadWrite:
		return "read-write"
	default:
		return "unknown"
	}
}

type WatchpointRequest struct {
	Slot    int
	Address Address
	Size    int
	Access  WatchAccess
}

type WatchpointRef struct {
	Thread     ThreadRef
	Slot       int
	Generation uint64
}

type WatchpointResult struct {
	Ref   WatchpointRef
	Token ThreadToken
}

type WatchpointHit struct {
	Ref     WatchpointRef
	Address Address
	Size    int
	Access  WatchAccess
}
