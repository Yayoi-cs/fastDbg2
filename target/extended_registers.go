package target

type ExtendedRegisterFormat uint8

const (
	ExtendedFormatUnknown ExtendedRegisterFormat = iota
	ExtendedFormatXSave
	ExtendedFormatFXSave
)

func (format ExtendedRegisterFormat) String() string {
	switch format {
	case ExtendedFormatXSave:
		return "linux-x86-xsave-standard"
	case ExtendedFormatFXSave:
		return "linux-x86-fxsave"
	default:
		return "unknown"
	}
}

type XStateComponent struct {
	ID     uint8
	Offset uint32
	Size   uint32
}

type XStateInfo struct {
	KernelFeatures     uint64
	Present            uint64
	ExtendedComponents []XStateComponent
}

type ExtendedRegisterState struct {
	Token        ThreadToken
	Architecture Architecture
	Format       ExtendedRegisterFormat
	Data         []byte
	XState       *XStateInfo
}
