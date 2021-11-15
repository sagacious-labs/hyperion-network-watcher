package program

const (
	CONNECTION_LATENCY = "hyperion.sagacious.dev/data/network/latency"
)

// EBPFProgram interface is to provide an abstraction
// on top of all of the ebpf programs
type EBPFProgram interface {
	Start() <-chan EBPFProgramData
	Stop()
}

// EBPFProgramData interface is to create an abstraction
// on top of the data that is returned by the ebpf programs
type EBPFProgramData interface {
	GetPID() int
}
