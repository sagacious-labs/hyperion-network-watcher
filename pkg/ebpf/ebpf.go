package ebpf

// EBPFProgram interface is desined to provide an abstraction
// on top of all of the ebpf programs
type EBPFProgram interface {
	Start() <-chan []byte
	Stop()
}
