package ebpf

import (
	"sync"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/ebpf/program"
)

type EBPF struct {
	progs []program.EBPFProgram
}

func New() *EBPF {
	return &EBPF{
		progs: make([]program.EBPFProgram, 0),
	}
}

// Start starts all of the ebpf programs and returns the data
func (ebpf *EBPF) Start() <-chan []byte {
	ch := make(chan []byte)

	// TCP Connection Latency program
	prog := program.NewTCPConnLat()
	ebpf.progs = append(ebpf.progs, prog)
	go ebpf.manageData(prog, ch)

	// TCP Top program
	progTop := program.NewTCPTop()
	ebpf.progs = append(ebpf.progs, progTop)
	go ebpf.manageData(progTop, ch)

	return ch
}

func (ebpf *EBPF) manageData(prog program.EBPFProgram, out chan []byte) {
	in := prog.Start()
	for data := range in {
		annotated := NewContainerAnnotatedEBPFData(data)
		if annotated != nil {
			out <- annotated.ToBytes()
		}
	}
}

func (ebpf *EBPF) Stop() {
	var wg sync.WaitGroup
	for _, prog := range ebpf.progs {
		wg.Add(1)
		go func(prog program.EBPFProgram) {
			prog.Stop()
			wg.Done()
		}(prog)
	}

	wg.Wait()
}
