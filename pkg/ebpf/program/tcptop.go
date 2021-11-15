package program

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/log"
)

// TCPConnLat implements ebpf program interface
//
// It provides interface to get TCP connection latency
// data from the host machine
type TCPTop struct {
	bin  string
	proc *exec.Cmd
}

// TCPConnLatData is the data format which is internally returned
// by the probe
type TCPTopData struct {
	Type       string  `json:"@type,omitempty"`
	PID        int     `json:"-"`
	Host       string  `json:"host,omitempty"`
	IPType     uint8   `json:"ip_type,omitempty"`
	SourceIP   string  `json:"source_ip,omitempty"`
	SourcePort string  `json:"source_port,omitempty"`
	DestIP     string  `json:"dest_ip,omitempty"`
	DestPort   string  `json:"dest_port,omitempty"`
	RxKB       float64 `json:"rx_kb"`
	TxKB       float64 `json:"tx_kb"`
}

// GetPID returns the process id for the data
func (d *TCPTopData) GetPID() int {
	return d.PID
}

// NewTCPConnLat returns instance of TCP connection latency prober
func NewTCPTop() EBPFProgram {
	return &TCPTop{
		bin: "./ebpf/tcptop.py",
	}
}

// Start starts the prober and returns a channels which can be used
// to listen for the data coming though the prober
//
// NOTE: The channel must not be blocked
func (c *TCPTop) Start() <-chan EBPFProgramData {
	cmd := exec.Command(c.bin)
	c.proc = cmd

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "PYTHONUNBUFFERED=true")

	stdout, _ := cmd.StdoutPipe()

	ch := make(chan EBPFProgramData, 8)

	if err := cmd.Start(); err != nil {
		println(err.Error())
		return nil
	}

	go func() {
		reader := bufio.NewReader(stdout)

		first := true
		for {
			data, e := reader.ReadString('\n')
			if e != nil {
				break
			}
			if first {
				first = false
				continue
			}

			parsed, _ := c.ParseStdout(data)
			if parsed == nil {
				continue
			}

			ch <- parsed
		}

		close(ch)
	}()

	return ch
}

// Stop will send SIGINT to the prober
func (c *TCPTop) Stop() {
	if c.proc == nil {
		return
	}

	c.proc.Process.Signal(os.Interrupt)
	c.proc.Wait()

	log.Logf("Stopped TCP Top Prober")
}

// ParseStdout will convert the prober stdout to TCPConnLatData
//
// NOTE: If the method fails then it will return the error - leaving the
// responsibility of the lost data to the caller
func (c *TCPTop) ParseStdout(str string) (*TCPTopData, error) {
	splitted := strings.Split(str, " ")

	aggregate := []string{}
	for _, data := range splitted {
		trimmed := strings.TrimSpace(data)
		if trimmed != "" {
			aggregate = append(aggregate, trimmed)
		}
	}

	if len(aggregate) != 9 {
		return nil, errors.New("stdout data of the prober must be of len() = 9")
	}

	// Get process ID
	pid, err := strconv.Atoi(aggregate[0])
	if err != nil {
		return nil, err
	}

	// Get host name
	host := aggregate[1]

	// Get type of the address
	ipType, err := strconv.Atoi(aggregate[2])
	if err != nil {
		return nil, err
	}

	// Get source IP address
	srcIP := aggregate[3]

	// Get source port
	srcPort := aggregate[4]

	// Get destination IP address
	destIP := aggregate[5]

	// Get destination port
	destPort := aggregate[6]

	// Get RX
	rx, err := strconv.ParseFloat(aggregate[7], 64)
	if err != nil {
		return nil, err
	}

	// Get TX
	tx, err := strconv.ParseFloat(aggregate[8], 64)
	if err != nil {
		return nil, err
	}

	return &TCPTopData{
		Type:       TCP_TOP,
		PID:        pid,
		Host:       host,
		IPType:     uint8(ipType),
		SourceIP:   srcIP,
		SourcePort: srcPort,
		DestIP:     destIP,
		DestPort:   destPort,
		TxKB:       tx,
		RxKB:       rx,
	}, nil
}
