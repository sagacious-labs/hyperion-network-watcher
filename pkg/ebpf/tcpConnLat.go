package ebpf

import (
	"bufio"
	"encoding/json"
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
type TCPConnLat struct {
	bin  string
	proc *exec.Cmd
}

// TCPConnLatData is the data format which is internally returned
// by the probe
type TCPConnLatData struct {
	PID      int     `json:"pid,omitempty"`
	Host     string  `json:"host,omitempty"`
	IPType   uint8   `json:"ip_type,omitempty"`
	SourceIP string  `json:"source_ip,omitempty"`
	DestIP   string  `json:"dest_ip,omitempty"`
	DestPort string  `json:"dest_port,omitempty"`
	Latency  float64 `json:"latency,omitempty"`
}

// ToBytes will convert the TCPConnLatData to bytes. This process
// converts the struct into json, if the process fails then NO error
// is returned, just nil is returned
func (d *TCPConnLatData) ToBytes() []byte {
	byt, _ := json.Marshal(d)
	return byt
}

// NewTCPConnLat returns instance of TCP connection latency prober
func NewTCPConnLat() EBPFProgram {
	return &TCPConnLat{
		bin: "/usr/share/bcc/tools/tcpconnlat",
	}
}

// Start starts the prober and returns a channels which can be used
// to listen for the data coming though the prober
//
// NOTE: The channel must not be blocked
func (c *TCPConnLat) Start() <-chan []byte {
	cmd := exec.Command(c.bin)
	c.proc = cmd

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "PYTHONUNBUFFERED=true")

	stdout, _ := cmd.StdoutPipe()

	ch := make(chan []byte, 8)

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

			ch <- parsed.ToBytes()
		}

		close(ch)
	}()

	return ch
}

// Stop will send SIGINT to the prober
func (c *TCPConnLat) Stop() {
	c.proc.Process.Signal(os.Interrupt)
	c.proc.Wait()
	log.Logf("Stopped TCP Connection Latency Prober")
}

// ParseStdout will convert the prober stdout to TCPConnLatData
//
// NOTE: If the method fails then it will return the error - leaving the
// responsibility of the lost data to the caller
func (c *TCPConnLat) ParseStdout(str string) (*TCPConnLatData, error) {
	splitted := strings.Split(str, " ")

	aggregate := []string{}
	for _, data := range splitted {
		trimmed := strings.TrimSpace(data)
		if trimmed != "" {
			aggregate = append(aggregate, trimmed)
		}
	}

	if len(aggregate) != 7 {
		return nil, errors.New("stdout data of the prober must be of len() = 7")
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

	// Get destination IP address
	destIP := aggregate[4]

	// Get destination port
	destPort := aggregate[5]

	// Get latency
	latency, err := strconv.ParseFloat(aggregate[6], 64)
	if err != nil {
		return nil, err
	}

	return &TCPConnLatData{
		PID:      pid,
		Host:     host,
		IPType:   uint8(ipType),
		SourceIP: srcIP,
		DestIP:   destIP,
		DestPort: destPort,
		Latency:  latency,
	}, nil
}
