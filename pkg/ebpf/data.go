package ebpf

import (
	"encoding/json"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/container"
	"github.com/sagacious-labs/hyperion-network-watcher/pkg/ebpf/program"
)

// ContainerAnnotatedEBPFData add container ID data to the EBPF data
type ContainerAnnotatedEBPFData struct {
	ContainerID string                  `json:"container_id,omitempty"`
	Data        program.EBPFProgramData `json:"data,omitempty"`
}

func NewContainerAnnotatedEBPFData(data program.EBPFProgramData) *ContainerAnnotatedEBPFData {
	id, ok := container.GetContainerID(int32(data.GetPID()))
	if !ok {
		return nil
	}

	return &ContainerAnnotatedEBPFData{
		Data:        data,
		ContainerID: id,
	}
}

func (c *ContainerAnnotatedEBPFData) ToBytes() []byte {
	byt, _ := json.Marshal(c)
	return byt
}
