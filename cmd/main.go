package main

import (
	"os"
	"os/signal"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/ebpf"
	"github.com/sagacious-labs/hyperion-network-watcher/pkg/log"
)

func main() {
	prog := ebpf.NewTCPConnLat()
	ch := prog.Start()

	go func() {
		for data := range ch {
			log.DataLog(data)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop
	prog.Stop()
}
