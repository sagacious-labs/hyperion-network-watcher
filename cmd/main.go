package main

import (
	"os"
	"os/signal"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/ebpf"
	"github.com/sagacious-labs/hyperion-network-watcher/pkg/log"
)

func main() {
	probe := ebpf.New()
	ch := probe.Start()

	go func() {
		for data := range ch {
			log.DataLog(data)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop
	probe.Stop()
}
