package log

import (
	"fmt"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/utils"
	"github.com/sagacious-labs/hyperion-sdk-go/pkg/ipc"
)

// Logf provides a similar interface as printf - this will call
// hyperion's logf if the process is running as Hyperion Child or else
// will call printf
//
// This method should not be used to send data to Hyperion as this
// method is meant to send logs to Hyperion and not data. To send data
// to hyperion, check DataLog method
func Logf(format string, args ...interface{}) {
	if utils.IsHyperionChild() {
		ipc.Logf(format, args...)
		return
	}

	fmt.Printf(format, args...)
}

// DataLog takes in data as byte slice and sends it to Hyperion if
// the process is running as Hyperion Child or else wille print it
// to the console
func DataLog(data []byte) {
	if utils.IsHyperionChild() {
		ipc.SendData(data)
		return
	}

	fmt.Printf("%s", data)
}
