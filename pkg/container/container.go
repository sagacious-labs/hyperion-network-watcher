package container

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sagacious-labs/hyperion-network-watcher/pkg/log"
	"github.com/sagacious-labs/hyperion-network-watcher/pkg/utils"
)

// ProcessIsContainer takes in a process ID and returns true if the process is running
// inside a docker container.
// The function uses environmental variables to determine if the process is running inside container
//
// It looks for the following enviromental variables in the process - presence of ANY one of them will return
// true:
//  - KUBERNETES_SERVICE_HOST
//  - POD_NAME
//  - HYPERION_ENABLED
func ProcessIsContainer(pid int32) bool {
	procfs := utils.ProcFS()

	environ, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(int(pid)), "environ"))
	if err != nil {
		log.Logf("failed to read environment of process: %d\n", pid)
		return false
	}

	vars := strings.Split(string(environ), "\x00")

	for _, env := range vars {
		if strings.Contains(env, "KUBERNETES_SERVICE_HOST") ||
			strings.Contains(env, "POD_NAME") ||
			strings.Contains(env, "HYPERION_ENABLED") {
			return true
		}
	}

	return false
}

// GetContainerID takes a process ID and returns container ID for that process
func GetContainerID(pid int32) (string, bool) {
	if ProcessIsContainer(pid) {
		procfs := utils.ProcFS()

		cgroup, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(int(pid)), "cgroup"))
		if err != nil {
			log.Logf("failed to read cgroups of process: %d\n", pid)
			return "", false
		}

		splitted := strings.Split(string(cgroup), "/")
		if len(splitted) == 0 {
			log.Logf("failed to get container id of process: %d\n", pid)
			return "", false
		}

		id := strings.Trim(splitted[len(splitted)-1], " \n")

		return id, true
	}

	return "", false
}
