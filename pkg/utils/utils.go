package utils

import "os"

// IsHyperionChild returns true if the process is running
// as hyperion child
//
// NOTE: The function returns false iff 'HYPERION_CHILD"
// is set to "false" or else it is assumed that the process
// is a hyperion child process
func IsHyperionChild() bool {
	return os.Getenv("HYPERION_CHILD") != "false"
}
