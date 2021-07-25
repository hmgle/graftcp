// +build go1.9

package local

import "os"

// GetExePath returns the path name for the executable that started
// the current process.
func GetExePath() string {
	exePath, _ := os.Executable()
	return exePath
}
