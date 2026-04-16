package local

import "os"

// GetExePath returns the path name for the executable that started
// the current process.
func GetExePath() string {
	exePath, err := os.Executable()
	if err == nil {
		return exePath
	}
	return "/proc/self/exe"
}
