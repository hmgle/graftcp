// +build !go1.9

package main

// GetExePath returns the path name for the executable that started
// the current process.
func GetExePath() string {
	return "/proc/self/exe"
}
