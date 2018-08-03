// +build !go1.9

package main

func GetExePath() string {
	return "/proc/self/exe"
}
