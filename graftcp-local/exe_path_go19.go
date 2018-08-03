// +build go1.9

package main

import "os"

func GetExePath() string {
	exePath, _ := os.Executable()
	return exePath
}
