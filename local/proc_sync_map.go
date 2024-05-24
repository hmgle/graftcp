//go:build go1.9
// +build go1.9

package local

import (
	"fmt"
	"strings"
	"sync"
)

var pidAddrMap sync.Map

// StorePidAddr store IP address and port for pid to pidAddrMap:
// pidAddrMap["127.0.0.1:1234"]"5678"
func StorePidAddr(pid, addr string) {
	pidAddrMap.Store(pid, addr)
}

// LoadPidAddr returns the address stored in the pidAddrMap for pid.
// The ok result indicates whether address was found in the pidAddrMap.
func LoadPidAddr(pid string) (addr string, ok bool) {
	v, ok := pidAddrMap.Load(pid)
	if !ok {
		return "", ok
	}
	addr, ok = v.(string)
	return
}

// DeletePidAddr delete pid's address information.
func DeletePidAddr(pid string) {
	pidAddrMap.Delete(pid)
}

// RangePidAddr calls f sequentially for each pid and addr present in the pidAddrMap.
// If f returns false, range stops the iteration.
func RangePidAddr(f func(pid, addr string) bool) {
	f2 := func(k, v interface{}) bool {
		p, _ := k.(string)
		a, _ := v.(string)
		return f(p, a)
	}
	pidAddrMap.Range(f2)
}

func PidAddrMapToString() string {
	var buf strings.Builder
	buf.WriteString("pidAddrMap: {\n")
	pidAddrMap.Range(func(k, v interface{}) bool {
		buf.WriteString(fmt.Sprintf("\t%v: %v\n", k, v))
		return true
	})
	buf.WriteString("}")
	return buf.String()
}
