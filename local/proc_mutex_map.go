// +build !go1.9

package local

import "sync"

var (
	pidAddrMap = struct {
		sync.RWMutex
		// map[pid]dest-address-info
		pidAddr map[string]string
	}{
		pidAddr: make(map[string]string),
	}
)

// StorePidAddr store IP address and port for pid to pidAddrMap:
// pidAddrMap["127.0.0.1:1234"]"5678"
func StorePidAddr(pid, addr string) {
	pidAddrMap.Lock()
	pidAddrMap.pidAddr[pid] = addr
	pidAddrMap.Unlock()
}

// LoadPidAddr returns the address stored in the pidAddrMap for pid.
// The ok result indicates whether address was found in the pidAddrMap.
func LoadPidAddr(pid string) (addr string, ok bool) {
	pidAddrMap.RLock()
	addr, ok = pidAddrMap.pidAddr[pid]
	pidAddrMap.RUnlock()
	if ok {
		return addr, true
	}
	return "", false

}

// DeletePidAddr delete pid's address information.
func DeletePidAddr(pid string) {
	pidAddrMap.Lock()
	delete(pidAddrMap.pidAddr, pid)
	pidAddrMap.Unlock()
}

// RangePidAddr calls f sequentially for each pid and addr present in the pidAddrMap.
// If f returns false, range stops the iteration.
func RangePidAddr(f func(pid, addr string) bool) {
	pidAddrMap.RLock()
	for k, e := range pidAddrMap.pidAddr {
		if !f(k, e) {
			break
		}
	}
	pidAddrMap.RUnlock()
}
