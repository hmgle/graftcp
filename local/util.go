package local

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

func getInodeByAddrs(localAddr, remoteAddr *net.TCPAddr) (inode string, err error) {
	s, err := netlink.SocketGet(localAddr, remoteAddr)
	if err != nil {
		return
	}
	return strconv.FormatUint(uint64(s.INode), 10), nil
}

func hasIncludeInode(pid, inode string) bool {
	pidInt, _ := strconv.Atoi(pid)
	if pidInt < 1 {
		return false
	}
	fds, _ := filepath.Glob("/proc/" + pid + "/fd/[0-9]*")
	for _, fd := range fds {
		link, _ := os.Readlink(fd)
		if strings.Contains(link, "socket:["+inode+"]") {
			return true
		}
	}
	if len(fds) == 0 {
		tidsFds, _ := filepath.Glob("/proc/[0-9]*/task/" + pid + "/fd/[0-9]*")
		for _, fd := range tidsFds {
			link, _ := os.Readlink(fd)
			if strings.Contains(link, "socket:["+inode+"]") {
				return true
			}
		}
	}
	return false
}
