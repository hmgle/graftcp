package local

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func ip2Hex(ip net.IP) string {
	if ip.To4() != nil { // IPv4
		ipHex := fmt.Sprintf("%08X", ip2int(ip))
		return ipHex[6:] + ipHex[4:6] + ipHex[2:4] + ipHex[:2]
	}
	// IPv6
	var ipv6Hex string

	ipHex := fmt.Sprintf("%08X", binary.BigEndian.Uint32(ip[:4]))
	ipv6Hex += ipHex[6:] + ipHex[4:6] + ipHex[2:4] + ipHex[:2]

	ipHex = fmt.Sprintf("%08X", binary.BigEndian.Uint32(ip[4:8]))
	ipv6Hex += ipHex[6:] + ipHex[4:6] + ipHex[2:4] + ipHex[:2]

	ipHex = fmt.Sprintf("%08X", binary.BigEndian.Uint32(ip[8:12]))
	ipv6Hex += ipHex[6:] + ipHex[4:6] + ipHex[2:4] + ipHex[:2]

	ipHex = fmt.Sprintf("%08X", binary.BigEndian.Uint32(ip[12:16]))
	ipv6Hex += ipHex[6:] + ipHex[4:6] + ipHex[2:4] + ipHex[:2]

	return ipv6Hex
}

func hexIPAddr(ipAddr string) string {
	ip := net.ParseIP(ipAddr)
	if len(ip) == 0 {
		return ""
	}
	return ip2Hex(ip)
}

func hexPort(port string) (string, error) {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04X", portInt), nil
}

// getInodeByAddrs, localAddr format: 127.0.0.1:1234
func getInodeByAddrs(localAddr, remoteAddr string, isTCP6 bool) (inode string, err error) {
	var (
		localIP    string
		localPort  string
		remoteIP   string
		remotePort string
	)
	localIP, localPort, err = splitAddr(localAddr, isTCP6)
	if err != nil {
		return
	}
	remoteIP, remotePort, err = splitAddr(remoteAddr, isTCP6)
	if err != nil {
		return
	}
	localIPHex := hexIPAddr(localIP)
	remoteIPHex := hexIPAddr(remoteIP)
	localPortHex, err := hexPort(localPort)
	if err != nil {
		return "", err
	}
	remotePortHex, err := hexPort(remotePort)
	if err != nil {
		return "", err
	}
	return getInode(localIPHex+":"+localPortHex, remoteIPHex+":"+remotePortHex, isTCP6)
}

const (
	localIPv4 = "127.0.0.1"
	localIPv6 = "[::1]"
)

// addr format: "127.0.0.1:53816"
func splitAddrIPv4(addr string) (ipv4 string, port string, err error) {
	addrSplit := strings.Split(addr, ":")
	if len(addrSplit) != 2 {
		err = fmt.Errorf("bad format of ipv4 addr: %s", addr)
		return
	}
	ipv4 = addrSplit[0]
	if ipv4 == "" {
		ipv4 = localIPv4
	}
	port = addrSplit[1]
	return
}

// addr format: "[::1]:53816"
func splitAddrIPv6(addr string) (ipv6 string, port string, err error) {
	if !strings.HasPrefix(addr, "[") || !strings.Contains(addr, "]:") {
		err = fmt.Errorf("bad format of ipv6 addr: %s", addr)
		return
	}
	sep := strings.LastIndex(addr, "]")
	ipv6 = addr[1:sep]
	port = addr[sep+2:]
	return
}

func splitAddr(addr string, isTCP6 bool) (ip string, port string, err error) {
	if isTCP6 {
		return splitAddrIPv6(addr)
	}
	return splitAddrIPv4(addr)
}

// getInode get the inode, localAddrHex format: 0100007F:04D2
func getInode(localAddrHex, remoteAddrHex string, isTCP6 bool) (inode string, err error) {
	var path string
	if isTCP6 {
		path = "/proc/net/tcp6"
	} else {
		path = "/proc/net/tcp"
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("bad format: %s", data)
	}

	// skip the first header line
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if strings.Contains(fields[1] /* local address:port */, localAddrHex) &&
			strings.Contains(fields[2] /* remote address:port */, remoteAddrHex) {
			return fields[9], nil // fields[9] is inode
		}
	}
	return "", fmt.Errorf("no inode for [%s %s]", localAddrHex, remoteAddrHex)
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
