package main

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
	ipHex := fmt.Sprintf("%08X", ip2int(ip))
	return ipHex[6:] + ipHex[4:6] + ipHex[2:4] + ipHex[:2]
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
func getInodeByAddrs(localAddr, remoteAddr string) (inode string, err error) {
	localAddrSplit := strings.Split(localAddr, ":")
	if len(localAddrSplit) != 2 {
		return "", fmt.Errorf("bad format of localAddr: %s", localAddr)
	}
	remoteAddrSplit := strings.Split(remoteAddr, ":")
	if len(remoteAddrSplit) != 2 {
		return "", fmt.Errorf("bad format of remoteAddr: %s", remoteAddr)
	}

	localIP := localAddrSplit[0]
	if len(localIP) == 0 {
		localIP = "127.0.0.1"
	}
	remoteIP := remoteAddrSplit[0]
	if len(remoteIP) == 0 {
		remoteIP = "127.0.0.1"
	}
	localIPHex := hexIPAddr(localIP)
	remoteIPHex := hexIPAddr(remoteIP)
	localPortHex, err := hexPort(localAddrSplit[1])
	if err != nil {
		return "", err
	}
	remotePortHex, err := hexPort(remoteAddrSplit[1])
	if err != nil {
		return "", err
	}

	return getInode(localIPHex+":"+localPortHex, remoteIPHex+":"+remotePortHex), nil
}

// getInode get the inode, localAddrHex format: 0100007F:04D2
func getInode(localAddrHex, remoteAddrHex string) (inode string) {
	data, err := ioutil.ReadFile("/proc/net/tcp")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return ""
	}

	// skip the first header line
	for _, line := range lines[1:] {
		if strings.Contains(line, localAddrHex) && strings.Contains(line, remoteAddrHex) {
			fields := strings.Fields(line)
			if len(fields) > 9 {
				return fields[9] // fields[9] is inode
			}
		}
	}
	return ""
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
