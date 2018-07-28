package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/jedisct1/dlog"

	"golang.org/x/net/proxy"
)

type Local struct {
	faddr *net.TCPAddr // Frontend address: graftcp-local address
	baddr *net.TCPAddr // Backend address: socks5 address
}

func NewLocal(faddr, baddr string) *Local {
	a1, err := net.ResolveTCPAddr("tcp", faddr)
	if err != nil {
		dlog.Fatalf("resolve frontend(%s) error: %s", faddr, err.Error())
	}
	a2, err := net.ResolveTCPAddr("tcp", baddr)
	if err != nil {
		dlog.Fatalf("resolve backend(%s) error: %s", baddr, err.Error())
	}
	return &Local{
		faddr: a1,
		baddr: a2,
	}
}

func (l *Local) Start() {
	ln, err := net.ListenTCP("tcp", l.faddr)
	if err != nil {
		dlog.Fatalf("net.ListenTCP(%s) err: %s", l.faddr.String(), err.Error())
	}
	defer ln.Close()
	dlog.Infof("graft-local start listening %s...", l.faddr.String())

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			dlog.Errorf("accept err: %s", err.Error())
			continue
		}
		go l.HandleConn(conn)
	}
}

func getPidByAddr(localAddr string) (pid string, destAddr string) {
	inode, err := getInodeByAddrs(localAddr, ListenAddr)
	if err != nil {
		dlog.Errorf("getInodeByAddrs(%s, %s) err: %s", localAddr, ListenAddr, err.Error())
		return "", ""
	}
	RangePidAddr(func(p, a string) bool {
		if hasIncludeInode(p, inode) {
			pid = p
			destAddr = a
			return false
		}
		return true
	})
	if pid != "" {
		DeletePidAddr(pid)
	}
	return
}

func (l *Local) HandleConn(conn net.Conn) error {
	raddr := conn.RemoteAddr()
	pid, addr := getPidByAddr(raddr.String())
	if pid == "" || addr == "" {
		dlog.Errorf("getPidByAddr(%s) failed", raddr.String())
		return fmt.Errorf("can't find the pid and addr for %s", raddr.String())
	}
	dlog.Infof("Request PID: %s, Source Addr: %s, Dest Addr: %s", pid, raddr.String(), addr)

	dialer, err := proxy.SOCKS5("tcp", l.baddr.String(), nil, proxy.Direct)
	if err != nil {
		dlog.Errorf("proxy.SOCKS5(\"tcp\", %s,...) err: %s", l.baddr, err.Error())
		return err
	}
	socks5Conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		dlog.Errorf("dialer.Dial(%s) err: %s", addr, err.Error())
		return err
	}
	go pipe(conn, socks5Conn)
	go pipe(socks5Conn, conn)
	return nil
}

func pipe(dst, src net.Conn) {
	for {
		n, err := io.Copy(dst, src)
		if err != nil {
			dlog.Errorf("io.Copy err: %s", err.Error())
			return
		}
		if n == 0 {
			return
		}
	}
}

func updateProcessAddrInfo() {
	r := bufio.NewReader(FifoFd)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			dlog.Errorf("r.ReadLine err: %s", err.Error())
			break
		}
		// dest_ipaddr:dest_port:pid
		s := strings.Split(string(line), ":")
		if len(s) != 3 {
			dlog.Errorf("r.ReadLine(): %d", string(line))
			continue
		}
		StorePidAddr(s[2], s[0]+":"+s[1])
	}
}

var (
	ListenAddr string
	Socks5Addr string
	ConfigFile string
	PipePath   string
	FifoFd     *os.File
)

func main() {
	var err error
	dlog.Init("graftcp-local", dlog.SeverityInfo, "")

	flag.StringVar(&ListenAddr, "listen", ":2233", "Listen address")
	flag.StringVar(&Socks5Addr, "socks5", "127.0.0.1:1080", "SOCKS5 address")
	flag.StringVar(&ConfigFile, "config", "", "Path to the configuration file")
	flag.StringVar(&PipePath, "pipepath", "/tmp/graftcplocal.fifo", "Pipe path for graftcp to send address info")
	flag.Parse()
	if ConfigFile != "" {
		ParseConfigFile(ConfigFile)
	}

	syscall.Mkfifo(PipePath, uint32(os.ModePerm))
	FifoFd, err = os.OpenFile(PipePath, os.O_RDWR, 0)
	if err != nil {
		dlog.Fatalf("os.OpenFile(%s) err: %s", PipePath, err.Error())
	}
	go updateProcessAddrInfo()

	l := NewLocal(ListenAddr, Socks5Addr)
	l.Start()
}
