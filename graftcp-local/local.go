package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/jedisct1/dlog"
	"golang.org/x/net/proxy"
)

type Local struct {
	faddr *net.TCPAddr // Frontend address: graftcp-local address
	baddr *net.TCPAddr // Backend address: socks5 address

	faddrString string
	baddrString string

	FifoFd *os.File
}

func NewLocal(listenAddr, socks5Addr string) *Local {
	a1, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		dlog.Fatalf("resolve frontend(%s) error: %s", listenAddr, err.Error())
	}
	a2, err := net.ResolveTCPAddr("tcp", socks5Addr)
	if err != nil {
		dlog.Fatalf("resolve backend(%s) error: %s", socks5Addr, err.Error())
	}
	return &Local{
		faddr:       a1,
		baddr:       a2,
		faddrString: listenAddr,
		baddrString: socks5Addr,
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

func (l *Local) getPidByAddr(localAddr string) (pid string, destAddr string) {
	inode, err := getInodeByAddrs(localAddr, l.faddrString)
	if err != nil {
		dlog.Errorf("getInodeByAddrs(%s, %s) err: %s", localAddr, l.faddrString, err.Error())
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
	pid, addr := l.getPidByAddr(raddr.String())
	if pid == "" || addr == "" {
		dlog.Errorf("getPidByAddr(%s) failed", raddr.String())
		conn.Close()
		return fmt.Errorf("can't find the pid and addr for %s", raddr.String())
	}
	dlog.Infof("Request PID: %s, Source Addr: %s, Dest Addr: %s", pid, raddr.String(), addr)

	dialer, err := proxy.SOCKS5("tcp", l.baddr.String(), nil, proxy.Direct)
	if err != nil {
		dlog.Errorf("proxy.SOCKS5(\"tcp\", %s,...) err: %s", l.baddr, err.Error())
		conn.Close()
		return err
	}
	socks5Conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		dlog.Errorf("dialer.Dial(%s) err: %s", addr, err.Error())
		conn.Close()
		return err
	}
	readChan, writeChan := make(chan int64), make(chan int64)
	go pipe(conn, socks5Conn, writeChan)
	go pipe(socks5Conn, conn, readChan)
	<-writeChan
	<-readChan
	conn.Close()
	socks5Conn.Close()
	return nil
}

func pipe(dst, src net.Conn, c chan int64) {
	n, _ := io.Copy(dst, src)
	c <- n
}

func (l *Local) UpdateProcessAddrInfo() {
	r := bufio.NewReader(l.FifoFd)
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
