package main

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"golang.org/x/net/proxy"
)

type modeT int

const (
	// AutoSelectMode: select socks5 if socks5 is reachable, else HTTP proxy
	AutoSelectMode modeT = iota
	// RandomSelectMode: select the reachable proxy randomly
	RandomSelectMode
	// OnlySocks5Mode: force use socks5
	OnlySocks5Mode
	// OnlyHttpProxyMode: force use HTTP proxy
	OnlyHttpProxyMode
)

type Local struct {
	faddr *net.TCPAddr // Frontend address: graftcp-local address

	faddrString string

	socks5Dialer    proxy.Dialer
	httpProxyDialer proxy.Dialer

	FifoFd *os.File

	selectMode modeT
}

func NewLocal(listenAddr, socks5Addr, httpProxyAddr string) *Local {
	listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		dlog.Fatalf("resolve frontend(%s) error: %s", listenAddr, err.Error())
	}
	local := &Local{
		faddr:       listenTCPAddr,
		faddrString: listenAddr,
	}

	socks5TCPAddr, err1 := net.ResolveTCPAddr("tcp", socks5Addr)
	httpProxyTCPAddr, err2 := net.ResolveTCPAddr("tcp", httpProxyAddr)
	if err1 != nil && err2 != nil {
		dlog.Fatalf(
			"neither %s nor %s can be resolved, resolve(%s): %v, resolve(%s): %v, please check the config for proxy",
			socks5Addr, httpProxyAddr, socks5Addr, err1, httpProxyAddr, err2)
	}
	if err1 == nil {
		dialerSocks5, err := proxy.SOCKS5("tcp", socks5TCPAddr.String(), nil, proxy.Direct)
		if err != nil {
			dlog.Errorf("proxy.SOCKS5(%s) fail: %s", socks5TCPAddr.String(), err.Error())
		} else {
			local.socks5Dialer = dialerSocks5
		}
	}
	if err2 == nil {
		httpProxyURI, _ := url.Parse("http://" + httpProxyTCPAddr.String())
		dialerHttpProxy, err := proxy.FromURL(httpProxyURI, proxy.Direct)
		if err != nil {
			dlog.Errorf("proxy.FromURL(%v) err: %s", httpProxyURI, err.Error())
		} else {
			local.httpProxyDialer = dialerHttpProxy
		}
	}
	return local
}

// SetSelectMode set the select mode for l.
func (l *Local) SetSelectMode(mode string) {
	switch mode {
	case "auto":
		l.selectMode = AutoSelectMode
	case "random":
		l.selectMode = RandomSelectMode
	case "only_http_proxy":
		l.selectMode = OnlyHttpProxyMode
	case "only_socks5":
		l.selectMode = OnlySocks5Mode
	}
}

func (l *Local) proxySelector() proxy.Dialer {
	if l == nil {
		return nil
	}
	switch l.selectMode {
	case AutoSelectMode:
		if l.socks5Dialer != nil {
			return l.socks5Dialer
		}
		return l.httpProxyDialer
	case RandomSelectMode:
		if l.socks5Dialer != nil && l.httpProxyDialer != nil {
			if rand.Intn(2) == 0 {
				return l.socks5Dialer
			}
			return l.httpProxyDialer
		} else if l.socks5Dialer != nil {
			return l.socks5Dialer
		}
		return l.httpProxyDialer
	case OnlySocks5Mode:
		return l.socks5Dialer
	case OnlyHttpProxyMode:
		return l.httpProxyDialer
	default:
		return l.socks5Dialer
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
	pid, destAddr := l.getPidByAddr(raddr.String())
	if pid == "" || destAddr == "" {
		dlog.Errorf("getPidByAddr(%s) failed", raddr.String())
		conn.Close()
		return fmt.Errorf("can't find the pid and destAddr for %s", raddr.String())
	}
	dlog.Infof("Request PID: %s, Source Addr: %s, Dest Addr: %s", pid, raddr.String(), destAddr)

	dialer := l.proxySelector()
	if dialer == nil {
		dlog.Errorf("bad dialer,  please check the config for proxy")
		conn.Close()
		return fmt.Errorf("bad dialer")
	}
	destConn, err := dialer.Dial("tcp", destAddr)
	if err != nil {
		dlog.Errorf("dialer.Dial(%s) err: %s", destAddr, err.Error())
		conn.Close()
		return err
	}
	readChan, writeChan := make(chan int64), make(chan int64)
	go pipe(conn, destConn, writeChan)
	go pipe(destConn, conn, readChan)
	<-writeChan
	<-readChan
	conn.Close()
	destConn.Close()
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

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}
