package local

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type modeT int

const (
	// AutoSelectMode select socks5 if socks5 is reachable, else HTTP proxy
	AutoSelectMode modeT = iota
	// RandomSelectMode select the reachable proxy randomly
	RandomSelectMode
	// OnlySocks5Mode force use socks5
	OnlySocks5Mode
	// OnlyHTTPProxyMode force use HTTP proxy
	OnlyHTTPProxyMode
	// DirectMode direct connect
	DirectMode
)

// Local ...
type Local struct {
	faddr *net.TCPAddr // Frontend address: graftcp-local address

	faddrString string

	socks5Dialer    proxy.Dialer
	httpProxyDialer proxy.Dialer
	directDialer    proxy.Dialer

	FifoFd *os.File

	selectMode modeT
}

// GetFAddr return faddrString and faddr of l.
func (l *Local) GetFAddr() (faddrString string, faddr *net.TCPAddr) {
	return l.faddrString, l.faddr
}

// NewLocal ...
func NewLocal(listenAddr, socks5Addr, socks5Username, socks5PassWord, httpProxyAddr string) *Local {
	listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		log.Fatalf("resolve frontend(%s) error: %s", listenAddr, err.Error())
	}
	local := &Local{
		faddr:       listenTCPAddr,
		faddrString: listenAddr,
	}
	local.directDialer = proxy.Direct

	socks5TCPAddr, err1 := net.ResolveTCPAddr("tcp", socks5Addr)
	httpProxyTCPAddr, err2 := net.ResolveTCPAddr("tcp", httpProxyAddr)
	if err1 != nil && err2 != nil {
		log.Fatalf(
			"neither %s nor %s can be resolved, resolve(%s): %v, resolve(%s): %v, please check the config for proxy",
			socks5Addr, httpProxyAddr, socks5Addr, err1, httpProxyAddr, err2)
	}
	if err1 == nil {
		var auth *proxy.Auth
		if socks5Username != "" {
			auth = &proxy.Auth{
				User:     socks5Username,
				Password: socks5PassWord,
			}
		}
		dialerSocks5, err := proxy.SOCKS5("tcp", socks5TCPAddr.String(), auth, proxy.Direct)
		if err != nil {
			log.Errorf("proxy.SOCKS5(%s) fail: %s", socks5TCPAddr.String(), err.Error())
		} else {
			local.socks5Dialer = dialerSocks5
		}
	}
	if err2 == nil {
		httpProxyURI, _ := url.Parse("http://" + httpProxyTCPAddr.String())
		dialerHTTPProxy, err := proxy.FromURL(httpProxyURI, proxy.Direct)
		if err != nil {
			log.Errorf("proxy.FromURL(%v) err: %s", httpProxyURI, err.Error())
		} else {
			local.httpProxyDialer = dialerHTTPProxy
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
		l.selectMode = OnlyHTTPProxyMode
	case "only_socks5":
		l.selectMode = OnlySocks5Mode
	case "direct":
		l.selectMode = DirectMode
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
		} else if l.httpProxyDialer != nil {
			return l.httpProxyDialer
		}
		return l.directDialer
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
	case OnlyHTTPProxyMode:
		return l.httpProxyDialer
	case DirectMode:
		return l.directDialer
	default:
		return l.socks5Dialer
	}
}

// StartListen start listening.
func (l *Local) StartListen() (ln *net.TCPListener, err error) {
	ln, err = net.ListenTCP("tcp", l.faddr)
	if err != nil {
		log.Fatalf("net.ListenTCP(%s) err: %s", l.faddr.String(), err.Error())
		return
	}
	log.Infof("graftcp-local start listening %s...", l.faddr.String())
	if l.faddr.Port == 0 {
		l.faddrString = ln.Addr().String()
		l.faddr, err = net.ResolveTCPAddr("tcp", l.faddrString)
		if err != nil {
			log.Errorf("net.ResolveTCPAddr err: %s", err.Error())
		}
	}
	return
}

// StartService start service.
func (l *Local) StartService(ln *net.TCPListener) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorf("accept err: %s", err.Error())
			}
			break
		}
		go l.HandleConn(conn)
	}
}

// Start listening and service.
func (l *Local) Start() {
	ln, _ := l.StartListen()
	defer ln.Close()

	l.StartService(ln)
}

func getPidByAddr(localAddr, remoteAddr *net.TCPAddr) (pid string, destAddr string) {
	inode, err := getInodeByAddrs(localAddr, remoteAddr)
	if err != nil {
		log.Errorf("getInodeByAddrs(%s, %s) err: %s", localAddr, remoteAddr, err.Error())
		return "", ""
	}
	for i := 0; i < 3; i++ { // try 3 times
		RangePidAddr(func(p, a string) bool {
			if hasIncludeInode(p, inode) {
				pid = p
				destAddr = a
				return false
			}
			return true
		})
		if pid != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid != "" {
		DeletePidAddr(pid)
	}
	return
}

// HandleConn handle conn.
func (l *Local) HandleConn(conn *net.TCPConn) error {
	raddr, laddr := conn.RemoteAddr().(*net.TCPAddr), conn.LocalAddr().(*net.TCPAddr)
	pid, destAddr := getPidByAddr(raddr, laddr)
	if pid == "" || destAddr == "" {
		log.Errorf("getPidByAddr(%s, %s) failed", raddr.String(), conn.LocalAddr().String())
		conn.Close()
		return fmt.Errorf("can't find the pid and destAddr for %s", raddr.String())
	}
	log.Infof("Request PID: %s, Source Addr: %s, Dest Addr: %s", pid, raddr.String(), destAddr)

	dialer := l.proxySelector()
	if dialer == nil {
		log.Errorf("bad dialer,  please check the config for proxy")
		conn.Close()
		return fmt.Errorf("bad dialer")
	}
	destConn, err := dialer.Dial("tcp", destAddr)
	if err != nil && l.selectMode == AutoSelectMode {
		if l.httpProxyDialer != nil && dialer != l.httpProxyDialer {
			log.Infof("try http_proxy for %s", destAddr)
			destConn, err = l.httpProxyDialer.Dial("tcp", destAddr)
		}
		if err != nil {
			log.Infof("dial %s direct", destAddr)
			destConn, err = net.Dial("tcp", destAddr)
		}
	}
	if err != nil {
		log.Errorf("dialer.Dial(%s) err: %s", destAddr, err.Error())
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
	now := time.Now()
	dst.SetDeadline(now)
	src.SetDeadline(now)
	c <- n
}

// UpdateProcessAddrInfo update process address info.
func (l *Local) UpdateProcessAddrInfo() {
	r := bufio.NewReader(l.FifoFd)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			log.Errorf("r.ReadLine err: %s", err.Error())
			break
		}
		copyLine := string(line)
		// dest_ipaddr:dest_port:pid
		s := strings.Split(copyLine, ":")
		if len(s) < 3 {
			log.Errorf("r.ReadLine(): %s", copyLine)
			continue
		}
		var (
			pid  string
			addr string
		)
		if len(s) > 3 { // IPv6
			pid = s[len(s)-1]
			destPort := s[len(s)-2]
			destIP := copyLine[:len(copyLine)-2-len(pid)-len(destPort)]
			addr = "[" + destIP + "]:" + destPort
		} else { // IPv4
			pid = s[2]
			addr = s[0] + ":" + s[1]
		}
		go func() {
			StorePidAddr(pid, addr)
			log.Debugf("StorePidAddr(%s, %s)", pid, addr)
		}()
	}
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}
