package local

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

type modeT int

var errBadDialer = errors.New("bad dialer")

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
	faddr *net.TCPAddr // Frontend address for the embedded local proxy

	faddrString string

	socks5Dialer    proxy.Dialer
	httpProxyDialer proxy.Dialer
	directDialer    proxy.Dialer
	socks5Addr      string
	socks5Username  string
	socks5Password  string

	routes    *RouteRegistry
	udpRoutes *DatagramRouteRegistry

	selectMode modeT
}

// GetFAddr return faddrString and faddr of l.
func (l *Local) GetFAddr() (faddrString string, faddr *net.TCPAddr) {
	return l.faddrString, l.faddr
}

// NewLocalListener creates a Local with only its frontend listener address and registries.
func NewLocalListener(listenAddr string) (*Local, error) {
	listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve frontend %q: %w", listenAddr, err)
	}
	local := &Local{
		faddr:       listenTCPAddr,
		faddrString: listenAddr,
		routes:      NewRouteRegistry(),
		udpRoutes:   NewDatagramRouteRegistry(),
	}
	local.directDialer = proxy.Direct

	return local, nil
}

// NewLocal ...
func NewLocal(listenAddr, socks5Addr, socks5Username, socks5PassWord, httpProxyAddr string) (*Local, error) {
	local, err := NewLocalListener(listenAddr)
	if err != nil {
		return nil, err
	}
	local.ConfigureProxy(socks5Addr, socks5Username, socks5PassWord, httpProxyAddr)
	return local, nil
}

// ConfigureProxy configures the upstream proxy dialers used by the local
// listener. Both halves are independent; passing an empty address clears the
// corresponding dialer without touching the other one. Errors in either
// configuration step are logged and the dialer is left unset so the caller
// can keep running with whatever upstreams remain.
func (l *Local) ConfigureProxy(socks5Addr, socks5Username, socks5PassWord, httpProxyAddr string) {
	l.ConfigureSOCKS5(socks5Addr, socks5Username, socks5PassWord)
	l.ConfigureHTTPProxy(httpProxyAddr)
}

// ConfigureSOCKS5 installs (or clears) the SOCKS5 dialer.
func (l *Local) ConfigureSOCKS5(addr, username, password string) {
	l.socks5Dialer = nil
	l.socks5Addr = ""
	l.socks5Username = ""
	l.socks5Password = ""

	if addr == "" {
		return
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Errorf("resolve socks5 proxy %q: %s", addr, err.Error())
		return
	}
	var auth *proxy.Auth
	if username != "" {
		auth = &proxy.Auth{User: username, Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", tcpAddr.String(), auth, proxy.Direct)
	if err != nil {
		log.Errorf("proxy.SOCKS5(%s) fail: %s", tcpAddr.String(), err.Error())
		return
	}
	l.socks5Dialer = dialer
	l.socks5Addr = tcpAddr.String()
	l.socks5Username = username
	l.socks5Password = password
}

// ConfigureHTTPProxy installs (or clears) the HTTP CONNECT dialer.
func (l *Local) ConfigureHTTPProxy(addr string) {
	l.httpProxyDialer = nil

	if addr == "" {
		return
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Errorf("resolve http proxy %q: %s", addr, err.Error())
		return
	}
	uri, err := url.Parse("http://" + tcpAddr.String())
	if err != nil {
		log.Errorf("parse http proxy URL: %s", err.Error())
		return
	}
	dialer, err := proxy.FromURL(uri, proxy.Direct)
	if err != nil {
		log.Errorf("proxy.FromURL(%v) err: %s", uri, err.Error())
		return
	}
	l.httpProxyDialer = dialer
}

// Registry exposes the route registry used by the local proxy listener.
func (l *Local) Registry() *RouteRegistry {
	if l == nil {
		return nil
	}
	return l.routes
}

// UDPRegistry exposes the datagram route registry used by the local UDP proxy.
func (l *Local) UDPRegistry() *DatagramRouteRegistry {
	if l == nil {
		return nil
	}
	return l.udpRoutes
}

var selectModes = map[string]modeT{
	"auto":            AutoSelectMode,
	"random":          RandomSelectMode,
	"only_http_proxy": OnlyHTTPProxyMode,
	"only_socks5":     OnlySocks5Mode,
	"direct":          DirectMode,
}

// SetSelectMode set the select mode for l.
func (l *Local) SetSelectMode(mode string) error {
	m, ok := selectModes[mode]
	if !ok {
		return fmt.Errorf("unknown proxy selection mode %q", mode)
	}
	l.selectMode = m
	return nil
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
		} else if l.httpProxyDialer != nil {
			return l.httpProxyDialer
		}
		return l.directDialer
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

func (l *Local) dialTCP(destAddr string) (net.Conn, error) {
	dialer := l.proxySelector()
	if dialer == nil {
		return nil, errBadDialer
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
	return destConn, err
}

// StartListen start listening.
func (l *Local) StartListen() (ln *net.TCPListener, err error) {
	ln, err = net.ListenTCP("tcp", l.faddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", l.faddr.String(), err)
	}
	log.Infof("mgraftcp local listener started on %s", l.faddr.String())
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
	ln, err := l.StartListen()
	if err != nil {
		log.Fatalf("l.StartListen err: %s", err.Error())
		return
	}
	defer ln.Close()

	l.StartService(ln)
}

// HandleConn handle conn.
func (l *Local) HandleConn(conn *net.TCPConn) error {
	raddr, laddr := conn.RemoteAddr().(*net.TCPAddr), conn.LocalAddr().(*net.TCPAddr)
	destAddr, ok := l.routes.Consume(laddr.IP)
	if !ok {
		log.Errorf("route lookup failed for source %s, local %s", raddr.String(), laddr.String())
		conn.Close()
		return fmt.Errorf("can't find the destAddr for %s", raddr.String())
	}

	log.Infof("Request Token: %s, Source Addr: %s, Dest Addr: %s", laddr.IP.String(), raddr.String(), destAddr)

	destConn, err := l.dialTCP(destAddr)
	if errors.Is(err, errBadDialer) {
		log.Errorf("bad dialer,  please check the config for proxy")
		conn.Close()
		return err
	}
	if err != nil {
		log.Errorf("dialer.Dial(%s) err: %s", destAddr, err.Error())
		conn.Close()
		return err
	}
	defer conn.Close()
	defer destConn.Close()
	relay(conn, destConn)
	return nil
}

// relay copies bytes in both directions between a and b until both sides are
// done. The first side to finish triggers a deadline on both connections so
// the still-blocked Read returns promptly; the second receive then unblocks.
func relay(a, b net.Conn) {
	errc := make(chan error, 2)
	go func() { errc <- copyAndCloseWrite(a, b) }()
	go func() { errc <- copyAndCloseWrite(b, a) }()

	<-errc
	now := time.Now()
	_ = a.SetDeadline(now)
	_ = b.SetDeadline(now)
	<-errc
}

func copyAndCloseWrite(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	return err
}
