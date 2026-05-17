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
	tcpDialTimeout = 30 * time.Second
	tcpRouteIdle   = 2 * time.Minute
	tcpRouteGC     = 30 * time.Second

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

type timeoutDialer struct {
	timeout time.Duration
}

func (d timeoutDialer) Dial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, d.timeout)
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
	local.directDialer = timeoutDialer{timeout: tcpDialTimeout}

	return local, nil
}

// NewLocal ...
func NewLocal(listenAddr, socks5Addr, socks5Username, socks5PassWord, httpProxyAddr string) (*Local, error) {
	local, err := NewLocalListener(listenAddr)
	if err != nil {
		return nil, err
	}
	if err := local.ConfigureProxy(socks5Addr, socks5Username, socks5PassWord, httpProxyAddr); err != nil {
		return nil, err
	}
	return local, nil
}

// ConfigureProxy configures the upstream proxy dialers used by the local
// listener. Both halves are independent; passing an empty address clears the
// corresponding dialer without touching the other one. Errors leave the
// affected dialer unset and are returned to the caller.
func (l *Local) ConfigureProxy(socks5Addr, socks5Username, socks5PassWord, httpProxyAddr string) error {
	var errs []error
	if err := l.ConfigureSOCKS5(socks5Addr, socks5Username, socks5PassWord); err != nil {
		errs = append(errs, err)
	}
	if err := l.ConfigureHTTPProxy(httpProxyAddr); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return l.ValidateProxyConfig()
}

// ConfigureSOCKS5 installs (or clears) the SOCKS5 dialer.
func (l *Local) ConfigureSOCKS5(addr, username, password string) error {
	l.socks5Dialer = nil
	l.socks5Addr = ""
	l.socks5Username = ""
	l.socks5Password = ""

	if addr == "" {
		return nil
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("resolve socks5 proxy %q: %w", addr, err)
	}
	var auth *proxy.Auth
	if username != "" {
		auth = &proxy.Auth{User: username, Password: password}
	}
	forward := l.directDialer
	if forward == nil {
		forward = timeoutDialer{timeout: tcpDialTimeout}
	}
	dialer, err := proxy.SOCKS5("tcp", tcpAddr.String(), auth, forward)
	if err != nil {
		return fmt.Errorf("create SOCKS5 proxy %q: %w", tcpAddr.String(), err)
	}
	l.socks5Dialer = dialer
	l.socks5Addr = tcpAddr.String()
	l.socks5Username = username
	l.socks5Password = password
	return nil
}

// ConfigureHTTPProxy installs (or clears) the HTTP CONNECT dialer.
func (l *Local) ConfigureHTTPProxy(addr string) error {
	l.httpProxyDialer = nil

	if addr == "" {
		return nil
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("resolve http proxy %q: %w", addr, err)
	}
	uri, err := url.Parse("http://" + tcpAddr.String())
	if err != nil {
		return fmt.Errorf("parse http proxy URL %q: %w", tcpAddr.String(), err)
	}
	forward := l.directDialer
	if forward == nil {
		forward = timeoutDialer{timeout: tcpDialTimeout}
	}
	dialer, err := proxy.FromURL(uri, forward)
	if err != nil {
		return fmt.Errorf("create HTTP proxy %q: %w", uri.String(), err)
	}
	l.httpProxyDialer = dialer
	return nil
}

// Registry exposes the route registry used by the local proxy listener.
func (l *Local) Registry() *RouteRegistry {
	return l.routes
}

// UDPRegistry exposes the datagram route registry used by the local UDP proxy.
func (l *Local) UDPRegistry() *DatagramRouteRegistry {
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

// ValidateProxyConfig reports selection modes that cannot possibly dial with
// the currently configured upstreams.
func (l *Local) ValidateProxyConfig() error {
	switch l.selectMode {
	case OnlySocks5Mode:
		if l.socks5Dialer == nil {
			return fmt.Errorf("proxy selection mode only_socks5 requires --socks5")
		}
	case OnlyHTTPProxyMode:
		if l.httpProxyDialer == nil {
			return fmt.Errorf("proxy selection mode only_http_proxy requires --http_proxy")
		}
	}
	return nil
}

func (l *Local) proxySelector() proxy.Dialer {
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
			destConn, err = timeoutDialer{timeout: tcpDialTimeout}.Dial("tcp", destAddr)
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
	done := make(chan struct{})
	go l.gcRouteLoop(done)
	defer close(done)

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

func (l *Local) gcRouteLoop(done <-chan struct{}) {
	ticker := time.NewTicker(tcpRouteGC)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.routes.SweepIdle(time.Now(), tcpRouteIdle)
		case <-done:
			return
		}
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
