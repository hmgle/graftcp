package local

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	udpPacketMaxSize    = 65535
	udpSessionIdle      = 2 * time.Minute
	udpSessionGCPeriod  = 30 * time.Second
	udpSessionReadLimit = 30 * time.Second
)

type udpForwarder interface {
	Write([]byte) error
	Close() error
}

type udpSession struct {
	key        string
	clientAddr *net.UDPAddr
	tokenIP    net.IP
	destAddr   string
	forwarder  udpForwarder
	ready      chan struct{}
	initErr    error
	lastSeen   time.Time
}

// UDPProxy forwards local UDP packets to their registered destinations.
type UDPProxy struct {
	local *Local

	conn       *net.UDPConn
	packetConn *ipv4.PacketConn

	mu       sync.Mutex
	sessions map[string]*udpSession
	closed   chan struct{}
}

// StartUDPProxy starts a generic UDP listener for token-routed datagrams.
func (l *Local) StartUDPProxy() (*UDPProxy, int, error) {
	udp4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, 0, fmt.Errorf("listen UDP proxy: %w", err)
	}
	packetConn := ipv4.NewPacketConn(udp4)
	if err := packetConn.SetControlMessage(ipv4.FlagDst, true); err != nil {
		_ = udp4.Close()
		return nil, 0, fmt.Errorf("enable UDP destination control message: %w", err)
	}
	p := &UDPProxy{
		local:      l,
		conn:       udp4,
		packetConn: packetConn,
		sessions:   make(map[string]*udpSession),
		closed:     make(chan struct{}),
	}
	go p.serve()
	go p.gcLoop()

	port := udp4.LocalAddr().(*net.UDPAddr).Port
	log.Infof("mgraftcp UDP proxy started on 0.0.0.0:%d", port)
	return p, port, nil
}

func (p *UDPProxy) Close() error {
	if p == nil {
		return nil
	}

	select {
	case <-p.closed:
	default:
		close(p.closed)
	}

	p.mu.Lock()
	sessions := p.sessions
	p.sessions = make(map[string]*udpSession)
	p.mu.Unlock()

	var closeErr error
	for _, session := range sessions {
		if session.forwarder != nil {
			if err := session.forwarder.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	}
	if err := p.conn.Close(); err != nil && closeErr == nil {
		closeErr = err
	}
	return closeErr
}

func (p *UDPProxy) serve() {
	buf := make([]byte, udpPacketMaxSize)
	for {
		n, cm, src, err := p.packetConn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorf("UDP proxy read err: %s", err.Error())
			}
			return
		}
		clientAddr, ok := src.(*net.UDPAddr)
		if !ok {
			log.Errorf("UDP proxy received packet from unsupported addr %v", src)
			continue
		}
		if cm == nil || cm.Dst == nil {
			log.Errorf("UDP proxy missing destination address for %s", clientAddr.String())
			continue
		}
		tokenIP := cm.Dst.To4()
		if tokenIP == nil {
			log.Errorf("UDP proxy got non-IPv4 destination %s", cm.Dst.String())
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		go p.handlePacket(clientAddr, tokenIP, payload)
	}
}

func (p *UDPProxy) handlePacket(clientAddr *net.UDPAddr, tokenIP net.IP, payload []byte) {
	destAddr, ok := p.local.udpRoutes.Lookup(tokenIP)
	if !ok {
		log.Errorf("UDP proxy route lookup failed for token %s from %s", tokenIP.String(), clientAddr.String())
		return
	}

	session, err := p.getSession(clientAddr, tokenIP, destAddr)
	if err != nil {
		log.Errorf("UDP proxy session for %s -> %s err: %s", clientAddr.String(), destAddr, err.Error())
		return
	}
	select {
	case <-session.ready:
	case <-p.closed:
		return
	}
	if session.initErr != nil {
		log.Errorf("UDP proxy session for %s -> %s err: %s", clientAddr.String(), destAddr, session.initErr.Error())
		return
	}
	if session.forwarder == nil {
		log.Errorf("UDP proxy session for %s -> %s has no forwarder", clientAddr.String(), destAddr)
		return
	}
	if err := session.forwarder.Write(payload); err != nil {
		log.Errorf("UDP proxy write for %s -> %s err: %s", clientAddr.String(), destAddr, err.Error())
		p.removeSession(session.key)
	}
}

func (p *UDPProxy) getSession(clientAddr *net.UDPAddr, tokenIP net.IP, destAddr string) (*udpSession, error) {
	key := udpSessionKey(clientAddr, tokenIP)
	now := time.Now()

	p.mu.Lock()
	if session, ok := p.sessions[key]; ok {
		session.lastSeen = now
		p.mu.Unlock()
		return session, nil
	}
	session := &udpSession{
		key:        key,
		clientAddr: cloneUDPAddr(clientAddr),
		tokenIP:    cloneIP(tokenIP),
		destAddr:   destAddr,
		ready:      make(chan struct{}),
		lastSeen:   now,
	}
	p.sessions[key] = session
	p.mu.Unlock()

	go p.initSession(session)
	return session, nil
}

func (p *UDPProxy) initSession(session *udpSession) {
	forwarder, err := p.local.newUDPForwarder(p, session.clientAddr, session.tokenIP, session.destAddr)

	p.mu.Lock()
	current := p.sessions[session.key] == session
	if current {
		session.forwarder = forwarder
		session.initErr = err
	}
	p.mu.Unlock()

	if !current {
		if forwarder != nil {
			_ = forwarder.Close()
		}
		close(session.ready)
		return
	}

	close(session.ready)
	if err != nil {
		p.removeSession(session.key)
	}
}

func (p *UDPProxy) sendToClient(payload []byte, tokenIP net.IP, clientAddr *net.UDPAddr) error {
	cm := &ipv4.ControlMessage{Src: tokenIP.To4()}
	_, err := p.packetConn.WriteTo(payload, cm, clientAddr)
	return err
}

func (p *UDPProxy) removeSession(key string) {
	p.mu.Lock()
	session, ok := p.sessions[key]
	if ok {
		delete(p.sessions, key)
	}
	p.mu.Unlock()
	if ok {
		if session.forwarder != nil {
			_ = session.forwarder.Close()
		}
	}
}

func (p *UDPProxy) gcLoop() {
	ticker := time.NewTicker(udpSessionGCPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.closeIdleSessions(time.Now())
		case <-p.closed:
			return
		}
	}
}

func (p *UDPProxy) closeIdleSessions(now time.Time) {
	var expired []*udpSession

	p.mu.Lock()
	for key, session := range p.sessions {
		if now.Sub(session.lastSeen) > udpSessionIdle {
			delete(p.sessions, key)
			expired = append(expired, session)
		}
	}
	p.mu.Unlock()

	for _, session := range expired {
		log.Infof("UDP proxy session idle timeout: %s -> %s", session.clientAddr.String(), session.destAddr)
		if session.forwarder != nil {
			_ = session.forwarder.Close()
		}
	}
	p.local.udpRoutes.SweepIdle(now, udpSessionIdle)
}

func (l *Local) newUDPForwarder(proxy *UDPProxy, clientAddr *net.UDPAddr, tokenIP net.IP, destAddr string) (udpForwarder, error) {
	switch l.selectMode {
	case OnlyHTTPProxyMode:
		return nil, fmt.Errorf("HTTP proxy mode does not support UDP")
	case DirectMode:
		forwarder, err := newDirectUDPForwarder(proxy, clientAddr, tokenIP, destAddr)
		if err != nil {
			return nil, err
		}
		return forwarder, nil
	case OnlySocks5Mode:
		forwarder, err := l.newSocks5UDPForwarder(proxy, clientAddr, tokenIP, destAddr)
		if err != nil {
			return nil, err
		}
		return forwarder, nil
	default:
		if l.socks5Addr != "" {
			forwarder, err := l.newSocks5UDPForwarder(proxy, clientAddr, tokenIP, destAddr)
			if err == nil {
				return forwarder, nil
			}
			log.Infof("SOCKS5 UDP associate failed for %s, fallback direct: %s", destAddr, err.Error())
		}
		forwarder, err := newDirectUDPForwarder(proxy, clientAddr, tokenIP, destAddr)
		if err != nil {
			return nil, err
		}
		return forwarder, nil
	}
}

type directUDPForwarder struct {
	proxy      *UDPProxy
	clientAddr *net.UDPAddr
	tokenIP    net.IP
	conn       *net.UDPConn
}

func newDirectUDPForwarder(proxy *UDPProxy, clientAddr *net.UDPAddr, tokenIP net.IP, destAddr string) (*directUDPForwarder, error) {
	destUDPAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP destination %q: %w", destAddr, err)
	}
	conn, err := net.DialUDP("udp", nil, destUDPAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP destination %q: %w", destAddr, err)
	}
	f := &directUDPForwarder{
		proxy:      proxy,
		clientAddr: cloneUDPAddr(clientAddr),
		tokenIP:    cloneIP(tokenIP),
		conn:       conn,
	}
	go f.readLoop()
	return f, nil
}

func (f *directUDPForwarder) Write(payload []byte) error {
	_, err := f.conn.Write(payload)
	return err
}

func (f *directUDPForwarder) Close() error {
	return f.conn.Close()
}

func (f *directUDPForwarder) readLoop() {
	buf := make([]byte, udpPacketMaxSize)
	for {
		if err := f.conn.SetReadDeadline(time.Now().Add(udpSessionReadLimit)); err != nil {
			return
		}
		n, err := f.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				log.Errorf("UDP direct read err: %s", err.Error())
			}
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if err := f.proxy.sendToClient(payload, f.tokenIP, f.clientAddr); err != nil {
			log.Errorf("UDP proxy response write to %s err: %s", f.clientAddr.String(), err.Error())
			return
		}
	}
}

func udpSessionKey(clientAddr *net.UDPAddr, tokenIP net.IP) string {
	return clientAddr.String() + "|" + tokenIP.String()
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   cloneIP(addr.IP),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
