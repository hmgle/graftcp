package local

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	dnsPacketMaxSize     = 65535
	dnsTCPTimeout        = 10 * time.Second
	dnsPacketConcurrency = 1024
)

// DNSProxy forwards local UDP DNS queries to an upstream DNS server over TCP.
type DNSProxy struct {
	local    *Local
	upstream string

	startOnce sync.Once
	mu        sync.Mutex
	conns     []*net.UDPConn
	packetSem chan struct{}
}

// ListenDNSProxy binds DNS UDP listeners on 127.0.0.1 and best-effort ::1.
func (l *Local) ListenDNSProxy(upstream string) (*DNSProxy, int, error) {
	if upstream == "" {
		return nil, 0, fmt.Errorf("empty DNS upstream")
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		return nil, 0, fmt.Errorf("invalid DNS upstream %q: %w", upstream, err)
	}

	udp4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, 0, fmt.Errorf("listen DNS udp4: %w", err)
	}
	port := udp4.LocalAddr().(*net.UDPAddr).Port
	p := &DNSProxy{
		local:     l,
		upstream:  upstream,
		conns:     []*net.UDPConn{udp4},
		packetSem: make(chan struct{}, dnsPacketConcurrency),
	}

	if udp6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port}); err == nil {
		p.conns = append(p.conns, udp6)
	} else {
		log.Warnf("DNS udp6 listener disabled on [::1]:%d: %s", port, err.Error())
	}

	return p, port, nil
}

// StartDNSProxy starts a DNS UDP listener on 127.0.0.1 and best-effort ::1.
func (l *Local) StartDNSProxy(upstream string) (*DNSProxy, int, error) {
	p, port, err := l.ListenDNSProxy(upstream)
	if err != nil {
		return nil, 0, err
	}
	p.Start()
	return p, port, nil
}

// Start serves packets on listeners that were already bound by ListenDNSProxy.
func (p *DNSProxy) Start() {
	if p == nil {
		return
	}
	p.startOnce.Do(func() {
		p.mu.Lock()
		conns := append([]*net.UDPConn(nil), p.conns...)
		p.mu.Unlock()

		for _, conn := range conns {
			go p.serve(conn)
		}
		if len(conns) > 0 {
			port := conns[0].LocalAddr().(*net.UDPAddr).Port
			log.Infof("mgraftcp DNS proxy started on 127.0.0.1:%d, upstream %s", port, p.upstream)
		}
	})
}

// Close stops all UDP listeners owned by the DNS proxy.
func (p *DNSProxy) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()

	var closeErr error
	for _, conn := range conns {
		if err := conn.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (p *DNSProxy) serve(conn *net.UDPConn) {
	buf := make([]byte, dnsPacketMaxSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorf("DNS udp read err: %s", err.Error())
			}
			return
		}
		if n == 0 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		select {
		case p.packetSem <- struct{}{}:
			go func() {
				defer func() { <-p.packetSem }()
				p.handle(conn, addr, query)
			}()
		default:
			log.Warnf("DNS proxy dropping query from %s: handlers busy", addr.String())
		}
	}
}

func (p *DNSProxy) handle(udpConn *net.UDPConn, clientAddr *net.UDPAddr, query []byte) {
	response, err := p.exchangeTCP(query)
	if err != nil {
		log.Errorf("DNS exchange for %s err: %s", clientAddr.String(), err.Error())
		return
	}
	if _, err := udpConn.WriteToUDP(response, clientAddr); err != nil {
		log.Errorf("DNS udp write to %s err: %s", clientAddr.String(), err.Error())
	}
}

func (p *DNSProxy) exchangeTCP(query []byte) ([]byte, error) {
	if len(query) > dnsPacketMaxSize {
		return nil, fmt.Errorf("DNS query too large: %d", len(query))
	}

	conn, err := p.local.dialTCP(p.upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(dnsTCPTimeout)); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 {
		return nil, fmt.Errorf("empty DNS TCP response")
	}
	response := make([]byte, respLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}
