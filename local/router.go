package local

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	loopbackStartToken uint32 = 0x7f000001 // 127.0.0.1
	loopbackEndToken   uint32 = 0x7ffffffe // 127.255.255.254
)

// LoopbackGen returns loopback token IPs from the 127.0.0.0/8 range.
//
// The generator cycles through the entire range. The pool is large enough that
// by the time a token wraps around, we assume any previous mapping is no longer
// in use.
type LoopbackGen struct {
	counter   atomic.Uint64
	start     uint32
	rangeSize uint32
}

func newLoopbackGen(start, end uint32) *LoopbackGen {
	return &LoopbackGen{
		start:     start,
		rangeSize: end - start + 1,
	}
}

func (g *LoopbackGen) nextToken() uint32 {
	offset := g.counter.Add(1) - 1
	return g.start + uint32(offset%uint64(g.rangeSize))
}

// RouteRegistry stores the original destination for each pending loopback token.
type RouteRegistry struct {
	mu        sync.Mutex
	routes    map[uint32]string
	allocator *LoopbackGen
}

// NewRouteRegistry creates a registry backed by the 127.0.0.0/8 loopback range.
func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{
		routes:    make(map[uint32]string),
		allocator: newLoopbackGen(loopbackStartToken, loopbackEndToken),
	}
}

func normalizeDestAddr(family int, host string, port uint16) (string, error) {
	if host == "" {
		return "", fmt.Errorf("empty destination host")
	}

	switch family {
	case syscall.AF_INET, syscall.AF_INET6:
		return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	default:
		return "", fmt.Errorf("unsupported address family %d", family)
	}
}

// Register assigns the next loopback token IP for a connect target.
func (r *RouteRegistry) Register(family int, host string, port uint16) (uint32, error) {
	if r == nil || r.allocator == nil {
		return 0, fmt.Errorf("route registry is not initialized")
	}
	destAddr, err := normalizeDestAddr(family, host, port)
	if err != nil {
		return 0, err
	}

	token := r.allocator.nextToken()
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[uint32]string)
	}
	if existing, ok := r.routes[token]; ok {
		log.Warnf("route registry token %s wrapped around; dropping pending dest %s",
			tokenToIP(token).String(), existing)
	}
	r.routes[token] = destAddr
	r.mu.Unlock()
	return token, nil
}

// Consume resolves and removes the destination registered for the accepted
// local loopback IP.
func (r *RouteRegistry) Consume(localIP net.IP) (string, bool) {
	if r == nil {
		return "", false
	}
	token, ok := ipToToken(localIP)
	if !ok {
		return "", false
	}

	r.mu.Lock()
	destAddr, ok := r.routes[token]
	if !ok {
		r.mu.Unlock()
		return "", false
	}
	delete(r.routes, token)
	r.mu.Unlock()
	return destAddr, true
}

// Forget releases the entry for token without consuming it. Callers that
// allocate a token but never end up using it (e.g. the C-side rewrite failed)
// should call Forget so the slot does not linger until wrap-around.
func (r *RouteRegistry) Forget(token uint32) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.routes, token)
	r.mu.Unlock()
}

func ipToToken(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}

func tokenToIP(token uint32) net.IP {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], token)
	return net.IPv4(buf[0], buf[1], buf[2], buf[3]).To4()
}

// DatagramRouteRegistry stores persistent UDP destination mappings.
//
// Unlike TCP routes, UDP routes are not consumed after the first packet because
// connected UDP sockets and multi-packet exchanges can reuse the same fake
// loopback endpoint.
type DatagramRouteRegistry struct {
	mu        sync.Mutex
	routes    map[uint32]datagramRoute
	tokens    map[string]uint32
	allocator *LoopbackGen
}

type datagramRoute struct {
	destAddr string
	lastSeen time.Time
}

func NewDatagramRouteRegistry() *DatagramRouteRegistry {
	return &DatagramRouteRegistry{
		routes:    make(map[uint32]datagramRoute),
		tokens:    make(map[string]uint32),
		allocator: newLoopbackGen(loopbackStartToken, loopbackEndToken),
	}
}

func (r *DatagramRouteRegistry) Register(family int, host string, port uint16) (uint32, error) {
	if r == nil || r.allocator == nil {
		return 0, fmt.Errorf("datagram route registry is not initialized")
	}
	destAddr, err := normalizeDestAddr(family, host, port)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	r.mu.Lock()
	if r.routes == nil {
		r.routes = make(map[uint32]datagramRoute)
	}
	if r.tokens == nil {
		r.tokens = make(map[string]uint32)
	}
	if token, ok := r.tokens[destAddr]; ok {
		route := r.routes[token]
		route.destAddr = destAddr
		route.lastSeen = now
		r.routes[token] = route
		r.mu.Unlock()
		return token, nil
	}

	token := r.allocator.nextToken()
	if oldRoute, ok := r.routes[token]; ok {
		delete(r.tokens, oldRoute.destAddr)
	}
	r.routes[token] = datagramRoute{destAddr: destAddr, lastSeen: now}
	r.tokens[destAddr] = token
	r.mu.Unlock()
	return token, nil
}

func (r *DatagramRouteRegistry) Lookup(localIP net.IP) (string, bool) {
	if r == nil {
		return "", false
	}
	token, ok := ipToToken(localIP)
	if !ok {
		return "", false
	}

	r.mu.Lock()
	route, ok := r.routes[token]
	if ok {
		route.lastSeen = time.Now()
		r.routes[token] = route
	}
	r.mu.Unlock()
	return route.destAddr, ok
}

// Forget releases the entry for token. Use after a UDP rewrite has failed and
// the token will never be observed by the embedded UDP listener.
func (r *DatagramRouteRegistry) Forget(token uint32) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if route, ok := r.routes[token]; ok {
		delete(r.routes, token)
		delete(r.tokens, route.destAddr)
	}
	r.mu.Unlock()
}

func (r *DatagramRouteRegistry) SweepIdle(now time.Time, maxIdle time.Duration) {
	if r == nil || maxIdle <= 0 {
		return
	}

	r.mu.Lock()
	for token, route := range r.routes {
		if now.Sub(route.lastSeen) > maxIdle {
			delete(r.routes, token)
			delete(r.tokens, route.destAddr)
		}
	}
	r.mu.Unlock()
}
