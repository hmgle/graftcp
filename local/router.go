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
	routes    map[uint32]routeEntry
	allocator *LoopbackGen
}

type routeEntry struct {
	destAddr string
	lastSeen time.Time
}

// NewRouteRegistry creates a registry backed by the 127.0.0.0/8 loopback range.
func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{
		routes:    make(map[uint32]routeEntry),
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
		r.routes = make(map[uint32]routeEntry)
	}
	if existing, ok := r.routes[token]; ok {
		log.Warnf("route registry token %s wrapped around; dropping pending dest %s",
			tokenToIP(token).String(), existing.destAddr)
	}
	r.routes[token] = routeEntry{destAddr: destAddr, lastSeen: time.Now()}
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
	route, ok := r.routes[token]
	if !ok {
		r.mu.Unlock()
		return "", false
	}
	delete(r.routes, token)
	r.mu.Unlock()
	return route.destAddr, true
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

func (r *RouteRegistry) SweepIdle(now time.Time, maxIdle time.Duration) {
	if r == nil || maxIdle <= 0 {
		return
	}

	r.mu.Lock()
	for token, route := range r.routes {
		if now.Sub(route.lastSeen) > maxIdle {
			delete(r.routes, token)
		}
	}
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

// DatagramRouteRegistry stores UDP destination mappings. Tokens that the
// kernel may retain after connect or a corked send live until the tracer exits.
// Routes used only for individual datagrams expire when idle.
type DatagramRouteRegistry struct {
	mu        sync.Mutex
	transient map[uint32]datagramRoute
	pinned    map[uint32]string // Permanent mappings need only their destination.
	tokens    map[string]uint32
	allocator *LoopbackGen
}

type datagramRoute struct {
	destAddr string
	pending  uint64
	inFlight uint64
	lastSeen time.Time // Zero until the first successful rewrite or Register.
}

func NewDatagramRouteRegistry() *DatagramRouteRegistry {
	return &DatagramRouteRegistry{
		transient: make(map[uint32]datagramRoute),
		tokens:    make(map[string]uint32),
		allocator: newLoopbackGen(loopbackStartToken, loopbackEndToken),
	}
}

// Register immediately makes a UDP route available to the listener.
func (r *DatagramRouteRegistry) Register(family int, host string, port uint16) (uint32, error) {
	return r.register(family, host, port, false)
}

// Reserve obtains a token for a rewrite that must be reported to FinishRewrite.
func (r *DatagramRouteRegistry) Reserve(family int, host string, port uint16) (uint32, error) {
	return r.register(family, host, port, true)
}

func (r *DatagramRouteRegistry) register(family int, host string, port uint16, pending bool) (uint32, error) {
	if r == nil || r.allocator == nil {
		return 0, fmt.Errorf("datagram route registry is not initialized")
	}
	destAddr, err := normalizeDestAddr(family, host, port)
	if err != nil {
		return 0, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transient == nil {
		r.transient = make(map[uint32]datagramRoute)
	}
	if r.tokens == nil {
		r.tokens = make(map[string]uint32)
	}

	token, ok := r.tokens[destAddr]
	if ok {
		if _, pinned := r.pinned[token]; pinned {
			return token, nil
		}
	} else {
		if len(r.tokens) >= int(r.allocator.rangeSize) {
			return 0, fmt.Errorf("datagram route registry token range is exhausted")
		}
		for {
			token = r.allocator.nextToken()
			if _, occupied := r.transient[token]; occupied {
				continue
			}
			if _, occupied := r.pinned[token]; !occupied {
				break
			}
		}
		r.tokens[destAddr] = token
	}

	route := r.transient[token]
	route.destAddr = destAddr
	if pending {
		route.pending++
	} else {
		route.lastSeen = time.Now()
	}
	r.transient[token] = route
	return token, nil
}

// StartUse exposes a reserved route just before the kernel receives its
// rewritten address. Another thread may send to it before the syscall exits.
func (r *DatagramRouteRegistry) StartUse(token uint32) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	route, ok := r.transient[token]
	if ok && route.inFlight < route.pending {
		route.inFlight++
		r.transient[token] = route
	}
}

// FinishUse pins a route when the kernel accepts a syscall that can retain the
// rewritten address. A failure releases the reservation.
func (r *DatagramRouteRegistry) FinishUse(token uint32, accepted bool) {
	r.finishRewrite(token, accepted, true)
}

// FinishRewrite completes a rewrite for an individual datagram.
func (r *DatagramRouteRegistry) FinishRewrite(token uint32, rewritten bool) {
	r.finishRewrite(token, rewritten, false)
}

func (r *DatagramRouteRegistry) finishRewrite(token uint32, accepted, inFlight bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	route, ok := r.transient[token]
	if !ok || (inFlight && route.inFlight == 0) ||
		(!inFlight && route.pending == route.inFlight) {
		return
	}
	// Pinning is permanent. Remaining reservations for this token may
	// finish in any order without changing its lifetime or visibility.
	if accepted && inFlight {
		if r.pinned == nil {
			r.pinned = make(map[uint32]string)
		}
		r.pinned[token] = route.destAddr
		delete(r.transient, token)
		return
	}
	route.pending--
	if inFlight {
		route.inFlight--
	}
	if accepted {
		route.lastSeen = time.Now()
	}
	if route.pending == 0 && route.lastSeen.IsZero() {
		delete(r.transient, token)
		delete(r.tokens, route.destAddr)
		return
	}
	r.transient[token] = route
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
	defer r.mu.Unlock()
	if dest, ok := r.pinned[token]; ok {
		return dest, true
	}
	route := r.transient[token]
	if route.lastSeen.IsZero() && route.inFlight == 0 {
		return "", false
	}
	if !route.lastSeen.IsZero() {
		route.lastSeen = time.Now()
		r.transient[token] = route
	}
	return route.destAddr, true
}

// SweepIdle reclaims routes whose token is not pinned or reserved.
func (r *DatagramRouteRegistry) SweepIdle(now time.Time, maxIdle time.Duration) {
	if r == nil || maxIdle <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for token, route := range r.transient {
		if route.pending == 0 && now.Sub(route.lastSeen) > maxIdle {
			delete(r.transient, token)
			delete(r.tokens, route.destAddr)
		}
	}
}
