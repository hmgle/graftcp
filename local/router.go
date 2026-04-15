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

	defaultPendingRouteTTL = 15 * time.Second
	defaultActiveRouteTTL  = 10 * time.Minute
	defaultGCInterval      = 30 * time.Second
)

type loopbackAllocator struct {
	counter   atomic.Uint64
	start     uint32
	rangeSize uint32
}

func newLoopbackAllocator(start, end uint32) *loopbackAllocator {
	return &loopbackAllocator{
		start:     start,
		rangeSize: end - start + 1,
	}
}

func (a *loopbackAllocator) next() uint32 {
	offset := a.counter.Add(1) - 1
	return a.start + uint32(offset%uint64(a.rangeSize))
}

type routeEntry struct {
	destAddr   string
	createdAt  time.Time
	acceptedAt time.Time
}

// RouteRegistry stores the original destination for each loopback token IP.
type RouteRegistry struct {
	mu         sync.Mutex
	routes     map[uint32]routeEntry
	allocator  *loopbackAllocator
	pendingTTL time.Duration
	activeTTL  time.Duration
	stopCh     chan struct{}
	doneCh     chan struct{}
}

// NewRouteRegistry creates a registry backed by the 127.0.0.0/8 loopback range.
func NewRouteRegistry() *RouteRegistry {
	r := &RouteRegistry{
		routes:     make(map[uint32]routeEntry),
		allocator:  newLoopbackAllocator(loopbackStartToken, loopbackEndToken),
		pendingTTL: defaultPendingRouteTTL,
		activeTTL:  defaultActiveRouteTTL,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
	go r.gcLoop(defaultGCInterval)
	return r
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

// Register allocates a unique loopback token IP for a connect target.
func (r *RouteRegistry) Register(family int, host string, port uint16) (uint32, error) {
	destAddr, err := normalizeDestAddr(family, host, port)
	if err != nil {
		return 0, err
	}

	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	for i := uint32(0); i < r.allocator.rangeSize; i++ {
		token := r.allocator.next()
		if _, exists := r.routes[token]; exists {
			continue
		}
		r.routes[token] = routeEntry{
			destAddr:  destAddr,
			createdAt: now,
		}
		return token, nil
	}

	return 0, fmt.Errorf("loopback token pool exhausted")
}

// Lookup returns the destination registered for the accepted local loopback IP.
func (r *RouteRegistry) Lookup(localIP net.IP) (uint32, string, bool) {
	token, ok := IPToToken(localIP)
	if !ok {
		return 0, "", false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.routes[token]
	if !ok {
		return 0, "", false
	}
	entry.acceptedAt = time.Now()
	r.routes[token] = entry
	return token, entry.destAddr, true
}

// ReleaseToken removes a token mapping. It is safe to call multiple times.
func (r *RouteRegistry) ReleaseToken(token uint32) bool {
	if token == 0 {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.routes[token]; !ok {
		return false
	}
	delete(r.routes, token)
	return true
}

// Close stops background cleanup.
func (r *RouteRegistry) Close() {
	select {
	case <-r.doneCh:
		return
	default:
	}

	close(r.stopCh)
	<-r.doneCh
}

func (r *RouteRegistry) gcLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(r.doneCh)
	}()

	for {
		select {
		case <-ticker.C:
			r.pruneExpired(time.Now())
		case <-r.stopCh:
			return
		}
	}
}

func (r *RouteRegistry) pruneExpired(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for token, entry := range r.routes {
		if entry.acceptedAt.IsZero() {
			if now.Sub(entry.createdAt) > r.pendingTTL {
				delete(r.routes, token)
			}
			continue
		}

		if now.Sub(entry.acceptedAt) > r.activeTTL {
			delete(r.routes, token)
		}
	}
}

// IPToToken converts an accepted loopback IP to its registry token.
func IPToToken(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}

// TokenToIP converts a registry token back to an IPv4 loopback address.
func TokenToIP(token uint32) net.IP {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], token)
	return net.IPv4(buf[0], buf[1], buf[2], buf[3]).To4()
}
