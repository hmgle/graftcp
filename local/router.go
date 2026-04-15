package local

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
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
	routes    sync.Map // map[uint32]string
	allocator *LoopbackGen
}

// NewRouteRegistry creates a registry backed by the 127.0.0.0/8 loopback range.
func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{
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
	destAddr, err := normalizeDestAddr(family, host, port)
	if err != nil {
		return 0, err
	}

	token := r.allocator.nextToken()
	r.routes.Store(token, destAddr)
	return token, nil
}

// Consume resolves and removes the destination registered for the accepted
// local loopback IP.
func (r *RouteRegistry) Consume(localIP net.IP) (uint32, string, bool) {
	token, ok := IPToToken(localIP)
	if !ok {
		return 0, "", false
	}

	destAddr, ok := r.loadAndDelete(token)
	if !ok {
		return 0, "", false
	}
	return token, destAddr, true
}

// ReleaseToken removes a token mapping. It is safe to call multiple times.
func (r *RouteRegistry) ReleaseToken(token uint32) bool {
	if token == 0 {
		return false
	}

	_, ok := r.routes.LoadAndDelete(token)
	return ok
}

func (r *RouteRegistry) loadAndDelete(token uint32) (string, bool) {
	value, ok := r.routes.LoadAndDelete(token)
	if !ok {
		return "", false
	}

	destAddr, ok := value.(string)
	if !ok {
		return "", false
	}
	return destAddr, true
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
