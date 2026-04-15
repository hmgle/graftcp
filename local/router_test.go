package local

import (
	"syscall"
	"testing"
	"time"
)

func TestRouteRegistryRegisterLookupReleaseIPv4(t *testing.T) {
	registry := NewRouteRegistry()
	defer registry.Close()

	token, err := registry.Register(syscall.AF_INET, "1.2.3.4", 443)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	gotToken, destAddr, ok := registry.Lookup(TokenToIP(token))
	if !ok {
		t.Fatal("Lookup() did not find registered token")
	}
	if gotToken != token {
		t.Fatalf("Lookup() token = %v, want %v", gotToken, token)
	}
	if destAddr != "1.2.3.4:443" {
		t.Fatalf("Lookup() destAddr = %q, want %q", destAddr, "1.2.3.4:443")
	}

	if !registry.ReleaseToken(token) {
		t.Fatal("ReleaseToken() returned false")
	}
	if _, _, ok := registry.Lookup(TokenToIP(token)); ok {
		t.Fatal("Lookup() succeeded after ReleaseToken()")
	}
}

func TestRouteRegistryRegisterLookupReleaseIPv6(t *testing.T) {
	registry := NewRouteRegistry()
	defer registry.Close()

	token, err := registry.Register(syscall.AF_INET6, "2001:db8::1", 8443)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	_, destAddr, ok := registry.Lookup(TokenToIP(token))
	if !ok {
		t.Fatal("Lookup() did not find registered IPv6 token")
	}
	if destAddr != "[2001:db8::1]:8443" {
		t.Fatalf("Lookup() destAddr = %q, want %q", destAddr, "[2001:db8::1]:8443")
	}
}

func TestRouteRegistryPruneExpired(t *testing.T) {
	registry := &RouteRegistry{
		routes:     make(map[uint32]routeEntry),
		allocator:  newLoopbackAllocator(loopbackStartToken, loopbackEndToken),
		pendingTTL: time.Millisecond,
		activeTTL:  time.Millisecond,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	pendingToken, err := registry.Register(syscall.AF_INET, "8.8.8.8", 53)
	if err != nil {
		t.Fatalf("Register() pending error = %v", err)
	}
	activeToken, err := registry.Register(syscall.AF_INET, "9.9.9.9", 53)
	if err != nil {
		t.Fatalf("Register() active error = %v", err)
	}
	if _, _, ok := registry.Lookup(TokenToIP(activeToken)); !ok {
		t.Fatal("Lookup() did not find active token")
	}

	time.Sleep(5 * time.Millisecond)
	registry.pruneExpired(time.Now())

	if _, _, ok := registry.Lookup(TokenToIP(pendingToken)); ok {
		t.Fatal("pending token was not pruned")
	}
	if _, _, ok := registry.Lookup(TokenToIP(activeToken)); ok {
		t.Fatal("active token was not pruned")
	}
}
