package local

import (
	"syscall"
	"testing"
	"time"
)

func TestRouteRegistryRegisterConsumeIPv4(t *testing.T) {
	registry := NewRouteRegistry()

	token, err := registry.Register(syscall.AF_INET, "1.2.3.4", 443)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	destAddr, ok := registry.Consume(tokenToIP(token))
	if !ok {
		t.Fatal("Consume() did not find registered token")
	}
	if destAddr != "1.2.3.4:443" {
		t.Fatalf("Consume() destAddr = %q, want %q", destAddr, "1.2.3.4:443")
	}

	if _, ok := registry.Consume(tokenToIP(token)); ok {
		t.Fatal("Consume() succeeded after the token was already consumed")
	}
}

func TestRouteRegistryRegisterConsumeIPv6(t *testing.T) {
	registry := NewRouteRegistry()

	token, err := registry.Register(syscall.AF_INET6, "2001:db8::1", 8443)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	destAddr, ok := registry.Consume(tokenToIP(token))
	if !ok {
		t.Fatal("Consume() did not find registered IPv6 token")
	}
	if destAddr != "[2001:db8::1]:8443" {
		t.Fatalf("Consume() destAddr = %q, want %q", destAddr, "[2001:db8::1]:8443")
	}
}

func TestRouteRegistryWrapAroundReusesTokens(t *testing.T) {
	registry := &RouteRegistry{
		allocator: newLoopbackGen(loopbackStartToken, loopbackStartToken+1),
	}

	firstToken, err := registry.Register(syscall.AF_INET, "1.1.1.1", 80)
	if err != nil {
		t.Fatalf("Register() first error = %v", err)
	}
	secondToken, err := registry.Register(syscall.AF_INET, "2.2.2.2", 80)
	if err != nil {
		t.Fatalf("Register() second error = %v", err)
	}
	thirdToken, err := registry.Register(syscall.AF_INET, "3.3.3.3", 80)
	if err != nil {
		t.Fatalf("Register() third error = %v", err)
	}

	if firstToken != thirdToken {
		t.Fatalf("expected wrap-around to reuse the first token, got %v and %v", firstToken, thirdToken)
	}
	if firstToken == secondToken {
		t.Fatalf("expected the second token to differ before wrap-around, got %v", secondToken)
	}

	destAddr, ok := registry.Consume(tokenToIP(firstToken))
	if !ok {
		t.Fatal("Consume() did not find the wrapped token")
	}
	if destAddr != "3.3.3.3:80" {
		t.Fatalf("Consume() destAddr after wrap = %q, want %q", destAddr, "3.3.3.3:80")
	}
}

func TestDatagramRouteRegistryRollbackKeepsSharedToken(t *testing.T) {
	registry := NewDatagramRouteRegistry()

	firstToken, err := registry.Reserve(syscall.AF_INET, "198.51.100.1", 5353)
	if err != nil {
		t.Fatalf("Reserve() first error = %v", err)
	}
	registry.StartUse(firstToken)
	registry.FinishUse(firstToken, true)
	secondToken, err := registry.Reserve(syscall.AF_INET, "198.51.100.1", 5353)
	if err != nil {
		t.Fatalf("Reserve() second error = %v", err)
	}
	if firstToken != secondToken {
		t.Fatalf("Reserve() returned different tokens for the same UDP destination: %v and %v", firstToken, secondToken)
	}

	registry.FinishRewrite(secondToken, false)
	destAddr, ok := registry.Lookup(tokenToIP(firstToken))
	if !ok {
		t.Fatal("Lookup() did not find reused token")
	}
	if destAddr != "198.51.100.1:5353" {
		t.Fatalf("Lookup() destAddr = %q, want %q", destAddr, "198.51.100.1:5353")
	}
}

func TestRouteRegistryForgetReleasesToken(t *testing.T) {
	registry := NewRouteRegistry()

	token, err := registry.Register(syscall.AF_INET, "203.0.113.1", 80)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registry.Forget(token)

	if _, ok := registry.Consume(tokenToIP(token)); ok {
		t.Fatal("Consume() found route after Forget()")
	}
}

func TestRouteRegistrySweepIdle(t *testing.T) {
	registry := NewRouteRegistry()

	token, err := registry.Register(syscall.AF_INET, "203.0.113.3", 443)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	registry.SweepIdle(time.Now().Add(time.Minute), time.Second)
	if _, ok := registry.Consume(tokenToIP(token)); ok {
		t.Fatal("Consume() found route after idle sweep")
	}
}

func TestDatagramRouteRegistryRollbackReleasesUnusedToken(t *testing.T) {
	registry := &DatagramRouteRegistry{
		allocator: newLoopbackGen(loopbackStartToken, loopbackStartToken),
	}

	token, err := registry.Reserve(syscall.AF_INET, "203.0.113.2", 9999)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := registry.Reserve(syscall.AF_INET, "203.0.113.2", 9999)
	if err != nil || shared != token {
		t.Fatalf("second Reserve() = %v, %v, want token %v", shared, err, token)
	}
	registry.FinishRewrite(token, false)

	if _, ok := registry.Lookup(tokenToIP(token)); ok {
		t.Fatal("Lookup() found an uncommitted route")
	}
	if _, err := registry.Register(syscall.AF_INET, "203.0.113.3", 9999); err == nil {
		t.Fatal("Register() overwrote a pending route")
	}

	registry.FinishRewrite(shared, false)
	if _, err := registry.Register(syscall.AF_INET, "203.0.113.3", 9999); err != nil {
		t.Fatalf("Register() after rollback: %v", err)
	}
	if _, err := registry.Register(syscall.AF_INET, "203.0.113.2", 9999); err == nil {
		t.Fatal("Register() overwrote a committed route")
	}
	if got, ok := registry.Lookup(tokenToIP(token)); !ok || got != "203.0.113.3:9999" {
		t.Fatalf("Lookup() = %q, %v, want 203.0.113.3:9999", got, ok)
	}
}

func TestDatagramRouteRegistryReclaimsIdleSendTokens(t *testing.T) {
	registry := &DatagramRouteRegistry{
		allocator: newLoopbackGen(loopbackStartToken, loopbackStartToken+1),
	}
	const idle = 2 * time.Minute
	sendToken, err := registry.Reserve(syscall.AF_INET, "203.0.113.2", 9999)
	if err != nil {
		t.Fatal(err)
	}
	registry.FinishRewrite(sendToken, true)

	connectedToken, err := registry.Reserve(syscall.AF_INET, "203.0.113.3", 9999)
	if err != nil {
		t.Fatal(err)
	}
	registry.FinishRewrite(connectedToken, true)
	connectToken, err := registry.Reserve(syscall.AF_INET, "203.0.113.3", 9999)
	if err != nil || connectToken != connectedToken {
		t.Fatalf("connect Reserve() = %v, %v, want token %v", connectToken, err, connectedToken)
	}
	registry.StartUse(connectToken)
	registry.FinishUse(connectToken, true)

	// A failed connect rewrite must not pin the transient route.
	failedToken, err := registry.Reserve(syscall.AF_INET, "203.0.113.2", 9999)
	if err != nil || failedToken != sendToken {
		t.Fatalf("failed connect Reserve() = %v, %v, want token %v", failedToken, err, sendToken)
	}
	now := time.Now().Add(idle + time.Second)
	registry.SweepIdle(now, idle)
	if _, err := registry.Register(syscall.AF_INET, "203.0.113.4", 9999); err == nil {
		t.Fatal("sweep reclaimed an in-progress rewrite")
	}
	registry.StartUse(failedToken)
	registry.FinishUse(failedToken, false)

	registry.SweepIdle(now, idle)
	if _, ok := registry.Lookup(tokenToIP(sendToken)); ok {
		t.Fatal("Lookup() found the expired send route")
	}
	if got, ok := registry.Lookup(tokenToIP(connectedToken)); !ok || got != "203.0.113.3:9999" {
		t.Fatalf("Lookup() after connect promotion = %q, %v", got, ok)
	}
	next, err := registry.Register(syscall.AF_INET, "203.0.113.4", 9999)
	if err != nil || next != sendToken {
		t.Fatalf("Register() after sweep = %v, %v, want token %v", next, err, sendToken)
	}
	if _, err := registry.Register(syscall.AF_INET, "203.0.113.2", 9999); err == nil {
		t.Fatal("Register() found a stale destination entry for the reclaimed token")
	}
}

func TestDatagramRouteRegistryLookupRefreshesIdleTime(t *testing.T) {
	registry := NewDatagramRouteRegistry()
	token, err := registry.Register(syscall.AF_INET, "203.0.113.2", 9999)
	if err != nil {
		t.Fatal(err)
	}
	const idle = 2 * time.Minute
	now := time.Now()
	route := registry.transient[token]
	route.lastSeen = now.Add(-idle - time.Second)
	registry.transient[token] = route
	if _, ok := registry.Lookup(tokenToIP(token)); !ok {
		t.Fatal("Lookup() missed the route before the sweep")
	}
	registry.SweepIdle(now, idle)
	if _, ok := registry.Lookup(tokenToIP(token)); !ok {
		t.Fatal("sweep reclaimed a route refreshed by Lookup()")
	}
}

func TestDatagramRouteRegistryPinWithOutstandingReservations(t *testing.T) {
	registry := &DatagramRouteRegistry{
		allocator: newLoopbackGen(loopbackStartToken, loopbackStartToken+1),
	}
	const host = "203.0.113.9"
	token, err := registry.Reserve(syscall.AF_INET, host, 53)
	if err != nil {
		t.Fatal(err)
	}
	// One connect succeeds while another connect and a send are pending.
	for range 2 {
		got, err := registry.Reserve(syscall.AF_INET, host, 53)
		if err != nil || got != token {
			t.Fatalf("Reserve() = %v, %v, want %v", got, err, token)
		}
	}
	registry.StartUse(token)
	registry.StartUse(token)
	registry.FinishUse(token, true)
	registry.FinishRewrite(token, false)
	registry.FinishUse(token, false)
	if _, ok := registry.transient[token]; ok {
		t.Fatal("pinned token remains in the idle sweep")
	}

	// Wrap the allocator with the pinned slot first and the other slot free.
	for _, port := range []uint16{54, 55} {
		other, err := registry.Register(syscall.AF_INET, host, port)
		if err != nil || other == token {
			t.Fatalf("Register(port %d) = %v, %v, reused pinned slot %v", port, other, err, token)
		}
		registry.SweepIdle(time.Now().Add(time.Hour), time.Minute)
	}
	if got, ok := registry.Lookup(tokenToIP(token)); !ok || got != host+":53" {
		t.Fatalf("Lookup() after token wrap = %q, %v", got, ok)
	}
}
