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

func TestDatagramRouteRegistryReusesTokenForSameDestination(t *testing.T) {
	registry := NewDatagramRouteRegistry()

	firstToken, err := registry.Register(syscall.AF_INET, "198.51.100.1", 5353)
	if err != nil {
		t.Fatalf("Register() first error = %v", err)
	}
	secondToken, err := registry.Register(syscall.AF_INET, "198.51.100.1", 5353)
	if err != nil {
		t.Fatalf("Register() second error = %v", err)
	}
	if firstToken != secondToken {
		t.Fatalf("Register() returned different tokens for the same UDP destination: %v and %v", firstToken, secondToken)
	}

	destAddr, ok := registry.Lookup(tokenToIP(firstToken))
	if !ok {
		t.Fatal("Lookup() did not find reused token")
	}
	if destAddr != "198.51.100.1:5353" {
		t.Fatalf("Lookup() destAddr = %q, want %q", destAddr, "198.51.100.1:5353")
	}
}

func TestDatagramRouteRegistrySweepIdle(t *testing.T) {
	registry := NewDatagramRouteRegistry()

	token, err := registry.Register(syscall.AF_INET, "198.51.100.2", 5353)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	registry.SweepIdle(time.Now().Add(time.Minute), time.Second)
	if _, ok := registry.Lookup(tokenToIP(token)); ok {
		t.Fatal("Lookup() found route after idle sweep")
	}

	nextToken, err := registry.Register(syscall.AF_INET, "198.51.100.2", 5353)
	if err != nil {
		t.Fatalf("Register() after sweep error = %v", err)
	}
	if nextToken == token {
		t.Fatalf("Register() reused swept destination token immediately: %v", token)
	}
}
