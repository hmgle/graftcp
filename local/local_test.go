package local

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type counterDialer struct {
	called atomic.Int32
	err    error
	conn   net.Conn
}

func (d *counterDialer) Dial(network, addr string) (net.Conn, error) {
	d.called.Add(1)
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

// TestDialTCPReturnsErrBadDialerWhenAllProxiesUnset exercises the BadDialer
// branch reached from HandleConn when the user picks a mode whose dialer was
// never configured (e.g. only_socks5 without a SOCKS5 address).
func TestDialTCPReturnsErrBadDialerWhenAllProxiesUnset(t *testing.T) {
	l, err := NewLocalListener(":0")
	if err != nil {
		t.Fatalf("NewLocalListener() error = %v", err)
	}
	if err := l.SetSelectMode("only_socks5"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}

	if _, err := l.dialTCP("example.com:80"); err == nil {
		t.Fatal("dialTCP() unexpectedly succeeded with no SOCKS5 dialer")
	} else if err != errBadDialer {
		t.Fatalf("dialTCP() err = %v, want errBadDialer", err)
	}
}

// TestDialTCPAutoFallsBackToHTTPThenDirect verifies that auto-select first
// tries the SOCKS5 dialer, then HTTP, then a direct net.Dial. The direct path
// uses a real loopback listener.
func TestDialTCPAutoFallsBackToHTTPThenDirect(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	l, err := NewLocalListener(":0")
	if err != nil {
		t.Fatalf("NewLocalListener() error = %v", err)
	}
	if err := l.SetSelectMode("auto"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}

	socks := &counterDialer{err: errBadDialer}
	httpd := &counterDialer{err: errBadDialer}
	l.socks5Dialer = socks
	l.httpProxyDialer = httpd

	conn, err := l.dialTCP(upstream.Addr().String())
	if err != nil {
		t.Fatalf("dialTCP() error = %v", err)
	}
	defer conn.Close()

	if got := socks.called.Load(); got != 1 {
		t.Fatalf("socks5 dialer called %d times, want 1", got)
	}
	if got := httpd.called.Load(); got != 1 {
		t.Fatalf("http dialer called %d times, want 1", got)
	}
}

// TestProxySelectorDirectMode confirms direct mode skips SOCKS5/HTTP entirely.
func TestProxySelectorDirectMode(t *testing.T) {
	l, err := NewLocalListener(":0")
	if err != nil {
		t.Fatalf("NewLocalListener() error = %v", err)
	}
	if err := l.SetSelectMode("direct"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}
	if _, ok := l.proxySelector().(timeoutDialer); !ok {
		t.Fatalf("proxySelector() = %T, want timeoutDialer", l.proxySelector())
	}
}

func TestConfigureProxyValidatesForcedModes(t *testing.T) {
	l, err := NewLocalListener(":0")
	if err != nil {
		t.Fatalf("NewLocalListener() error = %v", err)
	}
	if err := l.SetSelectMode("only_socks5"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}
	if err := l.ConfigureProxy("", "", "", ""); err == nil {
		t.Fatal("ConfigureProxy() succeeded without required SOCKS5 proxy")
	}
}

func TestConfigureProxyReturnsAddressErrors(t *testing.T) {
	l, err := NewLocalListener(":0")
	if err != nil {
		t.Fatalf("NewLocalListener() error = %v", err)
	}
	if err := l.ConfigureProxy("bad address", "", "", "also bad"); err == nil {
		t.Fatal("ConfigureProxy() succeeded for invalid proxy addresses")
	} else if msg := err.Error(); !strings.Contains(msg, "resolve socks5 proxy") ||
		!strings.Contains(msg, "resolve http proxy") {
		t.Fatalf("ConfigureProxy() err = %v, want both address errors", err)
	}
}
