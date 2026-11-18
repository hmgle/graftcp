package local

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type dialerFunc func(network, addr string) (net.Conn, error)

func (f dialerFunc) Dial(network, addr string) (net.Conn, error) {
	return f(network, addr)
}

type contextTestDialer struct {
	dialerFunc
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func (d contextTestDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialContext(ctx, network, addr)
}

func TestHTTPProxyConnectDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		forward := contextTestDialer{
			dialerFunc: func(string, string) (net.Conn, error) {
				time.Sleep(2 * tcpDialTimeout)
				return nil, errors.New("used Dial instead of DialContext")
			},
			dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(start.Add(tcpDialTimeout)) {
					return nil, errors.New("missing HTTP attempt deadline")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		dialer := httpDialer{forward: forward}
		_, err := dialer.Dial("tcp", "target.test:443")
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != tcpDialTimeout {
			t.Fatalf("Dial returned %v after %v, want connect timeout after %v", err, time.Since(start), tcpDialTimeout)
		}
	})
}

func TestHTTPProxyClosesLateConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, peer := net.Pipe()
		defer transport.Close()
		defer peer.Close()
		dialer := httpDialer{forward: dialerFunc(func(string, string) (net.Conn, error) {
			time.Sleep(2 * tcpDialTimeout)
			return transport, nil
		})}
		start := time.Now()
		_, err := dialer.Dial("tcp", "target.test:443")
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != tcpDialTimeout {
			t.Fatalf("Dial returned %v after %v, want connect timeout after %v", err, time.Since(start), tcpDialTimeout)
		}
		peer.SetReadDeadline(start.Add(3 * tcpDialTimeout))
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("late connection was not closed: %v", err)
		}
	})
}

func TestHTTPProxyHandshakeDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, peer := net.Pipe()
		defer transport.Close()
		defer peer.Close()
		// Bound the test even if the dialer never installs its own deadline.
		guard := time.AfterFunc(2*tcpDialTimeout, func() { peer.Close() })
		defer guard.Stop()
		go func() {
			if _, err := http.ReadRequest(bufio.NewReader(peer)); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(tcpDialTimeout / 4)
			if _, err := io.WriteString(peer, "HTTP/1.1 103 Early Hints\r\n\r\n"); err != nil {
				t.Error(err)
			}
			// Keep the tunnel open without sending a final response.
		}()
		dialer := httpDialer{forward: dialerFunc(func(string, string) (net.Conn, error) {
			time.Sleep(tcpDialTimeout / 4)
			return transport, nil
		})}
		start := time.Now()
		_, err := dialer.Dial("tcp", "target.test:443")
		if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) != tcpDialTimeout {
			t.Fatalf("Dial returned %v after %v, want timeout after %v", err, time.Since(start), tcpDialTimeout)
		}
	})
}

func TestHTTPProxyClearsHandshakeDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, peer := net.Pipe()
		defer transport.Close()
		defer peer.Close()
		go func() {
			if _, err := http.ReadRequest(bufio.NewReader(peer)); err != nil {
				t.Error(err)
				return
			}
			if _, err := io.WriteString(peer, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(2 * tcpDialTimeout)
			if _, err := io.WriteString(peer, "OK"); err != nil {
				t.Error(err)
			}
		}()
		dialer := httpDialer{forward: dialerFunc(func(string, string) (net.Conn, error) { return transport, nil })}
		conn, err := dialer.Dial("tcp", "target.test:443")
		if err != nil {
			t.Fatal(err)
		}
		var buf [2]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil || string(buf[:]) != "OK" {
			t.Fatalf("reading tunnel beyond handshake timeout: got %q, err %v", buf, err)
		}
	})
}

func TestHTTPProxyDialReturnsTransportWithoutBufferedData(t *testing.T) {
	transport, peer := net.Pipe()
	defer transport.Close()
	defer peer.Close()
	if err := transport.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		if _, err := http.ReadRequest(bufio.NewReader(peer)); err == nil {
			io.WriteString(peer, "HTTP/1.1 200 Connection Established\r\n\r\n")
		}
	}()
	dialer := httpDialer{
		host: "proxy.test:8080",
		forward: dialerFunc(func(string, string) (net.Conn, error) {
			return transport, nil
		}),
	}
	conn, err := dialer.Dial("tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	if conn != transport {
		t.Fatalf("Dial returned %T, want original transport %T", conn, transport)
	}
}

func TestHTTPProxyDialPreservesBufferedTunnelData(t *testing.T) {
	for _, tc := range []struct{ name, headers string }{
		{"plain", "200 OK\r\n"},
		{"early_hints", "103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 Connection Established\r\n"},
		{"multiple_interim", "100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n"},
		{"content_length", "200 OK\r\nContent-Length: 4\r\n"},
		{"transfer_encoding", "200 OK\r\nTransfer-Encoding: chunked\r\n"},
		{"other_success", "201 Created\r\n"},
		{"invalid_framing", "200 OK\r\nContent-Length: invalid\r\nTransfer-Encoding: unknown\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) { checkBufferedTunnelData(t, tc.headers) })
	}
}

func checkBufferedTunnelData(t *testing.T, headers string) {
	t.Helper()
	const tunnelData = "first-rest"

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer clientConn.Close()

		if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Errorf("SetDeadline() error = %v", err)
			return
		}
		r := bufio.NewReader(clientConn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Errorf("read CONNECT request: %v", err)
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := io.WriteString(clientConn, "HTTP/1.1 "+headers+"\r\n"+tunnelData); err != nil {
			t.Errorf("write CONNECT response: %v", err)
			return
		}
	}()

	dialer := &httpDialer{
		host: "proxy.test:8080",
		forward: dialerFunc(func(network, addr string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q, want tcp", network)
			}
			if addr != "proxy.test:8080" {
				t.Fatalf("addr = %q, want proxy.test:8080", addr)
			}
			return serverConn, nil
		}),
	}

	conn, err := dialer.Dial("tcp", "target.test:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if got := string(buf); got != tunnelData {
		t.Fatalf("tunnel data = %q, want %q", got, tunnelData)
	}

	<-serverDone
}

// TestHTTPProxyDialNon200StatusReturnsErrorWithoutPanic guards against the
// previous "strings.SplitN(resp.Status, ' ', 2)[1]" formatter, which panicked
// when the proxy returned a non-standard status line lacking a space.
func TestHTTPProxyDialNon200StatusReturnsErrorWithoutPanic(t *testing.T) {
	cases := []struct{ name, response, want string }{
		{"standard status", "HTTP/1.1 502 Bad Gateway\r\n\r\n", "connect proxy error: 502 Bad Gateway"},
		{"single-token line", "HTTP/1.1 503\r\n\r\n", "connect proxy error: 503"},
		{"final error after hints", "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "connect proxy error: 407 Proxy Authentication Required"},
		{"unexpected upgrade", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "connect proxy error: 101 Switching Protocols"},
		{"missing final response", "HTTP/1.1 103 Early Hints\r\n\r\n", "EOF"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()

			go func() {
				defer clientConn.Close()
				_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
				r := bufio.NewReader(clientConn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(clientConn, tc.response)
			}()

			dialer := &httpDialer{
				host: "proxy.test:8080",
				forward: dialerFunc(func(network, addr string) (net.Conn, error) {
					return serverConn, nil
				}),
			}
			_, err := dialer.Dial("tcp", "target.test:443")
			if err == nil {
				t.Fatal("Dial() succeeded for non-200 response")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
