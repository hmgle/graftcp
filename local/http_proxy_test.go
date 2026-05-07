package local

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type dialerFunc func(network, addr string) (net.Conn, error)

func (f dialerFunc) Dial(network, addr string) (net.Conn, error) {
	return f(network, addr)
}

func TestHTTPProxyDialPreservesBufferedTunnelData(t *testing.T) {
	const tunnelData = "early tunnel bytes"

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

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
		if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"+tunnelData); err != nil {
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

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, len(tunnelData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
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
	cases := map[string]string{
		"standard status":   "HTTP/1.1 502 Bad Gateway\r\n\r\n",
		"single-token line": "HTTP/1.1 503\r\n\r\n",
	}

	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
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
				_, _ = io.WriteString(clientConn, response)
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
			if !strings.Contains(err.Error(), "connect proxy error") {
				t.Fatalf("err = %v, want connect proxy error", err)
			}
		})
	}
}
