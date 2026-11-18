package local

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type dialerFunc func(network, addr string) (net.Conn, error)

func (f dialerFunc) Dial(network, addr string) (net.Conn, error) {
	return f(network, addr)
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
