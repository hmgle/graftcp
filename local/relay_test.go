package local

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

func TestRelayWithoutCloseWriteStopsBothDirections(t *testing.T) {
	client, a := net.Pipe()
	b, peer := net.Pipe()
	defer a.Close()
	defer b.Close()
	defer peer.Close()
	done := make(chan struct{})
	go func() {
		relay(a, b)
		close(done)
	}()
	client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay still waiting on a connection without CloseWrite")
	}
}

// Make the CONNECT parser receive headers and tunnel bytes in one read,
// regardless of how the loopback TCP stack splits the proxy's write.
type coalescedResponseConn struct {
	*net.TCPConn
	firstRead int
}

func (c *coalescedResponseConn) Read(p []byte) (int, error) {
	if c.firstRead > 0 {
		n := c.firstRead
		c.firstRead = 0
		return io.ReadAtLeast(c.TCPConn, p, n)
	}
	return c.TCPConn.Read(p)
}

func TestRelayResponseAfterClientHalfClose(t *testing.T) {
	const connectOK = "HTTP/1.1 200 OK\r\n\r\n"
	for _, tc := range []struct{ name, mode, early string }{
		{"direct", "direct", ""},
		{"only_socks5", "only_socks5", ""},
		{"only_http_proxy", "only_http_proxy", ""},
		{"buffered_http_proxy", "only_http_proxy", "early-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			upstream := ln.Addr().(*net.TCPAddr)
			var socks, httpProxy string
			switch tc.mode {
			case "only_socks5":
				socks = upstream.String()
			case "only_http_proxy":
				httpProxy = upstream.String()
			}
			l, err := NewLocal("0.0.0.0:0", socks, "", "", httpProxy)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.SetSelectMode(tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.early != "" {
				d := l.httpProxyDialer.(*httpDialer)
				forward := d.forward
				d.forward = dialerFunc(func(network, addr string) (net.Conn, error) {
					c, err := forward.Dial(network, addr)
					if err != nil {
						return nil, err
					}
					return &coalescedResponseConn{c.(*net.TCPConn), len(connectOK + tc.early)}, nil
				})
			}
			front, err := l.StartListen()
			if err != nil {
				t.Fatal(err)
			}
			defer front.Close()
			go l.StartService(front)
			token, err := l.Registry().Register(syscall.AF_INET, upstream.IP.String(), uint16(upstream.Port))
			if err != nil {
				t.Fatal(err)
			}
			client, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: tokenToIP(token), Port: front.Addr().(*net.TCPAddr).Port})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			deadline := time.Now().Add(3 * time.Second)
			client.SetDeadline(deadline)
			ln.SetDeadline(deadline)
			if _, err := io.WriteString(client, "request"); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}

			server, err := ln.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetDeadline(deadline)
			switch tc.mode {
			case "only_socks5":
				mock := &fakeSocks5UnixServer{targets: make(chan string, 1)}
				if err := mock.handleConn(server); err != nil {
					t.Fatal(err)
				}
			case "only_http_proxy":
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					t.Fatal(err)
				}
				if req.Method != http.MethodConnect || req.Host != upstream.String() {
					t.Fatalf("unexpected tunnel request: %s %s", req.Method, req.Host)
				}
				if _, err := io.WriteString(server, connectOK+tc.early); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := io.ReadAll(server); err != nil || string(got) != "request" {
				t.Fatalf("reading request to EOF: got %q, err %v", got, err)
			}
			if _, err := io.WriteString(server, "response"); err != nil {
				t.Fatal(err)
			}
			if err := server.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if got, err := io.ReadAll(client); err != nil || string(got) != tc.early+"response" {
				t.Fatalf("reading response to EOF: got %q, err %v", got, err)
			}
		})
	}
}
