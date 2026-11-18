package local

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"
)

type httpDialer struct {
	host     string
	isAuth   bool
	username string
	password string

	forward proxy.Dialer
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) CloseWrite() error {
	return closeWrite(c.Conn)
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if c.r.Buffered() > 0 {
		return c.r.Read(b)
	}
	return c.Conn.Read(b)
}

func (h *httpDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := (proxyHandshakeTransport{h.forward}).Dial("tcp", h.host)
	if err != nil {
		return nil, err
	}
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req := &http.Request{
		Method: "CONNECT",
		URL:    reqURL,
		Host:   addr,
		Header: make(http.Header),
	}
	if h.isAuth {
		req.SetBasicAuth(h.username, h.password)
	}
	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	if err := readConnectResponse(r); err != nil {
		conn.Close()
		return nil, err
	}
	if err := clearProxyDeadline(conn); err != nil {
		return nil, err
	}
	if r.Buffered() == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, r: r}, nil
}

// RFC 9110 section 9.3.6: the tunnel starts at the end of the 2xx headers,
// even if the proxy sent Content-Length or Transfer-Encoding.
func readConnectResponse(r *bufio.Reader) error {
	headers := textproto.NewReader(r)
	for {
		line, err := headers.ReadLine()
		if err != nil {
			return err
		}
		version, status, _ := strings.Cut(line, " ")
		status = strings.TrimLeft(status, " ")
		code, _, _ := strings.Cut(status, " ")
		n, err := strconv.Atoi(code)
		if _, _, ok := http.ParseHTTPVersion(version); !ok || len(code) != 3 || err != nil || n < 100 {
			return fmt.Errorf("malformed HTTP proxy status line: %q", line)
		}
		if _, err := headers.ReadMIMEHeader(); err != nil {
			return err
		}
		// A 101 switches protocols, which this CONNECT request did not request.
		if n < 200 && n != http.StatusSwitchingProtocols {
			continue
		}
		if n/100 != 2 {
			return fmt.Errorf("connect proxy error: %s", status)
		}
		return nil
	}
}

func newHTTPProxy(u *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	httpProxy := &httpDialer{
		host:    u.Host,
		forward: forward,
	}
	if u.User != nil {
		httpProxy.isAuth = true
		httpProxy.username = u.User.Username()
		httpProxy.password, _ = u.User.Password()
	}
	return httpProxy, nil
}

func init() {
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}
