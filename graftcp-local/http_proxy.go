package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
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

func (h *httpDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := h.forward.Dial("tcp", h.host)
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
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	io.Copy(ioutil.Discard, resp.Body)
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("connect proxy error: %v", strings.SplitN(resp.Status, " ", 2)[1])
	}
	return conn, nil
}

func newHttpProxy(u *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
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
	proxy.RegisterDialerType("http", newHttpProxy)
	proxy.RegisterDialerType("https", newHttpProxy)
}
