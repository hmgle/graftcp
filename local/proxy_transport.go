package local

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// Install one deadline for dialing the proxy and negotiating the tunnel.
type proxyHandshakeTransport struct{ forward proxy.Dialer }

func (d proxyHandshakeTransport) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d proxyHandshakeTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, tcpDialTimeout)
	defer cancel()
	conn, err := dialProxyContext(ctx, d.forward, network, addr)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func clearProxyDeadline(conn net.Conn) error {
	// A closed pipe can still have buffered tunnel data in its reader.
	if err := conn.SetDeadline(time.Time{}); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		conn.Close()
		return err
	}
	return nil
}

func dialProxyContext(ctx context.Context, forward proxy.Dialer, network, addr string) (net.Conn, error) {
	if d, ok := forward.(proxy.ContextDialer); ok {
		return d.DialContext(ctx, network, addr)
	}

	// A legacy Dial cannot be interrupted. If the caller times out, the
	// worker retains ownership of the connection and closes it on return.
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result)
	go func() {
		conn, err := forward.Dial(network, addr)
		select {
		case done <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
