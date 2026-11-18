package local

import (
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestSOCKS5ConnectDeadline(t *testing.T) {
	for _, outcome := range []string{"stalled_greeting", "stalled_auth", "stalled_reply", "open_tunnel"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport, peer := net.Pipe()
				defer transport.Close()
				defer peer.Close()
				l, err := NewLocalListener(":0")
				if err != nil {
					t.Fatal(err)
				}
				l.directDialer = dialerFunc(func(string, string) (net.Conn, error) {
					time.Sleep(tcpDialTimeout / 4)
					return transport, nil
				})
				if err := l.SetSelectMode("only_socks5"); err != nil {
					t.Fatal(err)
				}
				if err := l.ConfigureSOCKS5("127.0.0.1:1080", "user", "password"); err != nil {
					t.Fatal(err)
				}
				go func() {
					if outcome == "stalled_greeting" || outcome == "stalled_auth" {
						var greeting [4]byte // version, method count, and two methods
						if _, err := io.ReadFull(peer, greeting[:]); err != nil {
							t.Error(err)
							return
						}
						if outcome == "stalled_auth" {
							if _, err := peer.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
								t.Error(err)
								return
							}
							if _, err := io.CopyN(io.Discard, peer, 3+int64(len("userpassword"))); err != nil {
								t.Error(err)
							}
						}
						return
					}
					mock := fakeSocks5UnixServer{username: "user", password: "password"}
					if err := mock.negotiate(peer); err != nil {
						t.Error(err)
						return
					}
					if _, err := readSocks5ConnectTarget(peer); err != nil {
						t.Error(err)
						return
					}
					if outcome == "open_tunnel" {
						if _, err := peer.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
							t.Error(err)
							return
						}
						time.Sleep(2 * tcpDialTimeout)
						if _, err := io.WriteString(peer, "OK"); err != nil {
							t.Error(err)
						}
					}
				}()
				guard := time.AfterFunc(3*tcpDialTimeout, func() { peer.Close() })
				defer guard.Stop()
				start := time.Now()
				conn, err := l.dialTCP("example.com:443")
				if outcome != "open_tunnel" {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() || time.Since(start) != tcpDialTimeout {
						t.Fatalf("Dial returned %v after %v, want timeout after %v", err, time.Since(start), tcpDialTimeout)
					}
					if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
						t.Fatalf("expected failed connection to close, got %v", err)
					}
					return
				}
				if err != nil || conn != transport {
					t.Fatalf("expected original SOCKS5 transport, got %T, %v", conn, err)
				}
				var reply [2]byte
				if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "OK" {
					t.Fatalf("read from established tunnel: got %q, %v", reply, err)
				}
			})
		})
	}
}

func TestAutoFallbackAfterSOCKS5HandshakeTimeout(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	for _, next := range []string{"http", "direct"} {
		t.Run(next, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l, err := NewLocalListener(":0")
				if err != nil {
					t.Fatal(err)
				}
				if err := l.SetSelectMode("auto"); err != nil {
					t.Fatal(err)
				}
				socks, peer := net.Pipe()
				defer socks.Close()
				defer peer.Close()
				// Give the real SOCKS5 dialer a transport whose peer never replies.
				direct := l.directDialer
				l.directDialer = &counterDialer{conn: socks}
				if err := l.ConfigureSOCKS5("127.0.0.1:1080", "", ""); err != nil {
					t.Fatal(err)
				}
				l.directDialer = direct
				go func() {
					var greeting [3]byte
					if _, err := io.ReadFull(peer, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
						t.Errorf("SOCKS5 greeting = %v, err %v", greeting, err)
					}
				}()
				guard := time.AfterFunc(2*tcpDialTimeout, func() { peer.Close() })
				defer guard.Stop()

				var httpConn net.Conn
				if next == "http" {
					client, server := net.Pipe()
					defer client.Close()
					defer server.Close()
					httpConn = client
					l.httpProxyDialer = &counterDialer{conn: httpConn}
				}
				start := time.Now()
				conn, err := l.dialTCP(target.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if elapsed := time.Since(start); elapsed != tcpDialTimeout {
					t.Fatalf("fallback after %v, want %v", elapsed, tcpDialTimeout)
				}
				if next == "http" && conn != httpConn {
					t.Fatal("expected the configured HTTP proxy connection")
				}
				if next == "direct" && conn.RemoteAddr().String() != target.Addr().String() {
					t.Fatalf("expected direct connection to %v, got %v", target.Addr(), conn.RemoteAddr())
				}
			})
		})
	}
}
