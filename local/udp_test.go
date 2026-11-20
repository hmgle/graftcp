package local

import (
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestUDPProxyForwardsConnectedDatagramsAfterIdleGC(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP upstream error = %v", err)
	}
	defer upstream.Close()

	gotPayload := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		for range 2 {
			n, addr, err := upstream.ReadFromUDP(buf)
			if err != nil {
				return
			}
			gotPayload <- string(buf[:n])
			_, _ = upstream.WriteToUDP([]byte(strings.ToUpper(string(buf[:n]))), addr)
		}
	}()

	l, err := NewLocal(":0", "", "", "", "")
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if err := l.SetSelectMode("direct"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}
	proxy, port, err := l.StartUDPProxy()
	if err != nil {
		t.Fatalf("StartUDPProxy() error = %v", err)
	}
	defer proxy.Close()

	token, err := l.UDPRegistry().Reserve(syscall.AF_INET, "127.0.0.1", uint16(upstream.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatalf("UDP Register() error = %v", err)
	}
	l.UDPRegistry().StartUse(token)
	l.UDPRegistry().FinishUse(token, true)
	tokenIP := tokenToIP(token)
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: tokenIP, Port: port})
	if err != nil {
		t.Fatalf("DialUDP token error = %v", err)
	}
	defer client.Close()

	for i, payload := range []string{"hello", "after idle"} {
		if i == 1 {
			proxy.closeIdleSessions(time.Now().Add(udpSessionIdle + time.Second))
			proxy.mu.Lock()
			remaining := len(proxy.sessions)
			proxy.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("idle GC left %d sessions", remaining)
			}
		}
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatalf("client.Write() error = %v", err)
		}
		if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		buf := make([]byte, 512)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("client.Read() after sending %q: %v", payload, err)
		}
		if got, want := string(buf[:n]), strings.ToUpper(payload); got != want {
			t.Fatalf("client response = %q, want %q", got, want)
		}
		if got := <-gotPayload; got != payload {
			t.Fatalf("upstream payload = %q, want %q", got, payload)
		}
	}
}

func TestUDPProxyDoesNotBlockReadLoopDuringSessionInit(t *testing.T) {
	server := startSlowSocks5TCPServer(t)
	defer server.Close()

	l, err := NewLocal(":0", server.Addr(), "", "", "")
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if err := l.SetSelectMode("only_socks5"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}
	proxy, port, err := l.StartUDPProxy()
	if err != nil {
		t.Fatalf("StartUDPProxy() error = %v", err)
	}
	defer proxy.Close()

	firstToken, err := l.UDPRegistry().Register(syscall.AF_INET, "198.51.100.10", 9999)
	if err != nil {
		t.Fatalf("UDP Register() first error = %v", err)
	}
	secondToken, err := l.UDPRegistry().Register(syscall.AF_INET, "198.51.100.11", 9999)
	if err != nil {
		t.Fatalf("UDP Register() second error = %v", err)
	}

	firstClient, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: tokenToIP(firstToken), Port: port})
	if err != nil {
		t.Fatalf("DialUDP first token error = %v", err)
	}
	defer firstClient.Close()
	secondClient, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: tokenToIP(secondToken), Port: port})
	if err != nil {
		t.Fatalf("DialUDP second token error = %v", err)
	}
	defer secondClient.Close()

	if _, err := firstClient.Write([]byte("first")); err != nil {
		t.Fatalf("firstClient.Write() error = %v", err)
	}
	if _, err := secondClient.Write([]byte("second")); err != nil {
		t.Fatalf("secondClient.Write() error = %v", err)
	}

	if !server.WaitAccepts(2, time.Second) {
		t.Fatal("UDP read loop was blocked by a pending SOCKS5 UDP association")
	}
}

type slowSocks5TCPServer struct {
	ln      net.Listener
	accepts chan struct{}
	once    sync.Once
	mu      sync.Mutex
	conns   []net.Conn
}

func startSlowSocks5TCPServer(t *testing.T) *slowSocks5TCPServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp error = %v", err)
	}
	server := &slowSocks5TCPServer{
		ln:      ln,
		accepts: make(chan struct{}, 8),
	}
	go server.serve()
	return server
}

func (s *slowSocks5TCPServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *slowSocks5TCPServer) WaitAccepts(want int, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for i := 0; i < want; i++ {
		select {
		case <-s.accepts:
		case <-timer.C:
			return false
		}
	}
	return true
}

func (s *slowSocks5TCPServer) Close() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, conn := range s.conns {
			_ = conn.Close()
		}
	})
}

func (s *slowSocks5TCPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		s.accepts <- struct{}{}
	}
}

type failingUDPWrite struct {
	started chan struct{}
	release chan struct{}
}

func (f *failingUDPWrite) Write([]byte) error {
	close(f.started)
	<-f.release
	return net.ErrClosed
}

func (f *failingUDPWrite) Close() error { return nil }

func TestUDPProxyOldWriteFailureKeepsReplacement(t *testing.T) {
	proxy := listenTestUDPProxy(t)
	token, err := proxy.local.udpRoutes.Register(syscall.AF_INET, "127.0.0.1", 9999)
	if err != nil {
		t.Fatal(err)
	}
	tokenIP := tokenToIP(token)
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	destAddr := "127.0.0.1:9999"
	key := makeUDPSessionKey(clientAddr, tokenIP, destAddr)
	oldForwarder := &failingUDPWrite{started: make(chan struct{}), release: make(chan struct{})}
	releaseWrite := sync.OnceFunc(func() { close(oldForwarder.release) })
	defer releaseWrite()
	ready := make(chan struct{})
	close(ready)
	proxy.sessions[key] = &udpSession{
		key: key, ready: ready, forwarder: oldForwarder, lastSeen: time.Now(),
		clientAddr: clientAddr, tokenIP: tokenIP, destAddr: destAddr,
	}

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		proxy.handlePacket(clientAddr, tokenIP, []byte("old packet"))
	}()
	select {
	case <-oldForwarder.started:
	case <-time.After(2 * time.Second):
		t.Fatal("old handler never reached Write")
	}

	proxy.closeIdleSessions(time.Now().Add(udpSessionIdle + time.Second))
	replacement, err := proxy.getSession(clientAddr, tokenIP, destAddr)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-replacement.ready:
		if replacement.initErr != nil || replacement.forwarder == nil {
			t.Fatalf("replacement initialization: %v", replacement.initErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replacement session did not initialize")
	}

	releaseWrite()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("old handler did not finish")
	}
	proxy.mu.Lock()
	current := proxy.sessions[key]
	proxy.mu.Unlock()
	if current != replacement {
		t.Fatal("old write failure removed the replacement session")
	}
}

func TestUDPProxyRejectsSessionAfterClose(t *testing.T) {
	proxy := listenTestUDPProxy(t)
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	session, err := proxy.getSession(clientAddr, tokenToIP(loopbackStartToken), "127.0.0.1:9999")
	if session != nil {
		<-session.ready
		if session.forwarder != nil {
			_ = session.forwarder.Close()
		}
		t.Fatal("getSession created a forwarder after Close")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("getSession after Close = %v, want net.ErrClosed", err)
	}
}

func listenTestUDPProxy(t *testing.T) *UDPProxy {
	t.Helper()
	l, err := NewLocal(":0", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetSelectMode("direct"); err != nil {
		t.Fatal(err)
	}
	proxy, _, err := l.ListenUDPProxy()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func TestUDPProxyUsesNewSessionWhenTokenIsReassigned(t *testing.T) {
	proxy := listenTestUDPProxy(t)
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	tokenIP := tokenToIP(loopbackStartToken)
	first, err := proxy.getSession(clientAddr, tokenIP, "127.0.0.1:9998")
	if err != nil {
		t.Fatal(err)
	}
	second, err := proxy.getSession(clientAddr, tokenIP, "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("reassigned token reused a forwarder for the old destination")
	}
}

func TestUDPSessionKeyNormalizesIPv4(t *testing.T) {
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	token := tokenToIP(loopbackStartToken)
	const dest = "127.0.0.1:9999"
	mapped := makeUDPSessionKey(client, token, dest)
	client.IP = client.IP.To4()
	if makeUDPSessionKey(client, token, dest) != mapped {
		t.Fatal("IPv4 representations produced different session keys")
	}
}
