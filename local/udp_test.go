package local

import (
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestUDPProxyForwardsDirectDatagram(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP upstream error = %v", err)
	}
	defer upstream.Close()

	gotPayload := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := upstream.ReadFromUDP(buf)
		if err != nil {
			return
		}
		gotPayload <- string(buf[:n])
		_, _ = upstream.WriteToUDP([]byte(strings.ToUpper(string(buf[:n]))), addr)
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

	token, err := l.UDPRegistry().Register(syscall.AF_INET, "127.0.0.1", uint16(upstream.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatalf("UDP Register() error = %v", err)
	}
	tokenIP := tokenToIP(token)
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: tokenIP, Port: port})
	if err != nil {
		t.Fatalf("DialUDP token error = %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client.Write() error = %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client.Read() error = %v", err)
	}
	if got, want := string(buf[:n]), "HELLO"; got != want {
		t.Fatalf("client response = %q, want %q", got, want)
	}

	select {
	case got := <-gotPayload:
		if got != "hello" {
			t.Fatalf("upstream payload = %q, want %q", got, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive UDP payload")
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
