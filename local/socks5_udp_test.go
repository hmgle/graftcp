package local

import (
	"bytes"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestUDPProxyForwardsThroughSocks5UDPAssociate(t *testing.T) {
	server := startFakeSocks5UDPServer(t, []byte("pong"))
	defer server.Close()

	l, err := NewLocal(":0", server.TCPAddr(), "", "", "")
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

	token, err := l.UDPRegistry().Register(syscall.AF_INET, "198.51.100.10", 9999)
	if err != nil {
		t.Fatalf("UDP Register() error = %v", err)
	}
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: tokenToIP(token), Port: port})
	if err != nil {
		t.Fatalf("DialUDP token error = %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("ping")); err != nil {
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
	if got, want := string(buf[:n]), "pong"; got != want {
		t.Fatalf("SOCKS5 UDP response = %q, want %q", got, want)
	}

	select {
	case got := <-server.payloads:
		if string(got) != "ping" {
			t.Fatalf("SOCKS5 relay payload = %q, want %q", got, "ping")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 relay did not receive payload")
	}
}

func TestEncodeSocks5UDPAssociateRequestUsesBindPort(t *testing.T) {
	req, err := encodeSocks5UDPAssociateRequest(&net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 12345,
	})
	if err != nil {
		t.Fatalf("encodeSocks5UDPAssociateRequest() error = %v", err)
	}
	want := []byte{
		socks5Version, socks5CmdUDP, 0x00,
		socks5AtypIPv4, 0, 0, 0, 0,
		0x30, 0x39,
	}
	if !bytes.Equal(req, want) {
		t.Fatalf("encodeSocks5UDPAssociateRequest() = %v, want %v", req, want)
	}
}

type fakeSocks5UDPServer struct {
	tcpLn    net.Listener
	udpConn  *net.UDPConn
	payloads chan []byte
	once     sync.Once
}

func startFakeSocks5UDPServer(t *testing.T, response []byte) *fakeSocks5UDPServer {
	t.Helper()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp error = %v", err)
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = tcpLn.Close()
		t.Fatalf("Listen udp error = %v", err)
	}
	server := &fakeSocks5UDPServer{
		tcpLn:    tcpLn,
		udpConn:  udpConn,
		payloads: make(chan []byte, 1),
	}
	go server.serveTCP(t, response)
	go server.serveUDP(t, response)
	return server
}

func (s *fakeSocks5UDPServer) TCPAddr() string {
	return s.tcpLn.Addr().String()
}

func (s *fakeSocks5UDPServer) Close() {
	s.once.Do(func() {
		_ = s.tcpLn.Close()
		_ = s.udpConn.Close()
	})
}

func (s *fakeSocks5UDPServer) serveTCP(t *testing.T, response []byte) {
	conn, err := s.tcpLn.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Errorf("read greeting header: %v", err)
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("read methods: %v", err)
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
		t.Errorf("write auth reply: %v", err)
		return
	}

	req := make([]byte, 10)
	if _, err := io.ReadFull(conn, req); err != nil {
		t.Errorf("read UDP associate request: %v", err)
		return
	}
	udpPort := s.udpConn.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{socks5Version, 0x00, 0x00, socks5AtypIPv4, 127, 0, 0, 1, byte(udpPort >> 8), byte(udpPort)}
	if _, err := conn.Write(reply); err != nil {
		t.Errorf("write UDP associate reply: %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, conn)
}

func (s *fakeSocks5UDPServer) serveUDP(t *testing.T, response []byte) {
	buf := make([]byte, 512)
	n, addr, err := s.udpConn.ReadFromUDP(buf)
	if err != nil {
		return
	}
	payload, err := parseSocks5UDPDatagram(buf[:n])
	if err != nil {
		t.Errorf("parse SOCKS5 UDP datagram: %v", err)
		return
	}
	s.payloads <- payload
	packet, err := encodeSocks5UDPDatagram(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 9999}, response)
	if err != nil {
		t.Errorf("encode SOCKS5 UDP datagram: %v", err)
		return
	}
	_, _ = s.udpConn.WriteToUDP(packet, addr)
}
