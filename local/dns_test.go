package local

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestDNSProxyForwardsUDPQueryOverTCP(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00}
	response := []byte{0x12, 0x34, 0x81, 0x80}

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstream.Close()

	gotQuery := make(chan []byte, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		gotQuery <- payload

		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(response)))
		_, _ = conn.Write(lenBuf[:])
		_, _ = conn.Write(response)
	}()

	l, err := NewLocal(":0", "", "", "", "")
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if err := l.SetSelectMode("direct"); err != nil {
		t.Fatalf("SetSelectMode() error = %v", err)
	}

	proxy, port, err := l.StartDNSProxy(upstream.Addr().String())
	if err != nil {
		t.Fatalf("StartDNSProxy() error = %v", err)
	}
	defer proxy.Close()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer client.Close()

	if _, err := client.Write(query); err != nil {
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
	if string(buf[:n]) != string(response) {
		t.Fatalf("DNS response = %v, want %v", buf[:n], response)
	}

	select {
	case got := <-gotQuery:
		if string(got) != string(query) {
			t.Fatalf("upstream query = %v, want %v", got, query)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive query")
	}
}

func TestStartDNSProxyRejectsInvalidUpstream(t *testing.T) {
	l, err := NewLocal(":0", "", "", "", "")
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if _, _, err := l.StartDNSProxy("1.1.1.1"); err == nil {
		t.Fatal("StartDNSProxy() accepted upstream without port")
	}
}
