package local

import (
	"net"
	"strings"
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
