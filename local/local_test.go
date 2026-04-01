package local

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	acceptCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conn
	}()

	clientConn, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}

	select {
	case serverConn := <-acceptCh:
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})
		return clientConn, serverConn
	case err := <-errCh:
		_ = clientConn.Close()
		t.Fatalf("AcceptTCP: %v", err)
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		t.Fatal("timed out waiting for AcceptTCP")
	}

	return nil, nil
}

func TestPipeKeepsDestinationReadableAfterSourceHalfClose(t *testing.T) {
	dstConn, dstPeer := tcpPair(t)
	srcConn, srcPeer := tcpPair(t)

	done := make(chan int64, 1)
	go pipe(dstConn, srcConn, done)

	forwarded := []byte("hello")
	if _, err := srcPeer.Write(forwarded); err != nil {
		t.Fatalf("srcPeer.Write: %v", err)
	}
	if err := srcPeer.CloseWrite(); err != nil {
		t.Fatalf("srcPeer.CloseWrite: %v", err)
	}

	if err := dstPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("dstPeer.SetReadDeadline: %v", err)
	}
	gotForwarded := make([]byte, len(forwarded))
	if _, err := io.ReadFull(dstPeer, gotForwarded); err != nil {
		t.Fatalf("dstPeer.ReadFull: %v", err)
	}
	if !bytes.Equal(gotForwarded, forwarded) {
		t.Fatalf("forwarded bytes mismatch: got %q want %q", gotForwarded, forwarded)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not finish after source half-close")
	}

	reverse := []byte("world")
	if _, err := dstPeer.Write(reverse); err != nil {
		t.Fatalf("dstPeer.Write: %v", err)
	}

	readResult := make(chan error, 1)
	go func() {
		buf := make([]byte, len(reverse))
		if _, err := io.ReadFull(dstConn, buf); err != nil {
			readResult <- err
			return
		}
		if !bytes.Equal(buf, reverse) {
			readResult <- fmt.Errorf("reverse bytes mismatch: got %q want %q", buf, reverse)
			return
		}
		readResult <- nil
	}()

	select {
	case err := <-readResult:
		if err != nil {
			t.Fatalf("reverse read failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading reverse bytes after source half-close")
	}
}
