package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/net/proxy"
)

var (
	fifoFd *os.File
	bio    *bufio.Reader
)

type Local struct {
	faddr, baddr *net.TCPAddr
}

func newLocal(faddr, baddr string) *Local {
	a1, err := net.ResolveTCPAddr("tcp", faddr)
	if err != nil {
		log.Fatalln("resolve frontend error:", err)
	}
	a2, err := net.ResolveTCPAddr("tcp", baddr)
	if err != nil {
		log.Fatalln("resolve backend error:", err)
	}
	return &Local{
		faddr: a1,
		baddr: a2,
	}
}

func (s *Local) start() {
	ln, err := net.ListenTCP("tcp", s.faddr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Local) handleConn(conn net.Conn) error {
	buf := make([]byte, 4096)
	_, err := io.ReadFull(conn, buf[:8])
	if err != nil {
		log.Println("io.ReadFull() err: ", err)
		return err
	}
	magicNum := binary.BigEndian.Uint32(buf[:4])
	if magicNum != 3579 {
		log.Printf("magicNum: %d\n", magicNum)
		return fmt.Errorf("magicNum:%d != %d", magicNum, 3579)
	}
	addInfoLen := binary.BigEndian.Uint32(buf[4:8])
	if addInfoLen < 1 || addInfoLen > 4096 {
		log.Println("addInfoLen: ", addInfoLen)
		return fmt.Errorf("addInfoLen: %d", addInfoLen)
	}
	_, err = io.ReadFull(conn, buf[:addInfoLen])
	if err != nil {
		log.Println("io.ReadFull() err: ", err)
		return err
	}
	dialer, err := proxy.SOCKS5("tcp", s.baddr.String(), nil, proxy.Direct)
	if err != nil {
		log.Printf("proxy.SOCKS5(\"tcp\", %s,...) err: %v\n", s.baddr, err)
		return err
	}
	destAddr := string(buf[:addInfoLen])
	log.Printf("destAddr: %s\n", destAddr)
	socks5Conn, err := dialer.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("dialer.Dial(%s) err: %v\n", destAddr, err)
		return err
	}
	go pipe(conn, socks5Conn)
	go pipe(socks5Conn, conn)
	return nil
}

func pipe(dst, src net.Conn) {
	for {
		n, err := io.Copy(dst, src)
		if err != nil {
			log.Printf("io.Copy err: %s\n", err.Error())
			return
		}
		if n == 0 {
			return
		}
	}
}

func main() {
	var faddr, baddr string
	flag.StringVar(&faddr, "listen", ":2080", "host:port listen on")
	flag.StringVar(&baddr, "backend", "127.0.0.1:1080", "host:port of backend")
	flag.Parse()

	l := newLocal(faddr, baddr)
	l.start()
}

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}
