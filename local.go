package main

import (
	"flag"
	"io"
	"log"
	"net"

	"golang.org/x/net/proxy"
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
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
	if err != nil {
		return err
	}

	// TODO: dial dest addr
	socks5Conn, err := dialer.Dial("tcp", "127.0.0.1:2333")
	go pipe(conn, socks5Conn)
	go pipe(socks5Conn, conn)
	return nil
}

func pipe(dst, src net.Conn) {
	buf := make([]byte, 10)
	src.Read(buf)
	for {
		n, err := io.Copy(dst, src)
		log.Println("io.Copy : ", n)
		if err != nil {
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
