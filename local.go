package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"syscall"

	"golang.org/x/net/proxy"
)

var (
	fifoPath = flag.String("fifo", "/tmp/tcptrace.fifo", "fifo path")
)

var (
	fifoFd *os.File
	bio    *bufio.Reader
	fifoCh = make(chan string)
)

type Local struct {
	faddr, baddr *net.TCPAddr
}

func initFifo() {
	os.Remove(*fifoPath)
	err := syscall.Mkfifo(*fifoPath, 0666)
	if err != nil {
		log.Fatal(err)
	}
	fifoFd, err = os.Open(*fifoPath)
	if err != nil {
		log.Fatal(err)
	}
	bio = bufio.NewReader(fifoFd)
	for {
		line, _, err := bio.ReadLine()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("line: %s\n", string(line))
		fifoCh <- string(line)
	}
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
	dialer, err := proxy.SOCKS5("tcp", s.baddr.String(), nil, proxy.Direct)
	if err != nil {
		log.Printf("proxy.SOCKS5(\"tcp\", %s,...) err: %v\n", s.baddr, err)
		return err
	}

	destAddr := <-fifoCh
	log.Printf("destAddr: %s\n", destAddr)
	socks5Conn, err := dialer.Dial("tcp", destAddr)
	go pipe(conn, socks5Conn)
	go pipe(socks5Conn, conn)
	return nil
}

func pipe(dst, src net.Conn) {
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

	go initFifo()
	l := newLocal(faddr, baddr)
	l.start()
}

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}
