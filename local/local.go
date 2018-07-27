package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

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

func getPidByAddr(localAddr string) (pid string, destAddr string) {
	inode, err := getInodeByAddrs(localAddr, faddr)
	if err != nil {
		log.Printf("getInodeByAddrs(%s, %s) err: %s\n", localAddr, faddr, err.Error())
		return "", ""
	}
	RangePidAddr(func(p, a string) bool {
		if hasIncludeInode(p, inode) {
			pid = p
			destAddr = a
			return false
		}
		return true
	})
	if pid != "" {
		DeletePidAddr(pid)
	}
	return
}

func (s *Local) handleConn(conn net.Conn) error {
	raddr := conn.RemoteAddr()
	pid, addr := getPidByAddr(raddr.String())
	log.Println("pid: ", pid, "\naddr: ", addr)
	if pid == "" || addr == "" {
		return fmt.Errorf("can't find the pid and addr for %s", raddr.String())
	}

	dialer, err := proxy.SOCKS5("tcp", s.baddr.String(), nil, proxy.Direct)
	if err != nil {
		log.Printf("proxy.SOCKS5(\"tcp\", %s,...) err: %v\n", s.baddr, err)
		return err
	}
	socks5Conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("dialer.Dial(%s) err: %v\n", addr, err)
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

func updateProcessPortInfo() {
	r := bufio.NewReader(fifoFd)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			log.Fatal(err)
		}
		log.Println(string(line))
		// dest_ipaddr:dest_port:pid
		s := strings.Split(string(line), ":")
		if len(s) != 3 {
			log.Println("r.ReadLine() :", string(line))
			break
		}
		StorePidAddr(s[2], s[0]+":"+s[1])
	}
}

var faddr string

func main() {
	var (
		baddr    string
		pipePath string
		err      error
	)
	flag.StringVar(&faddr, "listen", ":2080", "host:port listen on")
	flag.StringVar(&baddr, "backend", "127.0.0.1:1080", "host:port of backend")
	flag.StringVar(&pipePath, "pipepath", "/tmp/graftcplocal.fifo", "pipe path")
	flag.Parse()

	syscall.Mkfifo(pipePath, uint32(os.ModePerm))
	fifoFd, err = os.OpenFile(pipePath, os.O_RDWR, 0)
	if err != nil {
		log.Fatal(err)
	}
	go updateProcessPortInfo()

	l := newLocal(faddr, baddr)
	l.start()
}

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}
