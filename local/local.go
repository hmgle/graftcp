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

type Local struct {
	faddr *net.TCPAddr // Frontend address: graftcp-local address
	baddr *net.TCPAddr // Backend address: socks5 address
}

func NewLocal(faddr, baddr string) *Local {
	a1, err := net.ResolveTCPAddr("tcp", faddr)
	if err != nil {
		log.Fatalf("resolve frontend(%s) error: %s\n", faddr, err.Error())
	}
	a2, err := net.ResolveTCPAddr("tcp", baddr)
	if err != nil {
		log.Fatalf("resolve backend(%s) error: %s\n", baddr, err.Error())
	}
	return &Local{
		faddr: a1,
		baddr: a2,
	}
}

func (l *Local) Start() {
	ln, err := net.ListenTCP("tcp", l.faddr)
	if err != nil {
		log.Fatalf("net.ListenTCP(%s) err: %s\n", l.faddr.String(), err.Error())
	}
	defer ln.Close()

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept err:", err)
			continue
		}
		go l.HandleConn(conn)
	}
}

func getPidByAddr(localAddr string) (pid string, destAddr string) {
	inode, err := getInodeByAddrs(localAddr, ListenAddr)
	if err != nil {
		log.Printf("getInodeByAddrs(%s, %s) err: %s\n", localAddr, ListenAddr, err.Error())
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

func (l *Local) HandleConn(conn net.Conn) error {
	raddr := conn.RemoteAddr()
	pid, addr := getPidByAddr(raddr.String())
	if pid == "" || addr == "" {
		return fmt.Errorf("can't find the pid and addr for %s", raddr.String())
	}

	dialer, err := proxy.SOCKS5("tcp", l.baddr.String(), nil, proxy.Direct)
	if err != nil {
		log.Printf("proxy.SOCKS5(\"tcp\", %s,...) err: %v\n", l.baddr, err)
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

func updateProcessAddrInfo() {
	r := bufio.NewReader(FifoFd)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			log.Printf("r.ReadLine err: %v\n", err)
			break
		}
		// dest_ipaddr:dest_port:pid
		s := strings.Split(string(line), ":")
		if len(s) != 3 {
			log.Println("r.ReadLine() :", string(line))
			continue
		}
		StorePidAddr(s[2], s[0]+":"+s[1])
	}
}

var (
	ListenAddr string
	Socks5Addr string
	FifoFd     *os.File
)

func main() {
	var (
		pipePath string
		err      error
	)
	flag.StringVar(&ListenAddr, "listen", ":2233", "Listen address")
	flag.StringVar(&Socks5Addr, "socks5", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.StringVar(&pipePath, "pipepath", "/tmp/graftcplocal.fifo", "Pipe path for graftcp to send address info")
	flag.Parse()

	syscall.Mkfifo(pipePath, uint32(os.ModePerm))
	FifoFd, err = os.OpenFile(pipePath, os.O_RDWR, 0)
	if err != nil {
		log.Fatal(err)
	}
	go updateProcessAddrInfo()

	l := NewLocal(ListenAddr, Socks5Addr)
	l.Start()
}

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}
