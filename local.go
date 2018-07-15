package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

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

func getPidByAddr(addr string) (pid string, destAddr string) {
	log.Printf("addr: %s\n", addr)
	addrSplit := strings.Split(addr, ":")
	if len(addrSplit) != 2 {
		return "", ""
	}
	port := addrSplit[1]
	log.Printf("port: %s\n", port)
	// lsof -i :1234 |awk 'NR > 1 {print $2}'
	cmd := fmt.Sprintf("lsof -i :%s | awk 'NR > 1 {print $2}'", port)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		log.Println(err)
		return "", ""
	}
	log.Println("out: ", string(out))
	pids := strings.Split(string(out), "\n")
	for _, pid := range pids {
		if addr, ok := ProcessPortMap[pid]; ok {
			return pid, addr
		}
	}
	return "", ""
}

func (s *Local) handleConn(conn net.Conn) error {
	raddr := conn.RemoteAddr()
	pid, addr := getPidByAddr(raddr.String())
	log.Println("pid: ", pid, "\naddr: ", addr)

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

var (
	// map[pid]dest-ip-info
	ProcessPortMap = make(map[string]string)
)

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
		ProcessPortMap[s[2]] = s[0] + ":" + s[1]
	}
}

func main() {
	var (
		faddr, baddr string
		pipePath     string
		err          error
	)
	flag.StringVar(&faddr, "listen", ":2080", "host:port listen on")
	flag.StringVar(&baddr, "backend", "127.0.0.1:1080", "host:port of backend")
	flag.StringVar(&pipePath, "pipepath", "/tmp/graftcplocal.fifo", "pipe path")
	flag.Parse()

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
