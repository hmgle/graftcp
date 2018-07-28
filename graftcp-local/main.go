package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"

	"golang.org/x/net/proxy"
)

type Local struct {
	faddr *net.TCPAddr // Frontend address: graftcp-local address
	baddr *net.TCPAddr // Backend address: socks5 address

	faddrString string
	baddrString string

	fifoFd *os.File
}

func NewLocal(listenAddr, socks5Addr string) *Local {
	a1, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		dlog.Fatalf("resolve frontend(%s) error: %s", listenAddr, err.Error())
	}
	a2, err := net.ResolveTCPAddr("tcp", socks5Addr)
	if err != nil {
		dlog.Fatalf("resolve backend(%s) error: %s", socks5Addr, err.Error())
	}
	return &Local{
		faddr:       a1,
		baddr:       a2,
		faddrString: listenAddr,
		baddrString: socks5Addr,
	}
}

func (l *Local) Start() {
	ln, err := net.ListenTCP("tcp", l.faddr)
	if err != nil {
		dlog.Fatalf("net.ListenTCP(%s) err: %s", l.faddr.String(), err.Error())
	}
	defer ln.Close()
	dlog.Infof("graft-local start listening %s...", l.faddr.String())

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			dlog.Errorf("accept err: %s", err.Error())
			continue
		}
		go l.HandleConn(conn)
	}
}

func (l *Local) getPidByAddr(localAddr string) (pid string, destAddr string) {
	inode, err := getInodeByAddrs(localAddr, l.faddrString)
	if err != nil {
		dlog.Errorf("getInodeByAddrs(%s, %s) err: %s", localAddr, l.faddrString, err.Error())
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
	pid, addr := l.getPidByAddr(raddr.String())
	if pid == "" || addr == "" {
		dlog.Errorf("getPidByAddr(%s) failed", raddr.String())
		return fmt.Errorf("can't find the pid and addr for %s", raddr.String())
	}
	dlog.Infof("Request PID: %s, Source Addr: %s, Dest Addr: %s", pid, raddr.String(), addr)

	dialer, err := proxy.SOCKS5("tcp", l.baddr.String(), nil, proxy.Direct)
	if err != nil {
		dlog.Errorf("proxy.SOCKS5(\"tcp\", %s,...) err: %s", l.baddr, err.Error())
		return err
	}
	socks5Conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		dlog.Errorf("dialer.Dial(%s) err: %s", addr, err.Error())
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
			dlog.Errorf("io.Copy err: %s", err.Error())
			return
		}
		if n == 0 {
			return
		}
	}
}

func (l *Local) updateProcessAddrInfo() {
	r := bufio.NewReader(l.fifoFd)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			dlog.Errorf("r.ReadLine err: %s", err.Error())
			break
		}
		// dest_ipaddr:dest_port:pid
		s := strings.Split(string(line), ":")
		if len(s) != 3 {
			dlog.Errorf("r.ReadLine(): %d", string(line))
			continue
		}
		StorePidAddr(s[2], s[0]+":"+s[1])
	}
}

type App struct {
	ListenAddr string
	Socks5Addr string
	PipePath   string
}

func (app *App) Start(s service.Service) error {
	if s != nil {
		go func() {
			app.run()
		}()
	} else {
		app.run()
	}
	return nil
}

func (app *App) run() {
	var err error

	l := NewLocal(app.ListenAddr, app.Socks5Addr)

	syscall.Mkfifo(app.PipePath, uint32(os.ModePerm))
	l.fifoFd, err = os.OpenFile(app.PipePath, os.O_RDWR, 0)
	if err != nil {
		dlog.Fatalf("os.OpenFile(%s) err: %s", app.PipePath, err.Error())
	}

	go l.updateProcessAddrInfo()
	l.Start()
}

func (app *App) Stop(s service.Service) error {
	return nil
}

func main() {
	var (
		err        error
		configFile string
	)
	dlog.Init("graftcp-local", dlog.SeverityInfo, "")

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}
	svcConfig := &service.Config{
		Name:             "graftcp-local",
		DisplayName:      "graftcp local service",
		Description:      "Translate graftcp TCP to SOCKS5",
		WorkingDirectory: pwd,
	}
	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	app := &App{}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}

	flag.StringVar(&app.ListenAddr, "listen", ":2233", "Listen address")
	flag.StringVar(&app.Socks5Addr, "socks5", "127.0.0.1:1080", "SOCKS5 address")
	flag.StringVar(&configFile, "config", "", "Path to the configuration file")
	flag.StringVar(&app.PipePath, "pipepath", "/tmp/graftcplocal.fifo", "Pipe path for graftcp to send address info")
	flag.Parse()
	if configFile != "" {
		ParseConfigFile(configFile, app)
	}

	dlog.Noticef("graftcp-local")
	if *svcFlag != "" {
		if svc == nil {
			dlog.Fatal("Built-in service installation is not supported on this platform")
		}
		if err := service.Control(svc, *svcFlag); err != nil {
			dlog.Fatal(err)
		}
		if *svcFlag == "install" {
			dlog.Notice("Installed as a service. Use `-service start` to start")
		} else if *svcFlag == "uninstall" {
			dlog.Notice("Service uninstalled")
		} else if *svcFlag == "start" {
			dlog.Notice("Service started")
		} else if *svcFlag == "stop" {
			dlog.Notice("Service stopped")
		} else if *svcFlag == "restart" {
			dlog.Notice("Service restarted")
		}
		return
	}
	if svc != nil {
		err = svc.Run()
		if err != nil {
			dlog.Fatal(err)
		}
	} else {
		app.Start(nil)
	}

	/*
		syscall.Mkfifo(PipePath, uint32(os.ModePerm))
		FifoFd, err = os.OpenFile(PipePath, os.O_RDWR, 0)
		if err != nil {
			dlog.Fatalf("os.OpenFile(%s) err: %s", PipePath, err.Error())
		}
		go updateProcessAddrInfo()

		l := NewLocal(ListenAddr, Socks5Addr)
		l.Start()
	*/
}
