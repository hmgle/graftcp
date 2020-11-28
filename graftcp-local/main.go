package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
)

var selectProxyMode string

type App struct {
	ListenAddr     string
	Socks5Addr     string
	Socks5Username string
	Socks5Password string
	HTTPProxyAddr  string
	PipePath       string
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

	l := NewLocal(app.ListenAddr, app.Socks5Addr, app.Socks5Username, app.Socks5Password, app.HTTPProxyAddr)
	dlog.Infof("select_proxy_mode: %s", selectProxyMode)
	l.SetSelectMode(selectProxyMode)

	syscall.Mkfifo(app.PipePath, uint32(os.ModePerm))
	os.Chmod(app.PipePath, 0666)
	l.FifoFd, err = os.OpenFile(app.PipePath, os.O_RDWR, 0)
	if err != nil {
		dlog.Fatalf("os.OpenFile(%s) err: %s", app.PipePath, err.Error())
	}

	go l.UpdateProcessAddrInfo()
	l.Start()
}

func (app *App) Stop(s service.Service) error {
	dlog.Noticef("graftcp-local stop")
	return nil
}

func main() {
	var configFile string
	dlog.Init("graftcp-local", dlog.SeverityInfo, "")

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}
	svcConfig := &service.Config{
		Name:             "graftcp-local",
		DisplayName:      "graftcp local service",
		Description:      "Translate graftcp TCP to SOCKS5 or HTTP proxy",
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
	flag.StringVar(&app.Socks5Username, "socks5_username", "", "SOCKS5 username")
	flag.StringVar(&app.Socks5Password, "socks5_password", "", "SOCKS5 password")
	flag.StringVar(&app.HTTPProxyAddr, "http_proxy", "", "http proxy address, e.g.: 127.0.0.1:8080")
	flag.StringVar(&selectProxyMode, "select_proxy_mode", "auto",
		"Set the mode for select a proxy [auto | random | only_http_proxy | only_socks5]")
	flag.StringVar(&configFile, "config", "", "Path to the configuration file")
	flag.StringVar(&app.PipePath, "pipepath", "/tmp/graftcplocal.fifo", "Pipe path for graftcp to send address info")
	flag.Parse()
	ParseConfigFile(configFile, app)
	dlog.Noticef("graftcp-local start")

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
}
