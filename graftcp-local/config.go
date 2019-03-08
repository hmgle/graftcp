package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jedisct1/dlog"
)

type Config struct {
	Listen          string // Listen address
	Logfile         string // Write logs to file
	Loglevel        int    // Log level (0-6)
	PipePath        string // Pipe path for graftcp to send address info
	Socks5          string // SOCKS5 address
	HttpProxy       string // HTTP proxy address
	UseSyslog       bool   // Use the system logger
	SelectProxyMode string // Set the mode for select a proxy (auto, random, only_http_proxy, only_socks5)
}

var Cfg = &Config{Loglevel: -1}

func setCfg(key, val string) {
	switch strings.ToLower(key) {
	case "listen":
		Cfg.Listen = val
	case "logfile":
		Cfg.Logfile = val
	case "loglevel":
		loglevel, err := strconv.Atoi(val)
		if err == nil {
			Cfg.Loglevel = loglevel
		}
	case "pipepath":
		Cfg.PipePath = val
	case "socks5":
		Cfg.Socks5 = val
	case "http_proxy":
		Cfg.HttpProxy = val
	case "usesyslog":
		if strings.ToLower(val) == "true" {
			Cfg.UseSyslog = true
		} else {
			Cfg.UseSyslog = false
		}
	case "select_proxy_mode":
		Cfg.SelectProxyMode = val
	}
}

func parseLine(line string) (key, val string) {
	items := strings.SplitN(line, "=", 2)
	if len(items) < 2 {
		return "", ""
	}
	return strings.TrimSpace(items[0]), strings.TrimSpace(items[1])
}

func ParseConfigFile(path string, app *App) error {
	if path == "" {
		// try default config file "graftcp-local.conf"
		exePath := GetExePath()
		defaultConf := filepath.Dir(exePath) + "/graftcp-local.conf"
		if _, err := os.Stat(defaultConf); err == nil {
			dlog.Infof("find config: %s", defaultConf)
			path = defaultConf
		} else {
			return nil
		}
	}

	file, err := os.Open(path)
	if err != nil {
		dlog.Errorf("os.Open(%s) err: %s", path, err.Error())
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				setCfg(parseLine(line))
				break
			}
			dlog.Errorf("reader.ReadString('\\n') err: %s, path: %s", err.Error, path)
			return err
		}
		setCfg(parseLine(line))
	}
	overrideConfig(app)
	return nil
}

func overrideConfig(app *App) {
	flagset := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })
	if !flagset["listen"] && Cfg.Listen != "" {
		app.ListenAddr = Cfg.Listen
	}
	if !flagset["socks5"] && Cfg.Socks5 != "" {
		app.Socks5Addr = Cfg.Socks5
	}
	if !flagset["http_proxy"] && Cfg.HttpProxy != "" {
		app.HttpProxyAddr = Cfg.HttpProxy
	}
	if !flagset["pipepath"] && Cfg.PipePath != "" {
		app.PipePath = Cfg.PipePath
	}
	if !flagset["logfile"] && Cfg.Logfile != "" {
		dlog.UseLogFile(Cfg.Logfile)
	}
	if !flagset["loglevel"] && Cfg.Loglevel >= 0 && Cfg.Loglevel <= 6 {
		dlog.SetLogLevel(dlog.Severity(Cfg.Loglevel))
	}
	if !flagset["syslog"] {
		dlog.UseSyslog(Cfg.UseSyslog)
	}
	if !flagset["select_proxy_mode"] && Cfg.SelectProxyMode != "" {
		selectProxyMode = Cfg.SelectProxyMode
	}
}
