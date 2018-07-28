package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jedisct1/dlog"
)

type Config struct {
	Listen    string // Listen address
	Logfile   string // Write logs to file
	Loglevel  int    // Log level (0-6)
	PipePath  string // Pipe path for graftcp to send address info
	Socks5    string // SOCKS5 address
	UseSyslog bool   // Use the system logger
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
	case "usesyslog":
		if strings.ToLower(val) == "true" {
			Cfg.UseSyslog = true
		} else {
			Cfg.UseSyslog = false
		}
	}
}

func parseLine(line string) (key, val string) {
	items := strings.SplitN(line, "=", 2)
	if len(items) < 2 {
		return "", ""
	}
	return strings.TrimSpace(items[0]), strings.TrimSpace(items[1])
}

func ParseConfigFile(path string) error {
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
	overrideConfig()
	return nil
}

func overrideConfig() {
	flagset := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })
	if !flagset["listen"] && Cfg.Listen != "" {
		ListenAddr = Cfg.Listen
	}
	if !flagset["socks5"] && Cfg.Socks5 != "" {
		Socks5Addr = Cfg.Socks5
	}
	if !flagset["pipepath"] && Cfg.PipePath != "" {
		PipePath = Cfg.PipePath
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
}
