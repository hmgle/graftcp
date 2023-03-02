package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hmgle/graftcp/local"
	"github.com/jedisct1/dlog"
)

// Config for graftcp-local.
type Config struct {
	Listen          string // Listen address
	Logfile         string // Write logs to file
	Loglevel        int    // Log level (0-6)
	PipePath        string // Pipe path for graftcp to send address info
	Socks5          string // SOCKS5 address
	Socks5Username  string // SOCKS5 proxy username
	Socks5Password  string // SOCKS5 proxy password
	HTTPProxy       string // HTTP proxy address
	UseSyslog       bool   // Use the system logger
	SelectProxyMode string // Set the mode for select a proxy (auto, random, only_http_proxy, only_socks5)
}

var cfg = &Config{Loglevel: -1}

func setCfg(key, val string) {
	switch strings.ToLower(key) {
	case "listen":
		cfg.Listen = val
	case "logfile":
		cfg.Logfile = val
	case "loglevel":
		loglevel, err := strconv.Atoi(val)
		if err == nil {
			cfg.Loglevel = loglevel
		}
	case "pipepath":
		cfg.PipePath = val
	case "socks5":
		cfg.Socks5 = val
	case "socks5_username":
		cfg.Socks5Username = val
	case "socks5_password":
		cfg.Socks5Password = val
	case "http_proxy":
		cfg.HTTPProxy = val
	case "usesyslog":
		if strings.ToLower(val) == "true" {
			cfg.UseSyslog = true
		} else {
			cfg.UseSyslog = false
		}
	case "select_proxy_mode":
		cfg.SelectProxyMode = val
	}
}

func parseLine(line string) (key, val string) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") {
		return
	}
	items := strings.SplitN(line, "=", 2)
	if len(items) < 2 {
		return "", ""
	}
	return strings.TrimSpace(items[0]), strings.TrimSpace(items[1])
}

func parseConfigFile(path string, app *App) error {
	if path == "" {
		// try default config file "graftcp-local.conf"
		exePath := local.GetExePath()
		defaultConf := filepath.Dir(exePath) + "/graftcp-local.conf"
		if _, err := os.Stat(defaultConf); err == nil {
			dlog.Infof("find config: %s", defaultConf)
			path = defaultConf
			goto loadConf
		}
		// try $HOME/.graftcp-local/graftcp-local.conf
		if homeDir, err := os.UserHomeDir(); err == nil {
			dotConf := homeDir + "/.graftcp-local/graftcp-local.conf"
			if _, err = os.Stat(dotConf); err == nil {
				dlog.Infof("find config: %s", dotConf)
				path = dotConf
				goto loadConf
			}
		}
		// try "/etc/graftcp-local/graftcp-local.conf"
		etcConf := "/etc/graftcp-local/graftcp-local.conf"
		if _, err := os.Stat(etcConf); err == nil {
			dlog.Infof("find config: %s", etcConf)
			path = etcConf
		} else {
			return nil
		}
	}

loadConf:
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
			dlog.Errorf("reader.ReadString('\\n') err: %s, path: %s", err.Error(), path)
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
	if !flagset["listen"] && cfg.Listen != "" {
		app.ListenAddr = cfg.Listen
	}
	if !flagset["socks5"] && cfg.Socks5 != "" {
		app.Socks5Addr = cfg.Socks5
	}
	if !flagset["socks5_username"] && cfg.Socks5Username != "" {
		app.Socks5Username = cfg.Socks5Username
	}
	if !flagset["socks5_password"] && cfg.Socks5Password != "" {
		app.Socks5Password = cfg.Socks5Password
	}
	if !flagset["http_proxy"] && cfg.HTTPProxy != "" {
		app.HTTPProxyAddr = cfg.HTTPProxy
	}
	if !flagset["pipepath"] && cfg.PipePath != "" {
		app.PipePath = cfg.PipePath
	}
	if !flagset["logfile"] && cfg.Logfile != "" {
		dlog.UseLogFile(cfg.Logfile)
	}
	if !flagset["loglevel"] && cfg.Loglevel >= 0 && cfg.Loglevel <= 6 {
		dlog.SetLogLevel(dlog.Severity(cfg.Loglevel))
	}
	if !flagset["syslog"] {
		dlog.UseSyslog(cfg.UseSyslog)
	}
	if !flagset["select_proxy_mode"] && cfg.SelectProxyMode != "" {
		selectProxyMode = cfg.SelectProxyMode
	}
}
