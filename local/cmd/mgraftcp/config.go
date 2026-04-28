package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hmgle/graftcp/local"
	"github.com/jedisct1/dlog"
	"github.com/pborman/getopt/v2"
)

type appConfig struct {
	httpProxyAddr   string
	selectProxyMode string
	socks5Addr      string
	socks5User      string
	socks5Pwd       string
	configFile      string
	dnsProxy        bool
	disableDNS      bool
	dnsServer       string
	udpProxy        bool
	disableUDP      bool

	blackIPFile    string
	whiteIPFile    string
	userName       string
	notIgnoreLocal bool
	enableDebugLog bool

	help        bool
	showVersion bool
}

func defaultConfig() appConfig {
	return appConfig{
		selectProxyMode: "auto",
		socks5Addr:      "127.0.0.1:1080",
		dnsServer:       "1.1.1.1:53",
	}
}

func (c *appConfig) registerFlags() {
	getopt.FlagLong(&c.httpProxyAddr, "http_proxy", 0, "http proxy address, e.g.: 127.0.0.1:8080")
	getopt.FlagLong(&c.selectProxyMode, "select_proxy_mode", 0, "Set the mode for select a proxy [auto | random | only_http_proxy | only_socks5 | direct]")
	getopt.FlagLong(&c.socks5Addr, "socks5", 0, "SOCKS5 address")
	getopt.FlagLong(&c.socks5User, "socks5_username", 0, "SOCKS5 username")
	getopt.FlagLong(&c.socks5Pwd, "socks5_password", 0, "SOCKS5 password")
	getopt.FlagLong(&c.dnsProxy, "enable-dns", 0, "Enable DNS proxy for UDP/53 queries")
	getopt.FlagLong(&c.disableDNS, "disable-dns", 0, "Disable DNS proxy")
	getopt.FlagLong(&c.dnsServer, "dns-server", 0, "DNS upstream server address, e.g.: 1.1.1.1:53")
	getopt.FlagLong(&c.udpProxy, "enable-udp", 0, "Enable generic UDP proxy")
	getopt.FlagLong(&c.disableUDP, "disable-udp", 0, "Disable generic UDP proxy")
	getopt.FlagLong(&c.enableDebugLog, "enable-debug-log", 0, "Enable debug log")
	getopt.FlagLong(&c.configFile, "config", 0, "Path to the configuration file")

	getopt.FlagLong(&c.blackIPFile, "blackip-file", 'b', "The IP in black-ip-file will connect direct")
	getopt.FlagLong(&c.whiteIPFile, "whiteip-file", 'w', "Only redirect the connect that destination ip in the white-ip-file to SOCKS5")
	getopt.FlagLong(&c.notIgnoreLocal, "not-ignore-local", 'n', "Connecting to local is not changed by default, this option will redirect it to SOCKS5")
	getopt.FlagLong(&c.userName, "username", 'u', "Run command as USERNAME handling setuid and/or setgid")
	getopt.FlagLong(&c.help, "help", 'h', "Display this help and exit")
	getopt.FlagLong(&c.showVersion, "version", 0, "Print the mgraftcp version information")
}

func (c *appConfig) set(key, val string) {
	switch strings.ToLower(key) {
	case "socks5":
		c.socks5Addr = val
	case "socks5_username":
		c.socks5User = val
	case "socks5_password":
		c.socks5Pwd = val
	case "http_proxy":
		c.httpProxyAddr = val
	case "select_proxy_mode":
		c.selectProxyMode = val
	case "dns_proxy", "enable_dns":
		c.dnsProxy = parseBool(val, false)
	case "dns_server", "dns-server":
		c.dnsServer = val
	case "udp_proxy", "enable_udp":
		c.udpProxy = parseBool(val, false)
	case "blackip_file_path", "blackip-file":
		c.blackIPFile = val
	case "whiteip_file_path", "whiteip-file":
		c.whiteIPFile = val
	case "username":
		c.userName = val
	case "ignore_local":
		c.notIgnoreLocal = !parseBool(val, true)
	case "not_ignore_local", "not-ignore-local":
		c.notIgnoreLocal = parseBool(val, false)
	}
}

func parseBool(val string, defaultValue bool) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func configKeyOverriddenByFlag(flagset map[string]bool, key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if flagset[key] {
		return true
	}

	switch key {
	case "blackip_file_path":
		return flagset["blackip-file"]
	case "whiteip_file_path":
		return flagset["whiteip-file"]
	case "ignore_local", "not_ignore_local":
		return flagset["not-ignore-local"]
	case "dns_proxy", "enable_dns":
		return flagset["enable-dns"] || flagset["disable-dns"]
	case "dns_server":
		return flagset["dns-server"]
	case "udp_proxy", "enable_udp":
		return flagset["enable-udp"] || flagset["disable-udp"]
	default:
		return false
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

func (c *appConfig) parseConfigFile(path string) error {
	if path == "" {
		exePath := local.GetExePath()
		defaultConf := filepath.Dir(exePath) + "/mgraftcp.conf"
		if _, err := os.Stat(defaultConf); err == nil {
			if c.enableDebugLog {
				dlog.Infof("find config: %s", defaultConf)
			}
			path = defaultConf
			goto loadConf
		}

		var dotConf string
		if xdgConfPath := os.Getenv("XDG_CONFIG_HOME"); xdgConfPath != "" {
			dotConf = filepath.Join(xdgConfPath, "mgraftcp", "mgraftcp.conf")
		} else if homeDir, err := os.UserHomeDir(); err == nil {
			dotConf = filepath.Join(homeDir, ".config", "mgraftcp", "mgraftcp.conf")
		}
		if _, err := os.Stat(dotConf); err == nil {
			if c.enableDebugLog {
				dlog.Infof("find config: %s", dotConf)
			}
			path = dotConf
			goto loadConf
		}

		etcConf := "/etc/mgraftcp/mgraftcp.conf"
		if _, err := os.Stat(etcConf); err == nil {
			if c.enableDebugLog {
				dlog.Infof("find config: %s", etcConf)
			}
			path = etcConf
		} else {
			return nil
		}
	}

loadConf:
	file, err := os.Open(path)
	if err != nil {
		if c.enableDebugLog {
			dlog.Errorf("os.Open(%s) err: %s", path, err.Error())
		}
		return err
	}
	defer file.Close()

	flagset := make(map[string]bool)
	getopt.Getopt(func(opt getopt.Option) bool {
		flagset[opt.LongName()] = true
		return true
	})
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if k, v := parseLine(line); !configKeyOverriddenByFlag(flagset, k) {
					c.set(k, v)
				}
				break
			}
			if c.enableDebugLog {
				dlog.Errorf("reader.ReadString('\\n') err: %s, path: %s", err.Error(), path)
			}
			return err
		}
		if k, v := parseLine(line); !configKeyOverriddenByFlag(flagset, k) {
			c.set(k, v)
		}
	}

	return nil
}

func (c appConfig) clientArgs(port int, dnsPort int, udpPort int, args []string) []string {
	fixArgs := []string{os.Args[0], "-p", strconv.Itoa(port)}
	if c.dnsProxy {
		fixArgs = append(fixArgs, "--dns-port", strconv.Itoa(dnsPort))
	}
	if c.udpProxy {
		fixArgs = append(fixArgs, "--udp-port", strconv.Itoa(udpPort))
	}
	if c.blackIPFile != "" {
		fixArgs = append(fixArgs, "-b", c.blackIPFile)
	}
	if c.whiteIPFile != "" {
		fixArgs = append(fixArgs, "-w", c.whiteIPFile)
	}
	if c.userName != "" {
		fixArgs = append(fixArgs, "-u", c.userName)
	}
	if c.notIgnoreLocal {
		fixArgs = append(fixArgs, "-n")
	}
	return append(fixArgs, args...)
}
