package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hmgle/graftcp/local"
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
	case "dns_proxy", "enable_dns", "enable-dns":
		setBoolField(&c.dnsProxy, val)
	case "dns_server", "dns-server":
		c.dnsServer = val
	case "udp_proxy", "enable_udp", "enable-udp":
		setBoolField(&c.udpProxy, val)
	case "blackip_file_path", "blackip-file":
		c.blackIPFile = val
	case "whiteip_file_path", "whiteip-file":
		c.whiteIPFile = val
	case "username":
		c.userName = val
	case "ignore_local":
		if b, ok := parseBool(val); ok {
			c.notIgnoreLocal = !b
		}
	case "not_ignore_local", "not-ignore-local":
		setBoolField(&c.notIgnoreLocal, val)
	}
}

// parseBool reports the boolean meaning of val and whether it was recognized.
func parseBool(val string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func setBoolField(dst *bool, val string) {
	if b, ok := parseBool(val); ok {
		*dst = b
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
		path = c.findDefaultConfigPath()
		if path == "" {
			return nil
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if c.enableDebugLog {
			appLogger.Errorf("os.Open(%s) err: %s", path, err.Error())
		}
		return err
	}
	defer file.Close()

	flagset := make(map[string]bool)
	getopt.Getopt(func(opt getopt.Option) bool {
		flagset[opt.LongName()] = true
		return true
	})

	sc := bufio.NewScanner(file)
	for sc.Scan() {
		k, v := parseLine(sc.Text())
		if k == "" || configKeyOverriddenByFlag(flagset, k) {
			continue
		}
		c.set(k, v)
	}
	if err := sc.Err(); err != nil {
		if c.enableDebugLog {
			appLogger.Errorf("scan config %s err: %s", path, err.Error())
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return nil
}

// findDefaultConfigPath searches the conventional locations for an mgraftcp
// configuration file and returns the first match, or "" when none exists.
func (c *appConfig) findDefaultConfigPath() string {
	candidates := []string{filepath.Join(filepath.Dir(local.GetExePath()), "mgraftcp.conf")}

	if xdgConfPath := os.Getenv("XDG_CONFIG_HOME"); xdgConfPath != "" {
		candidates = append(candidates, filepath.Join(xdgConfPath, "mgraftcp", "mgraftcp.conf"))
	} else if homeDir, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(homeDir, ".config", "mgraftcp", "mgraftcp.conf"))
	}
	candidates = append(candidates, "/etc/mgraftcp/mgraftcp.conf")

	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if c.enableDebugLog {
			appLogger.Infof("find config: %s", p)
		}
		return p
	}
	return ""
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
