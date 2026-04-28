package main

// #cgo LDFLAGS: -L../../.. -lgraftcp
//
// #include <stdlib.h>
//
// static char **alloc_string_slice(int len) {
//              return calloc(len, sizeof(char*));
// }
//
// int client_main(int argc, char **argv);
import "C"

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/hmgle/graftcp/local"
	"github.com/jedisct1/dlog"
	"github.com/pborman/getopt/v2"
)

func clientMain(args []string) int {
	argc := C.int(len(args))

	argv := (**C.char)(C.alloc_string_slice(argc + 1))
	if argv == nil {
		fmt.Fprintln(os.Stderr, "mgraftcp: failed to allocate argv")
		return 1
	}
	defer C.free(unsafe.Pointer(argv))

	argvSlice := unsafe.Slice(argv, len(args)+1)
	for i, arg := range args {
		argvSlice[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argvSlice[i]))
	}

	returnValue := C.client_main(argc, argv)
	return int(returnValue)
}

var (
	httpProxyAddr   string
	selectProxyMode string = "auto"
	socks5Addr      string = "127.0.0.1:1080"
	socks5User      string
	socks5Pwd       string
	configFile      string

	blackIPFile    string
	whiteIPFile    string
	userName       string
	notIgnoreLocal bool
	enableDebugLog bool

	help        bool
	showVersion bool

	version = "v0.7"
)

func init() {
	getopt.FlagLong(&httpProxyAddr, "http_proxy", 0, "http proxy address, e.g.: 127.0.0.1:8080")
	getopt.FlagLong(&selectProxyMode, "select_proxy_mode", 0, "Set the mode for select a proxy [auto | random | only_http_proxy | only_socks5 | direct]")
	getopt.FlagLong(&socks5Addr, "socks5", 0, "SOCKS5 address")
	getopt.FlagLong(&socks5User, "socks5_username", 0, "SOCKS5 username")
	getopt.FlagLong(&socks5Pwd, "socks5_password", 0, "SOCKS5 password")
	getopt.FlagLong(&enableDebugLog, "enable-debug-log", 0, "Enable debug log")
	getopt.FlagLong(&configFile, "config", 0, "Path to the configuration file")

	getopt.FlagLong(&blackIPFile, "blackip-file", 'b', "The IP in black-ip-file will connect direct")
	getopt.FlagLong(&whiteIPFile, "whiteip-file", 'w', "Only redirect the connect that destination ip in the white-ip-file to SOCKS5")
	getopt.FlagLong(&notIgnoreLocal, "not-ignore-local", 'n', "Connecting to local is not changed by default, this option will redirect it to SOCKS5")
	getopt.FlagLong(&userName, "username", 'u', "Run command as USERNAME handling setuid and/or setgid")
	getopt.FlagLong(&help, "help", 'h', "Display this help and exit")
	getopt.FlagLong(&showVersion, "version", 0, "Print the mgraftcp version information")
}

func setCfg(key, val string) {
	switch strings.ToLower(key) {
	case "socks5":
		socks5Addr = val
	case "socks5_username":
		socks5User = val
	case "socks5_password":
		socks5Pwd = val
	case "http_proxy":
		httpProxyAddr = val
	case "select_proxy_mode":
		selectProxyMode = val
	case "blackip_file_path", "blackip-file":
		blackIPFile = val
	case "whiteip_file_path", "whiteip-file":
		whiteIPFile = val
	case "username":
		userName = val
	case "ignore_local":
		notIgnoreLocal = !parseBool(val, true)
	case "not_ignore_local", "not-ignore-local":
		notIgnoreLocal = parseBool(val, false)
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

func parseConfigFile(path string) error {
	if path == "" {
		// try default config file "mgraftcp.conf"
		exePath := local.GetExePath()
		defaultConf := filepath.Dir(exePath) + "/mgraftcp.conf"
		if _, err := os.Stat(defaultConf); err == nil {
			if enableDebugLog {
				dlog.Infof("find config: %s", defaultConf)
			}
			path = defaultConf
			goto loadConf
		}
		// try $XDG_CONFIG_HOME/mgraftcp/mgraftcp.conf
		var dotConf string
		if xdgConfPath := os.Getenv("XDG_CONFIG_HOME"); xdgConfPath != "" {
			dotConf = filepath.Join(xdgConfPath, "mgraftcp", "mgraftcp.conf")
		} else if homeDir, err := os.UserHomeDir(); err == nil {
			dotConf = filepath.Join(homeDir, ".config", "mgraftcp", "mgraftcp.conf")
		}
		if _, err := os.Stat(dotConf); err == nil {
			dlog.Infof("find config: %s", dotConf)
			path = dotConf
			goto loadConf
		}
		// try "/etc/mgraftcp/mgraftcp.conf"
		etcConf := "/etc/mgraftcp/mgraftcp.conf"
		if _, err := os.Stat(etcConf); err == nil {
			if enableDebugLog {
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
		if enableDebugLog {
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
					setCfg(k, v)
				}
				break
			}
			if enableDebugLog {
				dlog.Errorf("reader.ReadString('\\n') err: %s, path: %s", err.Error(), path)
			}
			return err
		}
		if k, v := parseLine(line); !configKeyOverriddenByFlag(flagset, k) {
			setCfg(k, v)
		}
	}

	return nil
}

func main() {
	getopt.Parse()
	if showVersion {
		fmt.Printf("mgraftcp version %s\n", version)
		return
	}
	args := getopt.Args()
	if len(args) == 0 || help {
		getopt.Usage()
		return
	}
	if err := parseConfigFile(configFile); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		os.Exit(1)
	}

	retCode := 0
	defer func() { os.Exit(retCode) }()

	if enableDebugLog {
		dlog.Init("mgraftcp", dlog.SeverityDebug, "")
	} else {
		local.SetLogger(noopLogger{})
	}

	l, err := local.NewLocal(":0", socks5Addr, socks5User, socks5Pwd, httpProxyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		os.Exit(1)
	}
	if err := l.SetSelectMode(selectProxyMode); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		os.Exit(1)
	}
	activeRegistry = l.Registry()

	ln, err := l.StartListen()
	if err != nil {
		dlog.Fatalf("l.StartListen err: %s", err.Error())
	}
	go l.StartService(ln)
	defer ln.Close()

	_, faddr := l.GetFAddr()

	var fixArgs []string
	fixArgs = append(fixArgs, os.Args[0])
	fixArgs = append(fixArgs, "-p", strconv.Itoa(faddr.Port))
	if blackIPFile != "" {
		fixArgs = append(fixArgs, "-b", blackIPFile)
	}
	if whiteIPFile != "" {
		fixArgs = append(fixArgs, "-w", whiteIPFile)
	}
	if userName != "" {
		fixArgs = append(fixArgs, "-u", userName)
	}
	if notIgnoreLocal {
		fixArgs = append(fixArgs, "-n")
	}
	fixArgs = append(fixArgs, args[0:]...)
	retCode = clientMain(fixArgs)
}
