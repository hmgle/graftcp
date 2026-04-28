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
	"fmt"
	"os"
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

var version = "v0.7"

var cfg = defaultConfig()

func init() {
	cfg.registerFlags()
}

func main() {
	getopt.Parse()
	if cfg.showVersion {
		fmt.Printf("mgraftcp version %s\n", version)
		return
	}
	args := getopt.Args()
	if len(args) == 0 || cfg.help {
		getopt.Usage()
		return
	}
	if err := cfg.parseConfigFile(cfg.configFile); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		os.Exit(1)
	}

	retCode := 0
	defer func() { os.Exit(retCode) }()

	if cfg.enableDebugLog {
		dlog.Init("mgraftcp", dlog.SeverityDebug, "")
	} else {
		local.SetLogger(noopLogger{})
	}

	l, err := local.NewLocal(":0", cfg.socks5Addr, cfg.socks5User, cfg.socks5Pwd, cfg.httpProxyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		os.Exit(1)
	}
	if err := l.SetSelectMode(cfg.selectProxyMode); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		os.Exit(1)
	}
	if cfg.disableDNS && cfg.dnsProxy {
		fmt.Fprintln(os.Stderr, "mgraftcp: --enable-dns and --disable-dns cannot be used together")
		os.Exit(1)
	}
	if cfg.disableDNS {
		cfg.dnsProxy = false
	}
	if cfg.disableUDP && cfg.udpProxy {
		fmt.Fprintln(os.Stderr, "mgraftcp: --enable-udp and --disable-udp cannot be used together")
		os.Exit(1)
	}
	if cfg.disableUDP {
		cfg.udpProxy = false
	}
	activeRegistry = l.Registry()
	activeUDPRegistry = l.UDPRegistry()

	ln, err := l.StartListen()
	if err != nil {
		dlog.Fatalf("l.StartListen err: %s", err.Error())
	}
	go l.StartService(ln)
	defer ln.Close()

	dnsPort := 0
	if cfg.dnsProxy {
		dnsProxy, port, err := l.StartDNSProxy(cfg.dnsServer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
			os.Exit(1)
		}
		defer dnsProxy.Close()
		dnsPort = port
	}
	udpPort := 0
	if cfg.udpProxy {
		udpProxy, port, err := l.StartUDPProxy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
			os.Exit(1)
		}
		defer udpProxy.Close()
		udpPort = port
	}

	_, faddr := l.GetFAddr()

	retCode = clientMain(cfg.clientArgs(faddr.Port, dnsPort, udpPort, args))
}
