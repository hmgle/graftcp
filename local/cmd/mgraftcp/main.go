package main

// #cgo LDFLAGS: -L../../.. -lgraftcp
//
// #include <stdlib.h>
//
// static char **alloc_string_slice(int len) {
//              return calloc(len, sizeof(char*));
// }
//
// int client_prepare(int argc, char **argv);
// int client_trace(void);
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/hmgle/graftcp/local"
	"github.com/pborman/getopt/v2"
)

func clientPrepare(args []string) int {
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

	returnValue := C.client_prepare(argc, argv)
	return int(returnValue)
}

func clientTrace() int {
	return int(C.client_trace())
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
	if cfg.enableDebugLog {
		local.SetLogger(appLogger)
	}

	retCode := 0
	defer func() { os.Exit(retCode) }()

	if err := cfg.parseConfigFile(cfg.configFile); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		retCode = 1
		return
	}

	l, err := local.NewLocalListener(":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		retCode = 1
		return
	}
	if err := l.SetSelectMode(cfg.selectProxyMode); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		retCode = 1
		return
	}
	if err := l.ConfigureProxy(cfg.socks5Addr, cfg.socks5User, cfg.socks5Pwd, cfg.httpProxyAddr); err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
		retCode = 1
		return
	}
	if cfg.disableDNS && cfg.dnsProxy {
		fmt.Fprintln(os.Stderr, "mgraftcp: --enable-dns and --disable-dns cannot be used together")
		retCode = 1
		return
	}
	if cfg.disableDNS {
		cfg.dnsProxy = false
	}
	if cfg.disableUDP && cfg.udpProxy {
		fmt.Fprintln(os.Stderr, "mgraftcp: --enable-udp and --disable-udp cannot be used together")
		retCode = 1
		return
	}
	if cfg.disableUDP {
		cfg.udpProxy = false
	}
	activeRegistry = l.Registry()
	activeUDPRegistry = l.UDPRegistry()

	ln, err := l.StartListen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mgraftcp: l.StartListen err: %s\n", err.Error())
		retCode = 1
		return
	}
	defer ln.Close()

	dnsPort := 0
	var dnsProxy *local.DNSProxy
	if cfg.dnsProxy {
		var port int
		dnsProxy, port, err = l.ListenDNSProxy(cfg.dnsServer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
			retCode = 1
			return
		}
		defer dnsProxy.Close()
		dnsPort = port
	}
	udpPort := 0
	var udpProxy *local.UDPProxy
	if cfg.udpProxy {
		var port int
		udpProxy, port, err = l.ListenUDPProxy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mgraftcp: %v\n", err)
			retCode = 1
			return
		}
		defer udpProxy.Close()
		udpPort = port
	}

	_, faddr := l.GetFAddr()

	retCode = clientPrepare(cfg.clientArgs(faddr.Port, dnsPort, udpPort, args))
	if retCode != 0 {
		return
	}

	go l.StartService(ln)
	if dnsProxy != nil {
		dnsProxy.Start()
	}
	if udpProxy != nil {
		udpProxy.Start()
	}

	retCode = clientTrace()
}
