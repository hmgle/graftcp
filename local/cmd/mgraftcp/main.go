package main

// #cgo LDFLAGS: -L../../.. -lgraftcp
//
// #include <stdlib.h>
//
// static void *alloc_string_slice(int len) {
//              return malloc(sizeof(char*)*len);
// }
//
// int client_main(int argc, char **argv);
import "C"
import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/hmgle/graftcp/local"
	"github.com/jedisct1/dlog"
	"github.com/pborman/getopt/v2"
)

const (
	maxArgsLen = 0xfff
)

func clientMain(args []string) int {
	argc := C.int(len(args))

	argv := (*[maxArgsLen]*C.char)(C.alloc_string_slice(argc))
	defer C.free(unsafe.Pointer(argv))

	for i, arg := range args {
		argv[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argv[i]))
	}

	returnValue := C.client_main(argc, (**C.char)(unsafe.Pointer(argv)))
	return int(returnValue)
}

var (
	httpProxyAddr   string
	selectProxyMode string = "auto"
	socks5Addr      string = "127.0.0.1:1080"
	socks5User      string
	socks5Pwd       string

	blackIPFile    string
	whiteIPFile    string
	notIgnoreLocal bool
	enableDebugLog bool

	help        bool
	showVersion bool

	version = "v0.4"
)

func init() {
	getopt.FlagLong(&httpProxyAddr, "http_proxy", 0, "http proxy address, e.g.: 127.0.0.1:8080")
	getopt.FlagLong(&selectProxyMode, "select_proxy_mode", 0, "Set the mode for select a proxy [auto | random | only_http_proxy | only_socks5 | direct]")
	getopt.FlagLong(&socks5Addr, "socks5", 0, "SOCKS5 address")
	getopt.FlagLong(&socks5User, "socks5_username", 0, "SOCKS5 username")
	getopt.FlagLong(&socks5Pwd, "socks5_password", 0, "SOCKS5 password")
	getopt.FlagLong(&enableDebugLog, "enable-debug-log", 0, "enable debug log")

	getopt.FlagLong(&blackIPFile, "blackip-file", 'b', "The IP in black-ip-file will connect direct")
	getopt.FlagLong(&whiteIPFile, "whiteip-file", 'w', "Only redirect the connect that destination ip in the white-ip-file to SOCKS5")
	getopt.FlagLong(&notIgnoreLocal, "not-ignore-local", 'n', "Connecting to local is not changed by default, this option will redirect it to SOCKS5")
	getopt.FlagLong(&help, "help", 'h', "Display this help and exit")
	getopt.FlagLong(&showVersion, "version", 0, "Print the mgraftcp version information")
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

	retCode := 0
	defer func() { os.Exit(retCode) }()

	if enableDebugLog {
		dlog.Init("mgraftcp", dlog.SeverityDebug, "")
	} else {
		local.SetLogger(noopLogger{})
	}

	l := local.NewLocal(":0", socks5Addr, socks5User, socks5Pwd, httpProxyAddr)
	l.SetSelectMode(selectProxyMode)

	tmpDir, err := ioutil.TempDir("/tmp", "mgraftcp")
	if err != nil {
		log.Fatalf("ioutil.TempDir err: %s", err.Error())
	}
	defer os.RemoveAll(tmpDir)
	pipePath := tmpDir + "/mgraftcp.fifo"
	syscall.Mkfifo(pipePath, uint32(os.ModePerm))

	l.FifoFd, err = os.OpenFile(pipePath, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("os.OpenFile(%s) err: %s", pipePath, err.Error())
	}

	go l.UpdateProcessAddrInfo()
	ln, err := l.StartListen()
	if err != nil {
		log.Fatalf("l.StartListen err: %s", err.Error())
	}
	go l.StartService(ln)
	defer ln.Close()

	_, faddr := l.GetFAddr()

	var fixArgs []string
	fixArgs = append(fixArgs, os.Args[0])
	fixArgs = append(fixArgs, "-p", strconv.Itoa(faddr.Port), "-f", pipePath)
	if blackIPFile != "" {
		fixArgs = append(fixArgs, "-b", blackIPFile)
	}
	if whiteIPFile != "" {
		fixArgs = append(fixArgs, "-w", whiteIPFile)
	}
	if notIgnoreLocal {
		fixArgs = append(fixArgs, "-n")
	}
	fixArgs = append(fixArgs, args[0:]...)
	retCode = clientMain(fixArgs)
}
