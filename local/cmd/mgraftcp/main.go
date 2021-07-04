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
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hmgle/graftcp/local"
	"github.com/spf13/pflag"
)

const (
	maxArgsLen = 0xfff
)

func clientMain(args []string) int {
	argc := C.int(len(args))

	log.Printf("Got %v args: %v\n", argc, args)

	argv := (*[maxArgsLen]*C.char)(C.alloc_string_slice(argc))
	defer C.free(unsafe.Pointer(argv))

	for i, arg := range args {
		argv[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argv[i]))
	}

	returnValue := C.client_main(argc, (**C.char)(unsafe.Pointer(argv)))
	return int(returnValue)
}

func constructArgs(args []string) ([]string, []string) {
	server := make([]string, 0, len(args))
	client := make([]string, 0, len(args))

	isCommand := false
	for _, arg := range args {
		if isCommand {
			client = append(client, arg)
		} else {
			if strings.HasPrefix(arg, "--server") {
				server = append(server, strings.TrimPrefix(arg, "--server"))
			} else if strings.HasPrefix(arg, "--client") {
				client = append(client, strings.TrimPrefix(arg, "--client"))
			} else {
				isCommand = true
				client = append(client, arg)
			}
		}
	}

	return server, client
}

var (
	confPath        string
	httpProxyAddr   string
	logFile         string
	logLevel        int8
	selectProxyMode string
	socks5Addr      string
	socks5User      string
	socks5Pwd       string

	blackIPFile    string
	whiteIPFile    string
	notIgnoreLocal bool
)

func init() {
	pflag.StringVar(&confPath, "config", "", "Path to the configuration file")
	pflag.StringVar(&httpProxyAddr, "http_proxy", "", "http proxy address, e.g.: 127.0.0.1:8080")
	pflag.StringVar(&selectProxyMode, "select_proxy_mode", "auto", "Set the mode for select a proxy [auto | random | only_http_proxy | only_socks5 | direct]")
	pflag.StringVar(&socks5Addr, "socks5", "127.0.0.1:1080", "SOCKS5 address")
	pflag.StringVar(&socks5User, "socks5_username", "", "SOCKS5 username")
	pflag.StringVar(&socks5Pwd, "socks5_password", "", "SOCKS5 password")

	pflag.StringVarP(&blackIPFile, "blackip-file", "b", "", "The IP in black-ip-file will connect direct")
	pflag.StringVarP(&blackIPFile, "whiteip-file", "w", "", "Only redirect the connect that destination ip in the white-ip-file to SOCKS5")
	pflag.BoolVarP(&notIgnoreLocal, "not-ignore-local", "n", false, "Connecting to local is not changed by default, this option will redirect it to SOCKS5")
}

func usage() {
	log.Fatalf("Usage: mgraftcp [options] prog [prog-args]\n%v", pflag.CommandLine.FlagUsages())
}

func main() {
	pflag.Parse()
	args := pflag.Args()
	if len(args) == 0 {
		usage()
	}

	retCode := 0
	defer func() { os.Exit(retCode) }()

	// todo: we need special handle on args like '--help' which trigger os.Exit
	// todo: randomly set and detect port number if no one specified
	serverArgs, clientArgs := constructArgs(os.Args[1:])

	clientArgs = append(os.Args[:1], clientArgs...)

	// TODO: config args
	l := local.NewLocal(":0", socks5Addr, socks5User, socks5Pwd, httpProxyAddr)

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
	fixArgs = append(fixArgs, clientArgs[0])
	fixArgs = append(fixArgs, "-p", strconv.Itoa(faddr.Port), "-f", pipePath)
	fixArgs = append(fixArgs, clientArgs[1:]...)
	log.Printf("serverArgs: %+v, fixArgs: %+v\n", serverArgs, fixArgs)
	retCode = clientMain(fixArgs)
}
