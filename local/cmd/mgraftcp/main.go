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
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hmgle/graftcp/local"
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

func main() {

	// todo: we need special handle on args like '--help' which trigger os.Exit
	// todo: randomly set and detect port number if no one specified
	serverArgs, clientArgs := constructArgs(os.Args[1:])

	clientArgs = append(os.Args[:1], clientArgs...)

	// TODO: config args
	l := local.NewLocal(":0", "127.0.0.1:1080", "", "", "")

	pipePath := "/tmp/mgraftcp.fifo"
	syscall.Mkfifo(pipePath, uint32(os.ModePerm))
	os.Chmod(pipePath, 0666)
	var err error
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
	os.Exit(clientMain(fixArgs))
}
