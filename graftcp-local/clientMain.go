package main

// #cgo LDFLAGS: -L./contrib/lib -lgraftcp
//
// #include <stdlib.h>
// static void* alloc_string_slice(int len){
// return malloc(sizeof(char*)*len);
// }
//
// int client_main(int argc, char *argv[]);
import "C"

import (
	"unsafe"

	log "github.com/jedisct1/dlog"
)

const(
	maxArgsLen = 0xfff
)

func client_main(args []string) int{
	argc:=C.int(len(args))

	log.Debugf("Got %v args: %v\n", argc, args)

	argv:=(*[maxArgsLen]*C.char)(C.alloc_string_slice(argc))
	defer C.free(unsafe.Pointer(argv))

	for i, arg := range args{
		argv[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argv[i]))
	}

	returnValue := C.client_main(argc, (**C.char)(unsafe.Pointer(argv)))
	return int(returnValue)
}



