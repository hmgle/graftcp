package main

/*
#include <stdint.h>
*/
import "C"

import (
	"github.com/hmgle/graftcp/local"
)

var activeRegistry *local.RouteRegistry

//export mgraftcp_register_connect
func mgraftcp_register_connect(family C.int, addr *C.char, port C.uint16_t) C.uint32_t {
	if activeRegistry == nil || addr == nil {
		return 0
	}

	token, err := activeRegistry.Register(int(family), C.GoString(addr), uint16(port))
	if err != nil {
		return 0
	}

	return C.uint32_t(token)
}

//export mgraftcp_release_connect
func mgraftcp_release_connect(token C.uint32_t) {
	if activeRegistry == nil {
		return
	}

	activeRegistry.ReleaseToken(uint32(token))
}
