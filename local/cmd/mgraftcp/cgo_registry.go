package main

/*
#include <stdint.h>
*/
import "C"

import (
	"github.com/hmgle/graftcp/local"
)

var activeRegistry *local.RouteRegistry
var activeUDPRegistry *local.DatagramRouteRegistry

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

//export mgraftcp_register_udp
func mgraftcp_register_udp(family C.int, addr *C.char, port C.uint16_t) C.uint32_t {
	if activeUDPRegistry == nil || addr == nil {
		return 0
	}

	token, err := activeUDPRegistry.Register(int(family), C.GoString(addr), uint16(port))
	if err != nil {
		return 0
	}

	return C.uint32_t(token)
}
