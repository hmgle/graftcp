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

//export mgraftcp_reserve_udp
func mgraftcp_reserve_udp(family C.int, addr *C.char, port C.uint16_t) C.uint32_t {
	if activeUDPRegistry == nil || addr == nil {
		return 0
	}

	token, err := activeUDPRegistry.Reserve(int(family), C.GoString(addr), uint16(port))
	if err != nil {
		return 0
	}

	return C.uint32_t(token)
}

//export mgraftcp_forget_connect
func mgraftcp_forget_connect(token C.uint32_t) {
	if activeRegistry == nil || token == 0 {
		return
	}
	activeRegistry.Forget(uint32(token))
}

//export mgraftcp_finish_udp_rewrite
func mgraftcp_finish_udp_rewrite(token C.uint32_t, rewritten C.int) {
	if activeUDPRegistry == nil || token == 0 {
		return
	}
	activeUDPRegistry.FinishRewrite(uint32(token), rewritten != 0)
}

//export mgraftcp_start_udp_use
func mgraftcp_start_udp_use(token C.uint32_t) {
	activeUDPRegistry.StartUse(uint32(token))
}

//export mgraftcp_finish_udp_use
func mgraftcp_finish_udp_use(token C.uint32_t, accepted C.int) {
	activeUDPRegistry.FinishUse(uint32(token), accepted != 0)
}
