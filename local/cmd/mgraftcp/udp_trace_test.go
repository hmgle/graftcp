package main

import (
	"net"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/hmgle/graftcp/local"
)

func TestRejectedUDPConnectReleasesReservation(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "udp-connect-failure")
	buildTracerProbe(t, probe, filepath.Join("testdata", "udp-connect-failure.c"))

	for _, shared := range []bool{false, true} {
		name := "unused"
		if shared {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			registry := local.NewDatagramRouteRegistry()
			tokenIP := net.IPv4(127, 0, 0, 1)
			if shared {
				if _, err := registry.Register(syscall.AF_INET6, "::1", 9999); err != nil {
					t.Fatal(err)
				}
			}

			code := traceUDPProbe(t, registry, "45678", probe)
			if code == 77 {
				t.Skip("IPv6 is unavailable")
			}
			if code != 0 {
				t.Fatalf("tracee exit status = %d", code)
			}
			got, ok := registry.Lookup(tokenIP)
			if ok != shared || (shared && got != "[::1]:9999") {
				t.Fatalf("route after rejected connect = %q, %v (shared = %v)", got, ok, shared)
			}
		})
	}
}

// The tracer owns ptrace and the registry for the duration of this call.
// Keep these tests serial since the C tracer and callbacks use globals.
func traceUDPProbe(t *testing.T, registry *local.DatagramRouteRegistry, port string, probe string, args ...string) int {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	activeUDPRegistry = registry
	defer func() { activeUDPRegistry = nil }()
	command := append([]string{"graftcp", "--not-ignore-local", "--udp-port", port, "--", probe}, args...)
	if code := clientPrepare(command); code != 0 {
		t.Fatalf("clientPrepare() = %d", code)
	}
	return clientTrace()
}
