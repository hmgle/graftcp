package main

import (
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/hmgle/graftcp/local"
)

func TestIoctlCloseOnExecTracking(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "ioctl-cloexec")
	buildTracerProbe(t, probe, filepath.Join("testdata", "ioctl-cloexec.c"))
	loopback := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	upstream, err := net.ListenTCP("tcp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	proxy, err := net.ListenTCP("tcp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	upstreamPort := strconv.Itoa(upstream.Addr().(*net.TCPAddr).Port)
	proxyPort := strconv.Itoa(proxy.Addr().(*net.TCPAddr).Port)

	for _, filter := range []string{"tcp", "udp"} {
		for _, mode := range []string{"clear", "set"} {
			t.Run(filter+"/"+mode, func(t *testing.T) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				registry := local.NewRouteRegistry()
				activeRegistry = registry
				defer func() { activeRegistry = nil }()

				command := []string{"graftcp", "--not-ignore-local", "--local-port", proxyPort}
				if filter == "udp" {
					command = append(command, "--udp-port", proxyPort)
				}
				command = append(command, "--", probe, mode, upstreamPort, proxyPort)
				if code := clientPrepare(command); code != 0 {
					t.Fatalf("clientPrepare() = %d", code)
				}
				if code := clientTrace(); code != 0 {
					t.Errorf("tracee exit status = %d", code)
				}
				// Each case starts with a fresh registry and makes one connect.
				got, ok := registry.Consume(net.IPv4(127, 0, 0, 1))
				if mode == "clear" && (!ok || got != upstream.Addr().String()) {
					t.Errorf("route = %q, %v, want %s", got, ok, upstream.Addr())
				}
				if mode == "set" && ok {
					t.Errorf("unexpected route for a closed socket: %s", got)
				}
			})
		}
	}
}
