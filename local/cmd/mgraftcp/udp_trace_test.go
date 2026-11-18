package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

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

func TestCorkedUDPSurvivesIdleSweep(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "udp-cork")
	buildTracerProbe(t, probe, "-pthread", filepath.Join("testdata", "udp-cork.c"))

	for _, mode := range []string{"sendto", "sendmsg", "setsockopt", "thread", "fork", "native-fork"} {
		t.Run(mode, func(t *testing.T) {
			l, err := local.NewLocal(":0", "", "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := l.SetSelectMode("direct"); err != nil {
				t.Fatal(err)
			}
			proxy, port, err := l.StartUDPProxy()
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()

			controlDir, err := os.MkdirTemp("", "graftcp-cork-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(controlDir)
			controlName := filepath.Join(controlDir, "control")
			control, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlName, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()

			registry := l.UDPRegistry()
			upstreamAddr := upstream.LocalAddr().String()
			swept := make(chan error, 1)
			go func() {
				swept <- sweepBeforeFlush(control, registry, upstreamAddr)
			}()
			targetPort := strconv.Itoa(upstream.LocalAddr().(*net.UDPAddr).Port)
			code := traceUDPProbe(t, registry, strconv.Itoa(port), probe, mode, targetPort, controlName)
			if mode == "native-fork" && code == 77 {
				t.Skip("architecture has no native fork syscall")
			}
			if code != 0 {
				t.Errorf("tracee exit status = %d", code)
			}
			if err := <-swept; err != nil {
				t.Fatalf("synchronize idle sweep: %v", err)
			}

			if err := upstream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var data [64]byte
			n, _, err := upstream.ReadFromUDP(data[:])
			if err != nil || string(data[:n]) != "firstsecond" {
				t.Fatalf("upstream datagram = %q, %v, want firstsecond", data[:n], err)
			}
		})
	}
}

func sweepBeforeFlush(control *net.UnixListener, registry *local.DatagramRouteRegistry, upstreamAddr string) error {
	deadline := time.Now().Add(5 * time.Second)
	if err := control.SetDeadline(deadline); err != nil {
		return err
	}
	conn, err := control.AcceptUnix()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	var ready [1]byte
	if _, err := io.ReadFull(conn, ready[:]); err != nil {
		return err
	}
	if ready[0] != 'R' {
		return errors.New("unexpected readiness signal")
	}
	registry.SweepIdle(time.Now().Add(3*time.Minute), 2*time.Minute)
	// Each probe uses a fresh registry and rewrites one destination.
	if got, ok := registry.Lookup(net.IPv4(127, 0, 0, 1)); !ok || got != upstreamAddr {
		return fmt.Errorf("route after idle sweep = %q, %v, want %s", got, ok, upstreamAddr)
	}
	_, err = conn.Write([]byte("F"))
	return err
}
