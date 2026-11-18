package main

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const startupHelperEnv = "GRAFTCP_TEST_TRACER_STARTUP=1"
const startupHelperTest = "-test.run=^TestTracerStartupHelper$"

func TestTracerStartupHelper(t *testing.T) {
	if os.Getenv("GRAFTCP_TEST_TRACER_STARTUP") == "1" {
		args := []string{"--", "/bin/sh", "-c", "exit 37"}
		if i := slices.Index(os.Args, "--"); i >= 0 {
			// The first separator ends the Go test flags. The rest is
			// the graftcp command line, including its own separator.
			args = os.Args[i+1:]
		}
		os.Args = append([]string{"graftcp", "--config", "/dev/null", "--select_proxy_mode", "direct"}, args...)
		main()
	}
}

func TestTraceeDiesWithTracer(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd := exec.Command(os.Args[0], startupHelperTest, "--", "--", "/bin/sh", "-c", "printf R; read -r line")
	cmd.Env = append(os.Environ(), startupHelperEnv)
	cmd.Stdout = writer
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}()
	writer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(reader, ready[:]); err != nil || ready[0] != 'R' {
		t.Fatalf("waiting for tracee: got %q, err %v", ready, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// Keep stdin open: a surviving shell would stay in read with stdout open.
	if err := reader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(ready[:]); err != io.EOF {
		t.Fatalf("expected EOF after tracer death, got %v", err)
	}
}

func TestTraceeExitBeforeStartupStop(t *testing.T) {
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace is required to exercise nested tracing")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	// strace owns the forked child, so its PTRACE_TRACEME fails with EPERM.
	cmd := exec.CommandContext(ctx, strace, "-f", "-o", os.DevNull,
		os.Args[0], startupHelperTest)
	cmd.Env = append(os.Environ(), startupHelperEnv)
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("graftcp returned %v, want exit status 1\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("ptrace(PTRACE_TRACEME) failed: errno 1\n")) ||
		bytes.Contains(output, []byte("ptrace: ")) {
		t.Fatalf("unexpected startup diagnostic: %s", output)
	}
}

// Match cmd/internal/quoted.Split as used for CC by cgo: quotes are special
// only at the start of a field, and backslashes are literal.
func splitProbeCompiler(cc string) ([]string, error) {
	const spaces = " \t\r\n"
	var args []string
	for {
		cc = strings.TrimLeft(cc, spaces)
		if cc == "" {
			break
		}
		if cc[0] == '\'' || cc[0] == '"' {
			arg, rest, ok := strings.Cut(cc[1:], cc[:1])
			if !ok {
				return nil, fmt.Errorf("unterminated %c in CC", cc[0])
			}
			args = append(args, arg)
			cc = rest
			continue
		}
		end := strings.IndexAny(cc, spaces)
		if end < 0 {
			end = len(cc)
		}
		args = append(args, cc[:end])
		cc = cc[end:]
	}
	if len(args) == 0 || args[0] == "" {
		return nil, errors.New("CC has no executable")
	}
	return args, nil
}

func TestSplitProbeCompiler(t *testing.T) {
	for _, tc := range []struct {
		cc   string
		want []string
	}{
		{"gcc -fno-omit-frame-pointer", []string{"gcc", "-fno-omit-frame-pointer"}},
		{`"/opt/tool chain/cc" '-I/include dir' ""`, []string{"/opt/tool chain/cc", "-I/include dir", ""}},
		{`ccache gcc -DNAME="x" 'a\b'`, []string{"ccache", "gcc", `-DNAME="x"`, `a\b`}},
	} {
		got, err := splitProbeCompiler(tc.cc)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("CC %q: got %q, %v; want %q", tc.cc, got, err, tc.want)
		}
	}
	for _, cc := range []string{" \t", `"" -g`, `cc 'unfinished`} {
		if _, err := splitProbeCompiler(cc); err == nil {
			t.Errorf("expected invalid CC %q to fail", cc)
		}
	}
}

func probeCompiler(t *testing.T) string {
	t.Helper()
	if cc := os.Getenv("CC"); cc != "" {
		return cc
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		// Standalone test binaries can still build probes with the system cc.
		return "cc"
	}
	out, err := exec.CommandContext(t.Context(), goTool, "env", "CC").Output()
	if err != nil {
		t.Fatalf("go env CC: %v", err)
	}
	return strings.TrimSuffix(string(out), "\n")
}

func TestProbeCompilerUsesGoEnv(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is required to read GOENV")
	}
	const configured = "musl-gcc -fno-omit-frame-pointer"
	config := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(config, []byte("CC="+configured+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", config)
	t.Setenv("CC", "")
	if got := probeCompiler(t); got != configured {
		t.Fatalf("probe compiler = %q, want %q", got, configured)
	}
	t.Setenv("CC", "clang -g")
	if got := probeCompiler(t); got != "clang -g" {
		t.Fatalf("probe compiler = %q, want explicit CC", got)
	}
}

func startupProbeCommand(t *testing.T, probeName string, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := elf.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	if !slices.ContainsFunc(binary.Progs, func(p *elf.Prog) bool { return p.Type == elf.PT_INTERP }) {
		t.Skip("LD_PRELOAD requires a test binary with an ELF interpreter")
	}
	probeDir := t.TempDir()
	probe := filepath.Join(probeDir, probeName+".so")
	buildTracerProbe(t, probe, "-shared", "-fPIC", "-pthread", filepath.Join("testdata", probeName+".c"))
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, append([]string{startupHelperTest}, args...)...)
	// LD_PRELOAD splits paths on spaces and colons, including those in TMPDIR.
	cmd.Dir = probeDir
	cmd.Env = append(os.Environ(), startupHelperEnv, "LD_PRELOAD=./"+probeName+".so")
	cmd.WaitDelay = time.Second
	return cmd
}

func buildTracerProbe(t *testing.T, output string, args ...string) {
	t.Helper()
	compilerArgs, err := splitProbeCompiler(probeCompiler(t))
	if err != nil {
		t.Fatal(err)
	}
	cc, err := exec.LookPath(compilerArgs[0])
	if err != nil {
		t.Skipf("%s is required to build the startup probe", compilerArgs[0])
	}
	buildArgs := append(compilerArgs[1:], "-o", output)
	build := exec.CommandContext(t.Context(), cc, append(buildArgs, args...)...)
	if log, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", output, err, log)
	}
}

func TestTraceeKilledAtStartupStop(t *testing.T) {
	cmd := startupProbeCommand(t, "kill-at-stop")
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 137 || len(output) != 0 {
		t.Fatalf("graftcp returned %v, want silent exit status 137\n%s", err, output)
	}
}

func TestTracerDeathBeforeStartupStop(t *testing.T) {
	for _, phase := range []string{"before_registration", "before_sigstop"} {
		t.Run(phase, func(t *testing.T) {
			cmd := startupProbeCommand(t, "tracer-death")
			if phase == "before_registration" {
				cmd.Env = append(cmd.Env, "GRAFTCP_TEST_PAUSE_AT_FORK=1")
			}
			events, out, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer events.Close()
			defer out.Close()
			in, release, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			defer release.Close()
			cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			out.Close()
			if err := events.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var ready [1]byte
			if _, err := io.ReadFull(events, ready[:]); err != nil || ready[0] != 'R' {
				t.Fatalf("waiting for %s: got %q, err %v", phase, ready, err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			var exitErr *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("expected tracer death by SIGKILL: %v", err)
			}
			release.Close()
			if data, err := io.ReadAll(events); err != nil || len(data) != 0 {
				t.Fatalf("expected tracee exit before SIGSTOP: got %q, err %v", data, err)
			}
		})
	}
}

func TestRejectedPtraceOptions(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"reaps_tracee", "reaped SIGKILL"},
		{"termination_denied", "terminate tracee"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := startupProbeCommand(t, "reject-options")
			if tc.name == "termination_denied" {
				cmd.Env = append(cmd.Env, "GRAFTCP_TEST_DENY_KILL=1")
			}
			// Read through EOF from both processes, including a detached child.
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			cmd.Stderr = w
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			w.Close()
			err = cmd.Wait()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != int(syscall.EINVAL) {
				t.Errorf("expected exit status EINVAL, got %v", err)
			}
			if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			output, err := io.ReadAll(r)
			if err != nil || !bytes.Contains(output, []byte("ptrace(PTRACE_SETOPTIONS)")) ||
				!bytes.Contains(output, []byte(tc.want)) || bytes.Contains(output, []byte("execvp reached")) {
				t.Fatalf("unexpected startup events: %q (read error %v)", output, err)
			}
		})
	}
}

func TestConcurrentTracerStartup(t *testing.T) {
	for worker := range 8 {
		t.Run(fmt.Sprintf("worker%d", worker), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			for range 8 {
				cmd := exec.CommandContext(ctx, os.Args[0], startupHelperTest)
				cmd.Env = append(os.Environ(), startupHelperEnv)
				cmd.WaitDelay = time.Second
				output, err := cmd.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 {
					t.Fatalf("graftcp returned %v, want exit status 37\n%s", err, output)
				}
			}
		})
	}
}

func TestTracerResumesChildAfterForkEventESRCH(t *testing.T) {
	for _, operation := range []string{"fork", "vfork"} {
		for _, order := range []string{"parent_first", "child_first"} {
			t.Run(operation+"/"+order, func(t *testing.T) {
				cmd := startupProbeCommand(t, "esrch-on-fork-event", "--", "--", "./fork-event-child", operation)
				buildTracerProbe(t, filepath.Join(cmd.Dir, "fork-event-child"), filepath.Join("testdata", "fork-event-child.c"))
				if order == "child_first" {
					cmd.Env = append(cmd.Env, "GRAFTCP_TEST_CHILD_STOP_FIRST=1")
				}
				output, err := cmd.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 ||
					!bytes.Contains(output, []byte("missing creation event")) ||
					!bytes.Contains(output, []byte("root reaped grandchild")) {
					t.Fatalf("graftcp returned %v, want recovery and exit status 37\n%s", err, output)
				}
			})
		}
	}
}

func TestTracerInheritsSocketWhenChildStopsFirst(t *testing.T) {
	upstream, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	port := strconv.Itoa(upstream.Addr().(*net.TCPAddr).Port)
	cmd := startupProbeCommand(t, "esrch-on-fork-event", "--", "--not-ignore-local", "--", "./fork-event-child", "inherit", port)
	cmd.Env = append(cmd.Env, "GRAFTCP_TEST_KEEP_CREATOR=1")
	buildTracerProbe(t, filepath.Join(cmd.Dir, "fork-event-child"), filepath.Join("testdata", "fork-event-child.c"))

	upstreamResult := make(chan error, 1)
	if err := upstream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := upstream.AcceptTCP()
		if err == nil {
			defer conn.Close()
			_, err = io.WriteString(conn, "R")
		}
		upstreamResult <- err
	}()

	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 || len(output) != 0 {
		t.Fatalf("graftcp returned %v, want silent exit status 37 after proxying the inherited socket\n%s", err, output)
	}
	if err := <-upstreamResult; err != nil {
		t.Fatalf("upstream connection: %v", err)
	}
}

func TestTracerKeepsRootStatusAfterWorkerESRCH(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the probe targets x86-64 PTRACE_PEEKUSER register reads")
	}

	for _, operation := range []string{"socket", "dup", "fcntl"} {
		t.Run(operation, func(t *testing.T) {
			cmd := startupProbeCommand(t, "esrch-on-worker-return", "--", "--", "./worker", operation)
			buildTracerProbe(t, filepath.Join(cmd.Dir, "worker"), "-pthread", filepath.Join("testdata", "worker-syscall.c"))
			cmd.Env = append(cmd.Env, "GRAFTCP_TEST_WORKER_SYSCALL="+operation)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 ||
				string(output) != "injected ESRCH\nroot joined worker\n" {
				t.Fatalf("graftcp returned %v, want injected ESRCH, joined worker and exit status 37\n%s", err, output)
			}
		})
	}
}
