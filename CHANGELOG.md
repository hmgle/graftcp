# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [v0.9.0] - 2026-11-19

### Fixed

- Use the default SOCKS5 endpoint `127.0.0.1:1080` only when neither SOCKS5 nor
  HTTP is configured. With only an HTTP proxy configured, `auto` and `random`
  skip SOCKS5, and `only_socks5` reports a configuration error at startup.
  Supersedes the SOCKS5-fallback half of #93.
- Preserve responses after a TCP half-close so servers can reply to requests
  delimited by EOF.
- Handle informational HTTP CONNECT responses and preserve tunnel bytes that
  arrive with the final response. Bound the TCP proxy dial and handshake with
  a single deadline so a stalled proxy can trigger fallback in `auto` mode.
- Retain routes for connected and corked UDP sockets across idle cleanup.
  Failed UDP connects leave existing routes usable. Keep stale cleanup from
  closing replacement sessions and block new sessions during shutdown.
- Follow Linux file descriptor sharing and close-on-exec behavior across clone,
  unshare, exec, and `FIOCLEX` / `FIONCLEX` calls so UDP routes remain available
  through live descriptors.
- Require ptrace setup before running the target, reconcile child stops that
  arrive before their creation events, and preserve the root command's exit
  status when another traced task disappears.
- Rebuild C objects and invalidate the cgo cache when compilation settings or
  linked C inputs change. Use the Go version from `local/go.mod` for release
  builds.
- Label ARMv7 release packages `armhf` for Debian and `armv7hl` for RPM.
- Validate release binaries using their ELF headers so valid 386 builds pass
  on hosts that describe them as `Intel i386`.

## [v0.8.3] - 2026-07-15

### Fixed

- Build release packages with the requested target architecture instead of
  silently falling back to the host compiler.
- Verify the binary architecture before creating release packages.

## [v0.8.2] - 2026-07-01

### Added

- SOCKS5 proxy endpoints can now use Unix sockets for TCP CONNECT traffic, for example `unix:/path/tor.sock`.

### Fixed

- Keep DNS proxy sockaddr rewrites in place after `sendto()` returns so musl-based resolvers can validate DNS replies when DNS proxying is enabled, fixing issue #90.

## [v0.8.1] - 2026-06-07

### Added

- GitHub Actions release packaging for Linux `amd64`, `arm64`, `armv7`, and `386`.
- Release assets now include `.deb`, `.rpm`, and `.tar.gz` packages plus SHA-256 checksums.

## [v0.8.0] - 2026-05-30

### Added

- Single-binary `graftcp` entrypoint: tracer and local proxy are merged into one process, no daemon required.
- `mgraftcp` compatibility alias for users who adopted the merged command name before the merge back to `master`.
- Loopback token routing: each intercepted `connect(2)` gets a unique `127.x.y.z` token IP; the embedded listener resolves the original destination in-process.
- DNS-over-TCP proxy for UDP/53 queries (`--enable-dns`, `--dns-server`).
- Generic UDP proxy via SOCKS5 UDP ASSOCIATE or direct UDP (`--enable-udp`).
- seccomp-BPF filter to reduce ptrace overhead on supported kernels, with automatic per-syscall fallback on older kernels.
- XDG-style config file search path, preferring `graftcp.conf` while keeping `mgraftcp.conf` fallback paths.
- `--config` flag to override the default config path.
- `--disable-dns` and `--disable-udp` flags to override config-file defaults at runtime.
- `--select_proxy_mode=direct` option.

### Removed

- Standalone `graftcp-local` daemon; proxy functionality is embedded in `graftcp`.
- FIFO-based address passing (`/tmp/graftcplocal.fifo`).
- `netlink` / `/proc/<pid>/fd` socket inode reverse lookup.
- Fixed local listen port (`:2233`); replaced by ephemeral port plus in-process token routing.
- `make install_systemd` / `make enable_systemd` targets and the associated systemd unit.
- File logging, syslog, and log-level flags (`-logfile`, `-loglevel`, `-syslog`); `--enable-debug-log` to stderr remains.
- `kardianos/service`, `vishvananda/netlink`/`netns`, and `jedisct1/dlog` dependencies.
- C-side config layer (`conf.c` / `conf.h`, `-c` flag); configuration is now Go-side only.

### Migration from v0.7.x

Replace the two-step daemon workflow with a single command:

```sh
# Before (v0.7.x)
graftcp-local -listen :2233 -socks5 127.0.0.1:1080 &
graftcp curl https://example.com

# After (v0.8.0)
graftcp --socks5 127.0.0.1:1080 curl https://example.com
```

`mgraftcp` remains available as an alias, so existing `mgraftcp ...` commands continue to work.

**Config file**: prefer `graftcp.conf`. The `mgraftcp.conf` fallback paths are still recognized. Remove the old daemon keys `listen`, `pipepath`, `logfile`, `loglevel`, `use_syslog`, `local_addr`, and `local_port`; they are no longer recognized. See [`example-graftcp.conf`](./example-graftcp.conf) for the current key set.

**systemd**: the old unit installed by `make install_systemd` is gone. To run a command at boot, wrap it with `graftcp` in your own unit or `@reboot` cron entry.

**Logging**: replace `-logfile` / `-loglevel` with shell redirection:

```sh
graftcp --enable-debug-log ... 2>>/var/log/graftcp.log
```

[Unreleased]: https://github.com/hmgle/graftcp/compare/v0.9.0...HEAD
[v0.9.0]: https://github.com/hmgle/graftcp/compare/v0.8.3...v0.9.0
