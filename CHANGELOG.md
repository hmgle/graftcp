# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
