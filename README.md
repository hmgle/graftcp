# graftcp

**English** | [简体中文](./README.zh-CN.md)

## Introduction

`mgraftcp` redirects TCP connections from an arbitrary Linux process to SOCKS5 or HTTP proxies by tracing `connect(2)` with `ptrace(2)`. It can also redirect UDP/53 DNS queries to an embedded DNS-over-TCP forwarder when explicitly enabled.

This refactor removes the old `graftcp` + `graftcp-local` split runtime:

- `mgraftcp` is now the only supported entrypoint.
- There is no standalone local daemon.
- There is no FIFO, `/proc` scan, or `netlink` socket reverse lookup.
- Each intercepted connection gets a unique loopback token IP, and the embedded local proxy resolves that token in-process.

Compared with `tsocks`, `proxychains`, or `proxychains-ng`, this still does not depend on `LD_PRELOAD`, so statically linked binaries such as most Go programs can be traced as well.

## Installation

`graftcp` runs on Linux. Building `mgraftcp` requires Go and a C toolchain.

```sh
git clone https://github.com/hmgle/graftcp.git
cd graftcp
make
```

The build output is `local/mgraftcp`.

To install it:

```sh
sudo make install
```

## Usage

```console
$ ./local/mgraftcp --help
Usage: mgraftcp [-hn] [-b value] [--config value] [--disable-dns] [--dns-server value] [--enable-debug-log] [--enable-dns] [--http_proxy value] [--select_proxy_mode value] [--socks5 value] [--socks5_password value] [--socks5_username value] [-u value] [--version] [-w value] [parameters ...]
 -b, --blackip-file=value
                    The IP in black-ip-file will connect direct
     --config=value
                    Path to the configuration file
     --disable-dns  Disable DNS proxy
     --dns-server=value
                    DNS upstream server address, e.g.: 1.1.1.1:53 [1.1.1.1:53]
     --enable-debug-log
                    Enable debug log
     --enable-dns   Enable DNS proxy for UDP/53 queries
 -h, --help         Display this help and exit
     --http_proxy=value
                    http proxy address, e.g.: 127.0.0.1:8080
 -n, --not-ignore-local
                    Connecting to local is not changed by default, this option
                    will redirect it to SOCKS5
     --select_proxy_mode=value
                    Set the mode for select a proxy [auto | random |
                    only_http_proxy | only_socks5 | direct] [auto]
     --socks5=value
                    SOCKS5 address [127.0.0.1:1080]
     --socks5_password=value
                    SOCKS5 password
     --socks5_username=value
                    SOCKS5 username
 -u, --username=value
                    Run command as USERNAME handling setuid and/or setgid
     --version      Print the mgraftcp version information
 -w, --whiteip-file=value
                    Only redirect the connect that destination ip in the
                    white-ip-file to SOCKS5
```

Examples:

```sh
./local/mgraftcp --socks5 127.0.0.1:1080 curl https://example.com
./local/mgraftcp --enable-dns --dns-server 1.1.1.1:53 curl https://example.com
./local/mgraftcp --http_proxy 127.0.0.1:8080 git clone https://github.com/hmgle/graftcp.git
./local/mgraftcp bash --rcfile <(echo 'PS1="(mgraftcp) $PS1"')
```

## Configuration

`mgraftcp` looks for `mgraftcp.conf` in this order:

1. The file passed by `--config`
2. `$(dirname $0)/mgraftcp.conf`
3. `$XDG_CONFIG_HOME/mgraftcp/mgraftcp.conf`
4. `$HOME/.config/mgraftcp/mgraftcp.conf`
5. `/etc/mgraftcp/mgraftcp.conf`

An example config is available in [`example-mgraftcp.conf`](./example-mgraftcp.conf).

## How It Works

1. `mgraftcp` starts an embedded local TCP listener and then traces the target command with `ptrace(2)`.
2. For every intercepted `connect(2)`, it records the original destination in an in-process route table and allocates a unique loopback token IP from `127.0.0.0/8`.
3. The tracee's destination sockaddr is rewritten to that token IP plus the embedded listener port.
4. When the embedded listener accepts the connection, it reads the token from `LocalAddr()`, resolves the original destination from the route table, then dials the configured SOCKS5/HTTP/direct path.
5. `mgraftcp` intentionally keeps weak socket visibility semantics: it does not restore the original `connect()` buffer after the syscall returns.

For IPv6 `connect(2)`, `mgraftcp` rewrites to an IPv4-mapped loopback address (`::ffff:127.x.y.z`) so the same token registry can be reused.

When DNS proxying is enabled, `mgraftcp` also starts an embedded UDP DNS listener. UDP `connect()` and `sendto()` calls to port 53 are rewritten to that listener, and each DNS payload is forwarded to the configured upstream DNS server over TCP through the same proxy selection path.

## Notes

- Linux only.
- `ptrace(2)` permissions still apply. If tracing is blocked, check Yama `ptrace_scope`, capabilities, or run as root when appropriate.
- Local destinations are ignored by default. Use `--not-ignore-local` to proxy loopback/private-local connects as well.
- DNS proxying is disabled by default. Use `--enable-dns` to enable the UDP/53 DNS-over-TCP path, and `--dns-server` to choose the upstream server.
- DNS support is intentionally DNS-only. It does not implement generic UDP proxying or SOCKS5 UDP ASSOCIATE.
- The proxy configuration file covers proxy endpoints and the common routing flags. CLI flags still override config values.
- This branch intentionally does not virtualize `getpeername()` / `getsockname()`, and a traced program may observe the fake loopback endpoint in the original `connect()` buffer.
- The DNS path rewrites `connect()` / `sendto()` buffers with the same weak semantics; clients that require `recvfrom()` to report the original DNS server address may not be fully transparent.
- IPv6 is intentionally simplified to the IPv4-mapped loopback path; sockets that require `IPV6_V6ONLY=1` are out of scope by design.
- Socket tracking is best-effort and keyed by `(pid, fd)`, not by shared fd tables; `dup*`, `close_range()`, and cross-thread socket ownership are intentionally not modeled.
- Loopback-token registrations are reclaimed on accept, not on every failed or abandoned connect; stale entries may remain until the token space wraps and overwrites them.
- The design rationale and tradeoffs are documented in [docs/simplicity-first-mgraftcp-design.zh-CN.md](./docs/simplicity-first-mgraftcp-design.zh-CN.md).
