# graftcp

**English** | [简体中文](./README.zh-CN.md)

## Introduction

`mgraftcp` redirects TCP connections from an arbitrary Linux process to SOCKS5 or HTTP proxies by tracing `connect(2)` with `ptrace(2)`.

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
Usage: mgraftcp [-hn] [-b value] [--config value] [--enable-debug-log] [--http_proxy value] [--select_proxy_mode value] [--socks5 value] [--socks5_password value] [--socks5_username value] [-u value] [--version] [-w value] [parameters ...]
 -b, --blackip-file=value
                The IP in black-ip-file will connect direct
     --config=value
                Path to the configuration file
     --enable-debug-log
                Enable debug log
 -h, --help     Display this help and exit
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
     --version  Print the mgraftcp version information
 -w, --whiteip-file=value
                Only redirect the connect that destination ip in the
                white-ip-file to SOCKS5
```

Examples:

```sh
./local/mgraftcp --socks5 127.0.0.1:1080 curl https://example.com
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
5. The original sockaddr is restored in the tracee after the syscall exits, so the traced process still sees its own original destination argument.

For IPv6 `connect(2)`, `mgraftcp` rewrites to an IPv4-mapped loopback address (`::ffff:127.x.y.z`) so the same token registry can be reused.

## Notes

- Linux only.
- `ptrace(2)` permissions still apply. If tracing is blocked, check Yama `ptrace_scope`, capabilities, or run as root when appropriate.
- Local destinations are ignored by default. Use `--not-ignore-local` to proxy loopback/private-local connects as well.
- The proxy configuration file covers proxy endpoints and the common routing flags. CLI flags still override config values.
