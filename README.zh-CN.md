# graftcp

[English](./README.md) | **简体中文**

## 简介

`mgraftcp` 通过 `ptrace(2)` 拦截目标程序的 `connect(2)`，把任意 Linux 进程的 TCP 连接重定向到 SOCKS5 或 HTTP 代理。显式启用后，它也可以把 UDP/53 DNS 查询重定向到内嵌的 DNS-over-TCP 转发器。

这次重构后，旧的 `graftcp` + `graftcp-local` 双程序模型已经移除：

- `mgraftcp` 是唯一支持的入口。
- 不再需要单独启动本地守护进程。
- 不再使用 FIFO、`/proc` 扫描或 `netlink` 反查连接。
- 每次被拦截的连接都会分配一个唯一的 Loopback token IP，由内嵌本地代理在进程内直接回查原始目标地址。

和 `tsocks`、`proxychains`、`proxychains-ng` 不同，`mgraftcp` 仍然不依赖 `LD_PRELOAD`，所以对静态链接程序（例如大多数 Go 二进制）同样有效。

## 安装

`graftcp` 仅支持 Linux。构建 `mgraftcp` 需要 Go 和 C 工具链。

```sh
git clone https://github.com/hmgle/graftcp.git
cd graftcp
make
```

构建产物是 `local/mgraftcp`。

安装到系统：

```sh
sudo make install
```

## 用法

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

示例：

```sh
./local/mgraftcp --socks5 127.0.0.1:1080 curl https://example.com
./local/mgraftcp --enable-dns --dns-server 1.1.1.1:53 curl https://example.com
./local/mgraftcp --http_proxy 127.0.0.1:8080 git clone https://github.com/hmgle/graftcp.git
./local/mgraftcp bash --rcfile <(echo 'PS1="(mgraftcp) $PS1"')
```

## 配置文件

`mgraftcp` 按下面顺序查找 `mgraftcp.conf`：

1. `--config` 指定的文件
2. `$(dirname $0)/mgraftcp.conf`
3. `$XDG_CONFIG_HOME/mgraftcp/mgraftcp.conf`
4. `$HOME/.config/mgraftcp/mgraftcp.conf`
5. `/etc/mgraftcp/mgraftcp.conf`

示例配置见 [`example-mgraftcp.conf`](./example-mgraftcp.conf)。

## 工作原理

1. `mgraftcp` 先启动内嵌本地 TCP listener，再用 `ptrace(2)` 跟踪目标命令。
2. 每次拦截到 `connect(2)` 时，把原始目标地址登记到进程内路由表，并从 `127.0.0.0/8` 分配一个唯一 Loopback token IP。
3. 把 tracee 的目的 sockaddr 改写成这个 token IP 和内嵌 listener 的端口。
4. 内嵌 listener `accept` 到连接后，从 `LocalAddr()` 取出 token，直接在进程内解析出原始目标地址，再按 SOCKS5 / HTTP / direct 策略发起真实连接。
5. `mgraftcp` 有意固定为弱语义：`connect()` 返回后，不再把 tracee 原始 `sockaddr` 缓冲区写回去。

对 IPv6 `connect(2)`，当前实现会改写为 IPv4-mapped Loopback 地址 `::ffff:127.x.y.z`，从而复用同一套 token 路由逻辑。

启用 DNS 代理时，`mgraftcp` 还会启动一个内嵌 UDP DNS listener。目标端口为 53 的 UDP `connect()` 和 `sendto()` 会被改写到这个 listener，每个 DNS payload 再通过同一套 SOCKS5 / HTTP / direct 选择策略，以 TCP 方式转发到配置的上游 DNS 服务器。

## 说明

- 仅支持 Linux。
- 仍然受 `ptrace(2)` 权限限制；如果跟踪失败，请检查 Yama `ptrace_scope`、能力集或是否需要 root。
- 默认忽略本地目标地址；如果希望本地连接也走代理，使用 `--not-ignore-local`。
- DNS 代理默认关闭；使用 `--enable-dns` 启用 UDP/53 DNS-over-TCP 路径，使用 `--dns-server` 指定上游服务器。
- DNS 支持有意限定为 DNS-only；当前不实现通用 UDP 代理，也不实现 SOCKS5 UDP ASSOCIATE。
- 配置文件支持代理地址和常见路由选项；命令行参数仍然覆盖配置文件。
- 当前分支不会虚拟化 `getpeername()` / `getsockname()`，程序也可能在原始 `connect()` 缓冲区里看到 fake loopback endpoint。
- DNS 路径同样采用弱语义改写 `connect()` / `sendto()` 缓冲区；如果客户端强依赖 `recvfrom()` 返回原始 DNS 服务器地址，透明性可能不完整。
- IPv6 故意统一走 IPv4-mapped loopback；依赖 `IPV6_V6ONLY=1` 的 socket 不在当前设计目标内。
- socket 跟踪是按 `(pid, fd)` 做的 best-effort，而不是按共享 fd table 建模；`dup*`、`close_range()`、跨线程共享 socket 等场景都属于有意不覆盖的边界。
- loopback token 只会在本地 listener 成功 `accept()` 后回收；失败或放弃的连接可能留下残留条目，等待 token wrap-around 覆盖。
- 设计取舍和风险说明见 [docs/simplicity-first-mgraftcp-design.zh-CN.md](./docs/simplicity-first-mgraftcp-design.zh-CN.md)。
