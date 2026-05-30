# graftcp

[English](./README.md) | **简体中文**

## 简介

`graftcp` 通过 `ptrace(2)` 拦截目标程序的 socket syscall，把任意 Linux 进程的 TCP 连接重定向到 SOCKS5 或 HTTP 代理。显式启用后，它也可以把 UDP/53 DNS 查询重定向到内嵌的 DNS-over-TCP 转发器，并通过 SOCKS5 UDP ASSOCIATE 或 direct UDP 代理通用 UDP。

旧的 `graftcp` + `graftcp-local` 双程序模型已经合并成单个命令：

- `graftcp` 是主入口。
- `mgraftcp` 保留为兼容别名。
- 不再需要单独启动本地守护进程。
- 不再使用 FIFO、`/proc` 扫描或 `netlink` 反查连接。
- 每次被拦截的连接都会分配一个唯一的 Loopback token IP，由内嵌本地代理在进程内直接回查原始目标地址。

和 `tsocks`、`proxychains`、`proxychains-ng` 不同，`graftcp` 仍然不依赖 `LD_PRELOAD`，所以对静态链接程序（例如大多数 Go 二进制）同样有效。

## 安装

`graftcp` 仅支持 Linux。构建需要 Go 和 C 工具链。

```sh
git clone https://github.com/hmgle/graftcp.git
cd graftcp
make
```

构建产物是 `local/graftcp`。`local/mgraftcp` 会作为兼容别名一并生成。

安装到系统：

```sh
sudo make install
```

## 用法

```console
$ ./local/graftcp --help
Usage: graftcp [-hn] [-b value] [--config value] [--disable-dns] [--disable-udp] [--dns-server value] [--enable-debug-log] [--enable-dns] [--enable-udp] [--http_proxy value] [--select_proxy_mode value] [--socks5 value] [--socks5_password value] [--socks5_username value] [-u value] [--version] [-w value] [parameters ...]
 -b, --blackip-file=value
                    The IP in black-ip-file will connect direct
     --config=value
                    Path to the configuration file
     --disable-dns  Disable DNS proxy
     --disable-udp  Disable generic UDP proxy
     --dns-server=value
                    DNS upstream server address, e.g.: 1.1.1.1:53 [1.1.1.1:53]
     --enable-debug-log
                    Enable debug log
     --enable-dns   Enable DNS proxy for UDP/53 queries
     --enable-udp   Enable generic UDP proxy
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
     --version      Print version information
 -w, --whiteip-file=value
                    Only redirect the connect that destination ip in the
                    white-ip-file to SOCKS5
```

示例：

```sh
./local/graftcp --socks5 127.0.0.1:1080 curl https://example.com
./local/graftcp --enable-dns --dns-server 1.1.1.1:53 curl https://example.com
./local/graftcp --enable-udp --socks5 127.0.0.1:1080 your-udp-client
./local/graftcp --http_proxy 127.0.0.1:8080 git clone https://github.com/hmgle/graftcp.git
./local/graftcp bash --rcfile <(echo 'PS1="(graftcp) $PS1"')
```

已经使用合并后二进制的用户仍可用 `mgraftcp`，用法与 `graftcp` 相同。

## 配置文件

`graftcp` 按下面顺序查找配置文件：

1. `--config` 指定的文件
2. `$(dirname $0)/graftcp.conf`
3. `$(dirname $0)/mgraftcp.conf`
4. `$XDG_CONFIG_HOME/graftcp/graftcp.conf`
5. `$XDG_CONFIG_HOME/mgraftcp/mgraftcp.conf`
6. `$HOME/.config/graftcp/graftcp.conf`
7. `$HOME/.config/mgraftcp/mgraftcp.conf`
8. `/etc/graftcp/graftcp.conf`
9. `/etc/mgraftcp/mgraftcp.conf`

示例配置见 [`example-graftcp.conf`](./example-graftcp.conf)。[`example-mgraftcp.conf`](./example-mgraftcp.conf) 作为别名名称的兼容示例保留。

配置项与命令行参数一一对应：`dns_proxy = true` -> `--enable-dns`，`udp_proxy = true` -> `--enable-udp`，`ignore_local = false` -> `--not-ignore-local`。命令行参数会覆盖配置文件。

## 工作原理

1. `graftcp` 先启动内嵌本地 TCP listener，再用 `ptrace(2)` 跟踪目标命令。
2. 每次拦截到 `connect(2)` 时，把原始目标地址登记到进程内路由表，并从 `127.0.0.0/8` 分配一个唯一 Loopback token IP。
3. 把 tracee 的目的 sockaddr 改写成这个 token IP 和内嵌 listener 的端口。
4. 内嵌 listener `accept` 到连接后，从 `LocalAddr()` 取出 token，直接在进程内解析出原始目标地址，再按 SOCKS5 / HTTP / direct 策略发起真实连接。
5. syscall 返回后，`graftcp` 会 best-effort 恢复 tracee 原始 `sockaddr` 缓冲区。

对 IPv6 `connect(2)`，当前实现会改写为 IPv4-mapped Loopback 地址 `::ffff:127.x.y.z`，从而复用同一套 token 路由逻辑。

启用 DNS 代理时，`graftcp` 还会启动一个内嵌 UDP DNS listener。目标端口为 53 的 UDP `connect()` 和 `sendto()` 会被改写到这个 listener，每个 DNS payload 再通过同一套 SOCKS5 / HTTP / direct 选择策略，以 TCP 方式转发到配置的上游 DNS 服务器。

启用通用 UDP 代理时，`graftcp` 会启动另一个内嵌 UDP listener。UDP `connect()`、`sendto()` 和 `sendmsg()` 的目标地址会被改写成 loopback token endpoint；内嵌 listener 再把 token 映射回原始目标地址，并在选中 SOCKS5 时通过 SOCKS5 UDP ASSOCIATE 转发，或在 `direct` 模式和 fallback 场景下用 direct UDP 转发。

## 说明

- 仅支持 Linux。
- 仍然受 `ptrace(2)` 权限限制；如果跟踪失败，请检查 Yama `ptrace_scope`、能力集或是否需要 root。
- 在支持的内核上，`graftcp` 会安装 seccomp-BPF 过滤器，使只有 socket 相关 syscall 才陷入 tracer，从而降低跟踪开销；在不支持 seccomp 过滤的内核上则回退为对每个 syscall 停点。该行为自动生效，无需配置。
- 默认忽略本地目标地址；如果希望本地连接也走代理，使用 `--not-ignore-local`。
- DNS 代理默认关闭；使用 `--enable-dns` 启用 UDP/53 DNS-over-TCP 路径，使用 `--dns-server` 指定上游服务器。
- 通用 UDP 代理默认关闭；使用 `--enable-udp` 启用。
- HTTP 代理模式不支持通用 UDP。`auto` 会优先尝试 SOCKS5 UDP，失败时回退 direct UDP；`only_http_proxy` 会拒绝通用 UDP session。
- 同时启用 DNS 和通用 UDP 时，UDP/53 优先走 DNS-over-TCP 路径。
- 配置文件支持代理地址和常见路由选项；命令行参数仍然覆盖配置文件。
- TCP 和 UDP syscall 地址缓冲区会在 `connect()` / `sendto()` / `sendmsg()` 返回后 best-effort 恢复；如果客户端强依赖 `recvfrom()` 返回原始远端地址，透明性仍可能不完整。
- IPv6 故意统一走 IPv4-mapped loopback；依赖 `IPV6_V6ONLY=1` 的 socket 不在当前设计目标内。
- socket 跟踪按被跟踪 pid/fd 状态做 best-effort；`dup*` 和 `fcntl(F_DUPFD*)` 会 best-effort 复制，但 `close_range()`、`unshare(CLONE_FILES)` 和完整共享 fd table 语义属于有意不覆盖的边界。
- loopback token 会在本地 listener 成功 `accept()` 或空闲清理时回收，不保证覆盖每一个失败或放弃的连接。
- 当前设计有意优先采用单进程 tracer/proxy 与 loopback token 路由，不再使用旧的守护进程、FIFO 和 socket 反查模型。

## FAQ 与技巧

### 目标地址是 localhost 时，`graftcp` 会重定向吗？

默认不会。本地目标地址会被忽略。使用 `--not-ignore-local` 可以一并重定向。想忽略更多地址，把它们加入 black-ip 文件（`-b`）；想只重定向特定地址，加入 white-ip 文件（`-w`）。详见 `graftcp --help`。

### 我正遭受 DNS 缓存投毒攻击，`graftcp` 能处理 DNS 吗？

可以。使用 `--enable-dns` 把 UDP/53 查询以 DNS-over-TCP 经选定代理转发，`--dns-server` 指定上游解析器。[`dnscrypt-proxy`](https://github.com/jedisct1/dnscrypt-proxy) 等工具仍是不错的补充。

### 运行 `graftcp yay` 或 `graftcp sudo ...` 报错退出，怎么办？

Arch Linux 上的 `yay` 实际会调用 `sudo pacman ...`，这要求 tracer 拥有跟踪子进程的权限。可以用 `sudo` 启动 `graftcp` 再切回当前用户执行命令：`sudo graftcp sudo -u $USER yay`，或 `sudo graftcp -u $USER sudo ...`。

如果觉得命令太长，可以给一份二进制副本赋予所需 capability：

```sh
cp local/graftcp sumg
sudo setcap 'cap_sys_ptrace,cap_sys_admin+ep' ./sumg
# ./sumg yay
# ./sumg sudo ...
```

### `clone(2)` 有 `CLONE_UNTRACED` 标志可以避免被跟踪，`graftcp` 如何强制跟踪？

`graftcp` 会拦截 `clone(2)` 并清除 `CLONE_UNTRACED`，使派生的子进程无法逃脱跟踪。（该标志是给内核用的，用户态程序本不应设置它。）Linux 还可通过 [`/proc/sys/kernel/yama/ptrace_scope`](https://www.kernel.org/doc/Documentation/security/Yama.txt) 限制 `ptrace(2)`；如果跟踪失败，请检查该值。

### 支持 macOS 吗？

不支持。macOS 的 `ptrace(2)` 能力不足以实现本工具。参见 [issue 12](https://github.com/hmgle/graftcp/issues/12)。

## TODO

- [ ] 虚拟化 `getpeername()` / `getsockname()`，使被跟踪程序能看到原始远端地址
- [ ] 覆盖批量发送的 `sendmmsg()`，补全通用 UDP 代理的 syscall 支持

## 感谢及参考

- [maybe](https://github.com/p-e-w/maybe), [proxychains](http://proxychains.sourceforge.net/) and [proxychains-ng](https://github.com/rofl0r/proxychains-ng) for inspiration
- [strace](https://strace.io/)
- [uthash](https://troydhanson.github.io/uthash/)

## 许可证

Copyright &copy; 2016, 2018-2026 Hmgle &lt;dustgle@gmail.com&gt;

以 [GNU General Public License, version 3](https://www.gnu.org/licenses/gpl-3.0.html) 条款发布。
