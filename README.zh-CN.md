# graftcp

[English](./README.md) | **简体中文**

## 简介

`graftcp` 可以把任何指定程序（应用程序、脚本、shell 等）的 TCP 连接重定向到 SOCKS5 或 HTTP 代理。

对比 [tsocks](https://linux.die.net/man/8/tsocks)、[proxychains](http://proxychains.sourceforge.net/) 或 [proxychains-ng](https://github.com/rofl0r/proxychains-ng)，`graftcp` 并不使用 [LD_PRELOAD 技巧](https://stackoverflow.com/questions/426230/what-is-the-ld-preload-trick)来劫持共享库的 connect()、getaddrinfo()
等系列函数达到重定向目的，这种方法只对使用动态链接编译的程序有效，对于静态链接编译出来的程序，例如[默认选项编译的 Go 程序](https://golang.org/cmd/link/)，[proxychains-ng 就无效了](https://github.com/rofl0r/proxychains-ng/issues/199)。`graftcp` 使用 [`ptrace(2)`](https://en.wikipedia.org/wiki/Ptrace) 系统调用跟踪或修改任意指定程序的 connect 信息，对任何程序都有效。[工作原理](#principles)后面将会解释。

## 安装

### 源码安装

`graftcp` 在 Linux 系统内运行。 `graftcp-local` 使用 Go 编写, [Go](https://golang.org/doc/install) 环境是必需的。

```
git clone https://github.com/hmgle/graftcp.git
cd graftcp
make
```

make 执行完后，即可运行 `graftcp-local/graftcp-local` 和 `./graftcp`。可以把它们都安装进系统：

```sh
sudo make install
# Install systemed unit
sudo make install_systemd
# Activate systemd service
sudo make enable_systemd
```

### 二进制包安装

在 https://github.com/hmgle/graftcp/releases 下载 [Debian](https://github.com/hmgle/graftcp/releases/download/v0.4.0/graftcp_0.4.0-1_amd64.deb) 或者 [Arch Linux](https://github.com/hmgle/graftcp/releases/download/v0.4.0/graftcp-0.4.0-1-x86_64.pkg.tar.zst) 安装包并安装。

## 用法参数

`graftcp-local`:

```console
$ graftcp-local/graftcp-local -h
Usage of graftcp-local/graftcp-local:
  -config string
        Path to the configuration file
  -http_proxy string
        http proxy address, e.g.: 127.0.0.1:8080
  -listen string
        Listen address (default ":2233")
  -logfile string
        Write logs to file
  -loglevel value
        Log level (0-6) (default 1)
  -pipepath string
        Pipe path for graftcp to send address info (default "/tmp/graftcplocal.fifo")
  -select_proxy_mode string
        Set the mode for select a proxy [auto | random | only_http_proxy | only_socks5] (default "auto")
  -service string
        Control the system service: ["start" "stop" "restart" "install" "uninstall"]
  -socks5 string
        SOCKS5 address (default "127.0.0.1:1080")
  -syslog
        Send logs to the local system logger (Eventlog on Windows, syslog on Unix)
```

`graftcp`:

```console
$ graftcp -h
Usage: graftcp [options] prog [prog-args]

Options:
  -c --conf-file=<config-file-path>
                    Specify configuration file.
                    Default: $XDG_CONFIG_HOME/graftcp/graftcp.conf
  -a --local-addr=<graftcp-local-IP-addr>
                    graftcp-local's IP address. Default: localhost
  -p --local-port=<graftcp-local-port>
                    Which port is graftcp-local listening? Default: 2233
  -f --local-fifo=<fifo-path>
                    Path of fifo to communicate with graftcp-local.
                    Default: /tmp/graftcplocal.fifo
  -b --blackip-file=<black-ip-file-path>
                    The IP/CIDR in black-ip-file will connect direct
  -w --whiteip-file=<white-ip-file-path>
                    Only redirect the connect that destination IP/CIDR in
                    the white-ip-file to SOCKS5
  -n --not-ignore-local
                    Connecting to local is not changed by default, this
                    option will redirect it to SOCKS5
  -u --user=<username>
                    Run command as USERNAME handling setuid and/or setgid
  -V --version
                    Show version
  -h --help
                    Display this help and exit
```

`mgraftcp`: 是 `graftcp-local` 和 `graftcp` 的结合(`mgraftcp` = `graftcp-local` + `graftcp`)，可以用 `mgraftcp` 来代替 `graftcp` 而无需启动 `graftcp-local`。

```console
Usage: mgraftcp [-hn] [-b value] [--enable-debug-log] [--http_proxy value] [--select_proxy_mode value] \
    [--socks5 value] [--socks5_password value] [--socks5_username value] [--version] [-w value] prog [prog-args]
 -b, --blackip-file=value
                The IP/CIDR in black-ip-file will connect direct
     --enable-debug-log
                enable debug log
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
                Only redirect the connect that destination IP/CIDR in the
                white-ip-file to SOCKS5
```

### 配置文件

`graftcp-local` 和 `mgraftcp` 按下面的顺序查找配置文件：

1. 参数 `--config` 指定的文件
2. `$(可执行文件所在的目录)/graftcp-local.conf`
3. `$(XDG_CONFIG_HOME)/graftcp-local/graftcp-local.conf`, $XDG_CONFIG_HOME 缺省为 $HOME/.config.
4. `/etc/graftcp-local/graftcp-local.conf`

## 使用示例

假设你正在运行默认地址 "localhost:1080" 的 SOCKS5 代理，首先启动 `graftcp-local`：

```sh
graftcp-local/graftcp-local
```

通过 `graftcp` 安装来自 golang.org 的 Go 包:

```sh
./graftcp go get -v golang.org/x/net/proxy
```

通过 `graftcp` 打开 `Chromium` / `Chrome` / `Firefox` 浏览器，网页的所有请求都会重定向到 SOCKS5 代理：

```sh
./graftcp chromium-browser
```

通过 `graftcp` 启动 `Bash` / `Zsh` / `Fish`，在这个新开的 shell 里面执行的任何新命令产生的 TCP 连接都会重定向到 SOCKS5 代理：

```console
% ./graftcp bash
$ wget https://www.google.com
```

![demo](demo.gif)

<a id="principles"></a>

## 工作原理

要达到重定向一个 app 发起的的 TCP 连接到其他目标地址并且该 app 本身对此毫无感知的目的，大概需要这些条件：

- `fork(2)` 一个新进程，通过 `execve(2)` 启动该 app，并使用 `ptrace(2)` 进行跟踪，在 app 执行每一次 TCP 连接前，捕获并拦截这次 `connect(2)` 系统调用，获取目标地址的参数，并通过管道传给 `graftcp-local`。
- 修改这次 `connect(2)` 系统调用的目标地址参数为 `graftcp-local` 的地址，然后恢复执行被中断的系统调用。返回成功后，这个程序以为自己连的是原始的地址，但其实连的是 `graftcp-local` 的地址。这个就叫“移花接木”。
- `graftcp-local` 根据连接信息和目标地址信息，与 SOCKS5 proxy 建立连接，把 app 的请求的数据重定向到 SOCKS5 proxy。

这里可能有个疑问：既然可以修改任何系统调用的参数，那么通过修改 app 的 `write(2)` / `send(2)` 的参数，直接往 `buffer` 里面附加原始目标地址信息给 `graftcp-local` 不是更简单吗？答案是这无法做到。如果直接往运行在子进程的被跟踪程序的 `buffer` 添加信息，可能会造成缓冲区溢出，造成程序崩溃或者覆盖了其他数据。
另外，[`execve(2)` 会分离所有的共享内存](http://man7.org/linux/man-pages/man2/execve.2.html)，所以也不能通过共享内存的方式让被跟踪的 app 的 `write` buffer 携带更多的数据，因此这里采用管道方式给 `graftcp-local` 传递原始的目标地址信息。

简单的流程如下：

```
+---------------+             +---------+         +--------+         +------+
|   graftcp     |  dest host  |         |         |        |         |      |
|   (tracer)    +---PIPE----->|         |         |        |         |      |
|      ^        |  info       |         |         |        |         |      |
|      | ptrace |             |         |         |        |         |      |
|      v        |             |         |         |        |         |      |
|  +---------+  |             |         |         |        |         |      |
|  |         |  |  connect    |         | connect |        | connect |      |
|  |         +--------------->| graftcp +-------->| SOCKS5 +-------->| dest |
|  |         |  |             | -local  |         |  or    |         | host |
|  |  app    |  |  req        |         |  req    | HTTP   |  req    |      |
|  |(tracee) +--------------->|         +-------->| proxy  +-------->|      |
|  |         |  |             |         |         |        |         |      |
|  |         |  |  resp       |         |  resp   |        |  resp   |      |
|  |         |<---------------+         |<--------+        |<--------+      |
|  +---------+  |             |         |         |        |         |      |
+---------------+             +---------+         +--------+         +------+
```

## 常见问题解答及技巧

### 有哪些重定向 TCP 连接的方式？

主要有： 全局式、设置环境变量式和仅针对程序（或进程）式。

全局式：比如使用 `iptables` + `RedSocks` 可以把系统符合一定规则的流量转换为 SOCKS5 流量。这种方式的优点是全局有效；缺点是所有满足该规则的流量都被重定向了，影响范围较大。

设置环境变量方式：一些程序启动时会读取 proxy 相关的环境变量来决定是否将自己的数据转换为对应代理协议的流量，比如 `curl` 会[读取 `http_proxy`, `ftp_proxy`, `all_proxy` 环境变量并根据请求 scheme 来决定转换为哪种代理流量](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html)。这种方法只有程序本身实现了转换的功能才有效，局限性较大。

仅针对程序方式： 这种方式可以仅针对特定的程序执行重定向，比如 `tsocks` 或 `proxychains`。如前面提到，它们之前都是使用 `LD_PRELOAD` 劫持动态库方式实现，对 `Go` 之类默认静态链接编译的程序就无效了。`graftcp` 改进了这一点，能够重定向任何程序的 TCP 连接。

### 如果应用程序连接的目标地址是本机，使用 `graftcp` 会把该连接重定向到 SOCKS5 代理吗？

不会。默认会忽略目标地址为本地的连接，如果想重定向所有地址的话，可以使用 `-n`选项。如果想忽略更多的地址，可以把它们加入黑名单 IP 文件；如果想仅重定向某些 IP 地址，可以把这些地址加入白名单 IP 文件。使用 `graftcp --help` 获取设置参数。

### 我的 DNS 请求受到污染，`graftcp` 会处理 DNS 请求吗？

不会。`graftcp` 目前仅处理 TCP 连接。建议使用 `dnscrypt-proxy` 或 `ChinaDNS` 等方式解决 DNS 污染问题。

### 运行 `[m]graftcp yay` 或者 `graftcp sudo ...` 报错并退出，该如何解决？

Arch Linux 的 `yay` 实际也会调用 `sudo pacman ...`，这需要 tracer 具备 root 特权才能获取到跟踪子进程的权限。可以用 sudo 来启动 `[m]graftcp`，并指定当前用户运行后续命令：`sudo [m]graftcp sudo -u $USER yay`，或者 `sudo [m]graftcp -u $USER sudo ...`。
如何觉得上面命令太长，可以复制一个具有 CAP_SYS_PTRACE 和 CAP_SYS_ADMIN capabilities 的 [m]graftcp 副本：

```sh
cp mgraftcp sumg
sudo setcap 'cap_sys_ptrace,cap_sys_admin+ep' ./sumg
# ./sumg yay
# ./sumg sudo ...
```

### `clone(2)` 参数有个叫 `CLONE_UNTRACED` 的标志位，可以避免让父进程跟踪到自己，`graftcp` 是如何做到强制跟踪的？

`graftcp` 在子进程调用 `clone(2)` 之前会把它拦截，清除这个 `CLONE_UNTRACED` 标志位，所以被跟踪的子进程最终还是难逃被跟踪的命运。另外，这个 `CLONE_UNTRACED` 标志位本意是给内核使用的，普通程序不应该去设置它。

Linux 提供了一种限制被 `ptrace(2)` 跟踪的方法：设置 [`/proc/sys/kernel/yama/ptrace_scope`](https://www.kernel.org/doc/Documentation/security/Yama.txt) 的值，若 `ptrace(2)` 失效，请检查该值是否被修改过。

### 支持 macOS 吗？

不。macOS 的 [`ptrace(2)`](http://polarhome.com/service/man/?qf=ptrace&af=0&sf=0&of=Darwin&tf=2) 是个半残品。~~不过理论上参考 DTrace 那一套也能实现~~，见[issue 12](https://github.com/hmgle/graftcp/issues/12)。

## TODO

- [x] ARM/Linux 支持
- [x] i386/Linux 支持
- [ ] UDP 支持

## 感谢及参考

- [maybe](https://github.com/p-e-w/maybe), [proxychains](http://proxychains.sourceforge.net/) and [proxychains-ng](https://github.com/rofl0r/proxychains-ng) for inspiration
- [strace](https://strace.io/)
- [uthash](https://troydhanson.github.io/uthash/)
- [service](https://github.com/kardianos/service)
- [dlog](https://github.com/jedisct1/dlog)

## License

Copyright &copy; 2016, 2018-2024 Hmgle <dustgle@gmail.com>

根据 [GPLv3 许可](https://www.gnu.org/licenses/gpl-3.0.html)发布。
