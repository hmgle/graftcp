# SOCKSPTRACE

Socksptrace is a proxy tool inspiring by [maybe](https://github.com/p-e-w/maybe) and [proxychains](https://github.com/haad/proxychains).
It hooks `connect(2)` funciton via `ptrace(2)` and redirects the connection through SOCKS5 proxies.
