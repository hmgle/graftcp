/*
 * graftcp
 * Copyright (C) 2016, 2018-2026 Hmgle <dustgle@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <stddef.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <netinet/udp.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define ENABLE_SECCOMP_BPF
#endif
#ifdef ENABLE_SECCOMP_BPF
#include <linux/seccomp.h>
#include <linux/filter.h>
#endif /* ifdef ENABLE_SECCOMP_BPF */

#include "graftcp.h"
#include "cidr-trie.h"

#ifndef VERSION
#define VERSION "v0.7"
#endif

#ifdef SYS_close_range
/* Values from the Linux UAPI, also usable with older C library headers. */
#define GRAFTCP_CLOSE_RANGE_UNSHARE (1U << 1)
#define GRAFTCP_CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#ifndef PTRACE_O_EXITKILL
/* glibc declares this option as an enum, so use its Linux ABI value. */
#define PTRACE_O_EXITKILL (1U << 20)
#endif

extern uint32_t mgraftcp_register_connect(int family, const char *addr,
					  uint16_t port);
extern uint32_t mgraftcp_reserve_udp(int family, const char *addr,
				      uint16_t port);
extern void mgraftcp_forget_connect(uint32_t token);
extern void mgraftcp_finish_udp_rewrite(uint32_t token, int rewritten);
extern void mgraftcp_start_udp_use(uint32_t token);
extern void mgraftcp_finish_udp_use(uint32_t token, int accepted);

uint16_t DEFAULT_LOCAL_PORT      = 2233;
bool DEFAULT_IGNORE_LOCAL        = true;
uint16_t LOCAL_PROXY_PORT;
uint16_t DNS_PROXY_PORT;
uint16_t UDP_PROXY_PORT;

cidr_trie_t *BLACKLIST_IP     = NULL;
cidr_trie_t *WHITELIST_IP = NULL;


static uid_t run_uid;
static gid_t run_gid;
static char *run_home;
static gid_t *run_groups;
static int run_group_count;

static int exit_code = 0;
static pid_t root_pid = -1;
static int startup_fd = -1;
struct tracee_queue {
	struct proc_info *head;
	struct proc_info *tail;
};

static struct tracee_queue creators;
static struct tracee_queue waiting_children;
static uint64_t creation_seq;

/* Only used when a child dies before its creator reports its PID. */
struct reaped_child {
	pid_t pid;
	uint64_t creation_seq;
	struct reaped_child *next;
};
static struct reaped_child *reaped_children;

static void child_write_str(const char *s)
{
	size_t len = 0;

	while (s[len] != '\0')
		len++;
	while (len > 0) {
		ssize_t written = write(STDERR_FILENO, s, len);

		if (written <= 0)
			return;
		s += written;
		len -= (size_t)written;
	}
}

static void child_write_errno(int err)
{
	char buf[32];
	size_t pos = sizeof(buf);
	unsigned int val = err < 0 ? (unsigned int)-err : (unsigned int)err;

	buf[--pos] = '\0';
	if (val == 0) {
		buf[--pos] = '0';
	} else {
		while (val > 0 && pos > 0) {
			buf[--pos] = (char)('0' + (val % 10));
			val /= 10;
		}
	}
	child_write_str(&buf[pos]);
}

static void child_die_errno(const char *what)
{
	int err = errno;

	child_write_str("graftcp: ");
	child_write_str(what);
	child_write_str(" failed: errno ");
	child_write_errno(err);
	child_write_str("\n");
	_exit(err == 0 ? 1 : err);
}

/* xstrdup duplicates s and exits the process if allocation fails. The CLI
 * setup paths are not in a position to recover from OOM and would otherwise
 * each open-code the same perror+exit. */
static char *xstrdup(const char *s)
{
	char *copy = strdup(s);

	if (copy == NULL) {
		perror("strdup");
		exit(1);
	}
	return copy;
}

static uint16_t parse_port(const char *value, const char *option)
{
	char *end;
	unsigned long port;

	if (value == NULL || *value == '\0') {
		fprintf(stderr, "%s requires a port in 1..65535\n", option);
		exit(1);
	}
	errno = 0;
	port = strtoul(value, &end, 10);
	if (errno != 0 || *end != '\0' || port == 0 || port > UINT16_MAX) {
		fprintf(stderr, "%s invalid port '%s'; expected 1..65535\n",
			option, value);
		exit(1);
	}
	return (uint16_t)port;
}

static bool port_matches(uint16_t port, uint16_t expected)
{
	return expected != 0 && ntohs(port) == expected;
}

static bool is_loopback4(uint32_t ip)
{
	return (ntohl(ip) & 0xff000000U) == 0x7f000000U;
}

static bool is_internal_proxy_endpoint4(const struct sockaddr_in *sa,
					bool stream)
{
	if (!is_loopback4(sa->sin_addr.s_addr))
		return false;
	if (stream)
		return port_matches(sa->sin_port, LOCAL_PROXY_PORT);
	return port_matches(sa->sin_port, DNS_PROXY_PORT) ||
	       port_matches(sa->sin_port, UDP_PROXY_PORT);
}

static bool is_internal_proxy_endpoint6(const struct sockaddr_in6 *sa6,
					bool stream)
{
	const struct in6_addr *addr = &sa6->sin6_addr;
	uint32_t mapped4;
	bool loopback;

	if (IN6_IS_ADDR_LOOPBACK(addr))
		loopback = true;
	else if (IN6_IS_ADDR_V4MAPPED(addr)) {
		memcpy(&mapped4, addr->s6_addr + 12, sizeof(mapped4));
		loopback = is_loopback4(mapped4);
	} else {
		loopback = false;
	}
	if (!loopback)
		return false;
	if (stream)
		return port_matches(sa6->sin6_port, LOCAL_PROXY_PORT);
	return port_matches(sa6->sin6_port, DNS_PROXY_PORT) ||
	       port_matches(sa6->sin6_port, UDP_PROXY_PORT);
}

static void build_loopback_sockaddr4(struct sockaddr_in *sa, uint32_t token,
				     uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_port = htons(port);
	sa->sin_addr.s_addr = htonl(token);
}

static void build_loopback_sockaddr6(struct sockaddr_in6 *sa6, uint32_t token,
				     uint16_t port)
{
	uint32_t token_network = htonl(token);

	memset(sa6, 0, sizeof(*sa6));
	sa6->sin6_family = AF_INET6;
	sa6->sin6_port = htons(port);
	sa6->sin6_addr.s6_addr[10] = 0xff;
	sa6->sin6_addr.s6_addr[11] = 0xff;
	memcpy(sa6->sin6_addr.s6_addr + 12, &token_network,
	       sizeof(token_network));
}

static void build_dns_sockaddr6(struct sockaddr_in6 *sa6, uint16_t port)
{
	memset(sa6, 0, sizeof(*sa6));
	sa6->sin6_family = AF_INET6;
	sa6->sin6_port = htons(port);
	sa6->sin6_addr.s6_addr[15] = 1;
}

static bool ip4_is_ignore(uint32_t ip);
static bool ip6_is_ignore(uint8_t *ip);

/* dest_endpoint normalizes a tracee's destination sockaddr. */
struct dest_endpoint {
	sa_family_t family;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} sa;
	socklen_t len;
	uint16_t port;
	char ipstr[INET6_ADDRSTRLEN];
};

/* read_dest_endpoint pulls a sockaddr from the tracee at addr/addrlen and
 * fills the textual ip string for downstream registration. Returns false when
 * the address family is unsupported or the read fails.
 */
static bool read_dest_endpoint(pid_t pid, long addr, long addrlen,
			       struct dest_endpoint *out)
{
	sa_family_t family;

	if (addr == 0 || addrlen < (long)sizeof(family))
		return false;
	if (getdata(pid, addr, &family, sizeof(family)) < 0)
		return false;
	memset(out, 0, sizeof(*out));
	out->family = family;

	switch (family) {
	case AF_INET:
		if (addrlen < (long)sizeof(out->sa.v4))
			return false;
		if (getdata(pid, addr, &out->sa.v4, sizeof(out->sa.v4)) < 0)
			return false;
		out->len = sizeof(out->sa.v4);
		out->port = ntohs(SOCKPORT(out->sa.v4));
		if (inet_ntop(AF_INET, &out->sa.v4.sin_addr, out->ipstr,
			      sizeof(out->ipstr)) == NULL)
			return false;
		return true;
	case AF_INET6:
		if (addrlen < (long)sizeof(out->sa.v6))
			return false;
		if (getdata(pid, addr, &out->sa.v6, sizeof(out->sa.v6)) < 0)
			return false;
		out->len = sizeof(out->sa.v6);
		out->port = ntohs(SOCKPORT6(out->sa.v6));
		if (inet_ntop(AF_INET6, &out->sa.v6.sin6_addr, out->ipstr,
			      sizeof(out->ipstr)) == NULL)
			return false;
		return true;
	default:
		return false;
	}
}

/* dest_is_internal_proxy reports whether dest names one of the embedded
 * loopback proxy listeners we just installed, so we don't recurse into
 * ourselves.
 */
static bool dest_is_internal_proxy(const struct dest_endpoint *dest, bool stream)
{
	if (dest->family == AF_INET)
		return is_internal_proxy_endpoint4(&dest->sa.v4, stream);
	return is_internal_proxy_endpoint6(&dest->sa.v6, stream);
}

/* dest_is_in_ignore_list reports whether dest's address is on the user-supplied
 * blacklist or outside the user-supplied whitelist.
 */
static bool dest_is_in_ignore_list(struct dest_endpoint *dest)
{
	if (dest->family == AF_INET)
		return ip4_is_ignore(dest->sa.v4.sin_addr.s_addr);
	return ip6_is_ignore(dest->sa.v6.sin6_addr.s6_addr);
}

/* write_loopback_token rewrites the tracee's destination sockaddr at addr to
 * point at the loopback token, returning a pointer to the buffer that was
 * written (so callers can save the original for restore_sockaddr_if_needed).
 */
static bool write_loopback_token(pid_t pid, long addr,
				 const struct dest_endpoint *dest,
				 uint32_t token, uint16_t loopback_port)
{
	if (dest->family == AF_INET) {
		struct sockaddr_in proxy_sa;

		build_loopback_sockaddr4(&proxy_sa, token, loopback_port);
		return putdata(pid, addr, &proxy_sa, sizeof(proxy_sa)) == 0;
	}
	struct sockaddr_in6 proxy_sa6;

	build_loopback_sockaddr6(&proxy_sa6, token, loopback_port);
	return putdata(pid, addr, &proxy_sa6, sizeof(proxy_sa6)) == 0;
}

static void load_ip_file(char *path, cidr_trie_t **trie)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	unsigned int line_no = 0;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("fopen");
		exit(1);
	}
	while ((read = getline(&line, &len, f)) != -1) {
		line_no++;
		while (read > 0 && isspace((unsigned char)line[read - 1]))
			line[--read] = '\0';

		/* skip empty lines; let the parser validate the rest */
		if (read == 0)
			continue;
		if (*trie == NULL) {
			*trie = cidr_trie_new();
			if (*trie == NULL) {
				perror("calloc");
				exit(1);
			}
		}
		if (cidr_trie_insert_str(*trie, line, 1) < 0)
			fprintf(stderr, "%s:%u: invalid CIDR entry: %s\n",
				path, line_no, line);
	}
	free(line);
	fclose(f);
}

static bool ip4_is_ignore(uint32_t ip)
{
	if (BLACKLIST_IP) {
		if (cidr4_trie_lookup(BLACKLIST_IP, ntohl(ip)))
			return true;
	}
	if (WHITELIST_IP) {
		if (!cidr4_trie_lookup(WHITELIST_IP, ntohl(ip)))
			return true;
	}
	return false;
}

static bool ip6_is_ignore(uint8_t *ip)
{
	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)ip)) {
		uint32_t v4;
		memcpy(&v4, ip + 12, sizeof(v4));
		return ip4_is_ignore(v4);
	}
	if (BLACKLIST_IP) {
		if (cidr6_trie_lookup(BLACKLIST_IP, ip))
			return true;
	}
	if (WHITELIST_IP) {
		if (!cidr6_trie_lookup(WHITELIST_IP, ip))
			return true;
	}
	return false;
}

#ifdef ENABLE_SECCOMP_BPF
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SECCOMP_ARG_LO32_OFFSET(arg)					\
	(offsetof(struct seccomp_data, args[arg]) + sizeof(uint32_t))
#else
#define SECCOMP_ARG_LO32_OFFSET(arg)					\
		offsetof(struct seccomp_data, args[arg])
#endif
#define SECCOMP_SOCKET_ARG_FILTER_LEN 7
#ifdef SYS_dup2
#define SECCOMP_TRACE_DUP2(base)					\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_dup2,			\
		 SECCOMP_JUMP_OFFSET(base##_DUP2, base##_RET_TRACE), 0),
#else
#define SECCOMP_TRACE_DUP2(base)
#endif
#ifdef SYS_fcntl64
#define SECCOMP_TRACE_FCNTL64(base)					\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fcntl64,		\
		 SECCOMP_JUMP_OFFSET(base##_FCNTL64, base##_RET_TRACE), 0),
#else
#define SECCOMP_TRACE_FCNTL64(base)
#endif
#ifdef SYS_clone3
#define SECCOMP_TRACE_CLONE3(base) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, \
		 SECCOMP_JUMP_OFFSET(base##_CLONE3, base##_RET_TRACE), 0),
#else
#define SECCOMP_TRACE_CLONE3(base)
#endif
#ifdef SYS_fork
#define SECCOMP_TRACE_FORK(base) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fork, \
		 SECCOMP_JUMP_OFFSET(base##_FORK, base##_RET_TRACE), 0),
#else
#define SECCOMP_TRACE_FORK(base)
#endif
#ifdef SYS_vfork
#define SECCOMP_TRACE_VFORK(base) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_vfork, \
		 SECCOMP_JUMP_OFFSET(base##_VFORK, base##_RET_TRACE), 0),
#else
#define SECCOMP_TRACE_VFORK(base)
#endif
#ifdef SYS_close_range
#define SECCOMP_TRACE_CLOSE_RANGE(base) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close_range, \
		 SECCOMP_JUMP_OFFSET(base##_CLOSE_RANGE, base##_RET_TRACE), 0),
#else
#define SECCOMP_TRACE_CLOSE_RANGE(base)
#endif
#define SECCOMP_TRACE_FD_TABLE(base) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, \
		 SECCOMP_JUMP_OFFSET(base##_CLONE, base##_RET_TRACE), 0), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unshare, \
		 SECCOMP_JUMP_OFFSET(base##_UNSHARE, base##_RET_TRACE), 0), \
	SECCOMP_TRACE_CLONE3(base) \
	SECCOMP_TRACE_FORK(base) \
	SECCOMP_TRACE_VFORK(base) \
	SECCOMP_TRACE_CLOSE_RANGE(base) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, \
		 SECCOMP_JUMP_OFFSET(base##_IOCTL, base##_IOCTL_ARGS), 0),
#define SECCOMP_TRACE_DUP_SYSCALLS(base)				\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_dup,			\
		 SECCOMP_JUMP_OFFSET(base##_DUP, base##_RET_TRACE), 0),	\
	SECCOMP_TRACE_DUP2(base)					\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_dup3,			\
		 SECCOMP_JUMP_OFFSET(base##_DUP3, base##_RET_TRACE), 0), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fcntl,			\
		 SECCOMP_JUMP_OFFSET(base##_FCNTL, base##_RET_TRACE), 0), \
	SECCOMP_TRACE_FCNTL64(base)
#define SECCOMP_JUMP_OFFSET(from, to) ((to) - (from) - 1)
#define SECCOMP_LAYOUT_CHECK(name, expr)				\
	enum { name = 1 / !!(expr) }
#define SECCOMP_IOCTL_ARG_FILTER(base)					\
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_ARG_LO32_OFFSET(1)),	\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIOCLEX,			\
		 SECCOMP_JUMP_OFFSET(base##_FIOCLEX, base##_RET_TRACE), 0), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONCLEX,			\
		 SECCOMP_JUMP_OFFSET(base##_FIONCLEX, base##_RET_TRACE),	\
		 SECCOMP_JUMP_OFFSET(base##_FIONCLEX, base##_RET_ALLOW))
/*
 * These checks only need the low 32 bits of seccomp_data.args[]. Keep
 * SECCOMP_SOCKET_ARG_FILTER_LEN in sync with this macro, and keep the macro
 * immediately followed by RET TRACE and then RET ALLOW: its internal jumps
 * target those two return instructions by relative offset.
 */
#define SECCOMP_SOCKET_ARG_FILTER					\
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,				\
		 SECCOMP_ARG_LO32_OFFSET(0)),				\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0),		\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 5),	\
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,				\
		 SECCOMP_ARG_LO32_OFFSET(1)),				\
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK),		\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 1, 0),	\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_DGRAM, 0, 1)
static void install_seccomp()
{
	enum {
		FILTER_LD_NR,
		FILTER_CLOSE,
		FILTER_SOCKET,
		FILTER_CONNECT,
		FILTER_CLONE,
		FILTER_UNSHARE,
#ifdef SYS_clone3
		FILTER_CLONE3,
#endif
#ifdef SYS_fork
		FILTER_FORK,
#endif
#ifdef SYS_vfork
		FILTER_VFORK,
#endif
#ifdef SYS_close_range
		FILTER_CLOSE_RANGE,
#endif
		FILTER_IOCTL,
		FILTER_DUP,
	#ifdef SYS_dup2
		FILTER_DUP2,
	#endif
		FILTER_DUP3,
		FILTER_FCNTL,
	#ifdef SYS_fcntl64
		FILTER_FCNTL64,
	#endif
		FILTER_ALLOW_JUMP,
		FILTER_IOCTL_ARGS,
		FILTER_FIOCLEX,
		FILTER_FIONCLEX,
		FILTER_SOCKET_ARGS,
		FILTER_RET_TRACE =
			FILTER_SOCKET_ARGS + SECCOMP_SOCKET_ARG_FILTER_LEN,
		FILTER_RET_ALLOW,
	};
	enum {
		UDP_FILTER_LD_NR,
		UDP_FILTER_CLOSE,
		UDP_FILTER_SOCKET,
		UDP_FILTER_CONNECT,
		UDP_FILTER_SENDTO,
		UDP_FILTER_SENDMSG,
		UDP_FILTER_SETSOCKOPT,
		UDP_FILTER_CLONE,
		UDP_FILTER_UNSHARE,
#ifdef SYS_clone3
		UDP_FILTER_CLONE3,
#endif
#ifdef SYS_fork
		UDP_FILTER_FORK,
#endif
#ifdef SYS_vfork
		UDP_FILTER_VFORK,
#endif
#ifdef SYS_close_range
		UDP_FILTER_CLOSE_RANGE,
#endif
		UDP_FILTER_IOCTL,
		UDP_FILTER_DUP,
	#ifdef SYS_dup2
		UDP_FILTER_DUP2,
	#endif
		UDP_FILTER_DUP3,
		UDP_FILTER_FCNTL,
	#ifdef SYS_fcntl64
		UDP_FILTER_FCNTL64,
	#endif
		UDP_FILTER_ALLOW_JUMP,
		UDP_FILTER_IOCTL_ARGS,
		UDP_FILTER_FIOCLEX,
		UDP_FILTER_FIONCLEX,
		UDP_FILTER_SOCKET_ARGS,
		UDP_FILTER_RET_TRACE =
			UDP_FILTER_SOCKET_ARGS + SECCOMP_SOCKET_ARG_FILTER_LEN,
		UDP_FILTER_RET_ALLOW,
	};
	/*
	 * Trace socket() only for IPv4/IPv6 stream or datagram sockets. The
	 * syscall handlers still do the stateful checks after ptrace has access
	 * to registers.
	 */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,
			 SECCOMP_JUMP_OFFSET(FILTER_CLOSE, FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket,
			 SECCOMP_JUMP_OFFSET(FILTER_SOCKET, FILTER_SOCKET_ARGS), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect,
			 SECCOMP_JUMP_OFFSET(FILTER_CONNECT, FILTER_RET_TRACE), 0),
		SECCOMP_TRACE_FD_TABLE(FILTER)
		SECCOMP_TRACE_DUP_SYSCALLS(FILTER)
		BPF_STMT(BPF_JMP | BPF_JA,
			 SECCOMP_JUMP_OFFSET(FILTER_ALLOW_JUMP,
					     FILTER_RET_ALLOW)),
		SECCOMP_IOCTL_ARG_FILTER(FILTER),
		SECCOMP_SOCKET_ARG_FILTER,
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	SECCOMP_LAYOUT_CHECK(filter_layout_check,
			     ARRAY_SIZE(filter) == FILTER_RET_ALLOW + 1);
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	struct sock_filter udp_filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_CLOSE,
					     UDP_FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_SOCKET,
					     UDP_FILTER_SOCKET_ARGS), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_CONNECT,
					     UDP_FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_SENDTO,
					     UDP_FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_SENDMSG,
					     UDP_FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setsockopt,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_SETSOCKOPT,
					     UDP_FILTER_RET_TRACE), 0),
		SECCOMP_TRACE_FD_TABLE(UDP_FILTER)
		SECCOMP_TRACE_DUP_SYSCALLS(UDP_FILTER)
		BPF_STMT(BPF_JMP | BPF_JA,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_ALLOW_JUMP,
					     UDP_FILTER_RET_ALLOW)),
		SECCOMP_IOCTL_ARG_FILTER(UDP_FILTER),
		SECCOMP_SOCKET_ARG_FILTER,
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	SECCOMP_LAYOUT_CHECK(udp_filter_layout_check,
			     ARRAY_SIZE(udp_filter) ==
			     UDP_FILTER_RET_ALLOW + 1);
	struct sock_fprog udp_prog = {
		.len = (unsigned short)ARRAY_SIZE(udp_filter),
		.filter = udp_filter,
	};
	if (DNS_PROXY_PORT != 0 || UDP_PROXY_PORT != 0)
		prog = udp_prog;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0)
		return;
	if (errno == EACCES) {
		/*
		 * https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
		 *  Filters installed for the seccomp mode 2 sandbox persist across
		 *  execve and can change the behavior of newly-executed programs.
		 *  Unprivileged users are therefore only allowed to install such filters
		 *  if no_new_privs is set.
		 */
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			child_die_errno("prctl(PR_SET_NO_NEW_PRIVS)");
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
			child_die_errno("prctl(PR_SET_SECCOMP)");
		return;
	}
	child_die_errno("prctl(PR_SET_SECCOMP)");
}
#endif

void socket_pre_handle(struct proc_info *pinfp)
{
	int domain = get_syscall_arg(pinfp->pid, 0);
	int type = get_syscall_arg(pinfp->pid, 1);
	int socket_type = type & SOCK_TYPE_MASK;

#ifndef ENABLE_SECCOMP_BPF
	if (domain != AF_INET && domain != AF_INET6)
		return;
	if (socket_type != SOCK_STREAM && socket_type != SOCK_DGRAM)
		return;
#endif
	if (socket_type == SOCK_DGRAM) {
		int protocol;

		if (DNS_PROXY_PORT == 0 && UDP_PROXY_PORT == 0)
			return;

		protocol = get_syscall_arg(pinfp->pid, 2);
		if (protocol != 0 && protocol != IPPROTO_UDP)
			return;
	}
	pinfp->pending_socket = true;
	pinfp->pending_socket_domain = domain;
	pinfp->pending_socket_type = type;
}

static void clear_dup_tracking(struct proc_info *pinfp)
{
	if (pinfp == NULL)
		return;
	pinfp->pending_dup = false;
	pinfp->pending_dup_oldfd = -1;
	pinfp->pending_dup_newfd = -1;
	pinfp->pending_dup_fixed = false;
	pinfp->pending_dup_cloexec = false;
}

static void clear_sockaddr_restore(struct proc_info *pinfp)
{
	if (pinfp == NULL)
		return;
	pinfp->pending_sockaddr_restore = false;
	pinfp->sockaddr_restore_addr = 0;
	pinfp->sockaddr_restore_len = 0;
}

static void save_sockaddr_restore(struct proc_info *pinfp, long addr,
				  const void *sockaddr, size_t len)
{
	if (pinfp == NULL || addr == 0 || sockaddr == NULL ||
	    len > sizeof(pinfp->sockaddr_restore))
		return;
	pinfp->pending_sockaddr_restore = true;
	pinfp->sockaddr_restore_addr = addr;
	pinfp->sockaddr_restore_len = len;
	memcpy(pinfp->sockaddr_restore, sockaddr, len);
}

static void restore_sockaddr_if_needed(struct proc_info *pinfp)
{
	if (pinfp == NULL || !pinfp->pending_sockaddr_restore)
		return;
	if (putdata(pinfp->pid, pinfp->sockaddr_restore_addr,
		    pinfp->sockaddr_restore, pinfp->sockaddr_restore_len) < 0)
		fprintf(stderr, "graftcp restore sockaddr failed\n");
	clear_sockaddr_restore(pinfp);
}

static bool rewrite_udp_sockaddr(struct proc_info *pinfp, long addr,
				 long addrlen, bool may_retain_dest)
{
	struct dest_endpoint dest;
	uint32_t loopback_token;
	bool rewritten;

	if (pinfp == NULL)
		return false;
	if ((DNS_PROXY_PORT == 0 && UDP_PROXY_PORT == 0) || addr == 0)
		return false;
	if (!read_dest_endpoint(pinfp->pid, addr, addrlen, &dest))
		return false;
	if (dest_is_internal_proxy(&dest, false))
		return false;

	if (DNS_PROXY_PORT != 0 && dest.port == 53) {
		bool ok;

		if (dest.family == AF_INET) {
			struct sockaddr_in dns_sa;

			build_loopback_sockaddr4(&dns_sa, 0x7f000001, DNS_PROXY_PORT);
			ok = putdata(pinfp->pid, addr, &dns_sa, sizeof(dns_sa)) == 0;
		} else {
			struct sockaddr_in6 dns_sa6;

			build_dns_sockaddr6(&dns_sa6, DNS_PROXY_PORT);
			ok = putdata(pinfp->pid, addr, &dns_sa6, sizeof(dns_sa6)) == 0;
		}
		if (!ok) {
			fprintf(stderr, "graftcp rewrite DNS UDP failed\n");
		}
		return true;
	}

	if (UDP_PROXY_PORT == 0 || dest_is_in_ignore_list(&dest))
		return false;

	loopback_token = mgraftcp_reserve_udp(dest.family, dest.ipstr, dest.port);
	if (loopback_token == 0) {
		fprintf(stderr, "graftcp reserve UDP failed for %s:%d\n",
			dest.ipstr, dest.port);
		return false;
	}
	rewritten = write_loopback_token(pinfp->pid, addr, &dest,
					     loopback_token, UDP_PROXY_PORT);
	if (!rewritten) {
		fprintf(stderr, "graftcp rewrite UDP failed for %s:%d\n",
			dest.ipstr, dest.port);
		mgraftcp_finish_udp_rewrite(loopback_token, false);
	} else {
		if (may_retain_dest) {
			mgraftcp_start_udp_use(loopback_token);
			pinfp->pending_udp_token = loopback_token;
		} else {
			mgraftcp_finish_udp_rewrite(loopback_token, true);
		}
		save_sockaddr_restore(pinfp, addr, &dest.sa, dest.len);
	}
	return true;
}

static void tcp_connect_pre_handle(struct proc_info *pinfp)
{
	long addr = get_syscall_arg(pinfp->pid, 1);
	long addrlen = get_syscall_arg(pinfp->pid, 2);
	struct dest_endpoint dest;
	uint32_t loopback_token;

	if (!read_dest_endpoint(pinfp->pid, addr, addrlen, &dest))
		return;
	if (dest_is_internal_proxy(&dest, true))
		return;
	if (dest_is_in_ignore_list(&dest))
		return;

	loopback_token = mgraftcp_register_connect(dest.family, dest.ipstr,
						   dest.port);
	if (loopback_token == 0) {
		fprintf(stderr, "graftcp register connect failed for %s:%d\n",
			dest.ipstr, dest.port);
		return;
	}
	if (!write_loopback_token(pinfp->pid, addr, &dest, loopback_token,
				  LOCAL_PROXY_PORT)) {
		fprintf(stderr, "graftcp rewrite connect failed for %s:%d\n",
			dest.ipstr, dest.port);
		mgraftcp_forget_connect(loopback_token);
		return;
	}
	save_sockaddr_restore(pinfp, addr, &dest.sa, dest.len);
}

void connect_pre_handle(struct proc_info *pinfp)
{
	int socket_fd = get_syscall_arg(pinfp->pid, 0);
	long addr;
	long addrlen;

	if (is_tracked_stream_socket_fd(pinfp, socket_fd)) {
		tcp_connect_pre_handle(pinfp);
		return;
	}
	if (!is_tracked_dgram_socket_fd(pinfp, socket_fd))
		return;

	addr = get_syscall_arg(pinfp->pid, 1);
	addrlen = get_syscall_arg(pinfp->pid, 2);
	rewrite_udp_sockaddr(pinfp, addr, addrlen, true);
}

static bool udp_send_may_retain_dest(struct proc_info *pinfp, int fd, int flags_arg)
{
	long flags = get_syscall_arg(pinfp->pid, flags_arg);

	return (flags & MSG_MORE) != 0 || socket_may_cork(pinfp, fd);
}

void sendto_pre_handle(struct proc_info *pinfp)
{
	int socket_fd = get_syscall_arg(pinfp->pid, 0);
	long addr;
	long addrlen;

	if (!is_tracked_dgram_socket_fd(pinfp, socket_fd))
		return;
	addr = get_syscall_arg(pinfp->pid, 4);
	addrlen = get_syscall_arg(pinfp->pid, 5);
	rewrite_udp_sockaddr(pinfp, addr, addrlen,
			     udp_send_may_retain_dest(pinfp, socket_fd, 3));
}

void sendmsg_pre_handle(struct proc_info *pinfp)
{
	int socket_fd = get_syscall_arg(pinfp->pid, 0);
	long msg_addr = get_syscall_arg(pinfp->pid, 1);
	struct msghdr msg;

	if (!is_tracked_dgram_socket_fd(pinfp, socket_fd) || msg_addr == 0)
		return;
	if (getdata(pinfp->pid, msg_addr, &msg, sizeof(msg)) < 0)
		return;
	if (msg.msg_name == NULL)
		return;
	rewrite_udp_sockaddr(pinfp, (long)msg.msg_name, msg.msg_namelen,
			     udp_send_may_retain_dest(pinfp, socket_fd, 2));
}

static void setsockopt_pre_handle(struct proc_info *pinfp)
{
	int fd, enabled;
	long addr;

	if (UDP_PROXY_PORT == 0 ||
	    get_syscall_arg(pinfp->pid, 1) != IPPROTO_UDP ||
	    get_syscall_arg(pinfp->pid, 2) != UDP_CORK ||
	    get_syscall_arg(pinfp->pid, 4) < (long)sizeof(enabled))
		return;
	fd = get_syscall_arg(pinfp->pid, 0);
	if (!is_tracked_dgram_socket_fd(pinfp, fd))
		return;
	addr = get_syscall_arg(pinfp->pid, 3);
	/* Mark before resuming. Another task sharing the socket can send
	 * before we observe the result. Keep it marked across toggles. */
	if (getdata(pinfp->pid, addr, &enabled, sizeof(enabled)) < 0 || enabled)
		mark_socket_may_cork(pinfp, fd);
}

void close_pre_handle(struct proc_info *pinfp)
{
	int fd = get_syscall_arg(pinfp->pid, 0);
	untrack_socket_fd(pinfp, fd);
}

void dup_pre_handle(struct proc_info *pinfp)
{
	int oldfd = get_syscall_arg(pinfp->pid, 0);

	clear_dup_tracking(pinfp);
	if (!is_tracked_socket_fd(pinfp, oldfd))
		return;
	pinfp->pending_dup = true;
	pinfp->pending_dup_oldfd = oldfd;
}

void dup2_pre_handle(struct proc_info *pinfp)
{
	int oldfd = get_syscall_arg(pinfp->pid, 0);
	int newfd = get_syscall_arg(pinfp->pid, 1);

	clear_dup_tracking(pinfp);
	if (oldfd == newfd)
		return;
	pinfp->pending_dup = true;
	pinfp->pending_dup_oldfd = oldfd;
	pinfp->pending_dup_newfd = newfd;
	pinfp->pending_dup_fixed = true;
	pinfp->pending_dup_cloexec = pinfp->csn == SYS_dup3 &&
		(get_syscall_arg(pinfp->pid, 2) & O_CLOEXEC);
}

void fcntl_pre_handle(struct proc_info *pinfp)
{
	int oldfd = get_syscall_arg(pinfp->pid, 0);
	int cmd = get_syscall_arg(pinfp->pid, 1);

	clear_dup_tracking(pinfp);
	pinfp->fd_args[0] = oldfd;
	pinfp->fd_args[1] = cmd;
	if (cmd == F_SETFD)
		pinfp->fd_args[2] = get_syscall_arg(pinfp->pid, 2);
	if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
		return;
	if (!is_tracked_socket_fd(pinfp, oldfd))
		return;
	pinfp->pending_dup = true;
	pinfp->pending_dup_oldfd = oldfd;
	pinfp->pending_dup_cloexec = cmd == F_DUPFD_CLOEXEC;
}

void dup_exiting_handle(struct proc_info *pinfp, int retfd)
{
	int newfd;

	if (!pinfp->pending_dup)
		return;
	newfd = pinfp->pending_dup_fixed ? pinfp->pending_dup_newfd : retfd;
	if (retfd >= 0 && newfd >= 0) {
		if (pinfp->pending_dup_fixed)
			untrack_socket_fd(pinfp, newfd);
		if (copy_tracked_socket_fd(pinfp, pinfp,
					   pinfp->pending_dup_oldfd, newfd) < 0)
			fprintf(stderr, "graftcp failed to track duplicated socket fd %d\n",
				newfd);
		set_socket_cloexec(pinfp, newfd, pinfp->pending_dup_cloexec);
	}
	clear_dup_tracking(pinfp);
}

void clone_pre_handle(struct proc_info *pinfp)
{
	unsigned long flags = get_syscall_arg(pinfp->pid, 0);

	pinfp->clone_flags = errno == 0 ? flags : 0;
#if defined(__x86_64__)
	if (pinfp->clone_flags & CLONE_UNTRACED) {
		if (ptrace(PTRACE_POKEUSER, pinfp->pid, sizeof(long) * RDI,
			   flags & ~CLONE_UNTRACED) < 0)
			perror("ptrace(PTRACE_POKEUSER)");
		else
			pinfp->clone_flags &= ~CLONE_UNTRACED;
	}
#endif
}

void socket_exiting_handle(struct proc_info *pinfp, int fd)
{
	if (!pinfp->pending_socket)
		return;
	pinfp->pending_socket = false;
	if (fd < 0)
		return;
	if (track_socket_fd(pinfp, fd, pinfp->pending_socket_domain,
			    pinfp->pending_socket_type) < 0)
		fprintf(stderr, "graftcp failed to track socket fd %d\n", fd);
}

static void do_child(const char *username, int argc, char **argv, int ready_fd,
		     pid_t tracer_pid)
{
	char *args[argc + 1];
	int i;
	pid_t pid;
	char ready;
	ssize_t n;

	/* Until EXITKILL is installed, tracer death could leave us in SIGSTOP. */
	if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) < 0)
		child_die_errno("prctl(PR_SET_PDEATHSIG)");
	if (getppid() != tracer_pid)
		_exit(1);

	for (i = 0; i < argc; i++)
		args[i] = argv[i];
	args[argc] = NULL;
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
		child_die_errno("ptrace(PTRACE_TRACEME)");

	pid = getpid();
	/*
	 * Induce a ptrace stop so the tracer can set PTRACE_O_TRACESECCOMP
	 * before any seccomp trace events can fire.
	 */
	if (kill(pid, SIGSTOP) < 0)
		child_die_errno("kill(SIGSTOP)");
	/* Detaching a stopped child resumes it, even if tracer setup failed. */
	do {
		n = read(ready_fd, &ready, 1);
	} while (n < 0 && errno == EINTR);
	if (n != 1 || ready != 'R')
		_exit(1);
	close(ready_fd);
	/* EXITKILL now owns the tracee lifetime. Avoid inheriting this at exec. */
	if (prctl(PR_SET_PDEATHSIG, 0L, 0L, 0L, 0L) < 0)
		child_die_errno("prctl(clear PR_SET_PDEATHSIG)");
	if (username && run_group_count > 0 &&
	    setgroups((size_t)run_group_count, run_groups) < 0)
		child_die_errno("setgroups");
#ifdef ENABLE_SECCOMP_BPF
	install_seccomp();
#endif
	if (username) {
		if (setregid(run_gid, run_gid) < 0)
			child_die_errno("setregid");
		if (setreuid(run_uid, run_uid) < 0)
			child_die_errno("setreuid");
	}
	if (execvp(args[0], args) < 0)
		child_die_errno("execvp");
}

void start_tracee(const char *username, int argc, char **argv)
{
	pid_t child;
	pid_t tracer_pid = getpid();
	struct proc_info *pi;

	int pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
		perror("startup socketpair");
		exit(1);
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		exit(errno);
	} else if (child == 0) {
		close(pair[0]);
		do_child(username, argc, argv, pair[1], tracer_pid);
	}
	close(pair[1]);
	startup_fd = pair[0];
	root_pid = child;
	pi = alloc_proc_info(child);
	if (pi == NULL) {
		perror("calloc");
		exit(errno);
	}
	pi->flags |= FLAG_STARTUP;
}

/* A tracee can be in only one creation queue at a time. */
static void enqueue_tracee(struct tracee_queue *queue, struct proc_info *p)
{
	p->creation_prev = queue->tail;
	p->creation_next = NULL;
	if (queue->tail)
		queue->tail->creation_next = p;
	else
		queue->head = p;
	queue->tail = p;
}

static void dequeue_tracee(struct tracee_queue *queue, struct proc_info *p)
{
	if (p->creation_prev)
		p->creation_prev->creation_next = p->creation_next;
	else
		queue->head = p->creation_next;
	if (p->creation_next)
		p->creation_next->creation_prev = p->creation_prev;
	else
		queue->tail = p->creation_prev;
	p->creation_prev = NULL;
	p->creation_next = NULL;
}

static void start_child_creation(struct proc_info *p)
{
	p->flags |= FLAG_CREATING_CHILD;
	p->creation_seq = ++creation_seq;
	enqueue_tracee(&creators, p);
}

/* child_pid is zero if the creator retired without reporting a child. */
static bool finish_child_creation(struct proc_info *p, pid_t child_pid)
{
	struct reaped_child **link = &reaped_children;
	bool matched = false;

	if (!(p->flags & FLAG_CREATING_CHILD))
		return false;
	p->flags &= ~FLAG_CREATING_CHILD;
	dequeue_tracee(&creators, p);
	while (*link) {
		struct reaped_child *child = *link;
		/* Overlapping creators may both report the same numeric PID.
		 * Keep rejecting ambiguous events until every candidate retires. */
		if (child_pid == child->pid && p->creation_seq <= child->creation_seq)
			matched = true;
		if (!creators.head || creators.head->creation_seq > child->creation_seq) {
			*link = child->next;
			free(child);
		} else {
			link = &child->next;
		}
	}
	return matched;
}

static void remove_waiting_child(struct proc_info *child)
{
	if (child->waiting_for_parent) {
		child->waiting_for_parent = false;
		dequeue_tracee(&waiting_children, child);
	}
}

static int resume_tracee(struct proc_info *p, int sig)
{
	int request = PTRACE_SYSCALL;

#ifdef ENABLE_SECCOMP_BPF
	if (!exiting(p))
		request = PTRACE_CONT;
#endif
	if (ptrace(request, p->pid, 0, sig) == 0)
		return 0;
	if (errno != ESRCH)
		return -1;
	finish_child_creation(p, 0);
	return 0;
}

static int resume_unmatched_children(void)
{
	struct proc_info *oldest = creators.head;
	struct proc_info *child;

	/* Only creators already in the kernel when this stop was observed
	 * can supply the child's table. Later forks cannot prolong the wait. */
	while ((child = waiting_children.head) != NULL &&
	       (oldest == NULL || oldest->creation_seq > child->creation_seq)) {
		remove_waiting_child(child);
		fprintf(stderr, "graftcp: missing creation event for %d; inherited sockets are untracked\n",
			child->pid);
		if (resume_tracee(child, 0) < 0)
			return -1;
	}
	return 0;
}

static int remember_reaped_child(pid_t pid, uint64_t seq)
{
	struct reaped_child *child = malloc(sizeof(*child));

	if (child == NULL)
		return -1;
	child->pid = pid;
	child->creation_seq = seq;
	child->next = reaped_children;
	reaped_children = child;
	return 0;
}

static int inherit_child_proc_info(struct proc_info *parent, unsigned event)
{
	unsigned long new_pid = 0;
	struct proc_info *child;

	if (event != PTRACE_EVENT_CLONE && event != PTRACE_EVENT_FORK &&
	    event != PTRACE_EVENT_VFORK)
		return 0;
	/* clone3 arguments can change after the entry stop. Without a
	 * queued creator the child may already have resumed or exited. */
	if (!(parent->flags & FLAG_CREATING_CHILD))
		return 0;
	if (ptrace(PTRACE_GETEVENTMSG, parent->pid, 0, &new_pid) < 0) {
		int ret = errno == ESRCH ? 0 : -1;
		finish_child_creation(parent, 0);
		return ret;
	}
	if (finish_child_creation(parent, (pid_t)new_pid))
		return 0;
	child = find_proc_info((pid_t)new_pid);
	if (!child)
		child = alloc_proc_info((pid_t)new_pid);
	if (child == NULL)
		return -1;
	/* clone can report any of these events, depending on its flags. */
	if (exiting(parent) && (parent->clone_flags & CLONE_FILES) &&
	    (parent->csn == SYS_clone
#ifdef SYS_clone3
	     || parent->csn == SYS_clone3
#endif
	    ))
		share_tracked_sockets(child, parent);
	else if (copy_tracked_sockets(child, parent) < 0)
		return -1;

	if (child->waiting_for_parent) {
		remove_waiting_child(child);
		return resume_tracee(child, 0);
	}
	return 0;
}

int trace_syscall_entering(struct proc_info *pinfp)
{
	errno = 0;
	pinfp->csn = get_syscall_number(pinfp->pid);
	if (errno != 0)
		return -1;
	switch (pinfp->csn) {
	case SYS_socket:
		socket_pre_handle(pinfp);
		break;
	case SYS_connect:
		connect_pre_handle(pinfp);
		break;
	case SYS_sendto:
		sendto_pre_handle(pinfp);
		break;
	case SYS_sendmsg:
		sendmsg_pre_handle(pinfp);
		break;
	case SYS_setsockopt:
		setsockopt_pre_handle(pinfp);
		break;
	case SYS_close:
		close_pre_handle(pinfp);
		break;
	case SYS_clone:
		clone_pre_handle(pinfp);
		if (!(pinfp->clone_flags & CLONE_UNTRACED))
			start_child_creation(pinfp);
		break;
#ifdef SYS_clone3
	case SYS_clone3: {
		long addr = get_syscall_arg(pinfp->pid, 0);
		uint64_t flags;

		pinfp->clone_flags = 0;
		/* flags is the first field of the Linux clone_args ABI. */
		if (getdata(pinfp->pid, addr, &flags, sizeof(flags)) == 0)
			pinfp->clone_flags = flags;
		/* An untraced vfork can wait for its child without ever
		 * reporting a creation event. */
		if (!(pinfp->clone_flags & CLONE_UNTRACED))
			start_child_creation(pinfp);
		break;
	}
#endif
#ifdef SYS_fork
	case SYS_fork:
#endif
#ifdef SYS_vfork
	case SYS_vfork:
#endif
#if defined(SYS_fork) || defined(SYS_vfork)
		start_child_creation(pinfp);
		break;
#endif
	case SYS_unshare:
		pinfp->fd_args[0] = get_syscall_arg(pinfp->pid, 0);
		break;
	case SYS_ioctl:
		pinfp->fd_args[1] = get_syscall_arg(pinfp->pid, 1);
		if (pinfp->fd_args[1] == FIOCLEX || pinfp->fd_args[1] == FIONCLEX)
			pinfp->fd_args[0] = get_syscall_arg(pinfp->pid, 0);
		break;
#ifdef SYS_close_range
	case SYS_close_range:
		for (int i = 0; i < 3; i++)
			pinfp->fd_args[i] = get_syscall_arg(pinfp->pid, i);
		break;
#endif
	case SYS_dup:
		dup_pre_handle(pinfp);
		break;
#ifdef SYS_dup2
	case SYS_dup2:
		dup2_pre_handle(pinfp);
		break;
#endif
	case SYS_dup3:
		dup2_pre_handle(pinfp);
		break;
	case SYS_fcntl:
		fcntl_pre_handle(pinfp);
		break;
#ifdef SYS_fcntl64
	case SYS_fcntl64:
		fcntl_pre_handle(pinfp);
		break;
#endif
	}
	pinfp->flags |= FLAG_INSYSCALL;
	return 0;
}

static void finish_udp_use(struct proc_info *pinfp, bool accepted)
{
	if (pinfp->pending_udp_token == 0)
		return;
	mgraftcp_finish_udp_use(pinfp->pending_udp_token, accepted);
	pinfp->pending_udp_token = 0;
}

static void unshare_files(struct proc_info *pinfp)
{
	if (unshare_tracked_sockets(pinfp) < 0) {
		perror("copy socket table");
		exit(1);
	}
}

static void handle_exec(struct proc_info *pinfp)
{
	unsigned long old_tid = 0;
	struct proc_info *old;

	/* A non-leader exec takes over the leader's TID. */
	if (ptrace(PTRACE_GETEVENTMSG, pinfp->pid, 0, &old_tid) == 0 &&
	    old_tid != (unsigned long)pinfp->pid &&
	    (old = find_proc_info((pid_t)old_tid)) != NULL) {
		share_tracked_sockets(pinfp, old);
		finish_udp_use(old, true);
		finish_child_creation(old, 0);
		remove_waiting_child(old);
		free_proc_info(old);
	}
	finish_child_creation(pinfp, 0);
	remove_waiting_child(pinfp);
	unshare_files(pinfp);
	close_exec_sockets(pinfp);
	finish_udp_use(pinfp, true);
	pinfp->pending_socket = false;
	pinfp->clone_flags = 0;
	clear_dup_tracking(pinfp);
	clear_sockaddr_restore(pinfp);
#ifdef ENABLE_SECCOMP_BPF
	pinfp->flags &= ~FLAG_INSYSCALL;
	pinfp->csn = -1;
#else
	/* PTRACE_SYSCALL also reports the successful exec's exit stop. */
	pinfp->flags |= FLAG_INSYSCALL;
	pinfp->csn = SYS_execve;
#endif
}

int trace_syscall_exiting(struct proc_info *pinfp)
{
	int ret = 0;
	int child_ret;

	if (pinfp->csn == SYS_exit || pinfp->csn == SYS_exit_group) {
		ret = -1;
		goto end;
	}

	switch (pinfp->csn) {
	case SYS_socket:
		child_ret = get_retval(pinfp->pid);
		if (errno) {
			/* Let the wait loop collect the tracee exit status. */
			if (errno == ESRCH)
				goto end;
			perror("ptrace");
			exit(errno);
		}
		socket_exiting_handle(pinfp, child_ret);
		break;
	case SYS_connect:
	case SYS_sendto:
	case SYS_sendmsg:
		if (pinfp->pending_udp_token != 0) {
			child_ret = get_retval(pinfp->pid);
			/* An unreadable result may have installed the destination. */
			finish_udp_use(pinfp, child_ret >= 0 || errno != 0);
		}
		restore_sockaddr_if_needed(pinfp);
		break;
	case SYS_dup:
#ifdef SYS_dup2
	case SYS_dup2:
#endif
	case SYS_dup3:
	case SYS_fcntl:
#ifdef SYS_fcntl64
	case SYS_fcntl64:
#endif
		child_ret = get_retval(pinfp->pid);
		if (errno) {
			if (errno == ESRCH)
				goto end;
			perror("ptrace");
			exit(errno);
		}
		if (child_ret >= 0 &&
		    (pinfp->csn == SYS_fcntl
#ifdef SYS_fcntl64
		     || pinfp->csn == SYS_fcntl64
#endif
		    ) && pinfp->fd_args[1] == F_SETFD)
			set_socket_cloexec(pinfp, pinfp->fd_args[0],
					   pinfp->fd_args[2] & FD_CLOEXEC);
		dup_exiting_handle(pinfp, child_ret);
		break;
	case SYS_unshare:
		if ((pinfp->fd_args[0] & CLONE_FILES) && get_retval(pinfp->pid) == 0)
			unshare_files(pinfp);
		break;
	case SYS_ioctl:
		if ((pinfp->fd_args[1] == FIOCLEX || pinfp->fd_args[1] == FIONCLEX) &&
		    get_retval(pinfp->pid) == 0)
			set_socket_cloexec(pinfp, pinfp->fd_args[0],
					   pinfp->fd_args[1] == FIOCLEX);
		break;
#ifdef SYS_close_range
	case SYS_close_range:
		if (get_retval(pinfp->pid) == 0) {
			if (pinfp->fd_args[2] & GRAFTCP_CLOSE_RANGE_UNSHARE)
				unshare_files(pinfp);
			close_tracked_range(pinfp, pinfp->fd_args[0], pinfp->fd_args[1],
					    (pinfp->fd_args[2] & GRAFTCP_CLOSE_RANGE_CLOEXEC) != 0);
		}
		break;
#endif
	}
end:
	finish_child_creation(pinfp, 0);
	if (pinfp->csn != SYS_connect && pinfp->csn != SYS_sendto &&
	    pinfp->csn != SYS_sendmsg)
		clear_sockaddr_restore(pinfp);
	pinfp->flags &= ~FLAG_INSYSCALL;
	return ret;
}

int trace_syscall(struct proc_info *pinfp)
{
	return exiting(pinfp) ? trace_syscall_exiting(pinfp) :
	    trace_syscall_entering(pinfp);
}

static bool is_syscall_stop(int status)
{
	return WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80);
}

static bool is_group_stop(pid_t pid)
{
	siginfo_t si;

	errno = 0;
	if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0)
		return false;
	return errno == EINVAL;
}

int do_trace()
{
	pid_t child;
	int status;
	int sig;
	unsigned event;
	struct proc_info *pinfp;
	long ptrace_options = PTRACE_O_TRACESYSGOOD |
			      PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
#ifdef ENABLE_SECCOMP_BPF
			      PTRACE_O_TRACESECCOMP |
#endif
			      PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
			      PTRACE_O_EXITKILL;

	for (;;) {
		if (resume_unmatched_children() < 0)
			return -1;
		do {
			child = waitpid(-1, &status, __WALL);
		} while (child < 0 && errno == EINTR);
		if (child < 0) {
			if (errno == ECHILD)
				return 0;
			return -1;
		}
		pinfp = find_proc_info(child);
		if (!WIFSTOPPED(status)) {
			if (child == root_pid && WIFEXITED(status))
				exit_code = WEXITSTATUS(status);
			else if (child == root_pid && WIFSIGNALED(status))
				exit_code = 128 + WTERMSIG(status);
			if (!pinfp || pinfp->waiting_for_parent) {
				uint64_t seq = pinfp ? pinfp->creation_seq : creation_seq;

				if (creators.head && creators.head->creation_seq <= seq &&
				    remember_reaped_child(child, seq) < 0)
					return -1;
				if (!pinfp)
					continue;
			}
			/* A surviving alias may hold the destination if the task died. */
			finish_udp_use(pinfp, true);
			finish_child_creation(pinfp, 0);
			remove_waiting_child(pinfp);
			free_proc_info(pinfp);
			continue;
		}
		if (!pinfp) {
			pinfp = alloc_proc_info(child);
			/* The child's initial stop can arrive before the parent's
			 * creation event. Install its table before it runs. */
			if (pinfp && WSTOPSIG(status) == SIGSTOP) {
				pinfp->waiting_for_parent = true;
				pinfp->creation_seq = creation_seq;
				enqueue_tracee(&waiting_children, pinfp);
				continue;
			}
		}
		if (pinfp == NULL) {
			perror("calloc");
			exit(errno);
		}


		if (pinfp->flags & FLAG_STARTUP) {
			ssize_t n;

			if (ptrace(PTRACE_SETOPTIONS, child, 0,
				   ptrace_options) < 0) {
				int setup_errno = errno;

				/* SIGKILL can race the stop; wait for the exit status. */
				if (setup_errno == ESRCH)
					continue;
				/* EXITKILL is not active; the child is still at SIGSTOP. */
				if (kill(child, SIGKILL) < 0 && errno != ESRCH &&
				    ptrace(PTRACE_CONT, child, 0, SIGKILL) < 0 && errno != ESRCH) {
					perror("terminate tracee");
				} else {
					while (waitpid(child, NULL, __WALL) < 0) {
						if (errno == EINTR)
							continue;
						if (errno != ECHILD)
							perror("waitpid");
						break;
					}
				}
				errno = setup_errno;
				perror("ptrace(PTRACE_SETOPTIONS)");
				exit(setup_errno);
			}
			do {
				n = send(startup_fd, "R", 1, MSG_NOSIGNAL);
			} while (n < 0 && errno == EINTR);
			if (n < 0 && errno != EPIPE && errno != ECONNRESET) {
				perror("confirm tracee startup");
				exit(1);
			}
			close(startup_fd);
			startup_fd = -1;
			pinfp->flags &= ~FLAG_STARTUP;
		}
		event = ((unsigned)status >> 16);

		sig = 0;
		if (event != 0) {
			if (event == PTRACE_EVENT_EXEC)
				handle_exec(pinfp);
	#ifdef ENABLE_SECCOMP_BPF
			if (event == PTRACE_EVENT_SECCOMP &&
			    trace_syscall(pinfp) < 0)
				perror("trace_syscall");
	#endif
			if (inherit_child_proc_info(pinfp, event) < 0) {
				perror("initialize new tracee");
				return -1;
			}
			goto end;
		}
		if (is_syscall_stop(status)) {
			if (trace_syscall(pinfp) < 0)
				perror("trace_syscall");
			goto end;
		}

		sig = WSTOPSIG(status);
		if (sig == SIGSTOP || is_group_stop(child))
			sig = 0;
end:
		if (resume_tracee(pinfp, sig) < 0)
			return -1;
	}
	return 0;
}

static void usage(char **argv)
{
	fprintf(stderr, "Usage: %s [options] prog [prog-args]\n\n"
		"Options:\n"
		"  -p --local-port=<embedded-listener-port>\n"
		"                    Which embedded listener port should be used? Default: 2233\n"
		"  -b --blackip-file=<black-ip-file-path>\n"
		"                    The IP in black-ip-file will connect direct\n"
		"  -w --whiteip-file=<white-ip-file-path>\n"
		"                    Only redirect the connect that destination ip in the\n"
		"                    white-ip-file to SOCKS5\n"
		"  -n --not-ignore-local\n"
		"                    Connecting to local is not changed by default, this\n"
		"                    option will redirect it to SOCKS5\n"
		"  -u --user=<username>\n"
		"                    Run command as USERNAME handling setuid and/or setgid\n"
		"  -D --dns-port=<embedded-dns-port>\n"
		"                    Redirect UDP/53 queries to the embedded DNS listener\n"
		"  -U --udp-port=<embedded-udp-port>\n"
		"                    Redirect generic UDP packets to the embedded UDP listener\n"
		"  -V --version\n"
		"                    Show version\n"
		"  -h --help\n"
		"                    Display this help and exit\n"
		"\n", argv[0]);
}

static void prepare_run_groups(const char *username, gid_t gid)
{
	gid_t *groups;
	int ngroups = 16;

	for (;;) {
		int requested = ngroups;

		groups = calloc((size_t)ngroups, sizeof(*groups));
		if (groups == NULL) {
			perror("calloc");
			exit(1);
		}
		if (getgrouplist(username, gid, groups, &requested) >= 0) {
			free(run_groups);
			run_groups = groups;
			run_group_count = requested;
			return;
		}
		free(groups);
		if (requested > ngroups) {
			ngroups = requested;
			continue;
		}
		if (ngroups > INT_MAX / 2) {
			fprintf(stderr, "too many groups for user '%s'\n",
				username);
			exit(1);
		}
		ngroups *= 2;
	}
}

int client_prepare(int argc, char **argv)
{
	int opt, index;
	char *blackip_file_path = NULL;
	char *whiteip_file_path = NULL;
	char *username = NULL;
	char *saved_home = NULL;
	bool unset_home = false;
	bool ignore_local = DEFAULT_IGNORE_LOCAL;
	uint16_t local_proxy_port = DEFAULT_LOCAL_PORT;
	uint16_t dns_proxy_port = 0;
	uint16_t udp_proxy_port = 0;
	struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'V'},
		{"local-port", required_argument, 0, 'p'},
		{"dns-port", required_argument, 0, 'D'},
		{"udp-port", required_argument, 0, 'U'},
		{"blackip-file", required_argument, 0, 'b'},
		{"whiteip-file", required_argument, 0, 'w'},
		{"user", required_argument, 0, 'u'},
		{"not-ignore-local", no_argument, 0, 'n'},
		{0, 0, 0, 0}
	};

	optind = 1;
	optarg = NULL;
	exit_code = 0;
	root_pid = -1;

	while ((opt = getopt_long(argc, argv, "+Vhp:D:U:b:w:u:n", long_opts,
				    	&index)) != -1) {
		switch (opt) {
		case 'p':
			local_proxy_port = parse_port(optarg, "--local-port");
			break;
		case 'D':
			dns_proxy_port = parse_port(optarg, "--dns-port");
			break;
		case 'U':
			udp_proxy_port = parse_port(optarg, "--udp-port");
			break;
		case 'b':
			blackip_file_path = xstrdup(optarg);
			break;
		case 'w':
			whiteip_file_path = xstrdup(optarg);
			break;
		case 'n':
			ignore_local = false;
			break;
		case 'u':
			username = xstrdup(optarg);
			break;
		case 'V':
			fprintf(stderr, "graftcp %s\n", VERSION);
			exit(0);
		case 0:
		case 'h':
		default:
			usage(argv);
			exit(0);
		}
	}
	if (optind >= argc) {
		usage(argv);
		exit(1);
	}

	if (blackip_file_path)
		load_ip_file(blackip_file_path, &BLACKLIST_IP);
	if (whiteip_file_path)
		load_ip_file(whiteip_file_path, &WHITELIST_IP);
	if (ignore_local) {
		if (BLACKLIST_IP == NULL)
			BLACKLIST_IP = cidr_trie_new();
		if (BLACKLIST_IP == NULL) {
			perror("calloc");
			exit(1);
		}
		if (cidr_trie_insert_str(BLACKLIST_IP, "127.0.0.0/8", 1) < 0 ||
		    cidr_trie_insert_str(BLACKLIST_IP, "0.0.0.0/32", 1) < 0 ||
		    cidr_trie_insert_str(BLACKLIST_IP, "::1", 1) < 0) {
			fprintf(stderr, "failed to initialize local address blacklist\n");
			exit(1);
		}
	}
	LOCAL_PROXY_PORT = local_proxy_port;
	DNS_PROXY_PORT = dns_proxy_port;
	UDP_PROXY_PORT = udp_proxy_port;

	if (username) {
		struct passwd *pent;
		char *home;

		if (geteuid() != 0) {
			fprintf(stderr, "You must be root to use the -u option\n");
			exit(1);
		}
		pent = getpwnam(username);
		if (pent == NULL) {
			fprintf(stderr, "Cannot find user '%s'\n", username);
			exit(1);
		}
		run_gid = pent->pw_gid;
		run_uid = pent->pw_uid;
		home = getenv("HOME");
		if (home) {
			saved_home = xstrdup(home);
		} else {
			unset_home = true;
		}
		free(run_home);
		run_home = xstrdup(pent->pw_dir);
		prepare_run_groups(username, run_gid);
		if (setenv("HOME", run_home, 1) < 0) {
			perror("setenv");
			exit(1);
		}
	}

	start_tracee(username, argc - optind, argv + optind);
	if (saved_home) {
		if (setenv("HOME", saved_home, 1) < 0)
			perror("setenv");
	} else if (unset_home && unsetenv("HOME") < 0) {
		perror("unsetenv");
	}
	free(blackip_file_path);
	free(whiteip_file_path);
	free(username);
	free(saved_home);
	return 0;
}

int client_trace(void)
{
	int ret = do_trace();
	if (startup_fd >= 0) {
		close(startup_fd);
		startup_fd = -1;
	}
	return ret < 0 ? -1 : exit_code;
}

int client_main(int argc, char **argv)
{
	int ret;

	ret = client_prepare(argc, argv);
	if (ret != 0)
		return ret;
	return client_trace();
}
