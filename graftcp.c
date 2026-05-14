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
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define ENABLE_SECCOMP_BPF
#endif
#ifdef ENABLE_SECCOMP_BPF
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#endif /* ifdef ENABLE_SECCOMP_BPF */

#include "graftcp.h"
#include "cidr-trie.h"

#ifndef VERSION
#define VERSION "v0.7"
#endif

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0
#endif

extern uint32_t mgraftcp_register_connect(int family, const char *addr,
					  uint16_t port);
extern uint32_t mgraftcp_register_udp(int family, const char *addr,
				      uint16_t port);
extern void mgraftcp_forget_connect(uint32_t token);
extern void mgraftcp_forget_udp(uint32_t token);

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
#define SECCOMP_JUMP_OFFSET(from, to) ((to) - (from) - 1)
#define SECCOMP_LAYOUT_CHECK(name, expr)				\
	enum { name = 1 / !!(expr) }
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
	#if defined(__x86_64__)
		FILTER_CLONE,
	#endif
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
	#if defined(__x86_64__)
		UDP_FILTER_CLONE,
	#endif
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
#if defined(__x86_64__)
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,
			 SECCOMP_JUMP_OFFSET(FILTER_CLOSE, FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket,
			 SECCOMP_JUMP_OFFSET(FILTER_SOCKET, FILTER_SOCKET_ARGS), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect,
			 SECCOMP_JUMP_OFFSET(FILTER_CONNECT, FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone,
			 SECCOMP_JUMP_OFFSET(FILTER_CLONE, FILTER_RET_TRACE),
			 SECCOMP_JUMP_OFFSET(FILTER_CLONE, FILTER_RET_ALLOW)),
#else
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,
			 SECCOMP_JUMP_OFFSET(FILTER_CLOSE, FILTER_RET_TRACE), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket,
			 SECCOMP_JUMP_OFFSET(FILTER_SOCKET, FILTER_SOCKET_ARGS), 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect,
			 SECCOMP_JUMP_OFFSET(FILTER_CONNECT, FILTER_RET_TRACE),
			 SECCOMP_JUMP_OFFSET(FILTER_CONNECT, FILTER_RET_ALLOW)),
#endif
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
#if defined(__x86_64__)
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
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone,
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_CLONE,
					     UDP_FILTER_RET_TRACE),
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_CLONE,
					     UDP_FILTER_RET_ALLOW)),
#else
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
					     UDP_FILTER_RET_TRACE),
			 SECCOMP_JUMP_OFFSET(UDP_FILTER_SENDMSG,
					     UDP_FILTER_RET_ALLOW)),
#endif
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
	pinfp->pending_socket_type = socket_type;
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
		fprintf(stderr, "mgraftcp restore sockaddr failed\n");
	clear_sockaddr_restore(pinfp);
}

static bool rewrite_udp_sockaddr(struct proc_info *pinfp, long addr,
				 long addrlen)
{
	struct dest_endpoint dest;
	uint32_t loopback_token;

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
			fprintf(stderr, "mgraftcp rewrite DNS UDP failed\n");
		} else {
			save_sockaddr_restore(pinfp, addr, &dest.sa, dest.len);
		}
		return true;
	}

	if (UDP_PROXY_PORT == 0 || dest_is_in_ignore_list(&dest))
		return false;

	loopback_token = mgraftcp_register_udp(dest.family, dest.ipstr, dest.port);
	if (loopback_token == 0) {
		fprintf(stderr, "mgraftcp register UDP failed for %s:%d\n",
			dest.ipstr, dest.port);
		return false;
	}
	if (!write_loopback_token(pinfp->pid, addr, &dest, loopback_token,
				  UDP_PROXY_PORT)) {
		fprintf(stderr, "mgraftcp rewrite UDP failed for %s:%d\n",
			dest.ipstr, dest.port);
		mgraftcp_forget_udp(loopback_token);
	} else {
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
		fprintf(stderr, "mgraftcp register connect failed for %s:%d\n",
			dest.ipstr, dest.port);
		return;
	}
	if (!write_loopback_token(pinfp->pid, addr, &dest, loopback_token,
				  LOCAL_PROXY_PORT)) {
		fprintf(stderr, "mgraftcp rewrite connect failed for %s:%d\n",
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
	rewrite_udp_sockaddr(pinfp, addr, addrlen);
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
	rewrite_udp_sockaddr(pinfp, addr, addrlen);
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
	rewrite_udp_sockaddr(pinfp, (long)msg.msg_name, msg.msg_namelen);
}

void close_pre_handle(struct proc_info *pinfp)
{
	int fd = get_syscall_arg(pinfp->pid, 0);
	untrack_socket_fd(pinfp, fd);
}

void clone_pre_handle(struct proc_info *pinfp)
{
#if defined(__x86_64__)
	long flags = get_syscall_arg(pinfp->pid, 0);

	flags &= ~CLONE_UNTRACED;
	if (ptrace(PTRACE_POKEUSER, pinfp->pid, sizeof(long) * RDI, flags) < 0)
		perror("ptrace(PTRACE_POKEUSER)");
#elif defined(__arm__) || defined(__arm64__) || defined(__aarch64__)
	/* Do not know how to handle this */
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
		fprintf(stderr, "mgraftcp failed to track socket fd %d\n", fd);
}

void do_child(const char *username, int argc, char **argv)
{
	char *args[argc + 1];
	int i;
	pid_t pid;

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
	struct proc_info *pi;

	child = fork();
	if (child < 0) {
		perror("fork");
		exit(errno);
	} else if (child == 0) {
		do_child(username, argc, argv);
	}
	root_pid = child;
	pi = alloc_proc_info(child);
	if (pi == NULL) {
		perror("calloc");
		exit(errno);
	}
	pi->flags |= FLAG_STARTUP;
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
	case SYS_close:
		close_pre_handle(pinfp);
		break;
	case SYS_clone:
		clone_pre_handle(pinfp);
		break;
	}
	pinfp->flags |= FLAG_INSYSCALL;
	return 0;
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
			/* No such process, child exited */
			if (errno == ESRCH)
				exit(0);
			perror("ptrace");
			exit(errno);
		}
		socket_exiting_handle(pinfp, child_ret);
		break;
	case SYS_connect:
	case SYS_sendto:
	case SYS_sendmsg:
		restore_sockaddr_if_needed(pinfp);
		break;
	}
end:
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
		do {
			child = waitpid(-1, &status, __WALL);
		} while (child < 0 && errno == EINTR);
		if (child < 0) {
			if (errno == ECHILD)
				return 0;
			return -1;
		}
		pinfp = find_proc_info(child);
		if (!pinfp)
			pinfp = alloc_proc_info(child);
		if (pinfp == NULL) {
			perror("calloc");
			exit(errno);
		}

		if (pinfp->flags & FLAG_STARTUP) {
			pinfp->flags &= ~FLAG_STARTUP;

			if (ptrace(PTRACE_SETOPTIONS, child, 0,
				   ptrace_options) < 0) {
				perror("ptrace");
				exit(errno);
			}
		}
		event = ((unsigned)status >> 16);
		if (WIFSIGNALED(status) || WIFEXITED(status)
		    || !WIFSTOPPED(status)) {
			if (child == root_pid && WIFEXITED(status))
				exit_code = WEXITSTATUS(status);
			else if (child == root_pid && WIFSIGNALED(status))
				exit_code = 128 + WTERMSIG(status);
			free_proc_info(pinfp);
			continue;
		}

		sig = 0;
		if (event != 0) {
#ifdef ENABLE_SECCOMP_BPF
			if (event == PTRACE_EVENT_SECCOMP &&
			    trace_syscall(pinfp) < 0)
				perror("trace_syscall");
#endif
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
		/*
		 * Since the value returned by a successful PTRACE_PEEK*  request  may  be
		 * -1,  the  caller  must  clear  errno before the call of ptrace(2).
		 */
		errno = 0;
#ifdef ENABLE_SECCOMP_BPF
		if (ptrace(exiting(pinfp) ? PTRACE_SYSCALL : PTRACE_CONT,
					pinfp->pid, 0, sig) < 0) {
			if (errno == ESRCH)
				continue;
			return -1;
		}
#else
		if (ptrace(PTRACE_SYSCALL, pinfp->pid, 0, sig) < 0) {
			if (errno == ESRCH)
				continue;
			return -1;
		}
#endif
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
			local_proxy_port = atoi(optarg);
			break;
		case 'D':
			dns_proxy_port = atoi(optarg);
			break;
		case 'U':
			udp_proxy_port = atoi(optarg);
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
	if (do_trace() < 0)
		return -1;
	return exit_code;
}

int client_main(int argc, char **argv)
{
	int ret;

	ret = client_prepare(argc, argv);
	if (ret != 0)
		return ret;
	return client_trace();
}
