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

static int exit_code = 0;
static pid_t root_pid = -1;

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

		/* 7 is the shortest ip: (x.x.x.x) */
		if (read < 7)
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

static void load_blackip_file(char *path)
{
	load_ip_file(path, &BLACKLIST_IP);
}

static void load_whiteip_file(char *path)
{
	load_ip_file(path, &WHITELIST_IP);
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
static void install_seccomp()
{
	/*
	 * Keep the filter deliberately small. The syscall handlers do the
	 * detailed argument filtering after ptrace has access to registers.
	 */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
#if defined(__x86_64__)
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 1),
#else
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
#endif
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	struct sock_filter udp_filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
#if defined(__x86_64__)
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 5, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 1),
#else
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 0, 1),
#endif
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
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
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			exit(errno);
		}
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
			perror("prctl(PR_SET_SECCOMP)");
			exit(errno);
		}
		return;
	}
	perror("prctl(PR_SET_SECCOMP)");
	exit(errno);
}
#endif

void socket_pre_handle(struct proc_info *pinfp)
{
	int domain = get_syscall_arg(pinfp->pid, 0);
	int type = get_syscall_arg(pinfp->pid, 1);
	int protocol = get_syscall_arg(pinfp->pid, 2);
	int socket_type = type & SOCK_TYPE_MASK;

	if (domain != AF_INET && domain != AF_INET6)
		return;
	if (socket_type != SOCK_STREAM &&
	    ((DNS_PROXY_PORT == 0 && UDP_PROXY_PORT == 0) ||
	     socket_type != SOCK_DGRAM))
		return;
	if (socket_type == SOCK_DGRAM && protocol != 0 && protocol != IPPROTO_UDP)
		return;
	pinfp->pending_socket = true;
	pinfp->pending_socket_domain = domain;
	pinfp->pending_socket_type = socket_type;
}

static bool rewrite_udp_sockaddr(pid_t pid, long addr, long addrlen)
{
	sa_family_t family;
	struct sockaddr_in dest_sa;
	struct sockaddr_in6 dest_sa6;
	struct sockaddr_in dns_sa;
	struct sockaddr_in6 dns_sa6;
	struct sockaddr_in proxy_sa;
	struct sockaddr_in6 proxy_sa6;
	unsigned short dest_ip_port;
	char dest_str[INET6_ADDRSTRLEN];
	char *dest_ip_addr_str;
	uint32_t loopback_token;

	if ((DNS_PROXY_PORT == 0 && UDP_PROXY_PORT == 0) || addr == 0)
		return false;
	if (addrlen < (long)sizeof(family))
		return false;
	if (getdata(pid, addr, &family, sizeof(family)) < 0)
		return false;

	if (family == AF_INET) {
		if (addrlen < (long)sizeof(dest_sa))
			return false;
		if (getdata(pid, addr, &dest_sa, sizeof(dest_sa)) < 0)
			return false;
		dest_ip_port = SOCKPORT(dest_sa);
		if (DNS_PROXY_PORT != 0 && ntohs(dest_ip_port) == 53) {
			build_loopback_sockaddr4(&dns_sa, 0x7f000001, DNS_PROXY_PORT);
			if (putdata(pid, addr, &dns_sa, sizeof(dns_sa)) < 0)
				fprintf(stderr, "mgraftcp rewrite DNS UDP failed\n");
			return true;
		}
		if (UDP_PROXY_PORT == 0 || ip4_is_ignore(dest_sa.sin_addr.s_addr))
			return false;
		if (inet_ntop(AF_INET, &dest_sa.sin_addr, dest_str,
			      sizeof(dest_str)) == NULL)
			return false;
		dest_ip_addr_str = dest_str;
		loopback_token = mgraftcp_register_udp(family,
						       dest_ip_addr_str,
						       ntohs(dest_ip_port));
		if (loopback_token == 0) {
			fprintf(stderr, "mgraftcp register UDP failed for %s:%d\n",
				dest_ip_addr_str, ntohs(dest_ip_port));
			return false;
		}
		build_loopback_sockaddr4(&proxy_sa, loopback_token,
					 UDP_PROXY_PORT);
		if (putdata(pid, addr, &proxy_sa, sizeof(proxy_sa)) < 0)
			fprintf(stderr, "mgraftcp rewrite UDP failed for %s:%d\n",
				dest_ip_addr_str, ntohs(dest_ip_port));
		return true;
	} else if (family == AF_INET6) {
		if (addrlen < (long)sizeof(dest_sa6))
			return false;
		if (getdata(pid, addr, &dest_sa6, sizeof(dest_sa6)) < 0)
			return false;
		dest_ip_port = SOCKPORT6(dest_sa6);
		if (DNS_PROXY_PORT != 0 && ntohs(dest_ip_port) == 53) {
			build_dns_sockaddr6(&dns_sa6, DNS_PROXY_PORT);
			if (putdata(pid, addr, &dns_sa6, sizeof(dns_sa6)) < 0)
				fprintf(stderr, "mgraftcp rewrite DNS UDP failed\n");
			return true;
		}
		if (UDP_PROXY_PORT == 0 ||
		    ip6_is_ignore(dest_sa6.sin6_addr.s6_addr))
			return false;
		if (inet_ntop(AF_INET6, &dest_sa6.sin6_addr, dest_str,
			      sizeof(dest_str)) == NULL)
			return false;
		dest_ip_addr_str = dest_str;
		loopback_token = mgraftcp_register_udp(family,
						       dest_ip_addr_str,
						       ntohs(dest_ip_port));
		if (loopback_token == 0) {
			fprintf(stderr, "mgraftcp register UDP failed for %s:%d\n",
				dest_ip_addr_str, ntohs(dest_ip_port));
			return false;
		}
		build_loopback_sockaddr6(&proxy_sa6, loopback_token,
					 UDP_PROXY_PORT);
		if (putdata(pid, addr, &proxy_sa6, sizeof(proxy_sa6)) < 0)
			fprintf(stderr, "mgraftcp rewrite UDP failed for %s:%d\n",
				dest_ip_addr_str, ntohs(dest_ip_port));
		return true;
	}
	return false;
}

static void tcp_connect_pre_handle(struct proc_info *pinfp)
{
	long addr = get_syscall_arg(pinfp->pid, 1);
	long addrlen = get_syscall_arg(pinfp->pid, 2);
	sa_family_t family;
	struct sockaddr_in dest_sa;
	struct sockaddr_in6 dest_sa6;
	struct sockaddr_in proxy_sa;
	struct sockaddr_in6 proxy_sa6;
	unsigned short dest_ip_port;
	char *dest_ip_addr_str;
	char dest_str[INET6_ADDRSTRLEN];
	uint32_t loopback_token;

	if (addrlen < (long)sizeof(family))
		return;
	if (getdata(pinfp->pid, addr, &family, sizeof(family)) < 0)
		return;

	if (family == AF_INET) { /* IPv4 */
		if (addrlen < (long)sizeof(dest_sa))
			return;
		if (getdata(pinfp->pid, addr, &dest_sa, sizeof(dest_sa)) < 0)
			return;
		dest_ip_port = SOCKPORT(dest_sa);
		if (inet_ntop(AF_INET, &dest_sa.sin_addr, dest_str,
			      sizeof(dest_str)) == NULL)
			return;
		dest_ip_addr_str = dest_str;
		if (ip4_is_ignore(dest_sa.sin_addr.s_addr))
			return;
	} else if (family == AF_INET6) { /* IPv6 */
		if (addrlen < (long)sizeof(dest_sa6))
			return;
		if (getdata(pinfp->pid, addr, &dest_sa6, sizeof(dest_sa6)) < 0)
			return;
		dest_ip_port = SOCKPORT6(dest_sa6);
		if (ip6_is_ignore(dest_sa6.sin6_addr.s6_addr))
			return;
		inet_ntop(AF_INET6, &dest_sa6.sin6_addr, dest_str, INET6_ADDRSTRLEN);
		dest_ip_addr_str = dest_str;
	} else {
		return;
	}

	loopback_token = mgraftcp_register_connect(family,
						   dest_ip_addr_str,
						   ntohs(dest_ip_port));
	if (loopback_token == 0) {
		fprintf(stderr, "mgraftcp register connect failed for %s:%d\n",
			dest_ip_addr_str, ntohs(dest_ip_port));
		return;
	}

	if (family == AF_INET) { /* IPv4 */
		build_loopback_sockaddr4(&proxy_sa, loopback_token,
						 LOCAL_PROXY_PORT);
		if (putdata(pinfp->pid, addr, &proxy_sa, sizeof(proxy_sa)) < 0)
			fprintf(stderr, "mgraftcp rewrite connect failed for %s:%d\n",
				dest_ip_addr_str, ntohs(dest_ip_port));
	} else { /* IPv6 */
		build_loopback_sockaddr6(&proxy_sa6, loopback_token,
						 LOCAL_PROXY_PORT);
		if (putdata(pinfp->pid, addr, &proxy_sa6, sizeof(proxy_sa6)) < 0)
			fprintf(stderr, "mgraftcp rewrite connect failed for %s:%d\n",
				dest_ip_addr_str, ntohs(dest_ip_port));
	}
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
	rewrite_udp_sockaddr(pinfp->pid, addr, addrlen);
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
	rewrite_udp_sockaddr(pinfp->pid, addr, addrlen);
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
	rewrite_udp_sockaddr(pinfp->pid, (long)msg.msg_name, msg.msg_namelen);
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
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_TRACEME)");
		exit(errno);
	}

	pid = getpid();
	/*
	 * Induce a ptrace stop so the tracer can set PTRACE_O_TRACESECCOMP
	 * before any seccomp trace events can fire.
	 */
	kill(pid, SIGSTOP);
#ifdef ENABLE_SECCOMP_BPF
	install_seccomp();
#endif
	if (username) {
		if (initgroups(username, run_gid) < 0) {
			perror("initgroups");
			exit(errno);
		}

		if (setregid(run_gid, run_gid) < 0) {
			perror("setregid");
			exit(errno);
		}
		if (setreuid(run_uid, run_uid) < 0) {
			perror("setreuid");
			exit(errno);
		}
		if (setenv("HOME", run_home, 1) < 0)
			perror("setenv");
	}
	if (execvp(args[0], args) < 0) {
		fprintf(stderr, "graftcp %s: %s\n", args[0], strerror(errno));
		exit(errno);
	}
}

void init(const char *username, int argc, char **argv)
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
	}
end:
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
			return 0;
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

int client_main(int argc, char **argv)
{
	int opt, index;
	char *blackip_file_path = NULL;
	char *whiteip_file_path = NULL;
	char *username = NULL;
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
			blackip_file_path = strdup(optarg);
			if (blackip_file_path == NULL) {
				perror("strdup");
				exit(1);
			}
			break;
		case 'w':
			whiteip_file_path = strdup(optarg);
			if (whiteip_file_path == NULL) {
				perror("strdup");
				exit(1);
			}
			break;
		case 'n':
			ignore_local = false;
			break;
		case 'u':
			username = strdup(optarg);
			if (username == NULL) {
				perror("strdup");
				exit(1);
			}
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

	if (blackip_file_path)
		load_blackip_file(blackip_file_path);
	if (whiteip_file_path)
		load_whiteip_file(whiteip_file_path);
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
			run_home = strdup(pent->pw_dir);
			if (run_home == NULL) {
				perror("strdup");
				exit(1);
			}
		}

	init(username, argc - optind, argv + optind);
	free(blackip_file_path);
	free(whiteip_file_path);
	free(username);
	if (do_trace() < 0)
		return -1;
	return exit_code;
}
