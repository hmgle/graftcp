/*
 * graftcp
 * Copyright (C) 2016, 2018-2024 Hmgle <dustgle@gmail.com>
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
#include "conf.h"
#include "cidr-trie.h"

#ifndef VERSION
#define VERSION "v0.7"
#endif

struct sockaddr_in PROXY_SA;
struct sockaddr_in6 PROXY_SA6;

char *DEFAULT_LOCAL_ADDR         = "127.0.0.1";
char *LOCAL_DEFAULT_ADDR         = "0.0.0.0";
uint16_t DEFAULT_LOCAL_PORT      = 2233;
char *DEFAULT_LOCAL_PIPE_PAHT    = "/tmp/graftcplocal.fifo";
bool DEFAULT_IGNORE_LOCAL        = true;
int LOCAL_PIPE_FD;

cidr_trie_t *BLACKLIST_IP     = NULL;
cidr_trie_t *WHITELACKLIST_IP = NULL;


static uid_t run_uid;
static gid_t run_gid;
static char *run_home;

static int exit_code = 0;

static void load_ip_file(char *path, cidr_trie_t **trie)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("fopen");
		exit(1);
	}
	while ((read = getline(&line, &len, f)) != -1) {
		/* 7 is the shortest ip: (x.x.x.x) */
		if (read < 7)
			continue;
		line[read - 1] = '\0';
		if (*trie == NULL)
			*trie = cidr_trie_new();
		cidr_trie_insert_str(*trie, line, 1);
		line = NULL;
	}
	fclose(f);
}

static void load_blackip_file(char *path)
{
	load_ip_file(path, &BLACKLIST_IP);
}

static void load_whiteip_file(char *path)
{
	load_ip_file(path, &WHITELACKLIST_IP);
}

static bool ip4_is_ignore(uint32_t ip)
{
	if (BLACKLIST_IP) {
		if (cidr4_trie_lookup(BLACKLIST_IP, ntohl(ip)))
			return true;
	}
	if (WHITELACKLIST_IP) {
		if (!cidr4_trie_lookup(WHITELACKLIST_IP, ntohl(ip)))
			return true;
	}
	return false;
}

static bool ip6_is_ignore(uint8_t *ip)
{
	if (BLACKLIST_IP) {
		if (cidr6_trie_lookup(BLACKLIST_IP, ip))
			return true;
	}
	if (WHITELACKLIST_IP) {
		if (!cidr6_trie_lookup(WHITELACKLIST_IP, ip))
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
	 * syscalls to trace, sort by frequency in desc order for most cases:
	 *   close(...),
	 *   socket([AF_INET | AF_INET6], SOCK_STREAM, ...),
	 *   connect(...),
	 *   clone([CLONE_UNTRACED], ...) (only for x86_64)
	 */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				(offsetof(struct seccomp_data, nr))),
#if defined(__x86_64__)
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 10, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 7),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, SOCK_STREAM, 4, 5),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_UNTRACED, 0, 1),
#else
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 7, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, SOCK_STREAM, 1, 2),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
#endif
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
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
	struct socket_info *si = calloc(1, sizeof(*si));
	si->domain = get_syscall_arg(pinfp->pid, 0);
	si->type = get_syscall_arg(pinfp->pid, 1);

#ifndef ENABLE_SECCOMP_BPF
	/* If not TCP socket, ignore */
	if ((si->type & SOCK_STREAM) < 1
	     || (si->domain != AF_INET && si->domain != AF_INET6)) {
		free(si);
		return;
	}
#endif
	si->fd = -1;
	si->magic_fd = ((uint64_t)MAGIC_FD << 31) + pinfp->pid;
	add_socket_info(si);
}

void connect_pre_handle(struct proc_info *pinfp)
{
	int socket_fd = get_syscall_arg(pinfp->pid, 0);
	struct socket_info *si = find_socket_info((socket_fd << 31) + pinfp->pid);
	if (si == NULL)
		return;

	long addr = get_syscall_arg(pinfp->pid, 1);
	struct sockaddr_in dest_sa;
	struct sockaddr_in6 dest_sa6;
	unsigned short dest_ip_port;
	struct in_addr dest_ip_addr;
	char *dest_ip_addr_str;
	char dest_str[INET6_ADDRSTRLEN];

	getdata(pinfp->pid, addr, (char *)&dest_sa, sizeof(dest_sa));

	if (dest_sa.sin_family == AF_INET) { /* IPv4 */
		dest_ip_port = SOCKPORT(dest_sa);
		dest_ip_addr.s_addr = SOCKADDR(dest_sa);
		dest_ip_addr_str = inet_ntoa(dest_ip_addr);
		if (ip4_is_ignore(dest_ip_addr.s_addr))
			return;
	} else if (dest_sa.sin_family == AF_INET6) { /* IPv6 */
		getdata(pinfp->pid, addr, (char *)&dest_sa6, sizeof(dest_sa6));
		dest_ip_port = SOCKPORT6(dest_sa6);
		if (ip6_is_ignore(dest_sa6.sin6_addr.s6_addr))
			return;
		inet_ntop(AF_INET6, &dest_sa6.sin6_addr, dest_str, INET6_ADDRSTRLEN);
		dest_ip_addr_str = dest_str;
	} else {
		return;
	}

	if (dest_sa.sin_family == AF_INET) /* IPv4 */
		putdata(pinfp->pid, addr, (char *)&PROXY_SA, sizeof(PROXY_SA));
	else /* IPv6 */
		putdata(pinfp->pid, addr, (char *)&PROXY_SA6, sizeof(PROXY_SA6));

	char buf[1024] = { 0 };
	strcpy(buf, dest_ip_addr_str);
	strcat(buf, ":");
	sprintf(&buf[strlen(buf)], "%d:%d\n", ntohs(dest_ip_port), pinfp->pid);
	if (write(LOCAL_PIPE_FD, buf, strlen(buf)) <= 0) {
		if (errno)
			perror("write");
		fprintf(stderr, "write failed!\n");
	}
	gettimeofday(&si->conn_ti, NULL);
}

void close_pre_handle(struct proc_info *pinfp)
{
	int fd = get_syscall_arg(pinfp->pid, 0);
	struct socket_info *si = find_socket_info((fd << 31) + pinfp->pid);
	struct timeval now;
	unsigned long delta_ms;

	if (si) {
		gettimeofday(&now, NULL);
		delta_ms = (now.tv_sec - si->conn_ti.tv_sec) * 1000 +
			(now.tv_usec - si->conn_ti.tv_usec) / 1000;
		if (delta_ms < MIN_CLOSE_MSEC)
			usleep((MIN_CLOSE_MSEC - delta_ms) * 1000);

		del_socket_info(si);
		free(si);
	}
}

void clone_pre_handle(struct proc_info *pinfp)
{
#if defined(__x86_64__)
	long flags = get_syscall_arg(pinfp->pid, 0);

	flags &= ~CLONE_UNTRACED;
	ptrace(PTRACE_POKEUSER, pinfp->pid, sizeof(long) * RDI, flags);
#elif defined(__arm__) || defined(__arm64__) || defined(__aarch64__)
	/* Do not know how to handle this */
#endif
}

void socket_exiting_handle(struct proc_info *pinfp, int fd)
{
	struct socket_info *si;

	si = find_socket_info(((uint64_t)MAGIC_FD << 31) + pinfp->pid);
	if (si == NULL)
		return;
	si->fd = fd;
	del_socket_info(si);
	si->magic_fd = (fd << 31) + pinfp->pid;
	add_socket_info(si);
}

void do_child(struct graftcp_conf *conf, int argc, char **argv)
{
	char *args[argc + 1];
	int i;
	pid_t pid;

	for (i = 0; i < argc; i++)
		args[i] = argv[i];
	args[argc] = NULL;
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	if (conf->username) {
		if (initgroups(conf->username, run_gid) < 0) {
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

	pid = getpid();
	/*
	 * Induce a ptrace stop. Tracer (our parent)
	 * will resume us with PTRACE_SYSCALL and display
	 * the immediately following execve syscall.
	 */
	kill(pid, SIGSTOP);
	if (execvp(args[0], args) < 0) {
		fprintf(stderr, "graftcp %s: %s\n", args[0], strerror(errno));
		exit(errno);
	}
}

void init(struct graftcp_conf *conf, int argc, char **argv)
{
	pid_t child;
	struct proc_info *pi;

	child = fork();
	if (child < 0) {
		perror("fork");
		exit(errno);
	} else if (child == 0) {
#ifdef ENABLE_SECCOMP_BPF
		install_seccomp();
#endif
		do_child(conf, argc, argv);
	}
	pi = alloc_proc_info(child);
	pi->flags |= FLAG_STARTUP;
}

int trace_syscall_entering(struct proc_info *pinfp)
{
	pinfp->csn = get_syscall_number(pinfp->pid);
	switch (pinfp->csn) {
	case SYS_socket:
		socket_pre_handle(pinfp);
		break;
	case SYS_connect:
		connect_pre_handle(pinfp);
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

int do_trace()
{
	pid_t child;
	int status;
	int stopped;
	int sig;
	unsigned event;
	struct proc_info *pinfp;

	for (;;) {
		child = wait(&status);
		if (child < 0)
			return 0;
		pinfp = find_proc_info(child);
		if (!pinfp)
			pinfp = alloc_proc_info(child);

		if (pinfp->flags & FLAG_STARTUP) {
			pinfp->flags &= ~FLAG_STARTUP;

			if (ptrace(PTRACE_SETOPTIONS, child, 0,
				   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
#ifdef ENABLE_SECCOMP_BPF
				   PTRACE_O_TRACESECCOMP |
#endif
				   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) <
			    0) {
				perror("ptrace");
				exit(errno);
			}
		}
		event = ((unsigned)status >> 16);
#ifdef ENABLE_SECCOMP_BPF
		if (event != 0 && event != PTRACE_EVENT_SECCOMP) {
			sig = 0;
			goto end;
		}
#else
		if (event != 0) {
			sig = 0;
			goto end;
		}
#endif
		if (WIFSIGNALED(status) || WIFEXITED(status)
		    || !WIFSTOPPED(status)) {
			exit_code = WEXITSTATUS(status);
			/* TODO free pinfp */
			continue;
		}
		sig = WSTOPSIG(status);
		if (sig == SIGSTOP) {
			sig = 0;
			goto end;
		}
		if (sig != SIGTRAP) {
			siginfo_t si;
			stopped =
			    (ptrace(PTRACE_GETSIGINFO, child, 0, (long)&si) <
			     0);
			if (!stopped) {
				/* It's signal-delivery-stop. Inject the signal */
				goto end;
			}
		}
		if (trace_syscall(pinfp) < 0)
			continue;
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
		"  -c --conf-file=<config-file-path>\n"
		"                    Specify configuration file.\n"
		"                    Default: $XDG_CONFIG_HOME/graftcp/graftcp.conf\n"
		"  -a --local-addr=<graftcp-local-IP-addr>\n"
		"                    graftcp-local's IP address. Default: localhost\n"
		"  -p --local-port=<graftcp-local-port>\n"
		"                    Which port is graftcp-local listening? Default: 2233\n"
		"  -f --local-fifo=<fifo-path>\n"
		"                    Path of fifo to communicate with graftcp-local.\n"
		"                    Default: /tmp/graftcplocal.fifo\n"
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
		"  -V --version\n"
		"                    Show version\n"
		"  -h --help\n"
		"                    Display this help and exit\n"
		"\n", argv[0]);
}

int client_main(int argc, char **argv)
{
	int opt, index;
	struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'V'},
		{"conf-file", required_argument, 0, 'c'},
		{"local-addr", required_argument, 0, 'a'},
		{"local-port", required_argument, 0, 'p'},
		{"local-fifo", required_argument, 0, 'f'},
		{"blackip-file", required_argument, 0, 'b'},
		{"whiteip-file", required_argument, 0, 'w'},
		{"user", required_argument, 0, 'u'},
		{"not-ignore-local", no_argument, 0, 'n'},
		{0, 0, 0, 0}
	};

	struct graftcp_conf conf = {
		.local_addr             = DEFAULT_LOCAL_ADDR,
		.local_port             = &DEFAULT_LOCAL_PORT,
		.pipe_path              = DEFAULT_LOCAL_PIPE_PAHT,
		.blackip_file_path      = NULL,
		.whiteip_file_path      = NULL,
		.ignore_local           = &DEFAULT_IGNORE_LOCAL,
		.username               = NULL,
	};

	__defer_free char *conf_file_path = NULL;
	__defer_conf_free struct graftcp_conf file_conf;
	__defer_conf_free struct graftcp_conf cmd_conf;
	conf_init(&file_conf);
	conf_init(&cmd_conf);

	while ((opt = getopt_long(argc, argv, "+Vha:p:f:b:w:c:u:n", long_opts,
			    	&index)) != -1) {
		switch (opt) {
		case 'a':
			cmd_conf.local_addr = strdup(optarg);
			break;
		case 'p':
			cmd_conf.local_port = malloc(sizeof(*cmd_conf.local_port));
			*cmd_conf.local_port = atoi(optarg);
			break;
		case 'f':
			cmd_conf.pipe_path = strdup(optarg);
			break;
		case 'b':
			cmd_conf.blackip_file_path = strdup(optarg);
			break;
		case 'w':
			cmd_conf.whiteip_file_path = strdup(optarg);
			break;
		case 'n':
			cmd_conf.ignore_local = malloc(sizeof(*cmd_conf.ignore_local));
			*cmd_conf.ignore_local = false;
			break;
		case 'c':
			conf_file_path = strdup(optarg);
			break;
		case 'u':
			cmd_conf.username = strdup(optarg);
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
	conf_read(conf_file_path, &file_conf);
	conf_override(&conf, &file_conf);
	conf_override(&conf, &cmd_conf);

	if (conf.blackip_file_path)
		load_blackip_file(conf.blackip_file_path);
	if (conf.whiteip_file_path)
		load_whiteip_file(conf.whiteip_file_path);
	if (*conf.ignore_local) {
		if (BLACKLIST_IP == NULL)
			BLACKLIST_IP = cidr_trie_new();
		cidr_trie_insert_str(BLACKLIST_IP, conf.local_addr, 1);
		cidr_trie_insert_str(BLACKLIST_IP, LOCAL_DEFAULT_ADDR, 1);
	}
	PROXY_SA.sin_family = AF_INET;
	PROXY_SA.sin_port = htons(*conf.local_port);
	if (inet_aton(conf.local_addr, &PROXY_SA.sin_addr) == 0) {
		struct hostent *he;

		he = gethostbyname(conf.local_addr);
		if (he == NULL) {
			perror("gethostbyname");
			exit(errno);
		}
		memcpy(&PROXY_SA.sin_addr, he->h_addr, sizeof(struct in_addr));
	}
	PROXY_SA6.sin6_family = AF_INET6;
	PROXY_SA6.sin6_port = htons(*conf.local_port);
	if (inet_pton(AF_INET6, "::1", &PROXY_SA6.sin6_addr) < 0 ) {
		perror("inet_pton");
		exit(errno);
	}

	LOCAL_PIPE_FD = open(conf.pipe_path, O_WRONLY);
	if (LOCAL_PIPE_FD < 0) {
		perror("open fifo");
		fprintf(stderr, "It seems that graftcp-local is not running, should start graftcp-local first.\n");
		exit(errno);
	}

	if (conf.username) {
		struct passwd *pent;

		if (geteuid() != 0) {
			fprintf(stderr, "You must be root to use the -u option\n");
			exit(1);
		}
		pent = getpwnam(conf.username);
		if (pent == NULL) {
			fprintf(stderr, "Cannot find user '%s'\n", conf.username);
			exit(1);
		}
		run_gid = pent->pw_gid;
		run_uid = pent->pw_uid;
		run_home = strdup(pent->pw_dir);
	}

	init(&conf, argc - optind, argv + optind);
	if (do_trace() < 0)
		return -1;
	return exit_code;
}
