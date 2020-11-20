/*
 * graftcp
 * Copyright (C) 2016, 2018 Hmgle <dustgle@gmail.com>
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
#include <stdio.h>
#include <getopt.h>

#include "graftcp.h"
#include "string-set.h"

struct sockaddr_in PROXY_SA;
char *LOCAL_ADDR         = "127.0.0.1";
char *LOCAL_DEFAULT_ADDR = "0.0.0.0";
uint16_t LOCAL_PORT      = 2233;
char *LOCAL_PIPE_PAHT    = "/tmp/graftcplocal.fifo";
int LOCAL_PIPE_FD;

struct str_set *BLACKLIST_IP     = NULL;
struct str_set *WHITELACKLIST_IP = NULL;

static void load_ip_file(char *path, struct str_set **set)
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
	if (*set == NULL)
		*set = str_set_new();
	while ((read = getline(&line, &len, f)) != -1) {
		/* 7 is the shortest ip: (x.x.x.x) */
		if (read < 7)
			continue;
		line[read - 1] = '\0';
		str_set_put(*set, line);
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

static bool is_ignore(const char *ip)
{
	if (BLACKLIST_IP) {
		if (is_str_set_member(BLACKLIST_IP, ip))
			return true;
	}
	if (WHITELACKLIST_IP) {
		if (!is_str_set_member(WHITELACKLIST_IP, ip))
			return true;
	}
	return false;
}

void socket_pre_handle(struct proc_info *pinfp)
{
	struct socket_info *si = calloc(1, sizeof(*si));
	si->domain = get_syscall_arg(pinfp->pid, 0);
	si->type = get_syscall_arg(pinfp->pid, 1);

	/* If not TCP socket, ignore */
	if ((si->type & SOCK_STREAM) < 1
	     || (si->domain != AF_INET && si->domain != AF_INET6)) {
		free(si);
		return;
	}
	si->fd = -1;
	si->magic_fd = ((uint64_t)MAGIC_FD << 31) + pinfp->pid;
	add_socket_info(si);
}

void connect_pre_handle(struct proc_info *pinfp)
{
	int socket_fd = get_syscall_arg(pinfp->pid, 0);
	struct socket_info *si =
	    find_socket_info((socket_fd << 31) + pinfp->pid);
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
	} else if (dest_sa.sin_family == AF_INET6) { /* IPv6 */
		getdata(pinfp->pid, addr, (char *)&dest_sa6, sizeof(dest_sa6));
		dest_ip_port = SOCKPORT6(dest_sa6);
		inet_ntop(AF_INET6, &dest_sa6.sin6_addr, dest_str, INET6_ADDRSTRLEN);
		dest_ip_addr_str = dest_str;
	} else {
		return;
	}
	if (is_ignore(dest_ip_addr_str))
		return;

	putdata(pinfp->pid, addr, (char *)&PROXY_SA, sizeof(PROXY_SA));

	char buf[1024] = { 0 };
	char delimiter;
	strcpy(buf, dest_ip_addr_str);
	if (dest_sa.sin_family == AF_INET)		/* IPv4 */
		delimiter = ':';
	else if (dest_sa.sin_family == AF_INET6)	/* IPv6 */
		delimiter = '@';
	sprintf(&buf[strlen(buf)], "%c%d%c%d\n",
		delimiter, ntohs(dest_ip_port), delimiter, pinfp->pid);
	if (write(LOCAL_PIPE_FD, buf, strlen(buf)) <= 0) {
		if (errno)
			perror("write");
		fprintf(stderr, "write failed!\n");
	}
}

void close_pre_handle(struct proc_info *pinfp)
{
	int fd = get_syscall_arg(pinfp->pid, 0);
	struct socket_info *si = find_socket_info((fd << 31) + pinfp->pid);

	if (si) {
		del_socket_info(si);
		free(si);
	}
}

void clone_pre_handle(struct proc_info *pinfp)
{
	long flags = get_syscall_arg(pinfp->pid, 0);

	flags &= ~CLONE_UNTRACED;
	ptrace(PTRACE_POKEUSER, pinfp->pid, sizeof(long) * RDI, flags);
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

void do_child(int argc, char **argv)
{
	char *args[argc + 1];
	int i;
	pid_t pid;

	for (i = 0; i < argc; i++)
		args[i] = argv[i];
	args[argc] = NULL;
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
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

void init(int argc, char **argv)
{
	pid_t child;
	struct proc_info *pi;

	child = fork();
	if (child < 0) {
		perror("fork");
		exit(errno);
	} else if (child == 0) {
		do_child(argc, argv);
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
				   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) <
			    0) {
				perror("ptrace");
				exit(errno);
			}
		}
		event = ((unsigned)status >> 16);
		if (event != 0) {
			sig = 0;
			goto end;
		}
		if (WIFSIGNALED(status) || WIFEXITED(status)
		    || !WIFSTOPPED(status)) {
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
		if (ptrace(PTRACE_SYSCALL, pinfp->pid, 0, sig) < 0) {
			if (errno == ESRCH)
				continue;
			return -1;
		}
	}
	return 0;
}

static void usage(char **argv)
{
	fprintf(stderr, "Usage: %s [options] prog [prog-args]\n\n"
		"Options:\n"
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
		"  -h --help\n"
		"                    Display this help and exit\n"
		"\n", argv[0]);
}

int main(int argc, char **argv)
{
	int opt, index;
	bool ignore_local = true;
	struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"local-addr", required_argument, 0, 'a'},
		{"local-port", required_argument, 0, 'p'},
		{"local-fifo", required_argument, 0, 'f'},
		{"blackip-file", required_argument, 0, 'b'},
		{"whiteip-file", required_argument, 0, 'w'},
		{"not-ignore-local", no_argument, 0, 'n'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "+ha:p:f:b:w:n", long_opts,
			    	&index)) != -1) {
		switch (opt) {
		case 'a':
			LOCAL_ADDR = optarg;
			break;
		case 'p':
			LOCAL_PORT = atoi(optarg);
			break;
		case 'f':
			LOCAL_PIPE_PAHT = optarg;
			break;
		case 'b':
			load_blackip_file(optarg);
			break;
		case 'w':
			load_whiteip_file(optarg);
			break;
		case 'n':
			ignore_local = false;
			break;
		case 0:
		case 'h':
		default:
			usage(argv);
			exit(0);
		}
	}
	if (ignore_local) {
		if (BLACKLIST_IP == NULL)
			BLACKLIST_IP = str_set_new();
		str_set_put(BLACKLIST_IP, LOCAL_ADDR);
		str_set_put(BLACKLIST_IP, LOCAL_DEFAULT_ADDR);
	}
	PROXY_SA.sin_family = AF_INET;
	PROXY_SA.sin_port = htons(LOCAL_PORT);
	if (inet_aton(LOCAL_ADDR, &PROXY_SA.sin_addr) == 0) {
		struct hostent *he;

		he = gethostbyname(LOCAL_ADDR);
		if (he == NULL) {
			perror("gethostbyname");
			exit(errno);
		}
		memcpy(&PROXY_SA.sin_addr, he->h_addr, sizeof(struct in_addr));
	}

	LOCAL_PIPE_FD = open(LOCAL_PIPE_PAHT, O_WRONLY);
	if (LOCAL_PIPE_FD < 0) {
		perror("open fifo");
		fprintf(stderr, "It seems that graftcp-local is not running, should start graftcp-local first.\n");
		exit(errno);
	}

	init(argc - optind, argv + optind);
	return do_trace();
}
