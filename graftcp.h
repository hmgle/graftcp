/*
 * graftcp
 * Copyright (C) 2018, 2020 Hmgle <dustgle@gmail.com>
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
#ifndef GRAFTCP_H
#define GRAFTCP_H

#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#if defined(__x86_64__)
#include <sys/reg.h>
#include <linux/sched.h>
#elif defined(__arm__)
#include <asm/ptrace.h>
#elif defined(__arm64__) || defined(__aarch64__)
#include <asm/ptrace.h>
#include <linux/elf.h>
#endif
#include <sys/syscall.h>
#include <fcntl.h>
#include <assert.h>

#include "uthash.h"

#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__)

#ifndef SYS_socket
#define SYS_socket __NR_socket
#endif

#ifndef SYS_connect
#define SYS_connect __NR_connect
#endif

#ifndef SYS_close
#define SYS_close __NR_close
#endif

#ifndef SYS_clone
#define SYS_clone __NR_clone
#endif

#ifndef SYS_exit
#define SYS_exit __NR_exit
#endif

#ifndef SYS_exit_group
#define SYS_exit_group __NR_exit_group
#endif

#endif

#define satosin(x)  ((struct sockaddr_in *) &(x))
#define SOCKADDR(x) (satosin(x)->sin_addr.s_addr)
#define SOCKPORT(x) (satosin(x)->sin_port)

#define satosin6(x)  ((struct sockaddr_in6 *) &(x))
#define SOCKPORT6(x) (satosin6(x)->sin6_port)

#define MIN_CLOSE_MSEC 500

struct socket_key {
	pid_t pid;
	int fd;
};

static inline struct socket_key socket_key(pid_t pid, int fd)
{
	struct socket_key key;
	memset(&key, 0, sizeof(key));
	key.pid = pid;
	key.fd = fd;
	return key;
}

struct socket_info {
	struct socket_key key;
	int domain;
	int type;
	size_t dest_addr_len;
	char dest_addr[sizeof(struct sockaddr_in6)];
	struct timeval conn_ti;
	UT_hash_handle hh;	/* makes this structure hashable */
};

#define FLAG_STARTUP    00002
#define FLAG_INSYSCALL  00010

#define exiting(pinfp)  ((pinfp)->flags & FLAG_INSYSCALL)

struct proc_info {
	pid_t pid;
	int flags;
	int csn;		/* current syscall number */
	struct socket_info *pending_socket;
	UT_hash_handle hh;	/* makes this structure hashable */
};

void add_socket_info(struct socket_info *s);
void del_socket_info(struct socket_info *s);
struct socket_info *find_socket_info(pid_t pid, int fd);

void add_proc_info(struct proc_info *p);
void del_proc_info(struct proc_info *p);
struct proc_info *find_proc_info(pid_t pid);
struct proc_info *alloc_proc_info(pid_t pid);

int get_syscall_number(pid_t pid);
int get_retval(pid_t pid);
void set_retval(pid_t pid, long new_val);
long get_syscall_arg(pid_t pid, int order);

void getdata(pid_t child, long addr, char *dst, int len);
void putdata(pid_t child, long addr, char *src, int len);

#endif
