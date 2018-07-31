/*
 * graftcp
 * Copyright (C) 2018 Hmgle <dustgle@gmail.com>
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
#include "graftcp.h"

struct socket_info *SOCKET_INFO_TAB = NULL;

void add_socket_info(struct socket_info *s)
{
	HASH_ADD_INT(SOCKET_INFO_TAB, magic_fd, s);
}

void del_socket_info(struct socket_info *s)
{
	HASH_DEL(SOCKET_INFO_TAB, s);
}

struct socket_info *find_socket_info(uint64_t magic_fd)
{
	struct socket_info *s;

	HASH_FIND_INT(SOCKET_INFO_TAB, &magic_fd, s);
	return s;
}

struct proc_info *PROC_INFO_TAB = NULL;

void add_proc_info(struct proc_info *p)
{
	HASH_ADD_INT(PROC_INFO_TAB, pid, p);
}

void del_proc_info(struct proc_info *p)
{
	HASH_DEL(PROC_INFO_TAB, p);
}

struct proc_info *find_proc_info(pid_t pid)
{
	struct proc_info *p;

	HASH_FIND_INT(PROC_INFO_TAB, &pid, p);
	return p;
}

struct proc_info *alloc_proc_info(pid_t pid)
{
	struct proc_info *newp = calloc(1, sizeof(*newp));
	newp->pid = pid;
	add_proc_info(newp);
	return newp;
}

#ifndef offsetof
#define offsetof(a, b) __builtin_offsetof(a,b)
#endif

int get_syscall_number(pid_t pid)
{
#if 1
	errno = 0;
	int offset = offsetof(struct user, regs.orig_rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	assert(errno == 0);
	return (int)val;
#else				/* another way */
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	return regs.orig_rax;
#endif
}

int get_retval(pid_t pid)
{
#if 1
	errno = 0;
	int offset = offsetof(struct user, regs.rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	return (int)val;
#else				/* another way */
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.rax;
#endif
}

void set_retval(pid_t pid, long new_val)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	if (regs.rax == new_val)
		return;
	regs.rax = new_val;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	assert(errno == 0);
}

long get_syscall_arg(pid_t pid, int order)
{
	int offset;
	long val;

	switch (order) {
	case 0:
		offset = offsetof(struct user, regs.rdi);
		break;
	case 1:
		offset = offsetof(struct user, regs.rsi);
		break;
	case 2:
		offset = offsetof(struct user, regs.rdx);
		break;
	case 3:
		offset = offsetof(struct user, regs.r10);
		break;
	case 4:
		offset = offsetof(struct user, regs.r8);
		break;
	case 5:
		offset = offsetof(struct user, regs.r9);
		break;
	default:
		return -1;
	}
	errno = 0;
	val = ptrace(PTRACE_PEEKUSER, pid, offset);
	assert(errno == 0);
	return val;
}

void getdata(pid_t child, long addr, char *dst, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;

	i = 0;
	j = len / sizeof(long);
	laddr = dst;
	while (i < j) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
		memcpy(laddr, data.chars, sizeof(long));
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
		memcpy(laddr, data.chars, j);
	}
}

void putdata(pid_t child, long addr, char *src, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;

	i = 0;
	j = len / sizeof(long);
	laddr = src;
	while (i < j) {
		memcpy(data.chars, laddr, sizeof(long));
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
	}
}
