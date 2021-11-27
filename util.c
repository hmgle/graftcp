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

#if defined(__arm64__) || defined(__aarch64__)
struct arm_pt_regs {
	uint32_t uregs[18];
};
#define ARM_cpsr	uregs[16]
#define ARM_pc		uregs[15]
#define ARM_lr		uregs[14]
#define ARM_sp		uregs[13]
#define ARM_ip		uregs[12]
#define ARM_fp		uregs[11]
#define ARM_r10		uregs[10]
#define ARM_r9		uregs[9]
#define ARM_r8		uregs[8]
#define ARM_r7		uregs[7]
#define ARM_r6		uregs[6]
#define ARM_r5		uregs[5]
#define ARM_r4		uregs[4]
#define ARM_r3		uregs[3]
#define ARM_r2		uregs[2]
#define ARM_r1		uregs[1]
#define ARM_r0		uregs[0]
#define ARM_ORIG_r0	uregs[17]

static union {
	struct user_pt_regs aarch64_r;
	struct arm_pt_regs  arm_r;
} arm_regs_union;
#endif

int get_syscall_number(pid_t pid)
{
#if defined(__x86_64__)
#if 1
	errno = 0;
	int offset = offsetof(struct user, regs.orig_rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	assert(errno == 0);
	return (int)val;
#else			/* another way */
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	return regs.orig_rax;
#endif
#elif defined(__arm__)
	errno = 0;
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	return regs.ARM_r7;
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	assert(errno == 0);
	switch (iov.iov_len) {
	case sizeof(struct user_pt_regs):
		return arm_regs_union.aarch64_r.regs[8];
	case sizeof(struct arm_pt_regs):
		return arm_regs_union.arm_r.ARM_r7;
	}
	return -1;
#endif
}

int get_retval(pid_t pid)
{
#if defined(__x86_64__)
#if 1
	errno = 0;
	int offset = offsetof(struct user, regs.rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	return (int)val;
#else			/* another way */
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.rax;
#endif
#elif defined(__arm__)
	errno = 0;
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.ARM_r0;
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	assert(errno == 0);
	switch (iov.iov_len) {
	case sizeof(struct user_pt_regs):
		return arm_regs_union.aarch64_r.regs[0];
	case sizeof(struct arm_pt_regs):
		return arm_regs_union.arm_r.ARM_r0;
	}
	return -1;
#endif
}

void set_retval(pid_t pid, long new_val)
{
#if defined(__x86_64__)
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	if ((long)regs.rax == new_val)
		return;
	regs.rax = new_val;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	assert(errno == 0);
#elif defined(__arm__)
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	if ((long)regs.ARM_r0 == new_val)
		return;
	regs.ARM_r0 = new_val;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	assert(errno == 0);
#elif defined(__arm64__) || defined(__aarch64__)
	/* TODO */
#endif
}

long get_syscall_arg(pid_t pid, int order)
{
	long val;
#if defined(__x86_64__)
	int offset;

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
#elif defined(__arm__)
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	switch (order) {
	case 0:
		val = regs.ARM_ORIG_r0;
		break;
	case 1:
		val = regs.ARM_r1;
		break;
	case 2:
		val = regs.ARM_r2;
		break;
	case 3:
		val = regs.ARM_r3;
		break;
	case 4:
		val = regs.ARM_r4;
		break;
	case 5:
		val = regs.ARM_r5;
		break;
	default:
		return -1;
	}
#elif defined(__arm64__) || defined(__aarch64__)
	switch (order) {
	case 0:
		val = arm_regs_union.aarch64_r.regs[0];
		break;
	case 1:
		val = arm_regs_union.aarch64_r.regs[1];
		break;
	case 2:
		val = arm_regs_union.aarch64_r.regs[2];
		break;
	case 3:
		val = arm_regs_union.aarch64_r.regs[3];
		break;
	case 4:
		val = arm_regs_union.aarch64_r.regs[4];
		break;
	case 5:
		val = arm_regs_union.aarch64_r.regs[5];
		break;
	default:
		return -1;
	}
#endif
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
