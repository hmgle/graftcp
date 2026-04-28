/*
 * graftcp
 * Copyright (C) 2018, 2021-2026 Hmgle <dustgle@gmail.com>
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
#include <stdlib.h>

#include "graftcp.h"

static int find_tracked_socket_fd(const struct proc_info *pinfp, int fd)
{
	unsigned int i;

	if (pinfp == NULL || fd < 0)
		return -1;

	for (i = 0; i < pinfp->tracked_socket_count; i++) {
		if (pinfp->tracked_socket_fds[i] == fd)
			return (int)i;
	}
	return -1;
}

int track_socket_fd(struct proc_info *pinfp, int fd)
{
	int *fds;
	unsigned int new_cap;

	if (pinfp == NULL || fd < 0)
		return -1;
	if (find_tracked_socket_fd(pinfp, fd) >= 0)
		return 0;
	if (pinfp->tracked_socket_count >= pinfp->tracked_socket_cap) {
		new_cap = pinfp->tracked_socket_cap ?
			  pinfp->tracked_socket_cap * 2 : TRACKED_SOCKET_INITIAL_CAP;
		fds = realloc(pinfp->tracked_socket_fds,
			      new_cap * sizeof(*pinfp->tracked_socket_fds));
		if (fds == NULL)
			return -1;
		pinfp->tracked_socket_fds = fds;
		pinfp->tracked_socket_cap = new_cap;
	}

	pinfp->tracked_socket_fds[pinfp->tracked_socket_count++] = fd;
	return 0;
}

bool is_tracked_socket_fd(struct proc_info *pinfp, int fd)
{
	return find_tracked_socket_fd(pinfp, fd) >= 0;
}

void untrack_socket_fd(struct proc_info *pinfp, int fd)
{
	int idx;

	idx = find_tracked_socket_fd(pinfp, fd);
	if (idx < 0)
		return;

	pinfp->tracked_socket_fds[idx] =
		pinfp->tracked_socket_fds[--pinfp->tracked_socket_count];
}

static struct proc_info *PROC_INFO_LIST = NULL;

static struct proc_info **find_proc_info_slot(pid_t pid)
{
	struct proc_info **slot = &PROC_INFO_LIST;

	while (*slot != NULL && (*slot)->pid != pid)
		slot = &(*slot)->next;
	return slot;
}

static void add_proc_info(struct proc_info *p)
{
	if (p == NULL)
		return;
	p->next = PROC_INFO_LIST;
	PROC_INFO_LIST = p;
}

static void del_proc_info(struct proc_info *p)
{
	struct proc_info **slot;

	if (p == NULL)
		return;
	slot = find_proc_info_slot(p->pid);
	if (*slot == p)
		*slot = p->next;
}

struct proc_info *find_proc_info(pid_t pid)
{
	struct proc_info **slot = find_proc_info_slot(pid);

	return *slot;
}

struct proc_info *alloc_proc_info(pid_t pid)
{
	struct proc_info *newp = calloc(1, sizeof(*newp));

	if (newp == NULL)
		return NULL;
	newp->pid = pid;
	add_proc_info(newp);
	return newp;
}

void free_proc_info(struct proc_info *p)
{
	if (p == NULL)
		return;
	del_proc_info(p);
	free(p->tracked_socket_fds);
	free(p);
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
	if (errno != 0)
		return -1;
	return (int)val;
#else			/* another way */
	struct user_regs_struct regs;
	errno = 0;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	return regs.orig_rax;
#endif
#elif defined(__i386__)
	struct user_regs_struct regs;
	errno = 0;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	return regs.orig_eax;
#elif defined(__arm__)
	errno = 0;
	struct pt_regs regs;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	return regs.ARM_r7;
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	errno = 0;
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
		return -1;
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
	if (errno != 0)
		return -1;
	return (int)val;
#else			/* another way */
	struct user_regs_struct regs;
	errno = 0;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	return regs.rax;
#endif
#elif defined(__i386__)
	errno = 0;
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	return regs.eax;
#elif defined(__arm__)
	errno = 0;
	struct pt_regs regs;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	return regs.ARM_r0;
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	errno = 0;
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
		return -1;
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
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return;
	if ((long)regs.rax == new_val)
		return;
	regs.rax = new_val;
	(void)ptrace(PTRACE_SETREGS, pid, 0, &regs);
#elif defined(__i386__)
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return;
	if ((long)regs.eax == new_val)
		return;
	regs.eax = new_val;
	(void)ptrace(PTRACE_SETREGS, pid, 0, &regs);
#elif defined(__arm__)
	struct pt_regs regs;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return;
	if ((long)regs.ARM_r0 == new_val)
		return;
	regs.ARM_r0 = new_val;
	(void)ptrace(PTRACE_SETREGS, pid, 0, &regs);
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
		return;
	switch (iov.iov_len) {
	case sizeof(struct user_pt_regs):
		arm_regs_union.aarch64_r.regs[0] = new_val;
		break;
	case sizeof(struct arm_pt_regs):
		arm_regs_union.arm_r.ARM_r0 = new_val;
		break;
	default:
		return;
	}
	(void)ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
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
	if (errno != 0)
		return -1;
#elif defined(__i386__)
	struct user_regs_struct regs;
	errno = 0;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
	switch (order) {
	case 0:
		val = regs.ebx;
		break;
	case 1:
		val = regs.ecx;
		break;
	case 2:
		val = regs.edx;
		break;
	case 3:
		val = regs.esi;
		break;
	case 4:
		val = regs.edi;
		break;
	case 5:
		val = regs.ebp;
		break;
	default:
		return -1;
	}
#elif defined(__arm__)
	struct pt_regs regs;
	errno = 0;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
		return -1;
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

int getdata(pid_t child, long addr, void *dst, size_t len)
{
	char *laddr;
	size_t i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;

	if (addr == 0 || dst == NULL)
		return -1;

	i = 0;
	j = len / sizeof(long);
	laddr = dst;
	while (i < j) {
		errno = 0;
		data.val = ptrace(PTRACE_PEEKDATA, child,
				  addr + i * (long)sizeof(long), NULL);
		if (errno != 0)
			return -1;
		memcpy(laddr, data.chars, sizeof(long));
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		errno = 0;
		data.val = ptrace(PTRACE_PEEKDATA, child,
				  addr + i * (long)sizeof(long), NULL);
		if (errno != 0)
			return -1;
		memcpy(laddr, data.chars, j);
	}
	return 0;
}

int putdata(pid_t child, long addr, const void *src, size_t len)
{
	const char *laddr;
	size_t i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;

	if (addr == 0 || src == NULL)
		return -1;

	i = 0;
	j = len / sizeof(long);
	laddr = src;
	while (i < j) {
		memcpy(data.chars, laddr, sizeof(long));
		errno = 0;
		if (ptrace(PTRACE_POKEDATA, child,
			   addr + i * (long)sizeof(long), data.val) < 0)
			return -1;
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		errno = 0;
		data.val = ptrace(PTRACE_PEEKDATA, child,
				  addr + i * (long)sizeof(long), NULL);
		if (errno != 0)
			return -1;
		memcpy(data.chars, laddr, j);
		errno = 0;
		if (ptrace(PTRACE_POKEDATA, child,
			   addr + i * (long)sizeof(long), data.val) < 0)
			return -1;
	}
	return 0;
}
