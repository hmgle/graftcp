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

#include "graftcp.h"

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
	errno = 0;
	int offset = offsetof(struct user, regs.orig_rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	if (errno != 0)
		return -1;
	return (int)val;
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
	errno = 0;
	int offset = offsetof(struct user, regs.rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	if (errno != 0)
		return -1;
	return (int)val;
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
	static const int x64_arg_offsets[] = {
		offsetof(struct user, regs.rdi),
		offsetof(struct user, regs.rsi),
		offsetof(struct user, regs.rdx),
		offsetof(struct user, regs.r10),
		offsetof(struct user, regs.r8),
		offsetof(struct user, regs.r9),
	};

	if (order < 0 || order >= (int)(sizeof(x64_arg_offsets) /
					sizeof(x64_arg_offsets[0])))
		return -1;
	errno = 0;
	val = ptrace(PTRACE_PEEKUSER, pid, x64_arg_offsets[order]);
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
