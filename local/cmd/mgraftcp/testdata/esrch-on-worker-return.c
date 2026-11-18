#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>

#ifdef __GLIBC__
typedef enum __ptrace_request ptrace_request;
#else
typedef int ptrace_request;
#endif

static pid_t root;
static int injected;

long ptrace(ptrace_request request, ...)
{
	va_list args;
	pid_t pid;
	unsigned long addr, data;
	long value, number;
	const char *operation;

	if (request == PTRACE_TRACEME)
		return syscall(SYS_ptrace, request, 0, 0, 0);

	va_start(args, request);
	pid = va_arg(args, pid_t);
	addr = va_arg(args, unsigned long);
	data = va_arg(args, unsigned long);
	va_end(args);

	if (request == PTRACE_SETOPTIONS)
		root = pid;

	/* x86-64 uses PEEKUSER at rax to read the syscall return value. */
	if (request == PTRACE_PEEKUSER && addr == offsetof(struct user, regs.rax) &&
	    root && pid != root && !injected &&
	    (operation = getenv("GRAFTCP_TEST_WORKER_SYSCALL")) &&
	    syscall(SYS_ptrace, request, pid, offsetof(struct user, regs.orig_rax), &number) == 0 &&
	    ((number == SYS_socket && strcmp(operation, "socket") == 0) ||
	     (number == SYS_dup && strcmp(operation, "dup") == 0) ||
	     (number == SYS_fcntl && strcmp(operation, "fcntl") == 0))) {
		injected = 1;
		(void)write(STDERR_FILENO, "injected ESRCH\n", sizeof("injected ESRCH\n") - 1);
		errno = ESRCH;
		return -1;
	}

	if (request == PTRACE_PEEKTEXT || request == PTRACE_PEEKDATA ||
	    request == PTRACE_PEEKUSER) {
		if (syscall(SYS_ptrace, request, pid, addr, &value) < 0)
			return -1;
		errno = 0;
		return value;
	}
	return syscall(SYS_ptrace, request, pid, addr, data);
}
