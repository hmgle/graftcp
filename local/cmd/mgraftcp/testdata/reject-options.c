#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __GLIBC__
typedef enum __ptrace_request ptrace_request;
#else
typedef int ptrace_request;
#endif

static pid_t tracee;

/* Never run a target while the fault injection probe is loaded. */
int execvp(const char *file, char *const argv[])
{
	(void)write(2, "execvp reached\n", sizeof("execvp reached\n") - 1);
	_exit(125);
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	int local_status;
	if (!status)
		status = &local_status;
	pid_t result = wait4(pid, status, options, NULL);
	if (result > 0 && result == tracee && WIFSIGNALED(*status) &&
	    WTERMSIG(*status) == SIGKILL)
		(void)write(2, "reaped SIGKILL\n", sizeof("reaped SIGKILL\n") - 1);
	return result;
}

int kill(pid_t pid, int sig)
{
	if (tracee > 0 && pid == tracee && sig == SIGKILL && getenv("GRAFTCP_TEST_DENY_KILL")) {
		errno = EPERM;
		return -1;
	}
	return syscall(SYS_kill, pid, sig);
}

long ptrace(ptrace_request request, ...)
{
	va_list args;
	if (request == PTRACE_TRACEME)
		return syscall(SYS_ptrace, request, 0, 0, 0);
	if (request == PTRACE_CONT && getenv("GRAFTCP_TEST_DENY_KILL")) {
		errno = EINVAL;
		return -1;
	}
	if (request != PTRACE_SETOPTIONS)
		_exit(125);
	va_start(args, request);
	tracee = va_arg(args, pid_t);
	va_end(args);
	errno = EINVAL;
	return -1;
}
