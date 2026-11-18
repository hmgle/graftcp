#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static int pause_at_fork;

/* The test closes stdin after reaping the tracer. */
static void await_tracer_death(void)
{
	char byte;
	ssize_t result;

	if (write(STDOUT_FILENO, "R", 1) != 1)
		_exit(125);
	do {
		result = read(STDIN_FILENO, &byte, 1);
	} while (result < 0 && errno == EINTR);
	if (result != 0)
		_exit(125);
}

__attribute__((constructor)) static void setup(void)
{
	pause_at_fork = getenv("GRAFTCP_TEST_PAUSE_AT_FORK") != NULL;
	if (pause_at_fork && pthread_atfork(NULL, NULL, await_tracer_death) != 0)
		_exit(125);
}

int kill(pid_t pid, int sig)
{
	if (pid == getpid() && sig == SIGSTOP) {
		if (!pause_at_fork)
			await_tracer_death();
		/* Report the regression without actually leaving a stopped orphan. */
		(void)write(STDOUT_FILENO, "S", 1);
		_exit(125);
	}
	return syscall(SYS_kill, pid, sig);
}
