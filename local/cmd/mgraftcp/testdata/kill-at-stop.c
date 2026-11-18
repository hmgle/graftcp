#define _GNU_SOURCE
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

/* Deliver SIGKILL after the kernel reports the startup stop, before the
 * tracer installs its options. Leave the final wait status for the tracer. */
pid_t waitpid(pid_t pid, int *status, int options)
{
	pid_t child = wait4(pid, status, options, NULL);

	if (child > 0 && status && WIFSTOPPED(*status) &&
	    WSTOPSIG(*status) == SIGSTOP && kill(child, SIGKILL) < 0)
		_exit(125);
	return child;
}
