#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t root, creator, deferred_pid, waiting_child;
static int deferred_status;
static int stops_collected;

static pid_t wait_for(pid_t pid, int *status, int options)
{
	pid_t result;

	do {
		result = wait4(pid, status, options, NULL);
	} while (result < 0 && errno == EINTR);
	return result;
}

static int is_stop(int status, int signal)
{
	return WIFSTOPPED(status) && WSTOPSIG(status) == signal;
}

static int is_creation_event(int status)
{
	unsigned int event = (unsigned int)status >> 16;

	return event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK;
}

static pid_t fork_child(pid_t parent)
{
	unsigned long child = 0;

	if (ptrace(PTRACE_GETEVENTMSG, parent, 0, &child) < 0 || child == 0)
		_exit(125);
	return (pid_t)child;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	pid_t task, child = 0;
	int child_status = 0;
	siginfo_t death;
	int result;

	if (pid != -1 || options != __WALL || status == NULL)
		return wait4(pid, status, options, NULL);
	if (deferred_pid) {
		/* The initial SIGSTOP must still be active when the parent
		 * event is delivered. A resumed child might stop again at
		 * connect before the tracer asks for the next event. */
		if (waiting_child) {
			siginfo_t stop;

			if (ptrace(PTRACE_GETSIGINFO, waiting_child, 0, &stop) < 0 ||
			    stop.si_signo != SIGSTOP) {
				static const char message[] = "child resumed before creation event\n";

				write(STDERR_FILENO, message, sizeof(message) - 1);
				_exit(125);
			}
		}
		task = deferred_pid;
		*status = deferred_status;
		deferred_pid = 0;
		return task;
	}

	task = wait_for(pid, status, options);
	if (task <= 0 || stops_collected)
		return task;
	if (root == 0 && is_stop(*status, SIGSTOP))
		root = task;
	if (!creator && task == root && (unsigned)*status >> 16 == PTRACE_EVENT_FORK) {
		creator = fork_child(root);
		return task;
	}
	if (!creator)
		return task;

	/* Obtain both stops so the test can present them in either order. */
	if (task != root && task != creator && is_stop(*status, SIGSTOP)) {
		child = task;
		child_status = *status;
		task = wait_for(creator, status, options);
	}
	if (task != creator || !is_creation_event(*status)) {
		if (child)
			_exit(125);
		return task;
	}
	if (!child) {
		child = fork_child(creator);
		if (wait_for(child, &child_status, options) != child ||
		    !is_stop(child_status, SIGSTOP))
			_exit(125);
	}

	if (getenv("GRAFTCP_TEST_KEEP_CREATOR")) {
		waiting_child = child;
	} else {
		/* Leave the real death notification pending for the tracer. */
		if (kill(creator, SIGKILL) < 0)
			_exit(125);
		do {
			result = waitid(P_PID, creator, &death, WEXITED | WNOWAIT | __WALL);
		} while (result < 0 && errno == EINTR);
		if (result < 0 || death.si_code != CLD_KILLED || death.si_status != SIGKILL)
			_exit(125);
	}
	stops_collected = 1;

	if (waiting_child || getenv("GRAFTCP_TEST_CHILD_STOP_FIRST")) {
		deferred_pid = task;
		deferred_status = *status;
		*status = child_status;
		return child;
	}
	deferred_pid = child;
	deferred_status = child_status;
	return task;
}
