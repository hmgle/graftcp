/* Drive the real tracer, inspecting its process table after a late event. */
#define _GNU_SOURCE
/* Exercise private creation bookkeeping with deterministic event order. */
#include "graftcp.c"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static pid_t root, child;
static int fork_status, death_status;
static bool report_stop, unqueued;

/* The tracee does not open sockets. */
uint32_t mgraftcp_register_connect(int family, const char *addr, uint16_t port) { abort(); }
uint32_t mgraftcp_reserve_udp(int family, const char *addr, uint16_t port) { abort(); }
void mgraftcp_forget_connect(uint32_t token) { abort(); }
void mgraftcp_finish_udp_rewrite(uint32_t token, int rewritten) { abort(); }
void mgraftcp_start_udp_use(uint32_t token) { abort(); }
void mgraftcp_finish_udp_use(uint32_t token, int accepted) { abort(); }

/* Replay the real event with an unqueued creator. Check both possible
 * registry states without depending on a race in shared clone3 arguments. */
static void check_unqueued_event(void)
{
	struct proc_info parent = *find_proc_info(root);
	struct proc_info *live;

	parent.flags &= ~FLAG_CREATING_CHILD;
#ifdef SYS_clone3
	parent.csn = SYS_clone3;
	parent.clone_flags = CLONE_UNTRACED | CLONE_FILES;
#endif
	if (inherit_child_proc_info(&parent, PTRACE_EVENT_FORK) < 0 || find_proc_info(child)) {
		fprintf(stderr, "unqueued creator recreated a reaped child\n");
		exit(1);
	}
	live = alloc_proc_info(child);
	if (!live || track_socket_fd(live, 17, AF_INET, SOCK_DGRAM) < 0 ||
	    inherit_child_proc_info(&parent, PTRACE_EVENT_FORK) < 0 ||
	    !is_tracked_dgram_socket_fd(live, 17)) {
		fprintf(stderr, "unqueued creator replaced a live child's socket table\n");
		exit(1);
	}
	free_proc_info(live);
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	unsigned long new_pid;
	pid_t result;

	if (pid != -1 || options != __WALL)
		return wait4(pid, status, options, NULL);
	if (death_status) {
		*status = death_status;
		death_status = 0;
		return child;
	}
	if (fork_status) {
		if (unqueued)
			check_unqueued_event();
		*status = fork_status;
		fork_status = 0;
		return root;
	}

	/* Collect the creator's event before reading the child's status. */
	result = wait4(root && !child ? root : -1, status, options, NULL);
	if (result <= 0)
		return result;
	if (!root)
		root = result;
	if ((unsigned)*status >> 16 != PTRACE_EVENT_FORK)
		return result;
	if (ptrace(PTRACE_GETEVENTMSG, root, 0, &new_pid) < 0)
		abort();
	child = (pid_t)new_pid;
	fork_status = *status;
	if (wait4(child, status, options, NULL) != child || !WIFSTOPPED(*status))
		abort();
	if (kill(child, SIGKILL) < 0 ||
	    wait4(child, &death_status, options, NULL) != child ||
	    !WIFSIGNALED(death_status) || WTERMSIG(death_status) != SIGKILL)
		abort();
	if (!report_stop) {
		*status = death_status;
		death_status = 0;
	}
	return child;
}

static int test_overlapping_creators(void)
{
	struct proc_info a = {0}, b = {0}, later = {0};
	pid_t reused_pid = 42;

	start_child_creation(&a);
	start_child_creation(&b);
	if (remember_reaped_child(reused_pid, creation_seq) < 0)
		return 1;
	start_child_creation(&later);
	/* B reports the reused PID first. A's late event must still be
	 * rejected. A creator started after the death is unambiguous. */
	if (!finish_child_creation(&b, reused_pid) ||
	    finish_child_creation(&later, reused_pid) ||
	    !finish_child_creation(&a, reused_pid) || reaped_children != NULL) {
		fprintf(stderr, "incorrect PID match across overlapping forks\n");
		return 1;
	}
	return 0;
}

#if defined(SYS_clone3) && defined(CLONE_ARGS_SIZE_VER0)
static void stop_for_tracer(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 || kill(getpid(), SIGSTOP) < 0)
		_exit(1);
}

static int test_untraced_vfork(void)
{
	struct proc_info unrelated = {0}, live = {0}, a = {0}, b = {0};
	int gate[2], status;

	if (pipe(gate) < 0 || (unrelated.pid = fork()) < 0)
		return 1;
	if (unrelated.pid == 0) {
		struct clone_args args = {.flags = CLONE_UNTRACED | CLONE_VFORK,
					  .exit_signal = SIGCHLD};
		sigset_t blocked;
		char byte;
		close(gate[1]);
		sigemptyset(&blocked);
		sigaddset(&blocked, SIGCHLD);
		if (sigprocmask(SIG_BLOCK, &blocked, NULL) < 0)
			_exit(1);
		stop_for_tracer();
		pid_t pid = syscall(SYS_clone3, &args, CLONE_ARGS_SIZE_VER0);
		if (pid == 0)
			_exit(read(gate[0], &byte, 1) == 1 ? 0 : 1);
		if (pid < 0)
			_exit(errno == ENOSYS || errno == EPERM ? 77 : 1);
		_exit(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		      WEXITSTATUS(status) == 0 ? 0 : 1);
	}
	if (waitpid(unrelated.pid, &status, 0) != unrelated.pid || !WIFSTOPPED(status) ||
	    ptrace(PTRACE_SETOPTIONS, unrelated.pid, 0, PTRACE_O_TRACESYSGOOD |
		   PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL) < 0 ||
	    ptrace(PTRACE_SYSCALL, unrelated.pid, 0, 0) < 0 ||
	    waitpid(unrelated.pid, &status, 0) != unrelated.pid || !is_syscall_stop(status) ||
	    trace_syscall_entering(&unrelated) < 0 || unrelated.csn != SYS_clone3 ||
	    ptrace(PTRACE_CONT, unrelated.pid, 0, 0) < 0)
		return 1;

	if ((live.pid = fork()) < 0)
		return 1;
	if (live.pid == 0) {
		stop_for_tracer();
		_exit(write(gate[1], "R", 1) == 1 ? 0 : 1);
	}
	close(gate[1]);
	if (waitpid(live.pid, &status, 0) != live.pid || !WIFSTOPPED(status) ||
	    ptrace(PTRACE_SETOPTIONS, live.pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0)
		return 1;

	start_child_creation(&a);
	start_child_creation(&b);
	if (remember_reaped_child(live.pid, creation_seq) < 0)
		return 1;
	live.creation_seq = creation_seq;
	live.waiting_for_parent = true;
	enqueue_tracee(&waiting_children, &live);
	if (!finish_child_creation(&b, live.pid) || !finish_child_creation(&a, live.pid) ||
	    resume_unmatched_children() < 0 || live.waiting_for_parent) {
		fprintf(stderr, "untraced vfork held the waiting child\n");
		return 1;
	}
	if (waitpid(live.pid, &status, 0) != live.pid)
		return 1;
	/* The non-seccomp tracer resumes to the next syscall stop. */
	if (is_syscall_stop(status) &&
	    (ptrace(PTRACE_CONT, live.pid, 0, 0) < 0 || waitpid(live.pid, &status, 0) != live.pid))
		return 1;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
	    waitpid(unrelated.pid, &status, 0) != unrelated.pid ||
	    !WIFEXITED(status))
		return 1;
	close(gate[0]);
	if (WEXITSTATUS(status) == 77) {
		puts("clone3 unavailable at runtime; verified creator queue at syscall entry");
		return 0;
	}
	return WEXITSTATUS(status);
}
#endif

int main(int argc, char **argv)
{
	alarm(10);
	if (argc == 2 && strcmp(argv[1], "untraced-vfork") == 0) {
#if defined(SYS_clone3) && defined(CLONE_ARGS_SIZE_VER0)
		return test_untraced_vfork();
#else
		puts("skipping untraced vfork test: no clone3 headers");
		return 0;
#endif
	}
	if (argc == 2 && strcmp(argv[1], "overlap") == 0)
		return test_overlapping_creators();
	if (argc == 2 && strcmp(argv[1], "tracee") == 0) {
		int status;
		pid_t pid = fork();
		if (pid == 0)
			_exit(1);
		return pid > 0 && waitpid(pid, &status, 0) == pid &&
		       WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 1;
	}

	char *command[] = {"graftcp", "--", argv[0], "tracee", NULL};
	report_stop = argc == 2 && strcmp(argv[1], "stop-first") == 0;
	unqueued = argc == 2 && strcmp(argv[1], "unqueued") == 0;
	if (client_main(4, command) != 0 || child <= 0)
		return 1;
	if (find_proc_info(child)) {
		fprintf(stderr, "late fork event recreated the reaped child's process table entry\n");
		return 1;
	}
	return 0;
}
