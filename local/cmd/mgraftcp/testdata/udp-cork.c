#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void *cork_new_alias(void *arg)
{
	int *pipefd = arg;
	int alias, enabled = 1;

	if (read(pipefd[0], &alias, sizeof(alias)) != sizeof(alias) ||
	    setsockopt(alias, IPPROTO_UDP, UDP_CORK, &enabled, sizeof(enabled)) < 0)
		return arg;
	return NULL;
}

static int cork_from_existing_thread(int fd)
{
	int pipefd[2];
	pthread_t thread;
	void *result;
	int alias;

	if (pipe(pipefd) < 0 ||
	    pthread_create(&thread, NULL, cork_new_alias, pipefd) != 0)
		return -1;

	/* pthread_create has installed CLONE_FILES before this dup. */
	alias = dup(fd);
	if (alias < 0 || write(pipefd[1], &alias, sizeof(alias)) != sizeof(alias) ||
	    pthread_join(thread, &result) != 0 || result != NULL)
		return -1;

	close(alias);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

#ifdef SYS_fork
static int exit_clone(void *arg)
{
	(void)arg;
	return 0;
}
#endif

static int cork_from_fork(int fd, int native)
{
	int pipefd[2], status, enabled = 1;
	int alias = dup(fd);
	char ready;
	pid_t pid;

	if (alias < 0 || pipe(pipefd) < 0)
		return -1;
	if (native) {
#ifdef SYS_fork
		char stack[16384];

		/* Wait without any intervening seccomp-traced syscall. */
		pid = clone(exit_clone, stack + sizeof(stack), CLONE_FILES | SIGCHLD, NULL);
		if (pid < 0 || waitpid(pid, &status, 0) != pid ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			return -1;
		pid = syscall(SYS_fork);
#else
		return -1;
#endif
	} else {
		pid = fork();
	}
	if (pid < 0)
		return -1;
	if (pid == 0) {
		close(pipefd[1]);
		/* Close in the parent must leave the child's copy intact. */
		_exit(read(pipefd[0], &ready, 1) != 1 ||
		      setsockopt(alias, IPPROTO_UDP, UDP_CORK, &enabled, sizeof(enabled)) < 0);
	}
	close(alias);
	close(pipefd[0]);
	if (write(pipefd[1], "R", 1) != 1 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	close(pipefd[1]);
	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_in dest = {.sin_family = AF_INET};
	struct sockaddr_un control = {.sun_family = AF_UNIX};
	struct timeval timeout = {.tv_sec = 5};
	int flag = 1;
	int fd, sync_fd, writer = -1;
	char signal;
	ssize_t sent;
	int corked, from_thread, from_fork, native_fork;

	if (argc != 4 || strlen(argv[3]) >= sizeof(control.sun_path))
		return 1;
	native_fork = strcmp(argv[1], "native-fork") == 0;
#ifndef SYS_fork
	if (native_fork)
		return 77;
#endif

	alarm(10);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	sync_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0 || sync_fd < 0)
		goto fail;
	dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dest.sin_port = htons(atoi(argv[2]));
	strcpy(control.sun_path, argv[3]);
	if (connect(sync_fd, (struct sockaddr *)&control, sizeof(control)) < 0 ||
	    setsockopt(sync_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		goto fail;

	from_thread = strcmp(argv[1], "thread") == 0;
	from_fork = native_fork || strcmp(argv[1], "fork") == 0;
	corked = from_thread || from_fork || strcmp(argv[1], "setsockopt") == 0;
	if (from_thread || from_fork) {
		int ret = from_thread ? cork_from_existing_thread(fd) :
			  cork_from_fork(fd, native_fork);

		if (ret < 0)
			goto fail;
		sent = sendto(fd, "first", 5, 0, (struct sockaddr *)&dest, sizeof(dest));
	} else if (strcmp(argv[1], "setsockopt") == 0) {
		/* Duplicate first so the test exercises shared cork state. */
		writer = dup(fd);
		if (writer < 0 ||
		    setsockopt(fd, IPPROTO_UDP, UDP_CORK, &flag, sizeof(flag)) < 0)
			goto fail;
		sent = sendto(writer, "first", 5, 0, (struct sockaddr *)&dest, sizeof(dest));
	} else if (strcmp(argv[1], "sendmsg") == 0) {
		struct iovec part = {.iov_base = "first", .iov_len = 5};
		struct msghdr msg = {
			.msg_name = &dest, .msg_namelen = sizeof(dest),
			.msg_iov = &part, .msg_iovlen = 1,
		};
		sent = sendmsg(fd, &msg, MSG_MORE);
	} else {
		sent = sendto(fd, "first", 5, MSG_MORE, (struct sockaddr *)&dest, sizeof(dest));
	}

	/* Wait until the parent runs idle GC before submitting the datagram. */
	if (sent != 5 || write(sync_fd, "R", 1) != 1 || read(sync_fd, &signal, 1) != 1)
		goto fail;
	if (send(fd, "second", 6, 0) != 6)
		goto fail;
	if (corked) {
		flag = 0;
		if (setsockopt(fd, IPPROTO_UDP, UDP_CORK, &flag, sizeof(flag)) < 0)
			goto fail;
		if (writer >= 0)
			close(writer);
	}
	close(sync_fd);
	close(fd);
	return 0;

fail:
	perror("UDP cork probe");
	return 1;
}
