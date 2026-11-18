#define _GNU_SOURCE
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int connect_inherited_socket(const char *port)
{
	in_port_t original_port = htons(atoi(port));
	struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_port = original_port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in peer;
	socklen_t peer_len = sizeof(peer);
	int fd, status;
	char reply;
	pid_t child;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 125;
	child = fork();
	if (child == 0) {
		if (connect(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0 ||
		    getpeername(fd, (struct sockaddr *)&peer, &peer_len) < 0 ||
		    peer.sin_port == original_port ||
		    read(fd, &reply, 1) != 1 || reply != 'R')
			_exit(125);
		_exit(37);
	}
	close(fd);
	if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status))
		return 125;
	return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
	pid_t creator, child;
	int status;
	int inherit_socket = argc == 3 && strcmp(argv[1], "inherit") == 0;

	/* Adopt the grandchild when its creator dies. */
	if ((argc != 2 && !inherit_socket) ||
	    prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L) < 0)
		return 125;
	creator = fork();
	if (creator < 0)
		return 125;
	if (creator == 0) {
		if (inherit_socket)
			_exit(connect_inherited_socket(argv[2]));
		if (strcmp(argv[1], "vfork") == 0)
			_exit(vfork() == 0 ? 23 : 125);
#ifdef SYS_fork
		child = syscall(SYS_fork);
#else
		child = fork();
#endif
		_exit(child == 0 ? 23 : 125);
	}
	if (waitpid(creator, &status, 0) != creator)
		return 125;
	if (inherit_socket)
		return WIFEXITED(status) ? WEXITSTATUS(status) : 125;
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL)
		return 125;
	child = waitpid(-1, &status, 0);
	if (child < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 23)
		return 125;
	puts("root reaped grandchild");
	return 37;
}
