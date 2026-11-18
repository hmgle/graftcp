#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct sockaddr_in peer = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t len = sizeof(peer);
	char fd_arg[32];
	int fd, cloexec;

	if (argc != 4 && argc != 5)
		return 1;

	cloexec = strcmp(argv[1], "set") == 0;
	if (argc == 4) {
		alarm(5);
		fd = socket(AF_INET, SOCK_STREAM | (cloexec ? 0 : SOCK_CLOEXEC), 0);
		if (fd < 0)
			goto fail;
		/* Keep the closed fd above the dynamic loader's temporary fds. */
		if (cloexec) {
			struct rlimit limit;
			int min_fd = 100;
			int highfd;

			if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
				goto fail;
			/* Leave room to find a free fd under a low limit. */
			if (limit.rlim_cur / 2 < (rlim_t)min_fd)
				min_fd = (int)(limit.rlim_cur / 2);
			highfd = fcntl(fd, F_DUPFD, min_fd);
			if (highfd < 0)
				goto fail;
			close(fd);
			fd = highfd;
		}
		if (ioctl(fd, cloexec ? FIOCLEX : FIONCLEX) < 0)
			goto fail;
		snprintf(fd_arg, sizeof(fd_arg), "%d", fd);
		execl(argv[0], argv[0], argv[1], argv[2], argv[3], fd_arg, (char *)NULL);
		goto fail;
	}

	fd = atoi(argv[4]);
	peer.sin_port = htons(atoi(argv[2]));
	if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
		if (cloexec && errno == EBADF)
			return 0;
		goto fail;
	}
	if (cloexec) {
		fprintf(stderr, "TCP socket survived FIOCLEX and exec\n");
		return 1;
	}
	if (getpeername(fd, (struct sockaddr *)&peer, &len) < 0)
		goto fail;
	if (ntohs(peer.sin_port) != atoi(argv[3])) {
		fprintf(stderr, "TCP peer port = %u, want proxy port %s\n",
			ntohs(peer.sin_port), argv[3]);
		return 1;
	}
	return 0;

fail:
	perror("ioctl close-on-exec probe");
	return 1;
}
