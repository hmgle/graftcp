#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct sockaddr_in dest = {.sin_family = AF_INET};
	struct sockaddr_un control = {.sun_family = AF_UNIX};
	struct timeval timeout = {.tv_sec = 5};
	int flag = 1;
	int fd, sync_fd, writer;
	char signal;
	ssize_t sent;

	if (argc != 4 || strlen(argv[3]) >= sizeof(control.sun_path))
		return 1;

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

	if (strcmp(argv[1], "setsockopt") == 0) {
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
	if (strcmp(argv[1], "setsockopt") == 0) {
		flag = 0;
		if (setsockopt(fd, IPPROTO_UDP, UDP_CORK, &flag, sizeof(flag)) < 0)
			goto fail;
		close(writer);
	}
	close(sync_fd);
	close(fd);
	return 0;

fail:
	perror("UDP cork probe");
	return 1;
}
