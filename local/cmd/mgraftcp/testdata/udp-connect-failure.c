#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
	struct sockaddr_in6 dest = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(9999),
	};
	int enabled = 1;
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0 && errno == EAFNOSUPPORT)
		return 77;
	if (fd < 0 ||
	    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) < 0 ||
	    inet_pton(AF_INET6, "::1", &dest.sin6_addr) != 1) {
		perror("prepare UDP socket");
		return 1;
	}

	/* The original IPv6 address works, but the rewritten address is
	 * IPv4-mapped and the kernel rejects it on an IPv6-only socket. */
	if (connect(fd, (struct sockaddr *)&dest, sizeof(dest)) != -1 ||
	    errno != ENETUNREACH) {
		perror("expected ENETUNREACH for rewritten UDP connect");
		return 1;
	}
	close(fd);
	return 0;
}
