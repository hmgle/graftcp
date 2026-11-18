#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *worker(void *arg)
{
	const char *operation = arg;
	long fd;

	if (strcmp(operation, "socket") == 0)
		fd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
	else if (strcmp(operation, "dup") == 0)
		fd = syscall(SYS_dup, STDOUT_FILENO);
	else
		fd = syscall(SYS_fcntl, STDOUT_FILENO, F_DUPFD, 3);
	if (fd < 0)
		return arg;
	close(fd);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thread;
	void *result;

	if (argc != 2 || pthread_create(&thread, NULL, worker, argv[1]) != 0 ||
	    pthread_join(thread, &result) != 0 || result != NULL)
		return 125;
	puts("root joined worker");
	return 37;
}
