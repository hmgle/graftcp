#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <assert.h>

#include "tcptrace.h"

void do_child(int argc, char **argv)
{
  char *args [argc+1];
  int i;
  pid_t pid;
  struct pinf *pinfp;

  for (i=0; i<argc; i++)
    args[i] = argv[i];
  args[argc] = NULL;
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  pid = getpid();
  execvp(args[0], args);
}

int do_trace()
{
  return 0;
}

int main(int argc, char **argv)
{
  pid_t pid;

  pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(errno);
  } else if (pid == 0) {
    do_child(argc - 1, &argv[1]);
  }
  return do_trace();
}
