#include <stdio.h>
#include <unistd.h>
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

#include "tcptrace.h"

char *SOCKS_ADDR = "127.0.0.1";
uint16_t SOCKS_PORT = 2080;

int client_connect(const char *addr, uint16_t port)
{
  int s;
  struct sockaddr_in sa;
  int sock_opt = 1;

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return -1;

  /* disable Nagle */
  if ((setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &sock_opt,
                  sizeof(int))) == -1) {
    fprintf(stderr, "setsockopt failed!\n");
    exit(-1);
  }

  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  if (inet_aton(addr, &sa.sin_addr) == 0) {
    struct hostent *he;

    he = gethostbyname(addr);
    if (he == NULL) {
      fprintf(stderr, "can't resolve: %s\n", addr);
      close(s);
      return -1;
    }
    memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
  }
  if (connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    fprintf(stderr, "connect failed!\n");
    close(s);
    return -1;
  }
  return s;
}

void getdata(pid_t child, long addr, char *str, int len)
{
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[sizeof(long)];
  } data;
  i = 0;
  j = len / sizeof(long);
  laddr = str;
  while (i < j) {
    data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
    memcpy(laddr, data.chars, sizeof(long));
    ++i;
    laddr += sizeof(long);
  }
  j = len % sizeof(long);
  if (j != 0) {
    data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
    memcpy(laddr, data.chars, j);
  }
  str[len] = '\0';
}

void putdata(pid_t child, long addr, char *str, int len)
{
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[sizeof(long)];
  } data;
  i = 0;
  j = len / sizeof(long);
  laddr = str;
  while (i < j) {
    memcpy(data.chars, laddr, sizeof(long));
    ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
    ++i;
    laddr += sizeof(long);
  }
  j = len % sizeof(long);
  if (j != 0) {
    memcpy(data.chars, laddr, j);
    ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
  }
}

int main(int argc, char **argv)
{
  int proxy_fd;
  long sys;
  pid_t child;
  int status;
  struct user *user_space = (struct user *) 0;
  struct user_regs_struct regs;

  if (argc < 2) {
    printf("Usage: %s program_name [arguments]\n", argv[0]);
    return 0;
  }

  proxy_fd = client_connect(SOCKS_ADDR, SOCKS_PORT);
  if (proxy_fd < 0) {
    perror("connect");
    exit(errno);
  }

  child = fork();
  if (child == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(argv[1], &argv[1]);
  } else {
    for (;;) {
      wait(&status);
      if (WIFEXITED(status))
        break;

      sys = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.orig_rax, NULL);
      if (sys == SYS_write) {
        // 获取 write 系统调用参数值
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        // 更改 write 第一个参数值为 tcp 套接字值
        long ret;
        regs.rdi = proxy_fd;
        ret = ptrace(PTRACE_SETREGS, child, 0, &regs);
        if (ret) {
          perror("ptrace");
          exit(errno);
        }
      }
      ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
  }
  return 0;
}
