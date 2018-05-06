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
#include <fcntl.h>

#include "tcptrace.h"

#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)

char *LOCAL_ADDR = "127.0.0.1";
uint16_t LOCAL_PORT = 2080;

void getdata(pid_t child, long addr, char *dst, int len)
{
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[sizeof(long)];
  } data;
  i = 0;
  j = len / sizeof(long);
  laddr = dst;
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
  dst[len] = '\0';
}

void putdata(pid_t child, long addr, char *src, int len)
{
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[sizeof(long)];
  } data;
  i = 0;
  j = len / sizeof(long);
  laddr = src;
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

struct socket_info *SOCKET_TAB = NULL;

void add_socket_info(struct socket_info *s)
{
  HASH_ADD_INT(SOCKET_TAB, fd, s);
}

struct socket_info *find_socket_info(int fd)
{
  struct socket_info *s;

  HASH_FIND_INT(SOCKET_TAB, &fd, s);
  return s;
}

int main(int argc, char **argv)
{
  long sys;
  pid_t child;
  int status;
  struct user *user_space = (struct user *) 0;
  struct user_regs_struct regs;
  int fifo_fd;
  long tmp_addr;

  if (argc < 2) {
    printf("Usage: %s program_name [arguments]\n", argv[0]);
    return 0;
  }

  fifo_fd = open("/tmp/tcptrace.fifo", O_WRONLY);
  if (fifo_fd < 0) {
    perror("open");
    exit(errno);
  }

  struct sockaddr_in proxy_sa;
  struct sockaddr_in tmp_sa;
  socklen_t proxy_addrlen = sizeof(proxy_sa);
  proxy_sa.sin_family = AF_INET;
  proxy_sa.sin_port = htons(LOCAL_PORT);
  if (inet_aton(LOCAL_ADDR, &proxy_sa.sin_addr) == 0) {
    struct hostent *he;

    he = gethostbyname(LOCAL_ADDR);
    if (he == NULL) {
      fprintf(stderr, "can't resolve: %s\n", LOCAL_ADDR);
      return -1;
    }
    memcpy(&proxy_sa.sin_addr, he->h_addr, sizeof(struct in_addr));
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
      switch (sys) {
      case SYS_socket:
        fprintf(stderr, "%d:====\n", __LINE__);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        fprintf(stderr, "%d:====\n", __LINE__);
        struct socket_info *si = malloc(sizeof(*si));
        si->domain = regs.rdi;
        si->type = regs.rsi;
        // long ret = ptrace(PTRACE_SYSCALL, child, NULL, &regs);
        long ret = ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        // fprintf(stderr, "%d: ret = %d\n", __LINE__, (int)ret);
        // user_space = (struct user*)0;
        ret = ptrace(PTRACE_GETREGS, child, NULL, &regs);
        if (ret < 0) {
          fprintf(stderr, "%s:%d:======\n", __FILE__, __LINE__);
          // perror("ptrace");
          // exit(errno);
        }
        fprintf(stderr, "%s:%d:======\n", __FILE__, __LINE__);
        si->fd = (int)regs.rax;
        fprintf(stderr, "%d: domain: %d, type: %d, fd: %d\n", __LINE__, si->domain, si->type, si->fd);
        si->is_connected = false;
        add_socket_info(si);
        fprintf(stderr, "%d:====\n", __LINE__);
        break;
      case SYS_connect:
        fprintf(stderr, "%d:====\n", __LINE__);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        fprintf(stderr, "%d:====\n", __LINE__);
        int socket_fd = regs.rdi;
        fprintf(stderr, "%d: socket_fd: %d\n", __LINE__, socket_fd);
        struct socket_info *so_info = find_socket_info(socket_fd);
        if (so_info == NULL) {
          fprintf(stderr, "%d: find_socket_info(%d) return NULL\n", __LINE__, socket_fd);
          exit(-1);
        }
        if (so_info->type != SOCK_STREAM || so_info->domain != AF_INET) {
          fprintf(stderr, "%d: so_info->type: %d, so_info->domain: %d, fd: %d\n", __LINE__, so_info->type, so_info->domain, so_info->fd);
          ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        } else if (so_info->is_connected) {
          fprintf(stderr, "%d: so_info->is_connected: fd: %d\n", __LINE__, so_info->fd);
          ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        } else {
          tmp_addr = ptrace(PTRACE_PEEKUSER, child, &user_space->regs.rsi, NULL);
          getdata(child, tmp_addr, (char *)&tmp_sa, sizeof(tmp_sa));
          unsigned int ip_int = SOCKADDR(tmp_sa);
          unsigned short ip_port = SOCKPORT(tmp_sa);
          struct in_addr tmp_ip_addr;
          tmp_ip_addr.s_addr = ip_int;
          fprintf(stderr, "%d: The IP address is %s\n", __LINE__, inet_ntoa(tmp_ip_addr));
          fprintf(stderr, "%d: port: %d\n", __LINE__, ntohs(ip_port));
          putdata(child, tmp_addr, (char *)&proxy_sa, sizeof(proxy_sa));
          ptrace(PTRACE_SYSCALL, child, NULL, NULL);

          char buf[1024] = {0};
          strcpy(buf, inet_ntoa(tmp_ip_addr));
          strcat(&buf[strlen(buf)], ":");
          sprintf(&buf[strlen(buf)], "%d\n", ntohs(ip_port));
          fprintf(stderr, "%d: buf: %s\n", __LINE__, buf);
          ssize_t wlen;
          wlen = write(fifo_fd, buf, strlen(buf));
          fprintf(stderr, "%s: %d: write: %d\n", __FILE__, __LINE__, wlen);
          so_info->is_connected = true;
        }
        break;
      case SYS_close:
        // TODO
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        break;
      default:
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
      }
    }
  }
  return 0;
}
