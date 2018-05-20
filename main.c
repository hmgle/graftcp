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

#define satosin(x)  ((struct sockaddr_in *) &(x))
#define SOCKADDR(x) (satosin(x)->sin_addr.s_addr)
#define SOCKPORT(x) (satosin(x)->sin_port)

#ifndef offsetof
#define offsetof(a, b) __builtin_offsetof(a,b)
#endif
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off) {
  long val = ptrace(PTRACE_PEEKUSER, child, off);
  assert(errno == 0);
  return val;
}

char *LOCAL_ADDR = "127.0.0.1";
uint16_t LOCAL_PORT = 2080;
bool is_enter = false;
struct sockaddr_in proxy_sa;
int fifo_fd;

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

void del_socket_info(struct socket_info *s)
{
  HASH_DEL(SOCKET_TAB, s);
}

struct socket_info *find_socket_info(int fd)
{
  struct socket_info *s;

  HASH_FIND_INT(SOCKET_TAB, &fd, s);
  return s;
}

int do_child(const char *file, char *argv[])
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  kill(getpid(), SIGSTOP);
  return execvp(file, argv);
}

int socket_pre_handle(pid_t pid)
{
  struct user_regs_struct regs;
  struct socket_info *si = malloc(sizeof(*si));
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  assert(errno == 0);
  si->domain = regs.rdi;
  si->type = regs.rsi;
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  assert(errno == 0);
  si->fd = -1;
  si->is_connected = false;
  add_socket_info(si);
  return SYS_socket;
}

void connect_pre_handle(pid_t pid)
{
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  assert(errno == 0);
  int socket_fd = regs.rdi;
  struct socket_info *so_info = find_socket_info(socket_fd);
  if (so_info == NULL) {
    fprintf(stderr, "%s:%d: find_socket_info(%d) return NULL\n", __func__, __LINE__, socket_fd);
    exit(-1);
  }
  if (so_info->type != SOCK_STREAM || so_info->domain != AF_INET) {
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    return;
  }
  long addr = get_reg(pid, rsi);
  struct sockaddr_in tmp_sa;
  getdata(pid, addr, (char *)&tmp_sa, sizeof(tmp_sa));
  unsigned int ip_int = SOCKADDR(tmp_sa);
  unsigned short ip_port = SOCKPORT(tmp_sa);
  struct in_addr tmp_ip_addr;
  tmp_ip_addr.s_addr = ip_int;
  putdata(pid, addr, (char *)&proxy_sa, sizeof(proxy_sa));
  assert(errno == 0);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);

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

int wait_syscall_enter_stop(pid_t pid)
{
  int status;
  int syscall_num;

  for (;;) {
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    pid = wait(&status);
    if (WIFEXITED(status)) {
      return -1;
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
      syscall_num = get_reg(pid, orig_rax);
      switch (syscall_num) {
        case SYS_socket:
          return socket_pre_handle(pid);
          break;
        case SYS_connect:
          connect_pre_handle(pid);
          break;
        default:
          ;
      }
      return syscall_num;
    }
  }
}

int wait_syscall_exit_stop(pid_t pid, int syscall_num)
{
  int status;
  int ret;

  for (;;) {
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    pid = wait(&status);
    if (WIFEXITED(status)) {
      return -1;
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
      if (syscall_num == SYS_socket) {
        ret = get_reg(pid, rax);
        struct socket_info *so_info = find_socket_info(-1);
        if (so_info != NULL) {
          so_info->fd = ret;
          so_info->is_connected = false;
        }
      }
      return 0;
    }
  }
}

int do_trace(pid_t child)
{
  int status;
  int ret;
  const unsigned int options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
                               PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
  waitpid(child, &status, 0);
  assert(WIFSTOPPED(status));
  if (ptrace(PTRACE_SETOPTIONS, child, 0, options) < 0) {
    perror("ptrace");
    exit(errno);
  }
  for (;;)  {
    ret = wait_syscall_enter_stop(child);
    if (ret < 0) {
      return 0;
    }
    ret = wait_syscall_exit_stop(child, ret);
    if (ret < 0) {
      return 0;
    }
  }
}

int main(int argc, char **argv)
{
  long sys;
  pid_t child;
  int status;
  struct user *user_space = (struct user *) 0;
  struct user_regs_struct regs;
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
  if (child < 0) {
    perror("fork");
    exit(errno);
  } else if (child == 0) {
    return do_child(argv[1], &argv[1]);
  }
  return do_trace(child);
}
