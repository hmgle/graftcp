#ifndef _GRAFTCP_H
#define _GRAFTCP_H

#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <assert.h>

#include "uthash.h"

#define satosin(x)  ((struct sockaddr_in *) &(x))
#define SOCKADDR(x) (satosin(x)->sin_addr.s_addr)
#define SOCKPORT(x) (satosin(x)->sin_port)

struct socket_info {
  pid_t pid;
  int fd;
  uint64_t magic_fd;
  int domain;
  int type;
  struct in_addr dest_addr;
  unsigned int dest_port;
  UT_hash_handle hh;            /* makes this structure hashable */
};

/* magic fd number */
#define MAGIC_FD 7777777
#define MAGIC_NUM 3579

#define FLAG_STARTUP    00002
#define FLAG_INSYSCALL  00010

#define exiting(pinfp)  ((pinfp)->flags & FLAG_INSYSCALL)

struct proc_info {
  pid_t pid;
  int flags;
  int csn;                      /* current syscall number */
  struct socket_info *cws;      /* current process's writing socket info */
  UT_hash_handle hh;            /* makes this structure hashable */
};

void add_socket_info(struct socket_info *s);
void del_socket_info(struct socket_info *s);
struct socket_info *find_socket_info(uint64_t magic_fd);

void add_proc_info(struct proc_info *p);
void del_proc_info(struct proc_info *p);
struct proc_info *find_proc_info(pid_t pid);
struct proc_info *alloc_proc_info(pid_t pid);

int get_syscall_number(pid_t pid);
int get_retval(pid_t pid);
void set_retval(pid_t pid, long new_val);
long get_syscall_arg(pid_t pid, int order);

void getdata(pid_t child, long addr, char *dst, int len);
void putdata(pid_t child, long addr, char *src, int len);

#endif
