#include <stdio.h>

#include "graftcp.h"

char *LOCAL_ADDR = "127.0.0.1";
uint16_t LOCAL_PORT = 2080;
struct sockaddr_in PROXY_SA;

void socket_pre_handle(struct proc_info *pinfp)
{
  struct socket_info *si = calloc(1, sizeof(*si));
  si->domain = get_syscall_arg(pinfp->pid, 0);
  si->type = get_syscall_arg(pinfp->pid, 1);

  /* If not TCP socket, ignore */
  if ((si->type & SOCK_STREAM) < 1 || si->domain != AF_INET) {
    free(si);
    return;
  }
  si->fd = -1;
  si->magic_fd = (MAGIC_FD << 31) + pinfp->pid;
  si->is_writed = false;
  si->write_buf = NULL;
  add_socket_info(si);
}

void connect_pre_handle(struct proc_info *pinfp)
{
  int socket_fd = get_syscall_arg(pinfp->pid, 0);
  struct socket_info *si = find_socket_info((socket_fd << 31) + pinfp->pid);
  if (si == NULL)
    return;

  // XXX not need?
  if ((si->type & SOCK_STREAM) < 1 || si->domain != AF_INET)
    return;

  long addr = get_syscall_arg(pinfp->pid, 1);
  struct sockaddr_in tmp_sa;

  getdata(pinfp->pid, addr, (char *)&tmp_sa, sizeof(tmp_sa));

  unsigned int ip_int = SOCKADDR(tmp_sa);
  unsigned short ip_port = SOCKPORT(tmp_sa);
  struct in_addr tmp_ip_addr;

  tmp_ip_addr.s_addr = ip_int;
  putdata(pinfp->pid, addr, (char *)&PROXY_SA, sizeof(PROXY_SA));
  si->is_connected = true;
  si->dest_addr = tmp_ip_addr;
  si->dest_port = ip_port;
}

void close_pre_handle(struct proc_info *pinfp)
{
  int socket_fd = get_syscall_arg(pinfp->pid, 0);
  struct socket_info *si = find_socket_info((socket_fd << 31) + pinfp->pid);
  if (si == NULL) {
    return;
  }
  del_socket_info(si);
  if (si->write_buf != NULL) {
    free(si->write_buf);
  }
  free(si);
}

struct buf_info *set_write_buf(struct proc_info *pinfp,
                               struct in_addr dest_addr,
                               unsigned int dest_port,
                               char *buf, size_t buf_count)
{
  char dest_info[1024] = {0};
  uint32_t dest_info_len;

  strcpy(dest_info, inet_ntoa(dest_addr));
  strcat(&dest_info[strlen(dest_info)], ":");
  sprintf(&dest_info[strlen(dest_info)], "%d", ntohs(dest_port));
  dest_info_len = strlen(dest_info);

  char *new_buf = calloc(1, 4 + 4 + dest_info_len + buf_count);
  uint32_t nval = htonl(dest_info_len);
  uint32_t magic_num = htonl(MAGIC_NUM);

  memcpy(new_buf, &magic_num, 4);
  memcpy(new_buf + 4, &nval, 4);
  memcpy(new_buf + 4 + 4, dest_info, dest_info_len);
  memcpy(new_buf + 4 + 4 + dest_info_len, buf, buf_count);

  struct buf_info *new_buf_info = malloc(sizeof(*new_buf_info));
  new_buf_info->buf = new_buf;
  new_buf_info->size = 4 + 4 + dest_info_len + buf_count;
  return new_buf_info;
}

void write_pre_handle(struct proc_info *pinfp)
{
  int socket_fd = get_syscall_arg(pinfp->pid, 0);
  struct socket_info *si = find_socket_info((socket_fd << 31) + pinfp->pid);
  if (si == NULL || !si->is_connected || si->is_writed)
    return;

  long bufp_arg = get_syscall_arg(pinfp->pid, 1);
  long count = get_syscall_arg(pinfp->pid, 2);
  void *wbuf = calloc(count, sizeof(char));
  getdata(pinfp->pid, bufp_arg, wbuf, count);

  struct buf_info *wbi = set_write_buf(pinfp, si->dest_addr,
                                       si->dest_port, (char *)wbuf, count);

  /* modify write(fd, buf, count)'s buf arg */
  putdata(pinfp->pid, bufp_arg, wbi->buf, wbi->size);
  /* modify write(fd, buf, count)'s count arg */
  ptrace(PTRACE_POKEUSER, pinfp->pid, sizeof(long)*RDX, wbi->size);
  assert(errno == 0);

  si->first_write_return = count;
  si->write_buf = wbi;
  pinfp->cws = si;
}

void socket_exiting_handle(struct proc_info *pinfp, int fd)
{
  struct socket_info *si;

  si = find_socket_info((MAGIC_FD << 31) + pinfp->pid);
  if (si == NULL)
    return;

  si->fd = fd;
  si->is_connected = false;
  del_socket_info(si);
  si->magic_fd = (fd << 31) + pinfp->pid;
  add_socket_info(si);
}

void write_exiting_handle(struct proc_info *pinfp)
{
  if (pinfp->cws == NULL || pinfp->cws->is_writed)
    return;

  struct user_regs_struct regs;

  ptrace(PTRACE_GETREGS, pinfp->pid, 0, &regs);
  assert(errno == 0);

  /* write error, -1 is returned */
  if ((int64_t)regs.rax <= 0)
    return;

  if (regs.rax == pinfp->cws->first_write_return) {
    pinfp->cws->is_writed = true;
    return;
  }

  /* modify write's return value */
  regs.rax = pinfp->cws->first_write_return;
  ptrace(PTRACE_SETREGS, pinfp->pid, 0, &regs);
  assert(errno == 0);
  pinfp->cws->is_writed = true;
}

void do_child(int argc, char **argv)
{
  char *args [argc+1];
  int i;
  pid_t pid;

  for (i=0; i<argc; i++)
    args[i] = argv[i];
  args[argc] = NULL;
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  pid = getpid();
  /*
   * Induce a ptrace stop. Tracer (our parent)
   * will resume us with PTRACE_SYSCALL and display
   * the immediately following execve syscall.
   */
  kill(pid, SIGSTOP);
  execvp(args[0], args);
}

void init(int argc, char **argv)
{
  pid_t child;
  struct proc_info *pi;

  child = fork();
  if (child < 0) {
    perror("fork");
    exit(errno);
  } else if (child == 0) {
    do_child(argc - 1, &argv[1]);
  }
  pi = alloc_proc_info(child);
  pi->flags |= FLAG_STARTUP;
}

int trace_syscall_entering(struct proc_info *pinfp)
{
  pinfp->csn = get_syscall_number(pinfp->pid);
  switch (pinfp->csn) {
  case SYS_socket:
    socket_pre_handle(pinfp);
    break;
  case SYS_connect:
    connect_pre_handle(pinfp);
    break;
  case SYS_close:
    close_pre_handle(pinfp);
    break;
  case SYS_write:
    write_pre_handle(pinfp);
    break;
  }
  pinfp->flags |= FLAG_INSYSCALL;
  return 0;
}

int trace_syscall_exiting(struct proc_info *pinfp)
{
  int retval;
  retval = get_retval(pinfp->pid);
  switch (pinfp->csn) {
  case SYS_socket:
    socket_exiting_handle(pinfp, retval);
    break;
  case SYS_write:
    write_exiting_handle(pinfp);
    break;
  }
  pinfp->flags &= ~FLAG_INSYSCALL;
  return 0;
}

int trace_syscall(struct proc_info *pinfp)
{
  return exiting(pinfp) ? trace_syscall_exiting(pinfp) :
                          trace_syscall_entering(pinfp);
}

int do_trace()
{
  pid_t child;
  int status;
  struct proc_info *pinfp;

  for (;;) {
    child = wait(&status);
    if (child < 0) {
      perror("wait");
      return -1;
    }
    pinfp = find_proc_info(child);
    if (!pinfp) {
      pinfp = alloc_proc_info(child);
    }
    if (pinfp->flags & FLAG_STARTUP) {
      pinfp->flags &= ~FLAG_STARTUP;

      if (ptrace(PTRACE_SETOPTIONS, child, 0,
	    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	    PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) < 0) {
	perror("ptrace");
	exit(errno);
      }
    }
    if (trace_syscall(pinfp) < 0) {
      continue;
    }
    if (ptrace(PTRACE_SYSCALL, pinfp->pid, 0, 0) < 0) {
      perror("ptrace");
      return -1;
    }
  }
  return 0;
}

int main(int argc, char **argv)
{
  PROXY_SA.sin_family = AF_INET;
  PROXY_SA.sin_port = htons(LOCAL_PORT);
  if (inet_aton(LOCAL_ADDR, &PROXY_SA.sin_addr) == 0) {
    struct hostent *he;

    he = gethostbyname(LOCAL_ADDR);
    if (he == NULL) {
      perror("gethostbyname");
      exit(errno);
    }
    memcpy(&PROXY_SA.sin_addr, he->h_addr, sizeof(struct in_addr));
  }
  init(argc, argv);
  return do_trace();
}
