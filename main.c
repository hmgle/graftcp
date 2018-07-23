#include <stdio.h>

#include "graftcp.h"

char *LOCAL_ADDR = "127.0.0.1";
uint16_t LOCAL_PORT = 2080;
struct sockaddr_in PROXY_SA;
char *LOCAL_PIPE_PAHT = "/tmp/graftcplocal.fifo";
int LOCAL_PIPE_FD;

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

  char buf[1024] = {0};
  strcpy(buf, inet_ntoa(tmp_ip_addr));
  strcat(buf, ":");
  sprintf(&buf[strlen(buf)], "%d:%d\n", ntohs(ip_port), pinfp->pid);
  if (write(LOCAL_PIPE_FD, buf, strlen(buf)) <= 0) {
    if (errno)
      perror("write");
    fprintf(stderr, "write failed!\n");
  }
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
  }
  pinfp->flags |= FLAG_INSYSCALL;
  return 0;
}

int trace_syscall_exiting(struct proc_info *pinfp)
{
  int ret = 0;
  if (pinfp->csn == SYS_exit || pinfp->csn == SYS_exit_group) {
    ret = -1;
    goto end;
  }

  int child_ret;

  switch (pinfp->csn) {
  case SYS_socket:
    child_ret = get_retval(pinfp->pid);
    if (errno) {
      /* No such process, child exited */
      if (errno == ESRCH)
	exit(0);
      perror("ptrace");
      exit(errno);
    }
    socket_exiting_handle(pinfp, child_ret);
    break;
  }
end:
  pinfp->flags &= ~FLAG_INSYSCALL;
  return ret;
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
  int stopped;
  int sig;
  struct proc_info *pinfp;

  for (;;) {
    child = wait(&status);
    if (child < 0) {
      perror("wait");
      return -1;
    }
    pinfp = find_proc_info(child);
    if (!pinfp)
      pinfp = alloc_proc_info(child);

    if (pinfp->flags & FLAG_STARTUP) {
      pinfp->flags &= ~FLAG_STARTUP;

      if (ptrace(PTRACE_SETOPTIONS, child, 0,
	    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	    PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) < 0) {
	perror("ptrace");
	exit(errno);
      }
    }

    sig = WSTOPSIG(status);
    if (sig == SIGSTOP) {
      sig = 0;
      goto end;
    }
    if (sig != SIGTRAP) {
      siginfo_t si;
      stopped = (ptrace(PTRACE_GETSIGINFO, child, 0, (long) &si) < 0);
      if (!stopped) {
        /* It's signal-delivery-stop. Inject the signal */
        goto end;
      }
    }
    if (trace_syscall(pinfp) < 0)
      continue;
    sig = 0;
end:
    /*
     * Since the value returned by a successful PTRACE_PEEK*  request  may  be
     * -1,  the  caller  must  clear  errno before the call of ptrace(2).
     */
    errno = 0;
    if (ptrace(PTRACE_SYSCALL, pinfp->pid, 0, sig) < 0) {
      if (errno == ESRCH)
        continue;
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

  LOCAL_PIPE_FD = open(LOCAL_PIPE_PAHT, O_WRONLY);
  if (LOCAL_PIPE_FD < 0) {
    perror("open");
    exit(errno);
  }

  init(argc, argv);
  return do_trace();
}
