#ifndef _TCPTRACE_H
#define _TCPTRACE_H

#include <stdbool.h>

#include "uthash.h"

struct socket_info {
  int fd;
  int domain;
  int type;
  bool is_connected;
  UT_hash_handle hh;            /* makes this structure hashable */
};

#endif
