/*
 * graftcp
 * Copyright (C) 2018, 2021-2026 Hmgle <dustgle@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <stdlib.h>

#include "graftcp.h"

static int find_tracked_socket_fd(const struct proc_info *pinfp, int fd)
{
	unsigned int i;

	if (pinfp == NULL || fd < 0)
		return -1;

	for (i = 0; i < pinfp->tracked_socket_count; i++) {
		if (pinfp->tracked_sockets[i].fd == fd)
			return (int)i;
	}
	return -1;
}

int track_socket_fd(struct proc_info *pinfp, int fd, int domain, int type)
{
	struct tracked_socket *sockets;
	unsigned int new_cap;
	int idx;

	if (pinfp == NULL || fd < 0)
		return -1;
	idx = find_tracked_socket_fd(pinfp, fd);
	if (idx >= 0) {
		pinfp->tracked_sockets[idx].domain = domain;
		pinfp->tracked_sockets[idx].type = type;
		return 0;
	}
	if (pinfp->tracked_socket_count >= pinfp->tracked_socket_cap) {
		new_cap = pinfp->tracked_socket_cap ?
			  pinfp->tracked_socket_cap * 2 : TRACKED_SOCKET_INITIAL_CAP;
		sockets = realloc(pinfp->tracked_sockets,
			      new_cap * sizeof(*pinfp->tracked_sockets));
		if (sockets == NULL)
			return -1;
		pinfp->tracked_sockets = sockets;
		pinfp->tracked_socket_cap = new_cap;
	}

	pinfp->tracked_sockets[pinfp->tracked_socket_count++] =
		(struct tracked_socket){fd, domain, type};
	return 0;
}

bool is_tracked_socket_fd(struct proc_info *pinfp, int fd)
{
	return find_tracked_socket_fd(pinfp, fd) >= 0;
}

static bool is_tracked_socket_type(struct proc_info *pinfp, int fd, int type)
{
	int idx = find_tracked_socket_fd(pinfp, fd);

	if (idx < 0)
		return false;
	return (pinfp->tracked_sockets[idx].type & SOCK_TYPE_MASK) == type;
}

bool is_tracked_stream_socket_fd(struct proc_info *pinfp, int fd)
{
	return is_tracked_socket_type(pinfp, fd, SOCK_STREAM);
}

bool is_tracked_dgram_socket_fd(struct proc_info *pinfp, int fd)
{
	return is_tracked_socket_type(pinfp, fd, SOCK_DGRAM);
}

void untrack_socket_fd(struct proc_info *pinfp, int fd)
{
	int idx;

	idx = find_tracked_socket_fd(pinfp, fd);
	if (idx < 0)
		return;

	pinfp->tracked_sockets[idx] =
		pinfp->tracked_sockets[--pinfp->tracked_socket_count];
}

#define PROC_INFO_BUCKETS 256U

static struct proc_info *PROC_INFO_BUCKETS_TBL[PROC_INFO_BUCKETS];

static unsigned int proc_info_bucket(pid_t pid)
{
	return ((unsigned int)pid) & (PROC_INFO_BUCKETS - 1);
}

static struct proc_info **find_proc_info_slot(pid_t pid)
{
	struct proc_info **slot = &PROC_INFO_BUCKETS_TBL[proc_info_bucket(pid)];

	while (*slot != NULL && (*slot)->pid != pid)
		slot = &(*slot)->next;
	return slot;
}

static void add_proc_info(struct proc_info *p)
{
	struct proc_info **head;

	if (p == NULL)
		return;
	head = &PROC_INFO_BUCKETS_TBL[proc_info_bucket(p->pid)];
	p->next = *head;
	*head = p;
}

static void del_proc_info(struct proc_info *p)
{
	struct proc_info **slot;

	if (p == NULL)
		return;
	slot = find_proc_info_slot(p->pid);
	if (*slot == p)
		*slot = p->next;
}

struct proc_info *find_proc_info(pid_t pid)
{
	struct proc_info **slot = find_proc_info_slot(pid);

	return *slot;
}

struct proc_info *alloc_proc_info(pid_t pid)
{
	struct proc_info *newp = calloc(1, sizeof(*newp));

	if (newp == NULL)
		return NULL;
	newp->pid = pid;
	add_proc_info(newp);
	return newp;
}

void free_proc_info(struct proc_info *p)
{
	if (p == NULL)
		return;
	del_proc_info(p);
	free(p->tracked_sockets);
	free(p);
}
