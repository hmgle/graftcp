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

/* Shared by the tracked descriptors referring to one UDP socket. */
struct udp_socket_state {
	unsigned int refs;
	bool may_cork;
};

static void release_udp_socket_state(struct udp_socket_state *udp)
{
	if (udp != NULL && --udp->refs == 0)
		free(udp);
}

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

static int set_tracked_socket(struct proc_info *pinfp, struct tracked_socket socket)
{
	struct tracked_socket *sockets;
	unsigned int new_cap;
	int idx = find_tracked_socket_fd(pinfp, socket.fd);

	if (idx < 0) {
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
		idx = pinfp->tracked_socket_count++;
		pinfp->tracked_sockets[idx].udp = NULL;
	}
	if (socket.udp != NULL)
		socket.udp->refs++;
	release_udp_socket_state(pinfp->tracked_sockets[idx].udp);
	pinfp->tracked_sockets[idx] = socket;
	return 0;
}

int track_socket_fd(struct proc_info *pinfp, int fd, int domain, int type)
{
	struct tracked_socket socket = {.fd = fd, .domain = domain, .type = type};

	if (pinfp == NULL || fd < 0)
		return -1;
	if ((type & SOCK_TYPE_MASK) == SOCK_DGRAM) {
		socket.udp = calloc(1, sizeof(*socket.udp));
		if (socket.udp == NULL)
			return -1;
	}
	if (set_tracked_socket(pinfp, socket) < 0) {
		free(socket.udp);
		return -1;
	}
	return 0;
}

int copy_tracked_socket_fd(struct proc_info *dst, const struct proc_info *src,
			   int oldfd, int newfd)
{
	struct tracked_socket socket;
	int idx;

	if (dst == NULL || src == NULL || oldfd < 0 || newfd < 0)
		return -1;
	idx = find_tracked_socket_fd(src, oldfd);
	if (idx < 0)
		return 0;
	socket = src->tracked_sockets[idx];
	socket.fd = newfd;
	return set_tracked_socket(dst, socket);
}

int copy_tracked_sockets(struct proc_info *dst, const struct proc_info *src)
{
	unsigned int i;

	if (dst == NULL || src == NULL)
		return -1;
	for (i = 0; i < src->tracked_socket_count; i++) {
		if (set_tracked_socket(dst, src->tracked_sockets[i]) < 0)
			return -1;
	}
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

void mark_socket_may_cork(struct proc_info *pinfp, int fd)
{
	int idx = find_tracked_socket_fd(pinfp, fd);

	if (idx >= 0 && pinfp->tracked_sockets[idx].udp != NULL)
		pinfp->tracked_sockets[idx].udp->may_cork = true;
}

bool socket_may_cork(struct proc_info *pinfp, int fd)
{
	int idx = find_tracked_socket_fd(pinfp, fd);

	return idx >= 0 && pinfp->tracked_sockets[idx].udp != NULL &&
	       pinfp->tracked_sockets[idx].udp->may_cork;
}

void untrack_socket_fd(struct proc_info *pinfp, int fd)
{
	int idx;

	idx = find_tracked_socket_fd(pinfp, fd);
	if (idx < 0)
		return;

	release_udp_socket_state(pinfp->tracked_sockets[idx].udp);
	pinfp->tracked_sockets[idx] =
		pinfp->tracked_sockets[--pinfp->tracked_socket_count];
}

static struct proc_info *PROC_INFO_TAB;

static void add_proc_info(struct proc_info *p)
{
	if (p == NULL)
		return;
	HASH_ADD(hh, PROC_INFO_TAB, pid, sizeof(p->pid), p);
}

static void del_proc_info(struct proc_info *p)
{
	if (p == NULL)
		return;
	HASH_DEL(PROC_INFO_TAB, p);
}

struct proc_info *find_proc_info(pid_t pid)
{
	struct proc_info *p;

	HASH_FIND(hh, PROC_INFO_TAB, &pid, sizeof(pid), p);
	return p;
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
	unsigned int i;

	if (p == NULL)
		return;
	del_proc_info(p);
	for (i = 0; i < p->tracked_socket_count; i++)
		release_udp_socket_state(p->tracked_sockets[i].udp);
	free(p->tracked_sockets);
	free(p);
}
