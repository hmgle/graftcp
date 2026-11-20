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

struct socket_table {
	unsigned int refs;
	unsigned int count;
	unsigned int cap;
	struct tracked_socket *sockets;
};

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

	for (i = 0; i < pinfp->files->count; i++) {
		if (pinfp->files->sockets[i].fd == fd)
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
		if (pinfp->files->count >= pinfp->files->cap) {
			new_cap = pinfp->files->cap ?
				  pinfp->files->cap * 2 : TRACKED_SOCKET_INITIAL_CAP;
			sockets = realloc(pinfp->files->sockets,
					  new_cap * sizeof(*pinfp->files->sockets));
			if (sockets == NULL)
				return -1;
			pinfp->files->sockets = sockets;
			pinfp->files->cap = new_cap;
		}
		idx = pinfp->files->count++;
		pinfp->files->sockets[idx].udp = NULL;
	}
	if (socket.udp != NULL)
		socket.udp->refs++;
	release_udp_socket_state(pinfp->files->sockets[idx].udp);
	pinfp->files->sockets[idx] = socket;
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
	socket = src->files->sockets[idx];
	socket.fd = newfd;
	return set_tracked_socket(dst, socket);
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
	return (pinfp->files->sockets[idx].type & SOCK_TYPE_MASK) == type;
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

	if (idx >= 0 && pinfp->files->sockets[idx].udp != NULL)
		pinfp->files->sockets[idx].udp->may_cork = true;
}

bool socket_may_cork(struct proc_info *pinfp, int fd)
{
	int idx = find_tracked_socket_fd(pinfp, fd);

	return idx >= 0 && pinfp->files->sockets[idx].udp != NULL &&
	       pinfp->files->sockets[idx].udp->may_cork;
}

static void untrack_socket_at(struct socket_table *files, unsigned int idx)
{
	release_udp_socket_state(files->sockets[idx].udp);
	files->sockets[idx] = files->sockets[--files->count];
}

void untrack_socket_fd(struct proc_info *pinfp, int fd)
{
	int idx = find_tracked_socket_fd(pinfp, fd);

	if (idx >= 0)
		untrack_socket_at(pinfp->files, idx);
}

static void release_socket_table(struct socket_table *files)
{
	if (--files->refs != 0)
		return;
	for (unsigned int i = 0; i < files->count; i++)
		release_udp_socket_state(files->sockets[i].udp);
	free(files->sockets);
	free(files);
}

static struct socket_table *clone_socket_table(const struct socket_table *src)
{
	struct socket_table *files = calloc(1, sizeof(*files));

	if (files == NULL)
		return NULL;
	if (src->count != 0) {
		size_t size = src->count * sizeof(*files->sockets);

		files->sockets = malloc(size);
		if (!files->sockets) {
			free(files);
			return NULL;
		}
		memcpy(files->sockets, src->sockets, size);
		for (unsigned int i = 0; i < src->count; i++) {
			if (files->sockets[i].udp != NULL)
				files->sockets[i].udp->refs++;
		}
	}
	files->count = files->cap = src->count;
	files->refs = 1;
	return files;
}

int copy_tracked_sockets(struct proc_info *dst, const struct proc_info *src)
{
	struct socket_table *files;

	if (dst == NULL || src == NULL)
		return -1;
	files = clone_socket_table(src->files);
	if (files == NULL)
		return -1;
	release_socket_table(dst->files);
	dst->files = files;
	return 0;
}

void share_tracked_sockets(struct proc_info *dst, const struct proc_info *src)
{
	++src->files->refs;
	release_socket_table(dst->files);
	dst->files = src->files;
}

int unshare_tracked_sockets(struct proc_info *p)
{
	if (p->files->refs == 1)
		return 0;
	return copy_tracked_sockets(p, p);
}

void set_socket_cloexec(struct proc_info *p, int fd, bool enabled)
{
	int idx = find_tracked_socket_fd(p, fd);

	if (idx < 0)
		return;
	p->files->sockets[idx].type &= ~SOCK_CLOEXEC;
	if (enabled)
		p->files->sockets[idx].type |= SOCK_CLOEXEC;
}

void close_tracked_range(struct proc_info *p, unsigned int first,
			 unsigned int last, bool cloexec)
{
	unsigned int i = 0;

	while (i < p->files->count) {
		struct tracked_socket *sock = &p->files->sockets[i];

		if ((unsigned int)sock->fd < first || (unsigned int)sock->fd > last) {
			++i;
		} else if (cloexec) {
			sock->type |= SOCK_CLOEXEC;
			++i;
		} else {
			untrack_socket_at(p->files, i);
		}
	}
}

void close_exec_sockets(struct proc_info *p)
{
	unsigned int i = 0;

	while (i < p->files->count) {
		if (p->files->sockets[i].type & SOCK_CLOEXEC)
			untrack_socket_at(p->files, i);
		else
			++i;
	}
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
	newp->files = calloc(1, sizeof(*newp->files));
	if (newp->files == NULL) {
		free(newp);
		return NULL;
	}
	newp->files->refs = 1;
	newp->pid = pid;
	add_proc_info(newp);
	return newp;
}

void free_proc_info(struct proc_info *p)
{
	if (p == NULL)
		return;
	del_proc_info(p);
	release_socket_table(p->files);
	free(p);
}
