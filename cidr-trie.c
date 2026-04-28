/*
 * graftcp
 * Copyright (C) 2023 Hmgle <dustgle@gmail.com>
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

/* Inspired by nginx: ngx_radix_tree.c */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include "cidr-trie.h"

static trie_node_t *node_calloc()
{
	trie_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL)
		return NULL;
	node->left = NULL;
	node->right = NULL;
	node->value = TRIE_NO_VALUE;
	return node;
}

trie_t *trie_new()
{
	trie_t *trie = calloc(1, sizeof(*trie));
	if (trie == NULL)
		return NULL;
	trie->root = node_calloc();
	if (trie->root == NULL) {
		free(trie);
		return NULL;
	}
	return trie;
}

int trie32_insert(trie_t *trie, struct cidr_s *cidr, int value)
{
	trie_node_t *node, *next;
	uint32_t bit = 0x80000000;

	if (trie == NULL || trie->root == NULL || cidr == NULL)
		return -1;

	next = trie->root;
	for (node = trie->root; bit & cidr->mask; bit >>= 1) {
		next = cidr->addr & bit ? node->right : node->left;
		if (next == NULL)
			break;
		node = next;
	}
	if (next) {
		node->value = value;
		return 0;
	}
	for (; bit & cidr->mask; bit >>= 1) {
		next = node_calloc();
		if (next == NULL)
			return -1;
		if (cidr->addr & bit)
			node->right = next;
		else
			node->left = next;
		node = next;
	}
	node->value = value;
	return 0;
}

#define IPV4_MAX_TEXT_LENGTH 15
#define IPV6_MAX_TEXT_LENGTH 45

static int parse_prefix(const char *text, int max, int *prefix)
{
	char *end;
	long value;

	errno = 0;
	value = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' ||
	    value < 0 || value > max)
		return -1;
	*prefix = (int)value;
	return 0;
}

static int parse_cidr(const char *line, struct cidr_s *cidr)
{
	char *p;
	int prefix;
	char ipbuf[IPV4_MAX_TEXT_LENGTH + 1];
	struct in_addr addr;

	p = strchr(line, '/');
	if (p) {
		if (p == line || p - line > IPV4_MAX_TEXT_LENGTH)
			return -1;
		memcpy(ipbuf, line, p - line);
		ipbuf[p - line] = '\0';
		if (inet_pton(AF_INET, ipbuf, &addr) != 1)
			return -1;
		if (parse_prefix(p + 1, 32, &prefix) < 0)
			return -1;
		cidr->addr = ntohl(addr.s_addr);
		cidr->mask = prefix ?
			     (uint32_t)(0xffffffffu << (32 - prefix)) : 0;
	} else {
		if (inet_pton(AF_INET, line, &addr) != 1)
			return -1;
		cidr->mask = 0xffffffff;
		cidr->addr = ntohl(addr.s_addr);
	}
	return 0;
}

int trie32_insert_str(trie_t *trie, const char *ipstr, int value)
{
	struct cidr_s cidr;

	if (parse_cidr(ipstr, &cidr))
		return -1;
	return trie32_insert(trie, &cidr, value);
}

int trie32_lookup(trie_t *trie, uint32_t ip)
{
	uint32_t bit = 0x80000000;
	trie_node_t *node;

	for (node = trie->root; node;) {
		if (node->value != TRIE_NO_VALUE)
			return node->value;
		node = ip & bit ? node->right : node->left;
		bit >>= 1;
	}
	return TRIE_NO_VALUE;
}

int trie128_insert(trie_t *trie, struct cidr6_s *cidr6, int value)
{
	trie_node_t *node, *next;
	uint8_t bit = 0x80;
	unsigned int i = 0;

	if (trie == NULL || trie->root == NULL || cidr6 == NULL)
		return -1;

	next = trie->root;
	for (node = trie->root; bit & cidr6->mask.s6_addr[i];) {
		next = bit & cidr6->addr.s6_addr[i] ? node->right : node->left;
		if (next == NULL)
			break;
		bit >>= 1;
		node = next;
		if (bit == 0) {
			if (++i == 16)
				break;
			bit = 0x80;
		}
	}
	if (next) {
		node->value = value;
		return 0;
	}
	for (; bit & cidr6->mask.s6_addr[i];) {
		next = node_calloc();
		if (next == NULL)
			return -1;
		if (bit & cidr6->addr.s6_addr[i])
			node->right = next;
		else
			node->left = next;
		bit >>= 1;
		node = next;
		if (bit == 0) {
			if (++i == 16)
				break;
			bit = 0x80;
		}
	}
	node->value = value;
	return 0;
}

static void build_ipv6_mask(struct in6_addr *mask, int prefix)
{
	unsigned int i;

	memset(mask->s6_addr, 0, 16);
	for (i = 0; prefix >= 8 && i < 16; i++, prefix -= 8)
		mask->s6_addr[i] = 0xff;
	if (prefix > 0 && i < 16)
		mask->s6_addr[i] = (unsigned char)(0xffu << (8 - prefix));
}

static int parse_cidr6(const char *line, struct cidr6_s *cidr6)
{
	char *p;
	int prefix;
	char ip6buf[IPV6_MAX_TEXT_LENGTH + 1];

	p = strchr(line, '/');
	if (p) {
		if (p == line || p - line > IPV6_MAX_TEXT_LENGTH)
			return -1;
		memcpy(ip6buf, line, p - line);
		ip6buf[p - line] = '\0';
		if (inet_pton(AF_INET6, ip6buf, &cidr6->addr) != 1)
			return -1;
		if (parse_prefix(p + 1, 128, &prefix) < 0)
			return -1;
		build_ipv6_mask(&cidr6->mask, prefix);
	} else {
		if (inet_pton(AF_INET6, line, &cidr6->addr) != 1)
			return -1;
		memset(cidr6->mask.s6_addr, 0xff, 16);
	}
	return 0;
}

int trie128_insert_str(trie_t *trie, const char *ipstr, int value)
{
	struct cidr6_s cidr6;

	if (parse_cidr6(ipstr, &cidr6))
		return -1;
	return trie128_insert(trie, &cidr6, value);
}

int trie128_lookup(trie_t *trie, uint8_t *ip)
{
	trie_node_t *node;
	uint8_t bit = 0x80;
	unsigned int i = 0;

	for (node = trie->root; node;) {
		if (node->value != TRIE_NO_VALUE)
			return node->value;
		node = bit & ip[i] ? node->right : node->left;
		bit >>= 1;
		if (bit == 0) {
			i++;
			bit = 0x80;
		}
	}
	return TRIE_NO_VALUE;
}

cidr_trie_t *cidr_trie_new()
{
	cidr_trie_t *cidr_trie = calloc(1, sizeof(*cidr_trie));
	if (cidr_trie == NULL)
		return NULL;
	cidr_trie->cidr4_trie = NULL;
	cidr_trie->cidr6_trie = NULL;
	return cidr_trie;
}

int cidr_trie_insert_str(cidr_trie_t *cidr_trie, const char *ipstr, int value)
{
	char *p;

	if (cidr_trie == NULL || ipstr == NULL)
		return -1;

	p = strchr(ipstr, ':');
	if (p) {
		if (cidr_trie->cidr6_trie == NULL)
			cidr_trie->cidr6_trie = trie_new();
		if (cidr_trie->cidr6_trie == NULL)
			return -1;
		return trie128_insert_str(cidr_trie->cidr6_trie, ipstr, value);
	} else {
		if (cidr_trie->cidr4_trie == NULL)
			cidr_trie->cidr4_trie = trie_new();
		if (cidr_trie->cidr4_trie == NULL)
			return -1;
		return trie32_insert_str(cidr_trie->cidr4_trie, ipstr, value);
	}
}

int cidr4_trie_lookup(cidr_trie_t *cidr_trie, uint32_t ip)
{
	if (cidr_trie->cidr4_trie == NULL)
		return TRIE_NO_VALUE;
	return trie32_lookup(cidr_trie->cidr4_trie, ip);
}

int cidr6_trie_lookup(cidr_trie_t *cidr_trie, uint8_t *ip)
{
	if (cidr_trie->cidr6_trie == NULL)
		return TRIE_NO_VALUE;
	return trie128_lookup(cidr_trie->cidr6_trie, ip);
}
