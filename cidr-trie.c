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

#include "cidr-trie.h"

static trie_node_t *node_callc()
{
	trie_node_t *node = calloc(1, sizeof(*node));
	node->left = NULL;
	node->right = NULL;
	node->value = TRIE_NO_VALUE;
	return node;
}

trie_t *trie_new()
{
	trie_t *trie = calloc(1, sizeof(*trie));
	trie->root = node_callc();
	return trie;
}

void trie32_insert(trie_t *trie, struct cidr_s *cidr, int value)
{
	trie_node_t *node, *next;
	uint32_t bit = 0x80000000;

	next = trie->root;
	for (node = trie->root; bit & cidr->mask; bit >>= 1) {
		next = cidr->addr & bit ? node->right : node->left;
		if (next == NULL)
			break;
		node = next;
	}
	if (next) {
		node->value = value;
		return;
	}
	for (; bit & cidr->mask; bit >>= 1) {
		next = node_callc();
		if (cidr->addr & bit)
			node->right = next;
		else
			node->left = next;
		node = next;
	}
	node->value = value;
}

#define IPV4_MAX_TEXT_LENGTH 15
#define IPV6_MAX_TEXT_LENGTH 45

static int parse_cidr(const char *line, struct cidr_s *cidr)
{
	char *p;
	int shift;
	char ipbuf[IPV4_MAX_TEXT_LENGTH + 1];

	p = strchr(line, '/');
	if (p) {
		if (p - line > IPV4_MAX_TEXT_LENGTH)
			return -1;
		strncpy(ipbuf, line, p - line);
		ipbuf[p - line] = '\0';
		cidr->addr = ntohl(inet_addr(ipbuf));

		shift = strtol(++p, NULL, 0);
		if (shift < 0 || shift > 32)
			return -1;
		cidr->mask = shift ? (uint32_t)(0xffffffff << (32 - shift)) : 0;
	} else {
		cidr->mask = 0xffffffff;
		cidr->addr = ntohl(inet_addr(line));
	}
	return 0;
}

int trie32_insert_str(trie_t *trie, const char *ipstr, int value)
{
	struct cidr_s cidr;

	if (parse_cidr(ipstr, &cidr))
		return -1;
	trie32_insert(trie, &cidr, value);
	return 0;
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

void trie128_insert(trie_t *trie, struct cidr6_s *cidr6, int value)
{
	trie_node_t *node, *next;
	uint8_t bit = 0x80;
	unsigned int i = 0;

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
		return;
	}
	for (; bit & cidr6->mask.s6_addr[i];) {
		next = node_callc();
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
}

static int parse_cidr6(const char *line, struct cidr6_s *cidr6)
{
        char *p;
        int shift;
        char ip6buf[IPV6_MAX_TEXT_LENGTH + 1];
        uint8_t *mask;
        unsigned int i, s;

        p = strchr(line, '/');
        if (p) {
                if (p - line > IPV6_MAX_TEXT_LENGTH)
                        return -1;
                strncpy(ip6buf, line, p - line);
                ip6buf[p - line] = '\0';
                if (inet_pton(AF_INET6, ip6buf, &cidr6->addr) != 1)
                        return -1;

                shift = strtol(++p, NULL, 0);
                if (shift < 0 || shift > 128)
                        return -1;
                if (shift) {
                        mask = cidr6->mask.s6_addr;
                        for (i = 0; i < 16; i++) {
                                s = (shift > 8) ? 8 : shift;
                                shift -= s;
                                mask[i] = (unsigned char) (0xffu << (8 - s));
                        }
                } else {
                        memset(cidr6->mask.s6_addr, 0, 16);
                }
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
	trie128_insert(trie, &cidr6, value);
	return 0;
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
	cidr_trie->cidr4_trie = NULL;
	cidr_trie->cidr6_trie = NULL;
	return cidr_trie;
}

void cidr_trie_insert_str(cidr_trie_t *cidr_trie, const char *ipstr, int value)
{
	char *p;
	p = strchr(ipstr, ':');
	if (p) {
		if (cidr_trie->cidr6_trie == NULL)
			cidr_trie->cidr6_trie = trie_new();
		trie128_insert_str(cidr_trie->cidr6_trie, ipstr, value);
	} else {
		if (cidr_trie->cidr4_trie == NULL)
			cidr_trie->cidr4_trie = trie_new();
		trie32_insert_str(cidr_trie->cidr4_trie, ipstr, value);
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
