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

/* Inspired by nginx: ngx_radix_tree.h */
#ifndef CIDR_TRIE_H
#define CIDR_TRIE_H

#include <netinet/in.h>
#include <stdint.h>

#define TRIE_NO_VALUE 0

typedef struct trie_node_s trie_node_t;

struct trie_node_s {
	trie_node_t *left;
	trie_node_t *right;
	int value;
};

typedef struct {
	trie_node_t *root;
} trie_t;

struct cidr_s {
	uint32_t addr;
	uint32_t mask;
};

struct cidr6_s {
	struct in6_addr addr;
	struct in6_addr mask;
};

trie_t *trie_new();
void trie32_insert(trie_t *trie, struct cidr_s *cidr, int value);
int trie32_insert_str(trie_t *trie, const char *ipstr, int value);
int trie32_lookup(trie_t *trie, uint32_t ip);
void trie128_insert(trie_t *trie, struct cidr6_s *cidr6, int value);
int trie128_insert_str(trie_t *trie, const char *ipstr, int value);
int trie128_lookup(trie_t *trie, uint8_t *ip);

#endif
