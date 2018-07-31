/*
 * graftcp
 * Copyright (C) 2018 Hmgle <dustgle@gmail.com>
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
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "string-set.h"

/* see http://www.cse.yorku.ca/~oz/hash.html */
static unsigned long str_hash(const char *str)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) + c;	/* hash * 33 + c */

	return hash;
}

struct str_set *str_set_new()
{
	struct str_set *set;
	int i;

	set = calloc(1, sizeof(*set) + 509 * sizeof(set->buckets[0]));
	set->size = 509;
	set->buckets = (struct member **)(set + 1);
	for (i = 0; i < set->size; i++)
		set->buckets[i] = NULL;
	set->length = 0;
	return set;
}

void str_set_put(struct str_set *set, const char *elem)
{
	int i;
	struct member *p;

	assert(set);
	assert(elem);
	i = str_hash(elem) % set->size;
	for (p = set->buckets[i]; p; p = p->link) {
		if (strcmp(elem, p->element) == 0)
			break;
	}
	if (p == NULL) {
		p = calloc(1, sizeof(*p));
		p->element = elem;
		p->link = set->buckets[i];
		set->buckets[i] = p;
		set->length++;
	} else {
		p->element = elem;
	}
}

char *str_set_remove(struct str_set *set, const char *elem)
{
	int i;
	struct member **pp;

	assert(set);
	assert(elem);
	i = str_hash(elem) % set->size;
	for (pp = &set->buckets[i]; *pp; pp = &(*pp)->link) {
		if (strcmp(elem, (*pp)->element) == 0) {
			struct member *p = *pp;
			*pp = p->link;
			elem = p->element;
			free(p);
			set->length--;
			return (char *)elem;
		}
	}
	return NULL;
}

int str_set_length(struct str_set *set)
{
	assert(set);
	return set->length;
}

int is_str_set_member(struct str_set *set, const void *elem)
{
	int i;
	struct member *p;

	assert(set);
	assert(elem);
	i = str_hash(elem) % set->size;
	for (p = set->buckets[i]; p; p = p->link) {
		if (strcmp(elem, p->element) == 0)
			break;
	}
	return p != NULL;
}

void str_set_free(struct str_set **set)
{
	assert(set && *set);
	if ((*set)->length > 0) {
		int i;
		struct member *p, *q;
		for (i = 0; i < (*set)->size; i++) {
			for (p = (*set)->buckets[i]; p; p = q) {
				q = p->link;
				free(p);
			}
		}
	}
	free(*set);
}
