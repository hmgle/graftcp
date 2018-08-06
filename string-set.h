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
#ifndef STRING_SET_H
#define STRING_SET_H

struct str_set {
	int length;
	int size;
	struct member {
		struct member *link;
		const char *element;
	} **buckets;
};

struct str_set *str_set_new();
void str_set_put(struct str_set *set, const char *elem);
char *str_set_remove(struct str_set *set, const char *elem);
int str_set_length(struct str_set *set);
int is_str_set_member(struct str_set *set, const void *elem);
void str_set_free(struct str_set **set);

#endif
