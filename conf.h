/*
 * graftcp
 * Copyright (C) 2021, 2024 Hmgle <dustgle@gmail.com>
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
#ifndef CONF_H
#define CONF_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

struct graftcp_conf {
	char *local_addr;
	uint16_t *local_port;
	char *pipe_path;
	char *blackip_file_path;
	char *whiteip_file_path;
	bool *ignore_local;
	char *username;
};

typedef int (*config_cb)(const char *, const char *, struct graftcp_conf *);

struct graftcp_config_t {
	char *name;
	config_cb cb;
};

int conf_init(struct graftcp_conf *conf);
void conf_free(struct graftcp_conf *conf);
int conf_read(const char *path, struct graftcp_conf *conf);
void conf_override(struct graftcp_conf *w, const struct graftcp_conf *r);

static inline void __free_func(char **p)
{
	if (*p) {
		free(*p);
		*p = NULL;
	}
}

static inline void __conf_free_func(struct graftcp_conf *pconf)
{
	if (pconf)
		conf_free(pconf);
}

#define __defer_free __attribute__((cleanup(__free_func)))

#define __defer_conf_free __attribute__((cleanup(__conf_free_func)))

#endif
