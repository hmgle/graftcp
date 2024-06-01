/*
 * graftcp
 * Copyright (C) 2021, 2023, 2024 Hmgle <dustgle@gmail.com>
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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>

#include "conf.h"

static int config_local_addr(const char *, const char *, struct graftcp_conf *);
static int config_local_port(const char *, const char *, struct graftcp_conf *);
static int config_pipe_path(const char *, const char *, struct graftcp_conf *);
static int config_blackip_file_path(const char *, const char *, struct graftcp_conf *);
static int config_whiteip_file_path(const char *, const char *, struct graftcp_conf *);
static int config_ignore_local(const char *, const char *, struct graftcp_conf *);

static const struct graftcp_config_t config[] = {
	{ "local_addr",        config_local_addr        },
	{ "local_port",        config_local_port        },
	{ "pipepath",          config_pipe_path         },
	{ "blackip_file_path", config_blackip_file_path },
	{ "whiteip_file_path", config_whiteip_file_path },
	{ "ignore_local",      config_ignore_local      },
};

static int config_local_addr(const char *key, const char *value, struct graftcp_conf *conf)
{
	if (strlen(value) <= 0)
		return -1;
	conf->local_addr = strdup(value);
	return 0;
}

static int config_local_port(const char *key, const char *value, struct graftcp_conf *conf)
{
	int port;

	port = atoi(value);
	if (port <= 0)
		return -1;
	conf->local_port = malloc(sizeof(*conf->local_port));
	*conf->local_port = port;
	return 0;
}

static int config_pipe_path(const char *key, const char *value, struct graftcp_conf *conf)
{
	conf->pipe_path = strdup(value);
	return 0;
}

static int config_blackip_file_path(const char *key, const char *value, struct graftcp_conf *conf)
{
	conf->blackip_file_path = strdup(value);
	return 0;
}

static int config_whiteip_file_path(const char *key, const char *value, struct graftcp_conf *conf)
{
	conf->whiteip_file_path = strdup(value);
	return 0;
}

static int config_ignore_local(const char *key, const char *value, struct graftcp_conf *conf)
{
	conf->ignore_local = malloc(sizeof(*conf->ignore_local));
	if (strcmp(value, "true") || strcmp(value, "1"))
		*conf->ignore_local = true;
	else
		*conf->ignore_local = false;
	return 0;
}

static const size_t config_size = sizeof(config) / sizeof(struct graftcp_config_t);

static const struct graftcp_config_t *graftcp_getconfig(const char *key)
{
	int i;

#define MAX(a,b) (((a)>(b))?(a):(b))
	for (i = 0; i < config_size; i++) {
		if (!strncmp(config[i].name, key, MAX(strlen(config[i].name), strlen(key))))
			return &config[i];
	}
#undef MAX
	return NULL;
}

static int is_line_empty(char *line)
{
	int i;
	size_t len = strlen(line);

	for (i = 0; i < len; i++)
		if (!isspace(line[i]))
			return 0;
	return 1;
}

static int left_space(char *buf, size_t len)
{
	int i;
	for (i = 0; i < len; i++)
		if (buf[i] != ' ' && buf[i] != '\t')
			return i;
	return i;
}

static int right_space(char *buf, size_t len)
{
	int i;
	for (i = len - 1; i >= 0; i--)
		if (buf[i] != ' ' && buf[i] != '\t' && buf[i] != '\0' &&
		    buf[i] != '\n' && buf[i] != '\r')
			return i + 1;
	return 0;
}

static int parse_line(char *buf, struct graftcp_conf *conf)
{
	char *key;
	char *value;
	char *fs;

	if (is_line_empty(buf))
		return 0;
	buf += left_space(buf, strlen(buf));
	if (buf[0] == '#')
		return 0;

	fs = strstr(buf, "=");
	if (!fs)
		return -1;

	*fs = '\0';
	value = fs + 1;

	key = buf;
	key[right_space(key, strlen(key))] = '\0';

	value += left_space(value, strlen(value));
	value[right_space(value, strlen(value))] = '\0';

	const struct graftcp_config_t *config = graftcp_getconfig(key);
	if (!config) {
		fprintf(stderr, "unknown key %s", key);
		return -1;
	}

	return config->cb(key, value, conf);
}

int conf_init(struct graftcp_conf *conf)
{
	conf->local_addr = NULL;
	conf->local_port = NULL;
	conf->pipe_path = NULL;
	conf->blackip_file_path = NULL;
	conf->whiteip_file_path = NULL;
	conf->ignore_local = NULL;
	conf->username = NULL;
	return 0;
}

void conf_free(struct graftcp_conf *conf)
{
	if (conf->local_addr) {
		free(conf->local_addr);
		conf->local_addr = NULL;
	}
	if (conf->local_port) {
		free(conf->local_port);
		conf->local_port = NULL;
	}
	if (conf->pipe_path) {
		free(conf->pipe_path);
		conf->pipe_path = NULL;
	}
	if (conf->blackip_file_path) {
		free(conf->blackip_file_path);
		conf->blackip_file_path = NULL;
	}
	if (conf->whiteip_file_path) {
		free(conf->whiteip_file_path);
		conf->whiteip_file_path = NULL;
	}
	if (conf->ignore_local) {
		free(conf->ignore_local);
		conf->ignore_local = NULL;
	}
	if (conf->username) {
		free(conf->username);
		conf->username = NULL;
	}
}

static char *xdg_config_path_dup(void)
{
	const char *home, *config_home;
	char *path = NULL;
	const char *dotconf = ".config";
	const char *subdir = "graftcp";
	const char *confname = "graftcp.conf";

	config_home = getenv("XDG_CONFIG_HOME");
	if (config_home && *config_home) {
		size_t size = 3 + strlen(config_home) + strlen(subdir) + strlen(confname);
		path = calloc(size, sizeof(char));
		snprintf(path, size, "%s/%s/%s", config_home, subdir, confname);
		return path;
	}

	home = getenv("HOME");
	if (home) {
		size_t size = 4 + strlen(home) + strlen(dotconf) + strlen(subdir) + strlen(confname);
		path = calloc(size, sizeof(char));
		snprintf(path, size, "%s/%s/%s/%s", home, dotconf, subdir, confname);
		return path;
	}

	return NULL;
}

int conf_read(const char *path, struct graftcp_conf *conf)
{
	FILE *f;
	__defer_free char *xdg_config = NULL;
	__defer_free char *line = NULL;
	size_t len = 0;
	int err = 0;

	if (path == NULL) {
		xdg_config = xdg_config_path_dup();
		if (xdg_config == NULL)
			return 0;

		struct stat st;
		if (stat(xdg_config, &st))
			return 0;
		if (S_ISDIR(st.st_mode)) {
			fprintf(stderr, "%s is a directory not a config file\n", xdg_config);
			return -1;
		}
		path = xdg_config;
	}

	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "Failed to open %s\n", path);
		return -1;
	}

	while (getline(&line, &len, f) != -1) {
		err = parse_line(line, conf);
		if (err) {
			fprintf(stderr, "Failed to parse config: %s\n", line);
			break;
		}
	}
	fclose(f);
	return err;
}

void conf_override(struct graftcp_conf *w, const struct graftcp_conf *r)
{
	if (r->local_addr)
		w->local_addr = r->local_addr;
	if (r->local_port)
		w->local_port = r->local_port;
	if (r->pipe_path)
		w->pipe_path = r->pipe_path;
	if (r->blackip_file_path)
		w->blackip_file_path = r->blackip_file_path;
	if (r->whiteip_file_path)
		w->whiteip_file_path = r->whiteip_file_path;
	if (r->ignore_local)
		w->ignore_local = r->ignore_local;
	if (r->username)
		w->username = r->username;
}
