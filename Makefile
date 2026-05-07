# "Makefile" for graftcp.
# Copyright (C) 2016, 2018, 2020, 2021, 2023, 2024, 2026 Hmgle <dustgle@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

KERNEL := $(shell uname -s)
ifneq ($(KERNEL), Linux)
$(error only support Linux now.)
endif

BASE_VERSION ?= v0.7
RAW_VERSION := $(shell git rev-parse --is-inside-work-tree 1>/dev/null 2>&1 && \
               git describe --tags --always 2>/dev/null || echo "$(BASE_VERSION)")
ifeq ($(patsubst v%,,$(RAW_VERSION)),$(RAW_VERSION))
	VERSION := $(BASE_VERSION)
else
	VERSION := $(RAW_VERSION)
endif

# CROSS_COMPILE can be set on the command line
# make CROSS_COMPILE=arm-linux-gnueabi-
# Default value for CROSS_COMPILE is not to prefix executables

CROSS_COMPILE ?=

CC ?= $(CROSS_COMPILE)gcc
CXX ?= $(CROSS_COMPILE)g++
AR ?= $(CROSS_COMPILE)ar
ARFLAGS ?= rcs
GO ?= go

DEBUG ?= 0

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

INSTALL ?= install -D

CPPFLAGS += -DVERSION=\"$(VERSION)\"
CFLAGS += -Wall -MMD -MP
ifeq ($(DEBUG),1)
	CFLAGS += -O0 -g
else
	CFLAGS += -O2 -DNDEBUG
endif

LOCAL_DIR := local
TARGET := $(LOCAL_DIR)/mgraftcp

LIB_SRCS := graftcp.c util.c ptrace-ops.c cidr-trie.c
LIB_OBJS := $(LIB_SRCS:.c=.o)
LIB_DEPS := $(LIB_OBJS:.o=.d)

GO_BUILD_FILES := $(filter-out %_test.go,$(wildcard $(LOCAL_DIR)/*.go $(LOCAL_DIR)/cmd/mgraftcp/*.go))
GO_LDFLAGS ?= -s -w
GO_CACHE_DIR ?= $(CURDIR)/$(LOCAL_DIR)/.cache/go-build
GO_MOD_CACHE_DIR ?= $(CURDIR)/.gomodcache

CC_MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
TARGET_GOARCH :=
ifneq ($(findstring aarch64,$(CC_MACHINE)),)
	TARGET_GOARCH := arm64
else ifneq ($(findstring arm,$(CC_MACHINE)),)
	TARGET_GOARCH := arm
else ifneq ($(or $(findstring i386,$(CC_MACHINE)),$(findstring i486,$(CC_MACHINE)),$(findstring i586,$(CC_MACHINE)),$(findstring i686,$(CC_MACHINE))),)
	TARGET_GOARCH := 386
endif

GO_ENV := GOTOOLCHAIN=local GOCACHE=$(GO_CACHE_DIR) GOMODCACHE=$(GO_MOD_CACHE_DIR) \
	CGO_ENABLED=1 CC=$(CC) CXX=$(CXX) AR=$(AR)
ifdef TARGET_GOARCH
	GO_ENV += GOOS=linux GOARCH=$(TARGET_GOARCH)
endif

.DEFAULT_GOAL := all
.SUFFIXES:

.PHONY: all clean install uninstall test test-go test-c
all: $(TARGET)

libgraftcp.a: $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(TARGET): libgraftcp.a $(GO_BUILD_FILES) $(LOCAL_DIR)/go.mod $(LOCAL_DIR)/go.sum
	$(RM) $@
	$(GO_ENV) $(GO) -C $(LOCAL_DIR) build -o $(notdir $@) -ldflags "$(GO_LDFLAGS) -X main.version=$(VERSION)" ./cmd/mgraftcp

install: $(TARGET)
	$(INSTALL) $< $(DESTDIR)$(BINDIR)/mgraftcp

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/mgraftcp

test: test-c test-go

test-go: libgraftcp.a
	$(GO_ENV) $(GO) -C $(LOCAL_DIR) test ./...

CIDR_TRIE_TEST_BIN := cidr-trie_test
CIDR_TRIE_TEST_OBJS := cidr-trie_test.o cidr-trie.o

$(CIDR_TRIE_TEST_BIN): $(CIDR_TRIE_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

test-c: $(CIDR_TRIE_TEST_BIN)
	./$(CIDR_TRIE_TEST_BIN)

clean:
	$(RM) $(LIB_OBJS) $(LIB_DEPS) libgraftcp.a $(TARGET) \
		$(CIDR_TRIE_TEST_BIN) $(CIDR_TRIE_TEST_OBJS) cidr-trie_test.d

-include $(LIB_DEPS)
