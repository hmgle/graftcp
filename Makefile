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

BASE_VERSION ?= v0.9.0
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

CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar
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
TARGET := $(LOCAL_DIR)/graftcp
ALIAS_TARGET := $(LOCAL_DIR)/mgraftcp

LIB_SRCS := graftcp.c util.c ptrace-ops.c cidr-trie.c
LIB_OBJS := $(LIB_SRCS:.c=.o)
LIB_DEPS := $(LIB_OBJS:.o=.d)

GO_BUILD_FILES := $(filter-out %_test.go,$(wildcard $(LOCAL_DIR)/*.go $(LOCAL_DIR)/cmd/mgraftcp/*.go))
GO_LDFLAGS ?= -s -w
GO_CACHE_DIR ?= $(CURDIR)/$(LOCAL_DIR)/.cache/go-build
GO_MOD_CACHE_DIR ?= $(CURDIR)/.gomodcache

CC_MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
TARGET_GOARCH :=
TARGET_GOARM :=
ifneq ($(findstring aarch64,$(CC_MACHINE)),)
	TARGET_GOARCH := arm64
else ifneq ($(findstring arm,$(CC_MACHINE)),)
	TARGET_GOARCH := arm
	ifneq ($(findstring gnueabihf,$(CC_MACHINE)),)
		TARGET_GOARM := 7
	endif
else ifneq ($(or $(findstring i386,$(CC_MACHINE)),$(findstring i486,$(CC_MACHINE)),$(findstring i586,$(CC_MACHINE)),$(findstring i686,$(CC_MACHINE))),)
	TARGET_GOARCH := 386
endif

shell_quote = '$(subst ','"'"',$(1))'

# Preserve the Go toolchain default when Make has no caller-supplied flags.
ifeq ($(origin CGO_CPPFLAGS),undefined)
CGO_CPPFLAGS = $(shell GOTOOLCHAIN=local $(GO) env CGO_CPPFLAGS)
endif

# Go does not track external C library changes in its build/test cache.
# Hash the archive and its objects because thin archives only reference them.
GO_ENV = GOTOOLCHAIN=local GOCACHE=$(GO_CACHE_DIR) GOMODCACHE=$(GO_MOD_CACHE_DIR) \
	CGO_ENABLED=1 CC=$(CC) CXX=$(CXX) AR=$(AR) \
	CGO_CPPFLAGS=$(call shell_quote,$(CGO_CPPFLAGS))" -DGRAFTCP_ARCHIVE_HASH=$$(sha256sum libgraftcp.a $(LIB_OBJS) | sha256sum | cut -d ' ' -f 1)"
ifdef TARGET_GOARCH
	GO_ENV += GOOS=linux GOARCH=$(TARGET_GOARCH)
endif
ifdef TARGET_GOARM
	GO_ENV += GOARM=$(TARGET_GOARM)
endif

.DEFAULT_GOAL := all
.SUFFIXES:

.PHONY: all clean install uninstall test test-go test-c FORCE
all: $(TARGET) $(ALIAS_TARGET)

# Check effective options on every invocation, but preserve stamp timestamps
# when they are unchanged. Separate compilation from archive-only options.
# Stamps record the effective Make variable values.
C_CONFIG_STAMP := .cache/make/c-config
AR_CONFIG_STAMP := .cache/make/ar-config

FORCE:

define update_config_stamp
	tmp=$$(mktemp "$@.XXXXXX") && \
	trap 'rm -f -- "$$tmp"' EXIT && \
	trap 'exit 1' HUP INT TERM && \
	printf '%s\n' $(1) > "$$tmp" && \
	if ! cmp -s "$$tmp" "$@"; then mv -f -- "$$tmp" "$@"; fi
endef

$(C_CONFIG_STAMP): FORCE
	@mkdir -p $(dir $@)
	@$(call update_config_stamp,$(call shell_quote,CC=$(CC)) \
		$(call shell_quote,CPPFLAGS=$(CPPFLAGS)) \
		$(call shell_quote,CFLAGS=$(CFLAGS)))

$(AR_CONFIG_STAMP): FORCE
	@mkdir -p $(dir $@)
	@$(call update_config_stamp,$(call shell_quote,AR=$(AR)) \
		$(call shell_quote,ARFLAGS=$(ARFLAGS)))


libgraftcp.a: $(LIB_OBJS) $(AR_CONFIG_STAMP) Makefile
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(LIB_OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(TARGET): libgraftcp.a $(GO_BUILD_FILES) $(LOCAL_DIR)/go.mod $(LOCAL_DIR)/go.sum Makefile
	$(RM) $@
	$(GO_ENV) $(GO) -C $(LOCAL_DIR) build -o $(notdir $@) -ldflags "$(GO_LDFLAGS) -X main.version=$(VERSION)" ./cmd/mgraftcp

$(ALIAS_TARGET): $(TARGET)
	$(RM) $@
	ln -s $(notdir $<) $@

install: $(TARGET) $(ALIAS_TARGET)
	$(INSTALL) $(TARGET) $(DESTDIR)$(BINDIR)/graftcp
	ln -sf graftcp $(DESTDIR)$(BINDIR)/mgraftcp

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/graftcp
	$(RM) $(DESTDIR)$(BINDIR)/mgraftcp

test: test-c test-go

test-go: libgraftcp.a
	@# The C compiler reads testdata probes at runtime, outside Go's test cache.
	$(GO_ENV) $(GO) -C $(LOCAL_DIR) test -count=1 ./...

CIDR_TRIE_TEST_BIN := cidr-trie_test
CIDR_TRIE_TEST_OBJS := cidr-trie_test.o cidr-trie.o

$(LIB_OBJS) $(CIDR_TRIE_TEST_OBJS) reaped-child_test.o: $(C_CONFIG_STAMP) Makefile

$(CIDR_TRIE_TEST_BIN): $(CIDR_TRIE_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

reaped-child_test: reaped-child_test.o $(filter-out graftcp.o,$(LIB_OBJS))
	$(CC) $(CFLAGS) -o $@ $^

test-c: $(CIDR_TRIE_TEST_BIN) reaped-child_test
	./$(CIDR_TRIE_TEST_BIN)
	./reaped-child_test stop-first
	./reaped-child_test death-first
	./reaped-child_test unqueued
	./reaped-child_test overlap
	./reaped-child_test untraced-vfork

clean:
	$(RM) $(LIB_OBJS) $(LIB_DEPS) libgraftcp.a $(TARGET) $(ALIAS_TARGET) \
		$(CIDR_TRIE_TEST_BIN) $(CIDR_TRIE_TEST_OBJS) cidr-trie_test.d \
		reaped-child_test reaped-child_test.o reaped-child_test.d \
		$(C_CONFIG_STAMP) $(AR_CONFIG_STAMP)

-include $(LIB_DEPS) cidr-trie_test.d reaped-child_test.d
