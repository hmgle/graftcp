# "Makefile" for graftcp.
# Copyright (C) 2016, 2018, 2020, 2021, 2023, 2024 Hmgle <dustgle@gmail.com>
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

KERNEL = $(shell uname -s)
ifneq ($(KERNEL), Linux)
$(error only support Linux now.)
endif

VERSION = $(shell git rev-parse --is-inside-work-tree 1>/dev/null 2>&1 && \
             git describe --tags --always || echo "v0.7")

# CROSS_COMPILE can be set on the command line
# make CROSS_COMPILE=arm-linux-gnueabi-
# Default value for CROSS_COMPILE is not to prefix executables

CROSS_COMPILE ?=

CC		= $(CROSS_COMPILE)gcc
CXX		= $(CROSS_COMPILE)g++
AR		= $(CROSS_COMPILE)ar

debug = 0

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

INSTALL = install -D

CFLAGS += -Wall
ifeq ($(debug), 1)
	CFLAGS += -O0 -g
else
	CFLAGS += -O2 -DNDEBUG
endif

CFLAGS += -DVERSION=\"$(VERSION)\"
LDFLAGS ?=

SRC := $(wildcard *.c)

TARGET = local/mgraftcp

.PHONY: all clean
all: $(TARGET)

libgraftcp.a: graftcp.o util.o cidr-trie.o conf.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

local/mgraftcp: libgraftcp.a $(wildcard local/*.go local/cmd/mgraftcp/*.go local/go.mod local/go.sum)
	$(MAKE) -C $(dir $@) VERSION=$(VERSION) CC=$(CC) CXX=$(CXX) AR=$(AR) $(notdir $@)

.PHONY: install uninstall

install: local/mgraftcp
	$(MAKE) -C local $@

uninstall:
	$(MAKE) -C local $@

sinclude $(SRC:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
		sed 's,\(.*\)\.o[:]*,\1.o $@:,' < $@.$$$$ > $@; \
		rm -f $@.$$$$

clean:
	-rm -f *.o *.a graftcp *.d
	$(MAKE) -C local $@
