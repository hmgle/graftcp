# "Makefile" for graftcp.
# Copyright (C) 2016, 2018, 2020 Hmgle <dustgle@gmail.com>
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

VERSION = $(shell git describe --tags --always)

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

ifneq ($(shell echo $(VERSION) | head -c 1), v)
	VERSION=v0.3
endif
CFLAGS += -DVERSION=\"$(VERSION)\"

SRC := $(wildcard *.c)

GRAFTCP_LOCAL_BIN = graftcp-local/graftcp-local
TARGET = graftcp $(GRAFTCP_LOCAL_BIN)

all:: $(TARGET)


graftcp: cmd.o libgraftcp.a
	$(CC) $^ -o $@

libgraftcp.a: main.o util.o string-set.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(GRAFTCP_LOCAL_BIN)::
	$(MAKE) -C graftcp-local VERSION=$(VERSION)

install:: graftcp $(GRAFTCP_LOCAL_BIN)
	$(INSTALL) $< $(DESTDIR)$(BINDIR)/$<
	$(MAKE) -C graftcp-local $@

uninstall::
	-rm -f $(DESTDIR)$(BINDIR)/graftcp
	$(MAKE) -C graftcp-local $@

install_graftcp:: graftcp 
	$(INSTALL) $< $(DESTDIR)$(BINDIR)/$<

uninstall_graftcp::
	-rm -f $(DESTDIR)$(BINDIR)/graftcp

install_systemd::
	$(MAKE) -C graftcp-local install_systemd

uninstall_systemd::
	$(MAKE) -C graftcp-local uninstall_systemd

install_graftcp_local::
	$(MAKE) -C graftcp-local install

uninstall_graftcp_local::
	$(MAKE) -C graftcp-local uninstall

sinclude $(SRC:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
		sed 's,\(.*\)\.o[:]*,\1.o $@:,' < $@.$$$$ > $@; \
		rm -f $@.$$$$

clean::
	-rm -f *.o graftcp *.d
	$(MAKE) -C graftcp-local $@
