# "Makefile" for graftcp.
# Copyright (C) 2016, 2018 Hmgle <dustgle@gmail.com>
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

debug = 0

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

INSTALL = install -c

CFLAGS += -Wall
ifeq ($(debug), 1)
	CFLAGS += -O0 -g
else
	CFLAGS += -O2 -DNDEBUG
endif

SRC := $(wildcard *.c)

GRAFTCP_LOCAL_BIN = $(GOPATH)/bin/graftcp-local
TARGET = graftcp $(GRAFTCP_LOCAL_BIN)

all:: $(TARGET)

graftcp: main.o util.o string-set.o
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(GRAFTCP_LOCAL_BIN)::
	go get -v github.com/hmgle/graftcp/graftcp-local

install:: graftcp $(GRAFTCP_LOCAL_BIN)
	$(INSTALL) $< $(BINDIR); \
	graftcp-local -service install && graftcp-local -service start

uninstall:: $(GRAFTCP_LOCAL_BIN)
	-rm -f $(BINDIR)/graftcp; \
	graftcp-local -service uninstall

install_graftcp:: graftcp 
	$(INSTALL) $< $(BINDIR)

uninstall_graftcp::
	-rm -f $(BINDIR)/graftcp

install_graftcp_local:: $(GRAFTCP_LOCAL_BIN)
	graftcp-local -service install && graftcp-local -service restart

uninstall_graftcp_local:: $(GRAFTCP_LOCAL_BIN)
	graftcp-local -service stop && graftcp-local -service uninstall

sinclude $(SRC:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
		sed 's,\(.*\)\.o[:]*,\1.o $@:,' < $@.$$$$ > $@; \
		rm -f $@.$$$$

clean::
	-rm -f *.o $(TARGET) *.d
