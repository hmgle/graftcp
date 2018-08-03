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

TARGET = graftcp graftcp-local/graftcp-local

all:: $(TARGET)

graftcp: main.o util.o string-set.o
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

graftcp-local/graftcp-local: graftcp-local/*.go
	cd graftcp-local && go build

install:: graftcp graftcp-local/graftcp-local
	$(INSTALL) $< $(BINDIR); \
	cd graftcp-local && ./graftcp-local -service install && \
		./graftcp-local -service start

uninstall:: graftcp-local/graftcp-local
	-rm -f $(BINDIR)/graftcp; \
	cd graftcp-local && ./graftcp-local -service uninstall

install_graftcp:: graftcp 
	$(INSTALL) $< $(BINDIR)

uninstall_graftcp::
	-rm -f $(BINDIR)/graftcp

install_graftcp_local:: graftcp-local/graftcp-local
	cd graftcp-local && ./graftcp-local -service install && \
		./graftcp-local -service restart

uninstall_graftcp_local:: graftcp-local/graftcp-local
	cd graftcp-local && ./graftcp-local -service stop && \
		./graftcp-local -service uninstall

sinclude $(SRC:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
		sed 's,\(.*\)\.o[:]*,\1.o $@:,' < $@.$$$$ > $@; \
		rm -f $@.$$$$

clean::
	-rm -f *.o $(TARGET) *.d
