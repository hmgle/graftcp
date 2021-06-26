ifneq ($(shell echo $(VERSION) | head -c 1), v)
	VERSION=v0.4
endif

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

INSTALL = install -D

TARGET = cmd/graftcp-local/graftcp-local cmd/mgraftcp/mgraftcp 

all:: $(TARGET)

cmd/graftcp-local/graftcp-local: $(wildcard *.go) $(wildcard cmd/graftcp-local/*.go)
	cd cmd/graftcp-local && go build -ldflags "-s -w -X main.version=${VERSION}"

cmd/mgraftcp/mgraftcp: $(wildcard *.go) $(wildcard cmd/mgraftcp/*.go) ../libgraftcp.a
	cd cmd/mgraftcp && go build -ldflags "-s -w -X main.version=${VERSION}"

../libgraftcp.a:
	$(MAKE) -C .. libgraftcp.a

install:: cmd/graftcp-local/graftcp-local
	$(INSTALL) $< $(DESTDIR)$(BINDIR)/$<

SYSTEMD_UNIT_DIR:=$(shell pkg-config --variable=systemdsystemunitdir systemd 2>/dev/null)

install_systemd:: install
	$(if $(SYSTEMD_UNIT_DIR),,$(error SYSTEMD_UNIT_DIR is not defined))
	test -f $(DESTDIR)/etc/graftcp-local/graftcp-local.conf || \
		install -Dm644 example-graftcp-local.conf $(DESTDIR)/etc/graftcp-local/graftcp-local.conf
	install -Dm644 contrib/systemd/graftcp-local.service ${DESTDIR}/${SYSTEMD_UNIT_DIR}/graftcp-local.service
ifneq ($(PREFIX),/usr/)
	sed -i -re 's#/usr/bin/graftcp-local#$(subst #,\#,${PREFIX})/bin/graftcp-local#g' ${DESTDIR}/${SYSTEMD_UNIT_DIR}/graftcp-local.service
endif
	@echo "Enable and start the graftcp-local systemd unit"
	systemctl daemon-reload && systemctl --now enable graftcp-local.service

uninstall_systemd::
	$(if $(SYSTEMD_UNIT_DIR),,$(error SYSTEMD_UNIT_DIR is not defined))
	@echo "Disable and stop the graftcp-local systemd unit"
	systemctl disable --now graftcp-local.service
	rm -f ${DESTDIR}/${SYSTEMD_UNIT_DIR}/graftcp-local.service

uninstall::
	-rm -f $(DESTDIR)$(BINDIR)/$<

install_service:: cmd/graftcp-local/graftcp-local
	cmd/graftcp-local/graftcp-local -service install && cmd/graftcp-local/graftcp-local -service start

uninstall_service:: cmd/graftcp-local/graftcp-local
	cmd/graftcp-local/graftcp-local -service stop && cmd/graftcp-local/graftcp-local -service uninstall

clean::
	-rm -rf $(TARGET)
