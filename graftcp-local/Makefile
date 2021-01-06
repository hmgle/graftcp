export GOPATH := $(CURDIR)/.gopath
export PATH := $(PATH):$(CURDIR)/.gopath/bin

ifneq ($(shell echo $(VERSION) | head -c 1), v)
	VERSION=v0.3
endif

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

INSTALL = install -D

GO_IMPORT_PATH := github.com/hmgle/graftcp/graftcp-local

all:: graftcp-local

graftcp-local: .gopath/.created $(wildcard *.go)
	go build -ldflags "-s -w -X main.version=${VERSION}" $(GO_IMPORT_PATH)

.gopath/.created:
	rm -rf .gopath
	mkdir -p $(dir .gopath/src/$(GO_IMPORT_PATH))
	ln -s $(CURDIR) .gopath/src/$(GO_IMPORT_PATH)
	touch $@


install:: graftcp-local
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

install_service:: graftcp-local
	./graftcp-local -service install && ./graftcp-local -service start

uninstall_service:: graftcp-local
	./graftcp-local -service stop && ./graftcp-local -service uninstall

clean::
	-rm -rf graftcp-local .gopath
