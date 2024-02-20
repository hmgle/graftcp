ifneq ($(shell echo $(VERSION) | head -c 1), v)
	VERSION=v0.6
endif

GO_BUILD_PREFIX_FLAGS :=
CGO_FLAGS :=
ifneq ($(shell $(CC) -E -dM -xc /dev/null | grep __aarch64__),)
	GO_BUILD_PREFIX_FLAGS := GOOS=linux GOARCH=arm64
	CGO_FLAGS := CGO_ENABLED=1 CC=$(CC) CXX=$(CXX) AR=$(AR)
else ifneq  ($(shell $(CC) -E -dM -xc /dev/null | grep __arm__),)
	GO_BUILD_PREFIX_FLAGS := GOOS=linux GOARCH=arm
	CGO_FLAGS := CGO_ENABLED=1 CC=$(CC) CXX=$(CXX) AR=$(AR)
else ifneq  ($(shell $(CC) -E -dM -xc /dev/null | grep __i386__),)
	GO_BUILD_PREFIX_FLAGS := GOOS=linux GOARCH=386
	CGO_FLAGS := CGO_ENABLED=1 CC=$(CC) CXX=$(CXX) AR=$(AR)
endif

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

INSTALL = install -D

TARGET = graftcp-local mgraftcp

all:: $(TARGET)

graftcp-local: $(wildcard *.go cmd/graftcp-local/*.go)
	${GO_BUILD_PREFIX_FLAGS} go build -ldflags "-s -w -X main.version=${VERSION}" ./cmd/graftcp-local

mgraftcp: $(wildcard *.go cmd/mgraftcp/*.go) ../libgraftcp.a
	${GO_BUILD_PREFIX_FLAGS} ${CGO_FLAGS} go build -ldflags "-s -w -X main.version=${VERSION}" ./cmd/mgraftcp

../libgraftcp.a::
	$(MAKE) -C .. libgraftcp.a

install:: $(TARGET)
	$(INSTALL) $^ $(DESTDIR)$(BINDIR)/

SYSTEMD_UNIT_DIR:=$(shell pkg-config --variable=systemdsystemunitdir systemd 2>/dev/null)

install_systemd:: install
	$(if $(SYSTEMD_UNIT_DIR),,$(error SYSTEMD_UNIT_DIR is not defined))
	test -f $(DESTDIR)/etc/graftcp-local/graftcp-local.conf || \
		install -Dm644 example-graftcp-local.conf $(DESTDIR)/etc/graftcp-local/graftcp-local.conf
	install -Dm644 contrib/systemd/graftcp-local.service ${DESTDIR}/${SYSTEMD_UNIT_DIR}/graftcp-local.service
ifneq ($(PREFIX),/usr/)
	sed -i -re 's#/usr/bin/graftcp-local#$(subst #,\#,${PREFIX})/bin/graftcp-local#g' ${DESTDIR}/${SYSTEMD_UNIT_DIR}/graftcp-local.service
endif

enable_systemd::
	@echo "Enable and start the graftcp-local systemd unit"
	systemctl daemon-reload && systemctl --now enable graftcp-local.service

disable_systemd::
	@echo "Disable and stop the graftcp-local systemd unit"
	systemctl disable --now graftcp-local.service

uninstall_systemd:: disable_systemd
	$(if $(SYSTEMD_UNIT_DIR),,$(error SYSTEMD_UNIT_DIR is not defined))
	rm -f ${DESTDIR}/${SYSTEMD_UNIT_DIR}/graftcp-local.service

uninstall::
	-rm -f $(DESTDIR)$(BINDIR)/mgraftcp $(DESTDIR)$(BINDIR)/graftcp-local

install_service:: graftcp-local
	graftcp-local -service install && graftcp-local -service start

uninstall_service:: graftcp-local
	graftcp-local -service stop && graftcp-local -service uninstall

clean::
	-rm -rf $(TARGET)
