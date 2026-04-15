ifneq ($(shell echo $(VERSION) | head -c 1), v)
	VERSION=v0.7
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
GO_LDFLAGS ?= -s -w

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

INSTALL = install -D

TARGET = mgraftcp

.PHONY: all clean install uninstall

all: $(TARGET)

mgraftcp: $(wildcard *.go cmd/mgraftcp/*.go) ../libgraftcp.a
	${GO_BUILD_PREFIX_FLAGS} ${CGO_FLAGS} go build -ldflags "$(GO_LDFLAGS) -X main.version=${VERSION}" ./cmd/mgraftcp

../libgraftcp.a::
	$(MAKE) -C .. libgraftcp.a

install: $(TARGET)
	$(INSTALL) $^ $(DESTDIR)$(BINDIR)/

uninstall:
	-rm -f $(DESTDIR)$(BINDIR)/mgraftcp

clean:
	-rm -rf $(TARGET)
