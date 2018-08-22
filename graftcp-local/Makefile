GO_CMD := $(shell command -v go 2> /dev/null)
ifndef GO_CMD
$(error "go is not available, please install go")
endif

export GOPATH := $(CURDIR)/.gopath
export PATH := $(PATH):$(CURDIR)/.gopath/bin

GO_IMPORT_PATH := github.com/hmgle/graftcp/graftcp-local

all:: graftcp-local

graftcp-local: .gopath/.created $(wildcard *.go)
	go build -v $(GO_IMPORT_PATH)

.gopath/.created:
	rm -rf .gopath
	mkdir -p $(dir .gopath/src/$(GO_IMPORT_PATH))
	ln -s $(CURDIR) .gopath/src/$(GO_IMPORT_PATH)
	touch $@

install:: graftcp-local
	./graftcp-local -service install && ./graftcp-local -service restart

uninstall:: graftcp-local
	./graftcp-local -service stop && ./graftcp-local -service uninstall

clean::
	-rm -rf graftcp-local .gopath
