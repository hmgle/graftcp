all: graftcp graftcp-local/graftcp-local

graftcp: main.o util.o
	cc $^ -o $@

graftcp-local/graftcp-local: graftcp-local/*.go
	cd graftcp-local && go build

clean::
	rm -f *.o graftcp graftcp-local/graftcp-local
