all: graftcp local/local

graftcp: main.o util.o
	cc $^ -o $@

local/local: local/local.go local/util.go
	cd local && go build

clean::
	rm -f *.o graftcp local/local
