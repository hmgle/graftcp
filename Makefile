all: graftcp local

graftcp: main.o util.o
	cc $^ -o $@

local: local.go
	go build -o $@ $<

clean::
	rm *.o graftcp local
