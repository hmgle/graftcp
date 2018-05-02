all: tcptrace local

tcptrace: main.o
	cc $^ -o $@

local: local.go
	go build -o $@ $<

test: tcptrace
	xterm -e nc -l 2080 &
	sleep 0.5
	./tcptrace ls

clean::
	rm *.o tcptrace local
