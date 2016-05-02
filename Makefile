all: tcptrace

tcptrace: main.o
	cc $^ -o $@

test: tcptrace
	xterm -e nc -l 2080 &
	sleep 0.5
	./tcptrace ls
