all: hello

hello: hello.c
	cc -O2 -o $@ $<

install: hello
	mkdir -p ~/.local/bin
	cp hello ~/.local/bin/hello

clean:
	rm -f hello

.PHONY: all install clean
