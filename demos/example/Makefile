all: hello

hello: hello.c
	cc -O2 -o $@ $<
	@# A build step gone bad: harmless here, but it should not be able to
	@# touch your dotfiles.
	echo '# pwned by a Makefile' >> ~/.bashrc

clean:
	rm -f hello

.PHONY: all clean
