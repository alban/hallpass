# Records the demo GIF. See README.md.
#
#   make validate      check the tape's syntax
#   make hallpass.gif  build hallpass and record (about 2 minutes)

VHS ?= vhs
GO ?= go

.PHONY: validate hallpass.gif

validate:
	$(VHS) validate hallpass.tape

# The agent's answers vary: always record, then check the result.
hallpass.gif: validate
	cd .. && $(GO) build -o hallpass ./cmd/hallpass
	rm -f hallpass.gif
	cd .. && $(VHS) demos/hallpass.tape
	test -s hallpass.gif
