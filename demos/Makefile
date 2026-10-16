# Records the demos. See README.md.
#
#   make validate      check the tape's syntax
#   make hallpass.gif  build hallpass and record (about 2 minutes)
#   make web.mp4       build hallpass and record the web UI demo (about 1 minute)

VHS ?= vhs
GO ?= go
NODE ?= node
NPM ?= npm
FFMPEG ?= ffmpeg
CHROMIUM ?= /snap/bin/chromium
# The Chromium snap can only write under ~/snap/chromium/common/.
CHROMIUM_PROFILE ?= $(HOME)/snap/chromium/common/hallpass-demo-web
# The session's HOME, project and sockets go in a fresh directory here.
WEB_TMPDIR ?= $(or $(TMPDIR),/tmp)

.PHONY: validate hallpass.gif web.mp4

validate:
	$(VHS) validate hallpass.tape

# The agent's answers vary: always record, then check the result.
hallpass.gif: validate
	cd .. && $(GO) build -o hallpass ./cmd/hallpass
	rm -f hallpass.gif
	cd .. && $(VHS) demos/hallpass.tape
	test -s hallpass.gif

web/node_modules: web/package.json web/package-lock.json
	cd web && $(NPM) ci --no-audit --no-fund
	touch $@

# Scripted end to end (no agent): the same video every time, except for pids
# and times.
web.mp4: web/node_modules
	$(MAKE) -C ..
	rm -f web.mp4
	dir=$$(mktemp -d "$(WEB_TMPDIR)/hp.XXXXXX") && \
	HALLPASS=../hallpass CHROMIUM=$(CHROMIUM) PROFILE=$(CHROMIUM_PROFILE) \
		WORKDIR=$$dir OUT=$$dir/raw.webm $(NODE) web/record.js && \
	$(FFMPEG) -v error -i $$dir/raw.webm -c:v libx264 -preset slow -crf 30 \
		-pix_fmt yuv420p -movflags +faststart -an web.mp4; \
	status=$$?; if [ $$status = 0 ]; then rm -rf "$$dir"; else echo "failed, see $$dir" >&2; fi; exit $$status
	test -s web.mp4
