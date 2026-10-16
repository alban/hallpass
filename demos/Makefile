# Records the demos into media/. See README.md.
#
# One directory per demo, found automatically:
#   NAME/demo.tape  a terminal demo, recorded with VHS
#   NAME/record.js  a browser demo, recorded with Puppeteer
#   NAME/poster-at  optional: the second to take the poster from (default 1)
# Both write a raw webm, encoded the same way into media/NAME.mp4, with the
# poster frame in media/NAME.png.
#
#   make NAME       build hallpass and record one demo
#   make all        record every demo
#   make posters    take the posters again from the current videos
#   make validate   check the tapes' syntax
#   make list       list the demos

VHS ?= vhs
NODE ?= node
NPM ?= npm
FFMPEG ?= ffmpeg
CHROMIUM ?= /snap/bin/chromium
# The Chromium snap can only write under ~/snap/chromium/common/.
CHROMIUM_PROFILE ?= $(HOME)/snap/chromium/common/hallpass-demo
# Each recording runs in a fresh directory here, removed after success.
DEMO_TMPDIR ?= $(or $(TMPDIR),/tmp)
CRF ?= 30

TAPES := $(wildcard */demo.tape)
SCRIPTS := $(wildcard */record.js)
TERMINAL := $(TAPES:%/demo.tape=%)
BROWSER := $(SCRIPTS:%/record.js=%)
DEMOS := $(TERMINAL) $(BROWSER)

.PHONY: all list validate posters hallpass FORCE $(DEMOS)

all: $(DEMOS)

list:
	@for d in $(TERMINAL); do echo "$$d	media/$$d.mp4	terminal (VHS)"; done
	@for d in $(BROWSER); do echo "$$d	media/$$d.mp4	browser (Puppeteer)"; done

validate:
	for t in $(TAPES); do $(VHS) validate $$t || exit; done

$(DEMOS): %: media/%.mp4

hallpass:
	$(MAKE) -C ..

node_modules: package.json package-lock.json
	$(NPM) ci --no-audit --no-fund
	touch $@

# $(call poster,NAME): media/NAME.png from media/NAME.mp4 at NAME/poster-at.
poster = $(FFMPEG) -v error -y -ss $$(cat $(1)/poster-at 2>/dev/null || echo 1) \
	-i media/$(1).mp4 -frames:v 1 media/$(1).png

posters: $(DEMOS:%=poster-%)

poster-%:
	$(call poster,$*)

# $(call record,COMMAND): run COMMAND in a fresh $$dir, which writes
# $$dir/raw.webm, then encode it into $@ and take the poster.
define record
rm -f $@ media/$*.png
dir=$$(mktemp -d "$(DEMO_TMPDIR)/hp.XXXXXX") && \
	( $(1) ) && \
	$(FFMPEG) -v error -i $$dir/raw.webm -c:v libx264 -preset slow -crf $(CRF) \
		-pix_fmt yuv420p -movflags +faststart -an $@; \
	status=$$?; if [ $$status = 0 ]; then rm -rf "$$dir"; else echo "failed, see $$dir" >&2; fi; exit $$status
test -s $@
$(call poster,$*)
endef

# Always record: a demo shows the current hallpass, and some vary from run to
# run (an agent's answers): check the result before committing it.
media/%.mp4: %/demo.tape hallpass FORCE
	$(VHS) validate $<
	$(call record,cd .. && $(VHS) -o $$dir/raw.webm demos/$<)

media/%.mp4: %/record.js hallpass node_modules FORCE
	$(call record,HALLPASS=../hallpass CHROMIUM=$(CHROMIUM) PROFILE=$(CHROMIUM_PROFILE)-$* \
		WORKDIR=$$dir OUT=$$dir/raw.webm $(NODE) $<)
