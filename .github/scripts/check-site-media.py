#!/usr/bin/env python3
"""Check that the src and poster URLs of the built site point to files.

mkdocs --strict checks Markdown links, not the raw HTML of <video> and
<img> tags. Run after `mkdocs build`, from the repository root.
"""
import html.parser
import pathlib
import posixpath
import sys
import urllib.parse

SITE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "site")


class Refs(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("src", "poster") and value:
                self.urls.append(value)


def main():
    bad = 0
    for page in sorted(SITE.rglob("*.html")):
        parser = Refs()
        parser.feed(page.read_text(encoding="utf-8"))
        base = page.parent.relative_to(SITE).as_posix()
        for url in parser.urls:
            u = urllib.parse.urlsplit(url)
            if u.scheme or u.netloc or url.startswith(("/", "#", "data:")):
                continue
            target = posixpath.normpath(posixpath.join(base, urllib.parse.unquote(u.path)))
            if target.startswith("..") or not (SITE / target).is_file():
                print(f"{page.relative_to(SITE)}: {url}: not found", file=sys.stderr)
                bad += 1
    if bad:
        sys.exit(1)


main()
