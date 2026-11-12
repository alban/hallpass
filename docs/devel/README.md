# Developer docs

Not published on the website (`exclude_docs` in `mkdocs.yml`).

- [monitor.md](monitor.md): the monitor API and rule model (design).
- [web.md](web.md): `hallpass web`, a browser UI over the session API (design).
- [kubernetes.md](kubernetes.md): NRI node agent, CRDs and Headlamp plugin (design; lite mode node agent implemented).

## Website

Preview the website of a branch, with the version of mkdocs-material that the docs workflow uses:

```sh
python3 -m venv ~/.venv/mkdocs
~/.venv/mkdocs/bin/pip install mkdocs-material==9.5.39
~/.venv/mkdocs/bin/mkdocs serve
```

It serves on http://127.0.0.1:8000/hallpass/ and reloads on each change. Check both color schemes (the toggle in the header). Pull requests build the site with `--strict` but do not publish it. Diagrams: [diagrams/README.md](../../diagrams/README.md).
