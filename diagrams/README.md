# Diagrams

The sources of the documentation's diagrams, in [Mermaid](https://mermaid.js.org/).

| File | Use |
|---|---|
| `NAME.mmd` | the source |
| `../docs/assets/diagrams/NAME.svg`, `NAME-dark.svg` | the website, light and dark color scheme |
| `png/NAME.png`, `png/NAME-dark.png` | slides: 4× scale, on white or a dark background |

All are committed. After editing a source, render it from the repository root:

```sh
make diagrams
```

It needs Node.js: npm installs mermaid-cli and the Chromium it renders with in `diagrams/node_modules`. Only the changed sources are rendered; after updating mermaid-cli in `package.json`, run `make -B diagrams`. Check the result in the website ([Website](../docs/devel/README.md#website)), in both color schemes.

## Writing a diagram

- Steps are numbered (`showSequenceNumbers`); notes are not, so keep them for what a component records or decides.
- A trapped syscall goes in a red band: `rect rgba(214,39,40,0.15)`. Its answer says what the supervisor does: `emulate: …` (it does the syscall itself, differently), `continue: …` (the kernel does it), or `deny`.
- A network namespace is a `box transparent NAME`: a colored box would not suit both color schemes.
- Break long participant names and notes with `<br/>`: Mermaid does not wrap them, and the text overflows the box.
- Embed both variants in the page; Material shows the one of the reader's color scheme:

  ```markdown
  ![DNS with Go's resolver: ...](../assets/diagrams/NAME.svg#only-light)
  ![DNS with Go's resolver: ...](../assets/diagrams/NAME-dark.svg#only-dark)
  ```

## Slides

Use the PNGs. PowerPoint (Microsoft 365) can also insert the SVG, which stays sharp at any zoom; Google Slides cannot.
