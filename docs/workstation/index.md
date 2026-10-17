# Workstation

`hallpass` runs a program in your shell, on your own machine, and asks
you before it writes outside your project. You answer in the terminal,
in a desktop notification, from another terminal or in a browser.

```console
hallpass -- copilot      # or any command; no command: a shell
```

- [Install](install.md): requirements and build.
- [Usage](usage.md): flags, the default policy, agent CLIs, over ssh.
- [Strict mode](strict.md): enforce your answers in the kernel with
  BPF-LSM.
- [Use cases](use-cases.md): audit, CI, checking a tool's declared
  paths.
