# Workstation

`hallpass` runs a program in your shell, on your own machine, and asks
you before it writes outside your project. You answer in the terminal,
in a desktop notification, from another terminal or in a browser.

```console
hallpass -- copilot      # or any command; no command: a shell
```

- [Install](install.md): requirements and build.
- [Getting started](getting-started.md): a first session, step by step.
- [Usage](usage.md): the default policy, programs, network, agent
  CLIs, over ssh.
- [Agents](agents.md): let an agent ask in advance with
  `hallpass-request`.
- [CLI reference](reference.md): every flag.
- [Strict mode](strict.md): enforce your answers in the kernel with
  BPF-LSM.
- [Use cases](use-cases.md): audit, CI, checking a tool's declared
  paths.
