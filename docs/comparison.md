# Comparison with other tools

Many tools restrict what a process can do on Linux. hallpass is built for one situation: an AI agent works in a project directory, and from time to time it needs to write somewhere else or run an unexpected program. Rather than either refusing (and breaking the task) or allowing everything up front, hallpass pauses the write or the program and **asks you**: allow it once, for a few minutes or always, or deny it once or always.

Most tools below are static: the policy is decided before the program runs, and an access outside it fails. Others only detect and alert. Only hallpass, OpenSnitch and Claude Code's sandbox prompt at run time; OpenSnitch and Claude Code prompt about network connections only, hallpass about file writes, programs run and, opt-in, connections.

## At a glance

| Tool | Mediates | Asks at run time | Enforced by | Privileges | TOCTOU resistant | Workstation | Kubernetes |
|---|---|---|---|---|---|---|---|
| **hallpass lite** | file writes, exec, connections (opt-in) | yes | seccomp user notification + a supervisor | none | no | yes | yes |
| **hallpass strict** | file writes, exec, connections (opt-in) | yes | BPF-LSM | root to load | yes | yes | yes |
| [OpenSnitch](https://github.com/evilsocket/opensnitch) | outbound network | yes | NFQUEUE + a root daemon | root | yes | yes | no |
| [Tetragon](https://github.com/cilium/tetragon) | exec, files, network, syscalls | no (`TracingPolicy` CRDs) | eBPF (kprobes, BPF-LSM, ...) | root | [on LSM hooks](https://tetragon.io/docs/concepts/tracing-policy/hooks/) | as a host daemon | yes |
| [KubeArmor](https://github.com/kubearmor/KubeArmor) | exec, files, network, capabilities | no (CRDs, audit mode) | AppArmor, SELinux or BPF-LSM | capabilities | yes | as a host daemon | yes |
| [Falco](https://github.com/falcosecurity/falco) | syscalls | no; detection only | eBPF or kernel module | root | n/a (does not block) | as a host daemon | yes |
| [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [landrun](https://github.com/Zouuup/landrun) | files, TCP/UDP, IPC | no | Landlock LSM | none | yes | yes | no |
| [bubblewrap](https://github.com/containers/bubblewrap) | mounts, network on/off, namespaces | no | namespaces (+ caller's seccomp) | none | yes | yes | no |
| [firejail](https://github.com/netblue30/firejail) | files, network, syscalls | no (profiles) | namespaces, seccomp, Landlock | setuid root | yes | yes | no |
| [nsjail](https://github.com/google/nsjail) | files, network, syscalls, resources | no | namespaces, seccomp, cgroups | none (user namespaces) | yes | yes | no |
| [Codex CLI sandbox](https://github.com/openai/codex) | files, network on/off | no (fixed per session) | bubblewrap + seccomp | none | yes | yes | no |
| [Claude Code sandbox](https://github.com/anthropics/sandbox-runtime) | files, network domains | network only | bubblewrap + a network proxy | none | yes | yes | no |
| [gVisor](https://gvisor.dev) | all syscalls | no | a userspace kernel | none | yes | with Docker | yes (RuntimeClass) |
| Dev containers, VMs | everything outside the box | no | container runtime or hypervisor | varies | yes | yes | varies |

"TOCTOU resistant" means the decision is taken on the object the kernel acts on. A supervisor that checks the syscall's arguments and then lets the kernel run it can be raced by a multi-threaded process; see [How it works](how-it-works/strict.md#why-toctou).

## The tools

**OpenSnitch** is the closest in spirit: an interactive application firewall that pops up a dialog for each new outbound connection and turns answers into rules. It covers the network only, with a root daemon on netfilter's NFQUEUE. hallpass does the same for file writes, and, with the experimental network mediation, for connections by address (IP and port, or unix socket; no domain names), unprivileged in lite mode.

**Tetragon** and **KubeArmor** are Kubernetes runtime-security tools. Both enforce in the kernel, KubeArmor through an LSM (AppArmor, SELinux or BPF-LSM), Tetragon through eBPF programs that can override a hook's return value or kill the process. Policies are CRDs written ahead of time, with an audit mode to learn what a workload does. hallpass strict mode uses the same kernel mechanism (BPF-LSM), but the policy is built interactively as the agent runs, and a denied write can still be asked about and allowed.

**Falco** detects suspicious syscalls and raises alerts; it does not block. [Falco Talon](https://github.com/falcosecurity/falco-talon) reacts to the alerts after the fact, through the Kubernetes API (kill the pod, apply a network policy).

**Landlock** is a kernel LSM for unprivileged self-sandboxing: a process restricts its own file and network access, and its children's, before running untrusted code. [landrun](https://github.com/Zouuup/landrun) is a command-line wrapper for it. The rules can only be tightened, never relaxed, so there is no way to ask and then allow a path that was not allowed at the start.

**bubblewrap**, **firejail** and **nsjail** build a sandbox from namespaces (a private mount tree, network and PID namespaces) and seccomp filters, then run the program in it. The program sees only what was mounted in. bubblewrap is the unprivileged building block of Flatpak; firejail ships profiles for desktop applications and is setuid root; nsjail adds resource limits and is used for CTFs and fuzzing.

**The agents' own sandboxes.** Codex CLI runs commands under bubblewrap and seccomp on Linux (Seatbelt on macOS), in a mode chosen per session: read-only, write in the workspace, or no sandbox. Claude Code's sandbox also uses bubblewrap and sends network traffic through a proxy that can ask about unknown domains. In both, a write outside the allowed directories fails, and the agent then asks for permission to rerun the command without the sandbox. hallpass instead asks about the one write, while the command waits, and works for any agent.

**gVisor** runs containers on a userspace kernel that implements the syscalls itself. It isolates from the host kernel, for untrusted workloads; it does not decide about individual files.

**Dev containers and VMs** isolate the whole environment: the agent can do anything inside, nothing outside, unless something is mounted or shared. hallpass can run inside one to mediate what the agent does to the shared project directory.

## A different category

SELinux and AppArmor are system-wide mandatory access control: policy is attached to programs (labels or path profiles) by the administrator, not to one agent session. Kata Containers and Firecracker isolate at the VM boundary. They can all run under or around hallpass, but they answer a different question: what a program may ever do, rather than whether this write, now, is what you want.
