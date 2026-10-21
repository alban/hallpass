# Monitor

Status: implemented in lite and strict mode (`internal/rules`,
`internal/launch`, `internal/monitor`, `internal/defaults`; hallpass is a
client). Not yet: the BPF extensions for ops and subjects.

## Scope

hallpass is split in two layers:

- **Monitor** (`internal/monitor`): the mechanism, a reference monitor. It
  mediates a workload's accesses with seccomp user notification (lite) and
  BPF-LSM (strict), applies rules and verdicts, and reports what it cannot
  decide. It has no built-in policy, no notion of agents, shells or LLMs,
  and does not show prompts.
- **hallpass** (`cmd/hallpass`, `internal/ui`, `internal/tty`, ...): one UX
  on top. Defaults (workdir, `$TMPDIR`, devices, secret stores), prompts,
  answer keys, "allow folder" heuristics, timeouts, desktop notifications,
  the answer socket, `--log` formatting.

The name is for the reference monitor, and for the hall monitor who checks
hall passes. Rule files and profiles are hallpass UX and are not covered
here. The monitor stays in `internal/` until a second consumer (e.g. a
runc/NRI launcher) needs it: a public API is a compatibility promise.

## Concepts

- **Workload**: the policy domain. One hallpass session, or one container.
  One monitor serves one workload; a process serving several containers
  creates one monitor per container. There is no workload id in the API.
- **Listener**: one seccomp notification fd and the root pid its filter
  was installed on. hallpass has one; a container has one per process
  runc starts (`docker run`, then each `docker exec`).
- **Request**: an access no rule decides, reported to clients until a
  verdict closes it.
- **Verdict**: allow or deny one request, once. Lasting answers ("temp",
  "always", "never") are rules sent with the verdict.
- **Rule**: subject, ops, object, verdict; optionally an expiry and a set.
- **Generation**: a counter, incremented each time the rule set changes.

## Packages

```
cmd/hallpass  →  monitor, launch, ui, tty, config, defaults
monitor       →  seccomp, lsm, rules, procfs
launch        →  seccomp
privsep       →  lsm
seccomp, lsm, rules, procfs: no hallpass imports
```

- `rules`: rule types and `Eval`. Pure: no I/O, no clock (time is a
  parameter).
- `seccomp`: filter and listener (`Recv`, `IDValid`, `Continue`, `Deny`).
- `lsm`: loads BPF, fills the maps, grants, events. Keeps its own `Rule`
  and `ProcRule`: what BPF can express, nothing more.
- `monitor`: one workload: requests, coalescing, restart cache, `Apply`,
  events. Converts `rules.Rule` to `lsm.Rule`; the conversion rejects any
  field it does not handle (`ErrUnsupported`), so nothing is dropped
  silently.
- `launch`: hallpass's local launcher (see [Launch](#launch)).
- `defaults`: hallpass's default rules and the "allow folder" heuristic.

`seccomp` and `lsm` never import each other, so lite mode does not depend
on BPF. What couples them is ordering on one syscall: grant (or sync) in
BPF, then `Continue` the notification, keyed by the tid from the
notification. Only the monitor does that.

The monitor uses both through interfaces, so unit tests can fake them;
`Kernel` is nil in lite mode:

```go
type Kernel interface {
	AddMember(pid int) error
	Sync(rules []lsm.Rule, procs []lsm.ProcRule) error
	GrantOnce(tid int, paths []string, proc lsm.ProcRule) error
	Events(fn func(lsm.Event))
}

type Notifier interface {
	Recv(slot []byte) (seccomp.Notif, error)
	IDValid(id uint64) bool
	Continue(id uint64) error
	Deny(id uint64, errno int32) error
}
```

BPF is loaded and attached once per process, whatever the number of
monitors: N copies would run N programs on every LSM hook and on
`sys_exit`, for every task on the host (one `sys_exit` attachment costs
~200 ns per syscall even with an empty program). Each monitor gets a
session of the shared programs, an `lsm.Session`:

```go
l, _ := lsm.Load(...)                 // once
a, _ := l.NewSession(rootA)           // container A
b, _ := l.NewSession(rootB)           // container B
ma, _ := monitor.New(monitor.Config{Kernel: a})
```

`NewSession` allocates a non-zero u32 id. `AddMember` stores it in the
task's `members` storage, copied on fork. Rule and `/proc` rule keys carry
it, and the superblocks members mount are recorded with it, so a member is
only checked against its session's rules and may only write the `/proc`
files of its own session's processes. The one ring buffer reader
dispatches events by it.
Grants are per thread and need no id. A session's paths are those seen by
its root process (`root`, 0 for this process), which can be in another
mount namespace and chroot.

The CLI uses one session in its own private instance. The node agent loads
the programs once and makes one session per container. After a restart it
rebuilds the `LSM` from the fds in its fd-store (`FromFDs`, which reads the
rules left in the maps), `ResumeSession`s each saved id (the members keep
their marks in task storage), and `DropStale` deletes the rules of the
sessions it did not resume.

## Rule model

### Ops

```go
package rules

type Op uint32 // a bit, so that rules can carry a set of ops

const (
	OpWrite  Op = 1 << iota // open for write (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC)
	OpCreate                // mknod, open O_CREAT of a new file
	OpMkdir
	OpSymlink
	OpDelete // unlink, rmdir
	OpLink   // both objects: source and new name
	OpRename // both objects: old and new name
	OpTruncate
	OpConnect // connect, and sendto/sendmsg with MSG_FASTOPEN
	OpSend    // sendto, sendmsg, sendmmsg with a destination address

	OpFiles = OpTruncate<<1 - 1
	OpNet   = OpConnect | OpSend
	OpAll   = OpFiles | OpNet
)
```

Lite mode sees syscalls, strict mode sees LSM hooks:

| Op | seccomp (`seccomp/rules.go`) | LSM hook |
|---|---|---|
| Write | `openat` (write flags), `openat2`, `open`, `creat` | `file_open` |
| Create | `mknodat`, `openat`/`openat2` O_CREAT | `path_mknod`, `inode_create` |
| Mkdir | `mkdirat` | `path_mkdir` |
| Symlink | `symlinkat` | `path_symlink` |
| Delete | `unlinkat` | `path_unlink`, `path_rmdir` |
| Link | `linkat` | `path_link` |
| Rename | `renameat`, `renameat2` | `path_rename` |
| Truncate | `truncate` | `path_truncate` |
| Connect | `connect`; `sendto`, `sendmsg`, `sendmmsg` with `MSG_FASTOPEN` | `socket_connect`, `unix_stream_connect` |
| Send | `sendto` with an address, `sendmsg`, `sendmmsg` | `socket_sendmsg`, `unix_may_send` |

The network ops are notified only with `network` in `--mediate`
(`seccomp.Category`). A `sendmsg` without `msg_name` is continued at
once; for `sendmmsg`, every message with an address is evaluated and the
call is allowed only if all are.

Seccomp cannot tell create from write on `openat(O_CREAT)` for an existing
file; it reports `OpWrite|OpCreate`, and a rule must allow both. Strict
mode sees the exact op. Prompt text ("create directory", "delete") is
rendered by the UX from `Op`. BPF has no ops yet, so rules must use
`OpAll` for now.

`openat2` passes its flags in `struct open_how`, out of the filter's
reach: every call is notified, and the monitor reads the struct
(`procfs.ReadOpenHow`) and continues the calls without write intent.
`RESOLVE_IN_ROOT` paths are resolved with `procfs.ResolveInRoot`, which
clamps `..` and absolute symlinks at the dirfd and refuses magic links,
as the kernel does. The other `RESOLVE_*` flags only make the kernel
refuse more, so the plain resolution is safe for them.

### Objects

```go
type Object struct { // exactly one field is set
	Path    *PathObject
	Proc    *ProcObject
	Inet    *InetObject
	Unix    *UnixObject
	Unknown error // lite mode only: the path could not be read
}

type PathObject struct {
	Path string // absolute, symlink-resolved (lexical past the first missing component)
	Dev  uint64 // of the existing part; 0 when unknown (lite)
	Ino  uint64
}

// ProcObject is a write to another process's /proc/<pid>/<Name>, for a
// target outside the workload.
type ProcObject struct {
	Name   string  // e.g. "oom_score_adj"
	Target Subject // the target process, Comm used by rules
}

type InetObject struct {
	Proto       uint16         // IP protocol of the socket: 6 tcp, 17 udp...
	Addr        netip.AddrPort // IPv4-mapped IPv6 addresses are unmapped
	OwnListener bool           // loopback, listener started inside the sandbox
}

type UnixObject struct {
	Path        string // resolved; empty for an abstract name
	Abstract    bool
	Name        string // abstract name, without the leading NUL
	Type        int    // SOCK_STREAM...; display only
	OwnListener bool   // the peer socket was created inside the sandbox
}
```

Not objects, always allowed by the monitor (mechanism, not policy):
pipes and sockets reached through `/proc/<pid>/fd/N`, and writes by the
workload to its own processes' `/proc` files, for any of its listeners'
roots.

### Subjects

```go
type Subject struct {
	Chain []Task // Chain[0] is the requesting thread, then its parents up to the workload root
}

type Task struct {
	PID, TID       int
	StartTime      uint64 // boot-relative, from /proc/<pid>/stat; with PID, a stable identity
	Comm           string
	Exe            string
	ExeDev, ExeIno uint64
	Cmdline        []string // written by the process itself
	Cwd            string
}
```

The monitor reports the full chain; the UX truncates it for display.

### Rules

```go
type Rule struct {
	ID      uint64 // set by the monitor on Apply
	Subject SubjectMatch
	Ops     Op
	Object  ObjectMatch
	Verdict Verdict
	Label   string    // for Ask: shown in prompts, e.g. "SSH keys"
	Expires time.Time // zero: until removed
	Set     string    // opaque, chosen by the client
}

type Verdict int

const (
	Allow Verdict = iota
	Deny
	Ask // in BPF, a cut-off: see Strict mode
)

// SubjectMatch selects the processes a rule applies to. The zero value
// matches every process, the only behaviour for now; fields such as Exe
// or Under come later.
type SubjectMatch struct{}

type ObjectMatch struct { // exactly one field is set
	Path    *PathMatch
	Proc    *ProcMatch
	Inet    *InetMatch
	Unix    *UnixMatch
	Unknown bool // all unreadable paths (lite)
	OwnListener bool // loopback/unix destinations listened on inside the sandbox
	AnyNet  bool // every network destination, unix sockets included
}

type PathMatch struct {
	Path string // absolute; the monitor resolves it
	Tree bool   // the path and everything below it
}

type ProcMatch struct {
	Name string // /proc/<pid>/<Name>
	Comm string // of the target process
}

type InetMatch struct {
	Proto          uint16       // 0: any
	Prefix         netip.Prefix // zero: any address of any family
	PortLo, PortHi uint16       // inclusive; both 0: any port
}

type UnixMatch struct {
	Path     string // a socket file, or with Prefix a tree
	Abstract bool
	Name     string // with Prefix, every name starting with it
	Prefix   bool
}
```

Network matches are what BPF can evaluate: an LPM trie for prefixes, a
port range, inode rules for unix socket files. In strict mode a network
rule must cover both network ops, as a file rule covers every file op.

The monitor has one rule set and no persistence. `Set` lets a client
replace a group of rules atomically (remove the set and add its new rules
in one `Apply`). Precedence ignores sets. hallpass uses `implicit`
(defaults and `--allow-path`/`--deny-path`/`--ask-path`) and `session` (answers).

### Evaluation

For one object, from the rules whose subject, ops and object match and
that have not expired:

1. Any **Deny** wins, at any depth. A deny on a directory beats an allow
   below it and an allow-once grant. Both layers already work this way:
   the BPF walk ORs `deny_tree` along the path. A deny is a plain OR,
   with no ordering between rules.
2. Otherwise the **deepest** Allow or Ask decides. An Ask below an Allow
   cuts the Allow off (`ask ~/.ssh` inside an allowed `~`); an Allow below
   an Ask re-allows (`allow ~/.ssh/known_hosts`).
3. No match: a `Request`.

For two objects (rename, link), each is evaluated: any Deny denies, all
Allow allows, otherwise a `Request`.

### Strict mode

In strict mode, every rule must be evaluable in BPF. Today BPF has path
trie nodes with `allow_tree`, `allow_exact`, `ask_tree`, `ask_exact` (with
expiry), `deny_tree` and `deny_exact`, the same without asks for programs
(`exec_*`, read by `bprm_check_security`); proc keys {name, comm} with
allow/ask/deny and expiry; and per-thread one-shot grants. It has no ops
and no subjects. Exec rules cannot ask: a program no rule allows is asked
anyway. The monitor refuses rules it cannot enforce
(`ErrUnsupported`), so the UX cannot think a rule holds when the kernel
ignores it.

An Ask rule is a cut-off in BPF: no allow inherited from above. The kernel
follows `rules.Eval`: any Deny denies; otherwise the deepest Allow or Ask
decides, Ask on a tie. An asked access is denied in the kernel unless a
deeper Allow or the thread's "once" grant allows it: it is asked at seccomp
time like any unmatched access, and the answer becomes the grant. The path
walk clears the inherited allow at a node with a live ask, and an exact
allow or ask on the target applies after the tree rules of its node. Two
rules on one node from different host paths (a mount exposing a sub-tree)
are ordered by the depth of their host paths; their expiries are then
ignored in that ordering. Network entries carry the depth of their rule
(`rules.ObjectMatch.Depth`), and an inet or abstract lookup allows only if
the deepest live allow is deeper than the deepest live ask. An ask on
every unix socket stops the "any unix socket" allow. `OwnListener` has no
Ask in BPF (`ErrUnsupported`).

Network rules go to separate maps (`internal/lsm/net.go`): LPM tries for
IPv4 and IPv6 prefixes and for abstract unix names, each entry holding up
to a few rules with protocol, port range, verdict and expiry; a flag for
"any unix socket"; and unix socket files as path rules marked `net`. The
hooks are `socket_connect` and `socket_sendmsg` (inet), and
`unix_stream_connect` and `unix_may_send` (the peer's inode or abstract
name). Listeners started by a session's members are recorded at
`socket_post_create` (unix) and at the end of `inet_listen` (TCP), and
dropped at `sk_free_security`; the `OwnListener` rule enables them per
session. A "once" answer is a per-thread grant of the destination.

Rules are host paths, but BPF keys them by superblock and path within it:
each rule is compiled through `mountinfo` to every mount exposing it. A
new mount (a tmpfs on `~/proj/build`, a USB drive, a bind mount of
`~/.ssh`) needs the rules recompiled. The monitor polls
`/proc/<rootPID>/mountinfo`, which reports `EPOLLPRI|EPOLLERR` when that
mount namespace changes, so there is no wake-up without a change. No
notification is continued while a mount event is unprocessed, so an allow
is never continued into a BPF denial for a mount not yet compiled. Expired
rules and stale grants are pruned at the next sync; BPF and `rules.Eval`
enforce expiry themselves.

The realistic sync failure is a full BPF map (`rules`: 65536 nodes, one
per path component per mount exposing it; `proc`: 1024). `Apply` then
rolls back (see API). A failed resync after a mount change goes to
`Event.Warning`.

## API

```go
package monitor

type Config struct {
	Kernel Kernel // nil: lite mode
	// ProcRoot resolves paths through the caller's /proc/<tid>/root, and
	// reports them relative to it (the node agent, see kubernetes.md).
	ProcRoot bool
}

// New returns a monitor for one workload.
func New(cfg Config) (*Monitor, error)

// Attach starts mediating the processes behind seccompFD. rootPID is
// the process the filter was installed on, in the monitor's pid
// namespace. In strict mode, tasks become BPF members on their execve,
// which the filter must notify: the root may still run trusted runtime
// code until then (runc init). Called once per listener.
func (m *Monitor) Attach(seccompFD, rootPID int) error

// Events subscribes a client; each call returns a new channel. Opened,
// Closed, Rules and Warning events are sent at once: a prompt must not
// wait. Decided events are batched: the first after a quiet period is
// sent at once; later ones are held until 500 ms without new events, at
// most 2 s, so a steady stream cannot starve the client. All events are
// flushed before the channel is closed, when the workload is gone (all
// listeners hung up) or the monitor closed: a log is complete when the
// workload ends.
func (m *Monitor) Events(opts EventOptions) <-chan []Event

type EventOptions struct {
	// Decided also delivers accesses decided without asking (for logs,
	// tracers). Off by default: they can be many, and building their
	// subject costs /proc reads.
	Decided bool
}

// Apply is the only write entry point, and atomic: it computes the new
// rule set, syncs the kernel (strict), gives the verdicts, then closes
// the pending requests that the new rules decide. It returns the new
// generation. With IfGeneration != 0, it fails with ErrStale if the
// rules changed since that generation. If the kernel sync fails, Apply
// restores the previous rule set (userspace and kernel), gives no
// verdict and returns the error: the requests stay pending, so a client
// can remove rules and retry, or send the verdict alone.
//
// In strict mode, the grant of an allow verdict is made by the thread
// handling the syscall, just before it continues it (the grant needs the
// requesting thread and the resolved paths, which the worker holds); a
// failed grant is a Warning, and BPF then denies the syscall.
func (m *Monitor) Apply(d Decision) (gen uint64, err error)

// Snapshot lets a client join: pending requests and the rules, at
// generation gen; then follow Events.
func (m *Monitor) Snapshot() (pending []*Request, rules []rules.Rule, gen uint64)

// Close stops mediating: pending requests are closed as if their tasks
// died, and subscriptions are flushed and closed. The seccomp fds stay
// open until the process exits, so no task is left waiting on a closed
// fd (and the fd numbers are not reused under the workers): mediated
// syscalls fail with ENOSYS meanwhile, as after an exit.
func (m *Monitor) Close() error

var (
	ErrStale       = errors.New("monitor: rules changed since IfGeneration")
	ErrClosed      = errors.New("monitor: request already closed")
	ErrUnsupported = errors.New("monitor: rule not enforceable in strict mode")
)

type Event struct { // exactly one field is set
	Opened  *Request
	Closed  *Closed
	Rules   uint64   // the rule set changed: its new generation
	Decided *Decided // an access decided without asking (EventOptions.Decided)
	// Warning reports a failure no caller can receive, e.g. the resync
	// after a mount change.
	Warning string
	// Dropped counts Decided events lost because this client was too
	// slow. Opened, Closed and Rules are never dropped.
	Dropped uint64
}

type Request struct {
	ID      uint64
	Syscall string // e.g. "renameat2"
	Op      rules.Op
	Objects []Object // 1, or 2 for rename and link
	Subject Subject
	Facts   []Fact
	Advance *Advance // a request made in advance, see below
}

type Advance struct {
	Tree   bool          // Objects[0] and everything below it
	For    time.Duration // how long the grant is asked for; 0: the session
	Reason string        // written by the workload: display only
}

type Closed struct {
	ID  uint64 // Request.ID
	Why Reason
}

type Decided struct {
	Time    time.Time // of the decision: delivery may be batched
	Syscall string    // the LSM operation when BPF decided
	Op      rules.Op
	Objects []Object
	Subject Subject // the requesting task only, no ancestry walk
	Allowed bool
	// Why has one entry per object; on a deny, only the denied object's
	// is set.
	Why    []Reason
	Source Source
}

// Reason says why a request was closed or an access decided. At most
// one field is set; none when BPF decided (it does not know rule ids).
type Reason struct {
	Client  string // a verdict from this client (Decision.Client)
	Rule    uint64 // this rule
	Builtin string // mechanism, not a rule: "special-file" (pipe, socket),
	// "own-proc" (the workload writes its own /proc files), "restarted"
	// (restart cache), "bpf" (strict: other mount namespace or
	// unreadable path, continued for BPF to decide), "unresolvable" (the
	// path could not be resolved: denied), "execve" (continued: exec not
	// mediated), "exec-retry" (a verdict denied the same program to the
	// same thread just before: execvp trying the next $PATH directory)
	Died bool // the requesting task died
}

type Source int

const (
	SourceSeccomp Source = iota
	SourceLSM
)

type Decision struct {
	Verdicts     []Verdict
	AddRules     []rules.Rule
	RemoveRules  []uint64 // rules.Rule.ID
	RemoveSets   []string
	IfGeneration uint64
	Client       string // reported in Reason.Client
	TimedOut     bool   // nobody answered: an advance request gets ETIMEDOUT
}

// Verdict allows or denies one request, once. In strict mode, an allow
// is a per-thread, per-syscall grant in the kernel (task storage,
// cleared at sys_exit).
type Verdict struct {
	Request uint64 // Request.ID
	Allow   bool
}

type Fact struct {
	Kind  string // "listener-in-sandbox", "dns-name", "secret-store"...
	Value string
	Trust Trust
}

type Trust int

const (
	TrustKernel  Trust = iota // from the kernel (notification, BPF)
	TrustRacy                 // read from process memory; may change after the read
	TrustClaimed              // written by the process itself (cmdline, comm)
)
```

### Behaviour

- **Several clients** (TUI, answer socket, phone, web): the first verdict
  wins; the others get `Closed` and drop the prompt. A verdict on a closed
  request returns `ErrClosed`. A gRPC/HTTP adapter maps batches and
  `Apply` one-to-one to messages.
- **Coalescing**: concurrent requests from the same thread group with
  the same op and objects are one `Request`. Two processes writing the
  same file get two: the prompt names one process, so an answer must not
  release another. A syscall restarted after a signal is answered from a
  restart cache without a new `Request`. An exec denied by a verdict
  denies the same program to the same thread for a moment too: `execvp`
  tries each `$PATH` directory, and `/bin/curl` is `/usr/bin/curl` on
  most distributions, which would ask the same question twice.
- **Serialization** is the UX's: the monitor does not hold requests back
  while one is being answered. After each `Apply` it closes the pending
  requests the new rules decide, so an "allow folder" answer settles the
  queued prompts.
- **Timeouts** are the UX's: it sends a deny verdict. The monitor only
  closes requests whose task died. The kernel does not signal a withdrawn
  notification, so the monitor polls `IDValid` every second, only while
  requests are pending.
- **Rename and link** are reported as one `Request` per object, in order,
  for now (one prompt per path, as today).
- **Requests made in advance**: an execve of
  `/proc/self/hallpass/request?op=write&path=/dir/**&for=10m&reason=...`
  (`AdvanceDir`, see [usage](../workstation/usage.md#asking-in-advance))
  is never continued: execve is notified in every mode and category, and
  the monitor answers with an errno, so a shell prints it and no program
  runs. Without a monitor the path does not exist (`ENOENT`). The monitor
  parses the query (`EINVAL`, `ENAMETOOLONG` past `PATH_MAX`), fails it
  with `ENOSYS` when its category (files for `op=write`, exec for
  `op=exec`, network for `op=connect`) is not in `Config.Mediate`,
  since nothing would enforce a grant, resolves
  the path like a write's (a `unix:` path destination too), and
  evaluates the rules: covered
  (`EEXIST`, an allow for the whole tree or every destination, with no
  deny or ask rule inside it, lasting at least `for` minus
  min(`for`/10, 1m)), denied (`EPERM`),
  or a `Request` with `Advance` set and `Op` `OpFiles`, `OpExec` or
  `OpNet`. A write or exec request has the path as its object; a connect
  request has no object, its destinations are `Advance.Net` (an
  `ObjectMatch` from `rules.ParseNet`, inet prefixes masked).
  `Advance.Writable` tells that an exec target may be written without a
  prompt under the current rules (files mediated only).
  `check?` stops there (`ENOMSG` instead of a request). That
  request is coalesced with identical ones of the same thread group, is
  never settled by rules (the UX answers it: a grant is an `AddRules` of
  `Request.Grant(expires)`, an expiring allow rule in the `advance` set
  (`AdvanceSet`), plus an allow verdict), emits no `Decided`
  events, and fails the execve with `EALREADY` on an allow, `ETIMEDOUT`
  on a deny with `Decision.TimedOut`, `EPERM` on another deny. In strict
  mode the grant is a rule like any other, synced to the kernel; a
  process in another mount view than the session's gets `EINVAL`, since
  its path would not name the same file. `AddRules` refuses a deny or
  ask rule in the `advance` set. `release?op=...` removes, through
  `Apply` with `RemoveRules`, the unexpired allow rules of the `advance`
  set with the same ops and object as a grant for that target would
  have, emits a `Released` event and fails the execve with `ECANCELED`,
  or `ESRCH` when there is none.
- **Unreadable path** (lite): `Object{Unknown: err}`, matched only by
  `ObjectMatch{Unknown}` rules; a verdict allows that one syscall.
- **Other mount namespace or unreadable path** (strict): the monitor
  continues the syscall and lets BPF decide. It reports a `Decided` event
  with `Builtin` "bpf" for the continue, and BPF reports its own
  `Decided` (`SourceLSM`) if it denies.
- **Kernel sync failure** in `Apply`: hallpass warns and sends the verdict
  alone, and shows nothing on success. A smarter UI may offer to remove
  rules and retry, since the request stays pending.
- **No `os.Process`**: the monitor does not wait for or signal processes.
  Liveness comes from the listener fd (POLLHUP when no task uses the
  filter); the root pid is only used for `/proc`. Since
  Linux 6.11 (95036a79e7b5), `SECCOMP_IOCTL_NOTIF_RECV` on a filter with
  no task left returns `ENOENT` at once instead of blocking, which is
  also its error for a task killed before its notification was received:
  a worker stops on `ENOENT` only after POLLHUP, else it would spin.

## Launch

```go
package launch

type ProcSpec struct {
	Args []string // argv[0] is looked up in PATH
	Dir  string
	Env  []string
	// Files are the child's fds 0, 1, 2, ...; Setsid/Setctty as in
	// syscall.SysProcAttr (the TTY case).
	Files   []*os.File
	Setsid  bool
	Setctty bool
	// Whether new user and mount namespaces are refused (lite mode needs
	// it, see seccomp.Rules).
	AllowUserns bool
}

// Start starts spec paused before its first exec, with the seccomp
// filter installed. The caller attaches seccompFD and proc.Pid to a
// monitor, then calls release to let the child exec.
func Start(spec ProcSpec) (proc *os.Process, seccompFD int, release func() error, err error)
```

`launch` hands two ints to the monitor and does not import it. The
workload is a real child here: `Wait`, signal forwarding, subreaper and
`--wait=all` stay in hallpass, next to `launch`. runc/NRI are other
launchers.

**execve.** runc does not wait for the seccomp agent: it lets the child
continue as soon as it has a copy of the fd, then sends it to the agent
(`libcontainer/process_linux.go`), relying on notify actions to make the
child wait. The filter is installed just before the container's `execve`.
So the profile a runc/NRI integration injects must notify on `execve` and
`execveat`, and the monitor continues them only once `Attach` has
returned: no untrusted code runs before the process is a BPF member.
`ContainerProcessState.Pid` is the host pid, as `Attach` needs.

hallpass's own filter notifies on `execve` and `execveat` too. With
exec in `Config.Mediate` (the default), the monitor decides
them with the `OpExec` rules: the program's path is read and resolved
like a file's, plus the `#!` interpreters as the kernel will run them,
and an undecided one is asked about (see
[Programs](../how-it-works/exec.md)). Without it, the monitor continues
them (`Reason.Builtin` "execve"). Either way, in strict mode the
process is made a BPF member first. It costs one
notification round trip per exec: about 0.2 ms on the arm64 test VM,
where a fork and exec of `/bin/true` takes 1.1 ms. Go programs are multithreaded
and get SIGURG for preemption: `WAIT_KILLABLE_RECV` makes a received
notification immune to it; before it is received, the signal restarts
the syscall with a new notification (`-ERESTARTSYS`), which is decided
again. `TestGoExec` covers a Go program exec'ing
others from many goroutines while others spin, and `syscall.Exec` from a
multithreaded Go program; mediation must still hold after both.

## Deployment

The monitor must run in the host pid namespace (or an ancestor of the
workloads'): `SECCOMP_IOCTL_NOTIF_RECV` reports the task's pid in the
caller's pid namespace, and 0 when it is not visible there. `setns` cannot
move to a parent pid namespace. In Kubernetes: `hostPID: true`. A
`/host/proc` mount is enough for `/proc` reads, but not for this.

## Tracing

The API is enough for an strace-like client: subscribe with
`EventOptions{Decided: true}`, keep the rules from `Snapshot` and the
`Rules` events (to print a rule from its id), and print one line per
`Decided`, and per `Opened` and its `Closed`:

```
1234 openat   write   /home/u/proj/a.go           allow  rule 7 (allow tree /home/u/proj, implicit)
1234 openat   write   /home/u/.bashrc             ask -> deny (client tui)
1240 renameat rename  /tmp/x -> /home/u/proj/y    allow  rule 3, rule 7
1240 execve   -       /usr/bin/git                allow  builtin execve
```

Limits:

- Only syscalls the seccomp filter notifies: read-only opens and most
  syscalls never reach userspace. strace sees all of them.
- No return value: after Continue the monitor does not see the result.
- In strict mode, BPF decisions are reported for denies only, unless
  `lsm` logs allowed accesses too (`--log`), and without a rule id.
- `Decided` events can be dropped for a slow client (`Event.Dropped`).
