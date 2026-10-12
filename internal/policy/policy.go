// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy decides whether a resolved path access is allowed, denied, or
// needs to be asked. Precedence:
//
//  1. deny list (--deny) and paths denied during this session
//  2. workdir, allow list (--allow, built-in defaults) and folders allowed
//     during this session
//  3. otherwise Ask
//
// Known secret stores (~/.ssh, ~/.aws, ...) are not denied outright: they are
// asked about like anything else, but the prompt is flagged (see Warn) so an
// "allow" is a deliberate choice rather than a reflex.
package policy

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Decision is the outcome of evaluating an access.
type Decision int

const (
	Ask Decision = iota
	Allow
	Deny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "ask"
	}
}

// Engine holds the static rules and the decisions remembered for this session.
// It is safe for concurrent use.
type Engine struct {
	home    string
	workdir string
	tmpdir  string
	allow   []string
	deny    []string
	warn    []warnLoc

	mu            sync.Mutex
	sessionAllow  []grant             // folder prefixes ("Allow folder")
	sessionDenied map[string]struct{} // exact paths ("Never")
	proc          map[ProcKey]procRule
}

// warnLoc is a sensitive location: a write under path is still asked about,
// but the prompt is flagged with label (e.g. "SSH keys") in red.
type warnLoc struct {
	path  string
	label string
}

// ProcKey identifies a kind of write to another process's /proc directory:
// the file name and the target's command name, since pids change.
type ProcKey struct {
	Name string // e.g. "oom_score_adj"
	Comm string // target command, e.g. "bash"
}

type procRule struct {
	allow   bool
	expires time.Time // zero: rest of the session
}

// grant is an "Allow folder" answer; a zero expiry lasts for the session.
type grant struct {
	dir     string
	expires time.Time
}

// New builds an engine. All paths must be absolute; they are cleaned and, when
// they exist, symlink-resolved so they compare equal to resolved targets.
func New(home, workdir string, allow, deny []string) *Engine {
	home = canon(home)
	return &Engine{
		home:          home,
		workdir:       canon(workdir),
		allow:         canonAll(allow),
		deny:          canonAll(deny),
		warn:          sensitiveLocations(home),
		sessionDenied: map[string]struct{}{},
		proc:          map[ProcKey]procRule{},
	}
}

// SetTmpdir makes dir, the session's $TMPDIR, writable without asking. Call
// it before the engine is shared.
func (e *Engine) SetTmpdir(dir string) {
	e.tmpdir = canon(dir)
	e.allow = append(e.allow, e.tmpdir)
}

// sensitiveLabels maps a location under home to a human name for its secrets.
// Writes there are asked about like anywhere else, but the prompt is flagged
// so an "allow" is a deliberate choice, not a reflex. They are not denied
// outright: writing them is sometimes legitimate (ssh-keygen, gh auth login,
// aws configure), and a silent deny would hide the attempt instead of
// surfacing it.
var sensitiveLabels = map[string]string{
	".ssh":             "SSH keys",
	".gnupg":           "GnuPG keys",
	".aws":             "AWS credentials",
	".azure":           "Azure credentials",
	".config/gh":       "GitHub CLI credentials",
	".kube":            "Kubernetes credentials",
	".docker":          "Docker credentials",
	".netrc":           "network credentials",
	".git-credentials": "Git credentials",
}

// sensitiveLocations resolves sensitiveLabels against home, sorted by path.
func sensitiveLocations(home string) []warnLoc {
	out := make([]warnLoc, 0, len(sensitiveLabels))
	for name, label := range sensitiveLabels {
		out = append(out, warnLoc{path: canon(filepath.Join(home, name)), label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// Warn returns a short label when path is a known secret store (e.g. "SSH
// keys"), to flag the prompt. It returns "" otherwise.
func (e *Engine) Warn(path string) string {
	path = filepath.Clean(path)
	for _, w := range e.warn {
		if under(path, w.path) {
			return w.label
		}
	}
	return ""
}

// DefaultAllows returns devices that ordinary programs write to constantly
// and that hold nothing to protect. Shared scratch space (/tmp, /var/tmp,
// /dev/shm) is not in it: other programs read it too, so the user decides.
func DefaultAllows() []string {
	return []string{
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
		"/dev/tty", "/dev/ptmx", "/dev/pts",
	}
}

// Eval returns the decision for writing path.
func (e *Engine) Eval(path string) Decision {
	path = filepath.Clean(path)
	for _, d := range e.deny {
		if under(path, d) {
			return Deny
		}
	}
	e.mu.Lock()
	_, denied := e.sessionDenied[path]
	e.mu.Unlock()
	if denied {
		return Deny
	}
	if under(path, e.workdir) {
		return Allow
	}
	for _, a := range e.allow {
		if under(path, a) {
			return Allow
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for _, g := range e.sessionAllow {
		if under(path, g.dir) && (g.expires.IsZero() || now.Before(g.expires)) {
			return Allow
		}
	}
	return Ask
}

// AllowFolder allows everything under dir for the rest of the session.
func (e *Engine) AllowFolder(dir string) { e.AllowFolderFor(dir, 0) }

// AllowFolderFor allows everything under dir for ttl (0: rest of the session).
func (e *Engine) AllowFolderFor(dir string, ttl time.Duration) {
	g := grant{dir: filepath.Clean(dir)}
	if ttl > 0 {
		g.expires = time.Now().Add(ttl)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.sessionAllow {
		if r.dir == g.dir {
			if !r.expires.IsZero() && (g.expires.IsZero() || g.expires.After(r.expires)) {
				e.sessionAllow[i] = g
			}
			return
		}
	}
	e.sessionAllow = append(e.sessionAllow, g)
}

// DenyPath denies this exact path for the rest of the session, so a program
// retrying in a loop does not prompt again.
func (e *Engine) DenyPath(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessionDenied[filepath.Clean(path)] = struct{}{}
}

// EvalProc returns the decision for writing a file of another process's /proc
// directory, for a process outside the sandbox.
func (e *Engine) EvalProc(k ProcKey) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.proc[k]
	if !ok || (!r.expires.IsZero() && time.Now().After(r.expires)) {
		return Ask
	}
	if r.allow {
		return Allow
	}
	return Deny
}

// AllowProcFor allows k for ttl (0: rest of the session).
func (e *Engine) AllowProcFor(k ProcKey, ttl time.Duration) {
	r := procRule{allow: true}
	if ttl > 0 {
		r.expires = time.Now().Add(ttl)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if old, ok := e.proc[k]; ok && old.allow && old.expires.IsZero() {
		return // never shrink a session grant
	}
	e.proc[k] = r
}

// DenyProc denies k for the rest of the session.
func (e *Engine) DenyProc(k ProcKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proc[k] = procRule{}
}

// Rule is a path rule in the form strict mode's kernel enforcement takes:
// Path and, with Tree, everything below it.
type Rule struct {
	Path    string
	Tree    bool
	Deny    bool
	Expires time.Time // zero: rest of the session
}

// ProcRule is a decision on a ProcKey.
type ProcRule struct {
	ProcKey
	Deny    bool
	Expires time.Time
}

// Rules returns the decisions Eval takes without asking, as rules; anything
// they do not allow is to be asked about. Deny rules win over allow rules.
func (e *Engine) Rules() []Rule {
	var rs []Rule
	for _, d := range e.deny {
		rs = append(rs, Rule{Path: d, Tree: true, Deny: true})
	}
	rs = append(rs, Rule{Path: e.workdir, Tree: true})
	for _, a := range e.allow {
		rs = append(rs, Rule{Path: a, Tree: true})
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for p := range e.sessionDenied {
		rs = append(rs, Rule{Path: p, Deny: true})
	}
	now := time.Now()
	for _, g := range e.sessionAllow {
		if g.expires.IsZero() || now.Before(g.expires) {
			rs = append(rs, Rule{Path: g.dir, Tree: true, Expires: g.expires})
		}
	}
	return rs
}

// ProcRules returns the remembered decisions on other processes' /proc files.
func (e *Engine) ProcRules() []ProcRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	var rs []ProcRule
	now := time.Now()
	for k, r := range e.proc {
		if r.expires.IsZero() || now.Before(r.expires) {
			rs = append(rs, ProcRule{ProcKey: k, Deny: !r.allow, Expires: r.expires})
		}
	}
	return rs
}

// Describe returns the rules in effect, one per line, for people: denials
// first (they win), then what is writable without asking. Everything else
// is asked.
func (e *Engine) Describe() []string {
	deny, allow := e.Summary()
	out := []string{"Denied (wins over allowed):"}
	for _, s := range deny {
		out = append(out, "  "+s)
	}
	out = append(out, "Writable without asking:")
	for _, s := range allow {
		out = append(out, "  "+s)
	}
	if len(e.warn) > 0 {
		out = append(out, "Asked, and flagged as a secret store:")
		for _, w := range e.warn {
			out = append(out, "  "+e.short(w.path)+" ("+w.label+")")
		}
	}
	return append(out, "Anything else is asked. A folder rule covers everything below it.")
}

// short renders p relative to home with a leading ~ when possible.
func (e *Engine) short(p string) string {
	if under(p, e.home) {
		return "~" + strings.TrimPrefix(p, e.home)
	}
	return p
}

// Summary returns the denied and the allowed items, described for people.
func (e *Engine) Summary() (deny, allow []string) {
	short := e.short
	for _, r := range e.Rules() {
		s := short(r.Path)
		if !r.Tree {
			s += " (this path only)"
		}
		if !r.Expires.IsZero() {
			s += " (until " + r.Expires.Format("15:04:05") + ")"
		}
		if r.Path == e.workdir {
			s += " (project)"
		}
		if r.Path == e.tmpdir {
			s += " ($TMPDIR, removed at exit if empty)"
		}
		if r.Deny {
			deny = append(deny, s)
		} else {
			allow = append(allow, s)
		}
	}
	for _, r := range e.ProcRules() {
		s := "/proc/<pid>/" + r.Name + " of " + r.Comm + " processes"
		if !r.Expires.IsZero() {
			s += " (until " + r.Expires.Format("15:04:05") + ")"
		}
		if r.Deny {
			deny = append(deny, s)
		} else {
			allow = append(allow, s)
		}
	}
	return deny, allow
}

// FolderFor returns the folder offered by "Allow folder" for path, or "" when
// no folder is safe to offer. The folder is the tool's top-level directory
// rather than the immediate parent, so a cache with hundreds of subdirectories
// (e.g. ~/.cache/go-build/ab/...) is one prompt, not hundreds:
//
//	~/src/x/y/file           -> ~/src
//	~/.cache/go-build/ab/f   -> ~/.cache/go-build
//	~/.local/share/app/f     -> ~/.local/share/app
//	/opt/tool/lib/f          -> /opt/tool
//
// It never offers $HOME itself, /, or a folder containing a denied path.
func (e *Engine) FolderFor(path string) string {
	dir := filepath.Dir(filepath.Clean(path))
	var folder string
	if under(dir, e.home) && dir != e.home {
		rel, _ := filepath.Rel(e.home, dir)
		c := strings.Split(rel, "/")
		n := 1
		if strings.HasPrefix(c[0], ".") {
			n = 2
			if c[0] == ".local" {
				n = 3
			}
		}
		if n > len(c) {
			n = len(c)
		}
		folder = filepath.Join(append([]string{e.home}, c[:n]...)...)
	} else if !under(dir, e.home) && dir != "/" {
		c := strings.Split(strings.TrimPrefix(dir, "/"), "/")
		n := min(2, len(c))
		folder = "/" + filepath.Join(c[:n]...)
	}
	if folder == "" || under(e.home, folder) {
		return ""
	}
	for _, d := range e.deny {
		if under(d, folder) {
			// Offering it would look like it covers the secret.
			return ""
		}
	}
	for _, w := range e.warn {
		if under(w.path, folder) && w.path != folder {
			// A broad folder must not silently swallow a flagged secret
			// store nested under it (e.g. ~/.config over ~/.config/gh).
			return ""
		}
	}
	return folder
}

func canon(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func canonAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p != "" {
			out = append(out, canon(p))
		}
	}
	return out
}

// under reports whether path is prefix or lies beneath it, on a component
// boundary (/foo does not match /foobar).
func under(path, prefix string) bool {
	if path == prefix || prefix == "/" {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
