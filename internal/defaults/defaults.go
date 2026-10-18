// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package defaults is hallpass's policy, as monitor rules: the project
// directory, $TMPDIR, harmless devices and --allow are writable, --deny
// is denied, and anything else is asked. It also has what prompts need to
// offer good answers (FolderFor, Warn) and to describe the rules.
//
// Known secret stores (~/.ssh, ~/.aws, ...) are not denied outright: they are
// asked about like anything else, but the prompt is flagged (see Warn) so an
// "allow" is a deliberate choice rather than a reflex.
package defaults

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/alban/hallpass/internal/rules"
)

// Set is the rules.Rule.Set of the rules given by flags.
const Set = "implicit"

// Defaults is the policy of a session, before any answer.
type Defaults struct {
	canon   func(string) string
	home    string
	workdir string
	tmpdir  string
	allow   []string
	deny    []string
	warn    []warnLoc
	// ownListeners allows connections to listeners started inside the
	// sandbox.
	ownListeners bool
	// netAllow and netDeny are network destinations (--allow-net,
	// --deny-net).
	netAllow, netDeny []rules.ObjectMatch
}

// warnLoc is a sensitive location: a write under path is still asked about,
// but the prompt is flagged with label (e.g. "SSH keys") in red.
type warnLoc struct {
	path  string
	label string
}

// New builds the policy. All paths must be absolute; they are cleaned and,
// when they exist, symlink-resolved so they compare equal to resolved
// targets. An empty workdir grants no project directory (--no-implicit).
func New(home, workdir string, allow, deny []string) *Defaults {
	return build(canon, home, workdir, allow, deny)
}

// NewLexical is New for paths in another mount namespace (a container's):
// they are only cleaned, not symlink-resolved, since the symlinks of the
// caller's view of the filesystem do not apply to them.
func NewLexical(home, workdir string, allow, deny []string) *Defaults {
	return build(filepath.Clean, home, workdir, allow, deny)
}

func build(canon func(string) string, home, workdir string, allow, deny []string) *Defaults {
	home = canon(home)
	if workdir != "" {
		workdir = canon(workdir)
	}
	all := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, p := range in {
			if p != "" {
				out = append(out, canon(p))
			}
		}
		return out
	}
	return &Defaults{
		canon:   canon,
		home:    home,
		workdir: workdir,
		allow:   all(allow),
		deny:    all(deny),
		warn:    sensitiveLocations(canon, home),
	}
}

// SetTmpdir makes dir, the session's $TMPDIR, writable without asking.
func (d *Defaults) SetTmpdir(dir string) {
	d.tmpdir = d.canon(dir)
	d.allow = append(d.allow, d.tmpdir)
}

// AllowDevice makes a device path (e.g. the session's own terminal, /dev/pts/N)
// writable without asking.
func (d *Defaults) AllowDevice(path string) {
	if path != "" {
		d.allow = append(d.allow, d.canon(path))
	}
}

// AllowOwnListeners allows connections and sends to the loopback or unix
// listeners started inside the sandbox, when network is mediated.
func (d *Defaults) AllowOwnListeners() { d.ownListeners = true }

// AllowNet allows connections and sends to m, a network match
// (rules.ParseNet).
func (d *Defaults) AllowNet(m rules.ObjectMatch) { d.netAllow = append(d.netAllow, m) }

// DenyNet denies connections and sends to m, a network match.
func (d *Defaults) DenyNet(m rules.ObjectMatch) { d.netDeny = append(d.netDeny, m) }

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
func sensitiveLocations(canon func(string) string, home string) []warnLoc {
	out := make([]warnLoc, 0, len(sensitiveLabels))
	for name, label := range sensitiveLabels {
		out = append(out, warnLoc{path: canon(filepath.Join(home, name)), label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// Warn returns a short label when path is a known secret store (e.g. "SSH
// keys"), to flag the prompt. It returns "" otherwise.
func (d *Defaults) Warn(path string) string {
	path = filepath.Clean(path)
	for _, w := range d.warn {
		if rules.Under(path, w.path) {
			return w.label
		}
	}
	return ""
}

// DefaultAllows returns devices that ordinary programs write to constantly
// and that hold nothing to protect. Shared scratch space (/tmp, /var/tmp,
// /dev/shm) is not in it: other programs read it too, so the user decides.
// /dev/pts as a whole is not in it either: /dev/pts/N is another session's
// terminal, writable for escape-sequence injection or fake prompts. The
// session's own terminal is allowed separately (see TTYAllows).
func DefaultAllows() []string {
	return []string{
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
		"/dev/ptmx",
	}
}

// TTYAllows returns the session's own terminal: /dev/tty, which always
// names the opener's controlling terminal, and pts, the program's
// /dev/pts/N (empty when hallpass gives it no terminal).
func TTYAllows(pts string) []string {
	out := []string{"/dev/tty"}
	if pts != "" {
		out = append(out, pts)
	}
	return out
}

// Rules returns the policy as rules, in Set: deny trees win over allow
// trees, and anything they do not decide is asked.
func (d *Defaults) Rules() []rules.Rule {
	var rs []rules.Rule
	add := func(path string, v rules.Verdict) {
		rs = append(rs, rules.Rule{
			Ops:     rules.OpAll,
			Object:  rules.ObjectMatch{Path: &rules.PathMatch{Path: path, Tree: true}},
			Verdict: v,
			Set:     Set,
		})
	}
	for _, p := range d.deny {
		add(p, rules.Deny)
	}
	if d.workdir != "" {
		add(d.workdir, rules.Allow)
	}
	for _, p := range d.allow {
		add(p, rules.Allow)
	}
	if d.ownListeners {
		rs = append(rs, rules.Rule{
			Ops:     rules.OpNet,
			Object:  rules.ObjectMatch{OwnListener: true},
			Verdict: rules.Allow,
			Set:     Set,
		})
	}
	for _, m := range d.netDeny {
		rs = append(rs, rules.Rule{Ops: rules.OpNet, Object: m, Verdict: rules.Deny, Set: Set})
	}
	for _, m := range d.netAllow {
		rs = append(rs, rules.Rule{Ops: rules.OpNet, Object: m, Verdict: rules.Allow, Set: Set})
	}
	return rs
}

// Describe returns rs, one per line, for people: denials first (they
// win), then what is writable without asking. Everything else is asked.
func (d *Defaults) Describe(rs []rules.Rule) []string {
	deny, allow := d.Summary(rs)
	out := []string{"Denied (wins over allowed):"}
	for _, s := range deny {
		out = append(out, "  "+s)
	}
	out = append(out, "Allowed without asking:")
	for _, s := range allow {
		out = append(out, "  "+s)
	}
	if len(d.warn) > 0 {
		out = append(out, "Asked, and flagged as a secret store:")
		for _, w := range d.warn {
			out = append(out, "  "+d.Short(w.path)+" ("+w.label+")")
		}
	}
	return append(out, "Anything else is asked. A folder rule covers everything below it.")
}

// Short renders p relative to home with a leading ~ when possible.
func (d *Defaults) Short(p string) string {
	if rules.Under(p, d.home) {
		return "~" + strings.TrimPrefix(p, d.home)
	}
	return p
}

// Summary returns the denied and the allowed items of rs, described for
// people.
func (d *Defaults) Summary(rs []rules.Rule) (deny, allow []string) {
	for _, r := range rs {
		var s string
		switch o := r.Object; {
		case o.Path != nil:
			s = d.Short(o.Path.Path)
			if !o.Path.Tree {
				s += " (this path only)"
			}
		case o.Proc != nil:
			s = "/proc/<pid>/" + o.Proc.Name + " of " + o.Proc.Comm + " processes"
		case o.Unknown:
			s = "unknown paths"
		case o.OwnListener:
			s = "network: listeners started inside the sandbox"
		case o.IsNet():
			s = "network: " + o.NetString()
		}
		if !r.Expires.IsZero() {
			s += " (until " + r.Expires.Format("15:04:05") + ")"
		}
		if p := r.Object.Path; p != nil && r.Set == Set {
			if p.Path == d.workdir {
				s += " (project)"
			}
			if p.Path == d.tmpdir {
				s += " ($TMPDIR, removed at exit if empty)"
			}
		}
		switch r.Verdict {
		case rules.Deny:
			deny = append(deny, s)
		case rules.Allow:
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
func (d *Defaults) FolderFor(path string) string {
	dir := filepath.Dir(filepath.Clean(path))
	var folder string
	if rules.Under(dir, d.home) && dir != d.home {
		rel, _ := filepath.Rel(d.home, dir)
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
		folder = filepath.Join(append([]string{d.home}, c[:n]...)...)
	} else if !rules.Under(dir, d.home) && dir != "/" {
		c := strings.Split(strings.TrimPrefix(dir, "/"), "/")
		n := min(2, len(c))
		folder = "/" + filepath.Join(c[:n]...)
	}
	if folder == "" || rules.Under(d.home, folder) {
		return ""
	}
	for _, p := range d.deny {
		if rules.Under(p, folder) {
			// Offering it would look like it covers the secret.
			return ""
		}
	}
	for _, w := range d.warn {
		if rules.Under(w.path, folder) && w.path != folder {
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
