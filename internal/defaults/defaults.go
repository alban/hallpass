// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package defaults is hallpass's policy, as monitor rules: the project
// directory, $TMPDIR, harmless devices and --allow-path are writable,
// --deny-path is denied, --ask-path is asked even inside them, and
// anything else is asked. It also has what prompts need to offer good
// answers (FolderFor, Warn) and to describe the rules.
//
// Known secret stores (~/.ssh, ~/.aws, ...) are not denied outright: they are
// asked about like anything else, but the prompt is flagged (see Warn) so an
// "allow" is a deliberate choice rather than a reflex.
package defaults

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/alban/hallpass/internal/programs"
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
	// ask are trees asked about even inside an allowed one (--ask-path).
	ask []string
	// ownListeners allows connections to listeners started inside the
	// sandbox.
	ownListeners bool
	// netAllow, netDeny and netAsk are network destinations
	// (--allow-net, --deny-net, --ask-net).
	netAllow, netDeny, netAsk []rules.ObjectMatch
	// execAllow and execDeny are programs (--allow-exec, --deny-exec).
	execAllow, execDeny []rules.PathMatch
	// groups are the program groups, resolved (SetGroups); execGroups the
	// names of those allowed (--allow-exec=@name).
	groups     []programs.Group
	execGroups []string
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

// AskPath asks about the tree under path, absolute, even when a less
// specific allow covers it (~/.config/gh inside an allowed ~/.config); a
// more specific allow still allows.
func (d *Defaults) AskPath(path string) {
	if path != "" {
		d.ask = append(d.ask, d.canon(path))
	}
}

// AllowNet allows connections and sends to m, a network match
// (rules.ParseNet).
func (d *Defaults) AllowNet(m rules.ObjectMatch) { d.netAllow = append(d.netAllow, m) }

// DenyNet denies connections and sends to m, a network match.
func (d *Defaults) DenyNet(m rules.ObjectMatch) { d.netDeny = append(d.netDeny, m) }

// AskNet asks about connections and sends to m, a network match, even
// when a less specific allow covers them.
func (d *Defaults) AskNet(m rules.ObjectMatch) { d.netAsk = append(d.netAsk, m) }

// AllowExec lets the program at path run without asking, or with tree
// every program below path. path is absolute; it is resolved like the
// policy's paths.
func (d *Defaults) AllowExec(path string, tree bool) {
	d.execAllow = addProgram(d.execAllow, rules.PathMatch{Path: d.canon(path), Tree: tree})
}

// SetGroups sets the program groups, resolved as the sandbox finds them:
// prompts offer a program's group (Group), AllowGroup allows one.
func (d *Defaults) SetGroups(gs []programs.Group) {
	d.groups = make([]programs.Group, len(gs))
	for i, g := range gs {
		d.groups[i] = programs.Group{Name: g.Name}
		for _, m := range g.Members {
			d.groups[i].Members = append(d.groups[i].Members, d.canon(m))
		}
	}
}

// AllowGroup lets the programs of group name (SetGroups) run without
// asking.
func (d *Defaults) AllowGroup(name string) {
	for _, n := range d.execGroups {
		if n == name {
			return
		}
	}
	d.execGroups = append(d.execGroups, name)
}

// group returns the group named name, resolved, and whether it is known.
func (d *Defaults) group(name string) (programs.Group, bool) {
	for _, g := range d.groups {
		if g.Name == name {
			return g, true
		}
	}
	return programs.Group{Name: name}, false
}

// Group returns the first group program path belongs to, ok false for
// none.
func (d *Defaults) Group(path string) (g programs.Group, ok bool) {
	for _, g := range d.groups {
		for _, m := range g.Members {
			if m == path {
				return g, true
			}
		}
	}
	return programs.Group{}, false
}

// DenyExec denies running the program at path, or with tree every
// program below path.
func (d *Defaults) DenyExec(path string, tree bool) {
	d.execDeny = addProgram(d.execDeny, rules.PathMatch{Path: d.canon(path), Tree: tree})
}

// addProgram appends m to l unless it is there already: several names
// often resolve to one program (sh and dash).
func addProgram(l []rules.PathMatch, m rules.PathMatch) []rules.PathMatch {
	for _, o := range l {
		if o.Path == m.Path && o.Tree == m.Tree {
			return l
		}
	}
	return append(l, m)
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
	for _, p := range d.ask {
		add(p, rules.Ask)
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
	for _, m := range d.netAsk {
		rs = append(rs, rules.Rule{Ops: rules.OpNet, Object: m, Verdict: rules.Ask, Set: Set})
	}
	for _, p := range d.execDeny {
		rs = append(rs, rules.Rule{Ops: rules.OpExec, Object: rules.ObjectMatch{Path: &p}, Verdict: rules.Deny, Set: Set})
	}
	for _, p := range d.execAllow {
		rs = append(rs, rules.Rule{Ops: rules.OpExec, Object: rules.ObjectMatch{Path: &p}, Verdict: rules.Allow, Set: Set})
	}
	for _, name := range d.execGroups {
		g, _ := d.group(name)
		rs = append(rs, GroupRules(g, rs, Set)...)
	}
	return rs
}

// GroupRules returns the rules allowing the programs of group g, labelled
// with its name, in set, but for the programs rs already allow for good.
func GroupRules(g programs.Group, rs []rules.Rule, set string) []rules.Rule {
	allowed := map[string]bool{}
	for _, r := range rs {
		if p := r.Object.Path; p != nil && r.Ops == rules.OpExec && r.Verdict == rules.Allow && !p.Tree && len(p.Args) == 0 && r.Expires.IsZero() {
			allowed[p.Path] = true
		}
	}
	var out []rules.Rule
	for _, m := range g.Members {
		if allowed[m] {
			continue
		}
		allowed[m] = true
		out = append(out, rules.Rule{Ops: rules.OpExec, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: m}}, Verdict: rules.Allow, Label: g.Name, Set: set})
	}
	return out
}

// Describe returns rs, one per line, for people: denials first (they
// win), then what is writable without asking, the exceptions asked
// about, and the programs that run without asking. Everything else is
// asked.
func (d *Defaults) Describe(rs []rules.Rule) []string {
	deny, allow, ask, run := d.Summary(rs)
	out := []string{"Denied (wins over allowed):"}
	for _, s := range deny {
		out = append(out, "  "+s)
	}
	out = append(out, "Allowed without asking:")
	for _, s := range allow {
		out = append(out, "  "+s)
	}
	if len(ask) > 0 {
		out = append(out, "Asked, even inside what is allowed:")
		for _, s := range ask {
			out = append(out, "  "+s)
		}
	}
	if len(run) > 0 {
		out = append(out, "Programs run without asking:")
		for _, s := range run {
			out = append(out, "  "+s)
		}
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

// Summary returns the denied, the allowed and the asked items of rs,
// described for people; run is the programs allowed to run, a group
// (rules labelled with its name) on one line with its member count.
func (d *Defaults) Summary(rs []rules.Rule) (deny, allow, ask, run []string) {
	groups := map[string]bool{}
	for _, r := range rs {
		var s string
		switch o := r.Object; {
		case o.Path != nil && r.Ops == rules.OpExec:
			if strings.HasPrefix(r.Label, "@") && r.Verdict == rules.Allow {
				if !groups[r.Label] {
					groups[r.Label] = true
					run = append(run, d.groupLine(r.Label, rs))
				}
				continue
			}
			s = d.Short(o.Path.Path)
			if o.Path.Tree {
				s += " (and every program below)"
			}
			if r.Verdict != rules.Allow {
				s = "exec: " + s
			}
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
		if r.Label != "" && r.Verdict == rules.Deny {
			s += " (" + r.Label + ")"
		}
		if p := r.Object.Path; p != nil && r.Set == Set && r.Ops != rules.OpExec {
			if p.Path == d.workdir {
				s += " (project)"
			}
			if p.Path == d.tmpdir {
				s += " ($TMPDIR, removed at exit if empty)"
			}
		}
		switch {
		case r.Verdict == rules.Deny:
			deny = append(deny, s)
		case r.Verdict == rules.Allow && r.Ops == rules.OpExec:
			run = append(run, s)
		case r.Verdict == rules.Allow:
			allow = append(allow, s)
		case r.Verdict == rules.Ask:
			ask = append(ask, s)
		}
	}
	return deny, allow, ask, run
}

// groupLine describes group name, allowed by rules labelled with it in rs.
func (d *Defaults) groupLine(name string, rs []rules.Rule) string {
	if g, ok := d.group(name); ok {
		return g.String()
	}
	g := programs.Group{Name: name}
	for _, r := range rs {
		if r.Label == name && r.Ops == rules.OpExec && r.Object.Path != nil {
			g.Members = append(g.Members, r.Object.Path.Path)
		}
	}
	return g.String()
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
