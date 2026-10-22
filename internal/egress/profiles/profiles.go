// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package profiles is the knowledge of tools, as data: for each
// credential, the hosts it is for, where its value comes from, the
// environment that gives the tool its placeholder, and the variables to
// keep from the sandbox. hallpass's proxy (internal/egress) knows no
// tool; a new tool is a profile file, embedded here or in the user's
// ~/.config/hallpass/credentials.d/.
//
// A plain name ("gh") is a built-in profile, and only that; "config:NAME"
// is the user's own NAME.toml (hallpass-node: its ConfigMap's), and only
// that: a profile of the user's never shadows a built-in one, and a
// built-in one added later never takes the place of the user's.
//
// Profiles are written in a subset of TOML: one "key = value" per line,
// values a "string", an integer (digits), an array of strings, or an
// inline table of strings.
package profiles

import (
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/secrets"
)

//go:embed data/*.toml
var embedded embed.FS

// Profile is how a tool's credential is brokered.
type Profile struct {
	// Name is the profile's name; Find sets it to the name it was
	// asked for: "gh", or "config:ghe" for the user's own.
	Name   string
	Hosts  []string // the hosts the value goes to; "*.example.com" for the names below
	Source secrets.Source
	// Mask: the sandbox gets a placeholder, the proxy puts the value on
	// the wire. Otherwise ("pass") the sandbox gets the value itself, for
	// a credential already scoped (short-lived, least privilege).
	Mask  bool
	Shape Shape             // the placeholder's
	Env   map[string]string // set in the sandbox; "{placeholder}" is replaced
	Strip []string          // removed from the sandbox's environment
}

// ConfigPrefix names a profile of the user's own: "config:ghe".
const ConfigPrefix = "config:"

// Load returns profile ref: built in ("gh"), or the user's own in dir
// ("config:ghe" is dir/ghe.toml). Neither falls back to the other.
func Load(dir, ref string) (*Profile, error) {
	var config func(string) ([]byte, string, error)
	if dir != "" {
		config = func(name string) ([]byte, string, error) {
			where := filepath.Join(dir, name+".toml")
			b, err := os.ReadFile(where)
			return b, where, err
		}
	}
	return Find(ref, config)
}

// Find returns profile ref: built in ("gh"), or "config:NAME", which
// config returns: the profile's text and where it is, for the errors,
// or an error wrapping os.ErrNotExist when it has none. Neither falls
// back to the other.
func Find(ref string, config func(name string) (b []byte, where string, err error)) (*Profile, error) {
	name, isConfig := strings.CutPrefix(ref, ConfigPrefix)
	if !ValidName(name) {
		return nil, fmt.Errorf("credential %q: not a profile name (NAME, or config:NAME)", ref)
	}
	var b []byte
	var where string
	var err error
	if isConfig {
		if config == nil {
			return nil, fmt.Errorf("credential %q: no profiles of your own here", ref)
		}
		b, where, err = config(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("credential %q: no %s%s", ref, where, builtinHint(name))
		}
		if err != nil {
			return nil, err
		}
	} else {
		where = "built-in " + name
		b, err = embedded.ReadFile("data/" + name + ".toml")
		if err != nil {
			return nil, fmt.Errorf("credential %q: no built-in profile %s (built-in: %s); a profile file of your own is named \"config:%s\"", ref, name, strings.Join(Builtin(), ", "), name)
		}
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	if p.Name != name {
		return nil, fmt.Errorf("%s: name %q, want %q", where, p.Name, name)
	}
	p.Name = ref
	return p, nil
}

// builtinHint names the built-in profile name, if there is one, for the
// error of a missing config:name.
func builtinHint(name string) string {
	if slices.Contains(Builtin(), name) {
		return fmt.Sprintf(" (the built-in profile is named %q)", name)
	}
	return ""
}

// Builtin returns the names of the embedded profiles.
func Builtin() []string {
	es, _ := embedded.ReadDir("data")
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(e.Name(), ".toml"))
	}
	return out
}

// ValidName reports whether s can name a profile: lower-case letters,
// digits, - and _.
func ValidName(s string) bool {
	return s != "" && len(s) <= 64 && !strings.ContainsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	})
}

// ValidRef reports whether s can refer to a profile: NAME, or
// config:NAME.
func ValidRef(s string) bool {
	return ValidName(strings.TrimPrefix(s, ConfigPrefix))
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Parse reads a profile.
func Parse(b []byte) (*Profile, error) {
	kv, err := parseTOML(string(b))
	if err != nil {
		return nil, err
	}
	p := &Profile{Mask: true}
	str := func(k string) (string, error) {
		v, ok := kv[k]
		if !ok {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("%s: want a string", k)
		}
		return s, nil
	}
	list := func(k string) ([]string, error) {
		v, ok := kv[k]
		if !ok {
			return nil, nil
		}
		l, ok := v.([]string)
		if !ok {
			return nil, fmt.Errorf("%s: want an array of strings", k)
		}
		return l, nil
	}
	for k := range kv {
		if !slices.Contains([]string{"name", "hosts", "source", "scheme", "mode", "prefix", "chars", "length", "env", "strip"}, k) {
			return nil, fmt.Errorf("unknown key %q", k)
		}
	}
	if p.Name, err = str("name"); err != nil {
		return nil, err
	}
	if !ValidName(p.Name) {
		return nil, fmt.Errorf("name %q: want a lowercase word", p.Name)
	}
	if p.Hosts, err = list("hosts"); err != nil {
		return nil, err
	}
	if len(p.Hosts) == 0 {
		return nil, errors.New("hosts: none")
	}
	src, err := str("source")
	if err != nil {
		return nil, err
	}
	if p.Source, err = secrets.Parse(src); err != nil {
		return nil, err
	}
	switch mode, _ := str("mode"); mode {
	case "", "mask":
	case "pass":
		p.Mask = false
	default:
		return nil, fmt.Errorf("mode %q: want mask or pass", mode)
	}
	switch scheme, _ := str("scheme"); scheme {
	// The proxy replaces placeholders in header values and inside Basic
	// authorization: "header" and "basic" are both that.
	case "", "header", "basic":
	default:
		return nil, fmt.Errorf("scheme %q: want header or basic (sigv4 is not supported)", scheme)
	}
	p.Shape = DefaultShape
	if _, ok := kv["prefix"]; ok {
		if p.Shape.Prefix, err = str("prefix"); err != nil {
			return nil, err
		}
	}
	if _, ok := kv["chars"]; ok {
		if p.Shape.Chars, err = str("chars"); err != nil {
			return nil, err
		}
	}
	if v, ok := kv["length"]; ok {
		if p.Shape.Length, ok = v.(int); !ok {
			return nil, errors.New("length: want an integer")
		}
	}
	if _, err := p.Shape.Placeholder(); err != nil {
		return nil, err
	}
	if v, ok := kv["env"]; ok {
		m, ok := v.(map[string]string)
		if !ok {
			return nil, errors.New("env: want an inline table of strings")
		}
		p.Env = m
	}
	if p.Strip, err = list("strip"); err != nil {
		return nil, err
	}
	for k := range p.Env {
		if !envName.MatchString(k) {
			return nil, fmt.Errorf("env: %q is not a variable name", k)
		}
	}
	for _, k := range p.Strip {
		if !envName.MatchString(k) {
			return nil, fmt.Errorf("strip: %q is not a variable name", k)
		}
	}
	return p, nil
}

// Shape is what a placeholder looks like, in case a tool checks the
// format of its token: Prefix, then Length random characters of Chars.
// A profile sets it with the keys prefix, chars and length; each one it
// does not set is DefaultShape's.
type Shape struct {
	Prefix string // literal: letters, digits, _ and -
	Chars  string // letters, digits, _ and -, and ranges: "A-Za-z0-9"
	Length int
}

// DefaultShape is "hallpass_" and 32 lower-case letters and digits.
var DefaultShape = Shape{Prefix: "hallpass_", Chars: "a-z0-9", Length: 32}

var (
	prefixRE = regexp.MustCompile(`^[A-Za-z0-9_\-]*$`)
	charsRE  = regexp.MustCompile(`^(?:[A-Za-z0-9]-[A-Za-z0-9]|[A-Za-z0-9_\-])+$`)
)

// Placeholder returns a random value of shape s, e.g. "ghp_" and 36
// characters of "A-Za-z0-9".
func (s Shape) Placeholder() (string, error) {
	if !prefixRE.MatchString(s.Prefix) {
		return "", fmt.Errorf("prefix %q: want letters, digits, _ and -", s.Prefix)
	}
	if !charsRE.MatchString(s.Chars) {
		return "", fmt.Errorf("chars %q: want letters, digits, _, - and ranges (a-z)", s.Chars)
	}
	n := s.Length
	if n < 16 || n > 256 {
		return "", fmt.Errorf("length %d: want 16 to 256 random characters", n)
	}
	var class []byte
	add := func(x byte) {
		if !slices.Contains(class, x) {
			class = append(class, x)
		}
	}
	c := s.Chars
	for i := 0; i < len(c); i++ {
		if i+2 < len(c) && c[i+1] == '-' {
			if c[i] > c[i+2] {
				return "", fmt.Errorf("chars %q: range %s backwards", c, c[i:i+3])
			}
			for x := c[i]; x <= c[i+2]; x++ {
				add(x)
			}
			i += 2
			continue
		}
		add(c[i])
	}
	// A placeholder must not be guessable: another session's, or a
	// value the sandbox makes up to get it replaced.
	if bits := float64(n) * math.Log2(float64(len(class))); bits < 96 {
		return "", fmt.Errorf("chars %q, length %d: %.0f random bits, want 96 or more", c, n, bits)
	}
	b := []byte(s.Prefix)
	for range n {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(class))))
		if err != nil {
			return "", err
		}
		b = append(b, class[k.Int64()])
	}
	return string(b), nil
}

// parseTOML reads the subset of TOML of profiles.
func parseTOML(s string) (map[string]any, error) {
	out := map[string]any{}
	for i, line := range strings.Split(s, "\n") {
		fail := func(err error) error { return fmt.Errorf("line %d: %w", i+1, err) }
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fail(errors.New("want key = value"))
		}
		k = strings.TrimSpace(k)
		if _, dup := out[k]; dup {
			return nil, fail(fmt.Errorf("%s twice", k))
		}
		val, rest, err := parseValue(strings.TrimSpace(v))
		if err != nil {
			return nil, fail(err)
		}
		if rest = strings.TrimSpace(rest); rest != "" && rest[0] != '#' {
			return nil, fail(fmt.Errorf("unexpected %q", rest))
		}
		out[k] = val
	}
	return out, nil
}

func parseValue(s string) (any, string, error) {
	switch {
	case s != "" && s[0] >= '0' && s[0] <= '9':
		end := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
		if end < 0 {
			end = len(s)
		}
		n, err := strconv.Atoi(s[:end])
		if err != nil {
			return nil, "", fmt.Errorf("%q: %w", s[:end], err)
		}
		return n, s[end:], nil
	case strings.HasPrefix(s, `"`):
		return parseString(s)
	case strings.HasPrefix(s, "["):
		var l []string
		s = strings.TrimSpace(s[1:])
		for !strings.HasPrefix(s, "]") {
			v, rest, err := parseString(s)
			if err != nil {
				return nil, "", err
			}
			l = append(l, v.(string))
			s = strings.TrimSpace(rest)
			if strings.HasPrefix(s, ",") {
				s = strings.TrimSpace(s[1:])
			} else if !strings.HasPrefix(s, "]") {
				return nil, "", errors.New("want , or ] in an array")
			}
		}
		return l, s[1:], nil
	case strings.HasPrefix(s, "{"):
		m := map[string]string{}
		s = strings.TrimSpace(s[1:])
		for !strings.HasPrefix(s, "}") {
			k, rest, ok := strings.Cut(s, "=")
			if !ok {
				return nil, "", errors.New("want key = value in an inline table")
			}
			v, rest, err := parseString(strings.TrimSpace(rest))
			if err != nil {
				return nil, "", err
			}
			m[strings.TrimSpace(k)] = v.(string)
			s = strings.TrimSpace(rest)
			if strings.HasPrefix(s, ",") {
				s = strings.TrimSpace(s[1:])
			} else if !strings.HasPrefix(s, "}") {
				return nil, "", errors.New("want , or } in an inline table")
			}
		}
		return m, s[1:], nil
	}
	return nil, "", fmt.Errorf("%q: want a string, an integer, an array or an inline table", s)
}

// parseString reads a basic string ("..." with \" and \\ escapes).
func parseString(s string) (any, string, error) {
	if !strings.HasPrefix(s, `"`) {
		return nil, "", fmt.Errorf("%q: want a string", s)
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			if i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			return nil, "", errors.New("only \\\" and \\\\ escapes")
		default:
			b.WriteByte(c)
		}
	}
	return nil, "", errors.New("unterminated string")
}

// Brokered is a credential ready for the proxy, and what the sandbox
// gets instead of its value.
type Brokered struct {
	Credential egress.Credential
	Env        []string // KEY=value set in the sandbox: the placeholder
	Strip      []string // variables removed from the sandbox
}

// Broker makes the credential of profile p with value: a placeholder of
// the profile's shape (mask), the environment naming it, the hosts.
func (p *Profile) Broker(value string) (*Brokered, error) {
	if strings.TrimSpace(value) == "" {
		// An empty value is in every header: every request to another
		// host would look like a leak.
		return nil, fmt.Errorf("credential %s: empty value", p.Name)
	}
	b := &Brokered{Credential: egress.Credential{Name: p.Name, Value: value}}
	shown := value
	if p.Mask {
		ph, err := p.Shape.Placeholder()
		if err != nil {
			return nil, err
		}
		b.Credential.Placeholder, shown = ph, ph
	}
	for _, h := range p.Hosts {
		host, suffix, err := rules.ParseHost(h)
		if err != nil {
			return nil, fmt.Errorf("credential %s: %w", p.Name, err)
		}
		b.Credential.Hosts = append(b.Credential.Hosts, egress.Host{Name: host, Suffix: suffix})
	}
	for _, k := range slices.Sorted(maps.Keys(p.Env)) {
		b.Env = append(b.Env, k+"="+strings.ReplaceAll(p.Env[k], "{placeholder}", shown))
	}
	b.Strip = append(b.Strip, p.Strip...)
	if p.Source.Kind == "env" {
		// The value's own variable never reaches the sandbox.
		b.Strip = append(b.Strip, p.Source.Arg)
	}
	return b, nil
}
