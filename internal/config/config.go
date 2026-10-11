// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package config reads and writes hallpass's settings file, a list of
// "key = value" lines ('#' starts a comment). The sandbox must never be able
// to write it: callers add Dir to the denied paths.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Dir returns hallpass's configuration directory.
func Dir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "hallpass"), nil
}

// Config is the content of a settings file.
type Config struct {
	path   string
	values map[string]string
}

// Load reads the settings file in dir; a missing file is empty.
func Load(dir string) (*Config, error) {
	c := &Config{path: filepath.Join(dir, "config"), values: map[string]string{}}
	f, err := os.Open(c.path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: want key = value", c.path, n)
		}
		c.values[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return c, sc.Err()
}

// Path returns the settings file's path.
func (c *Config) Path() string { return c.path }

// Get returns the value of key, "" when unset.
func (c *Config) Get(key string) string { return c.values[key] }

// Set changes key and rewrites the file (comments are not kept).
func (c *Config) Set(key, value string) error {
	c.values[key] = value
	keys := make([]string, 0, len(c.values))
	for k := range c.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# hallpass settings\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, c.values[k])
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path)
}
