// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package secrets reads the values of credentials, for the proxy to put
// on the wire in place of the placeholders the sandbox holds. hallpass
// brokers secrets, it does not store them: a source says where a value
// lives, and the value stays in the supervisor's memory for the session.
package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Source is where a credential's value comes from.
type Source struct {
	Kind string // "env", "file" or "cmd"
	Arg  string // the variable, the file, the command line
}

// Parse reads a source: "env:NAME" (taken from hallpass's environment,
// and removed from the sandbox's), "file:PATH" (its content, without the
// final newline; "~/" is $HOME) or "cmd:COMMAND ARGS..." (its output,
// run by hallpass outside the sandbox, without a shell).
func Parse(s string) (Source, error) {
	kind, arg, ok := strings.Cut(s, ":")
	if !ok || arg == "" {
		return Source{}, fmt.Errorf("source %q: want env:NAME, file:PATH or cmd:COMMAND", s)
	}
	switch kind {
	case "env", "file", "cmd":
		return Source{Kind: kind, Arg: arg}, nil
	}
	return Source{}, fmt.Errorf("source %q: want env:NAME, file:PATH or cmd:COMMAND", s)
}

func (s Source) String() string { return s.Kind + ":" + s.Arg }

// cmdTimeout bounds a cmd: source (gh auth token, op read...).
const cmdTimeout = 30 * time.Second

// maxValue bounds a value.
const maxValue = 64 << 10

// Get returns the value of s: one line, no surrounding blanks. An empty
// value is an error: a credential that injects nothing must not look
// like it works.
func (s Source) Get(ctx context.Context) (string, error) {
	var b []byte
	var err error
	switch s.Kind {
	case "env":
		b = []byte(os.Getenv(s.Arg))
	case "file":
		p := s.Arg
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			home, herr := os.UserHomeDir()
			if herr != nil {
				return "", herr
			}
			p = home + "/" + rest
		}
		b, err = os.ReadFile(p)
	case "cmd":
		args := strings.Fields(s.Arg)
		ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if b, err = cmd.Output(); err != nil {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
	default:
		return "", fmt.Errorf("source %s: unknown kind", s)
	}
	if err != nil {
		return "", fmt.Errorf("source %s: %w", s, err)
	}
	if len(b) > maxValue {
		return "", fmt.Errorf("source %s: more than %d bytes", s, maxValue)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("source %s: empty", s)
	}
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", errors.New("source " + s.String() + ": more than one line")
	}
	return v, nil
}
