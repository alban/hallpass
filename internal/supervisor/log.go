// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import "time"

type logEntry struct {
	Time     string `json:"time"`
	PID      uint32 `json:"pid"`
	Exe      string `json:"exe,omitempty"`
	Syscall  string `json:"syscall"`
	Path     string `json:"path,omitempty"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func (s *session) log(e logEntry) {
	if s.logEnc == nil {
		return
	}
	e.Time = time.Now().Format(time.RFC3339Nano)
	s.logMu.Lock()
	_ = s.logEnc.Encode(e)
	s.logMu.Unlock()
}
