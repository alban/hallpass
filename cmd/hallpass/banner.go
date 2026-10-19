// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/alban/hallpass/internal/ui"
)

// banner is the line printed on stderr when the sandbox starts: the mode,
// the session (the supervisor's pid, as `hallpass answer` and `hallpass
// web` show it) and where its requests are answered. menu: the terminal
// overlay, with its Ctrl-] menu, is on.
func banner(strict bool, pid int, asker ui.Asker, menu bool) string {
	mode := "lite"
	if strict {
		mode = "strict"
	}
	s := fmt.Sprintf("hallpass: sandbox started (%s, session %d).", mode, pid)
	const web = "run 'hallpass web' in another terminal for the full UI."
	switch asker.(type) {
	case ui.AutoDeny:
		return s + " Requests are denied without asking (--ask=deny)."
	case ui.AutoAllow:
		return s + " Requests are allowed without asking (--ask=allow)."
	case ui.Remote:
		return s + fmt.Sprintf(" Answer from another terminal: 'hallpass answer %d', or 'hallpass web' for the full UI.", pid)
	case *ui.Desktop:
		return s + " Requests show as desktop notifications; " + web
	}
	if menu {
		return s + " Ctrl-] for the menu; " + web
	}
	return s + " R" + web[1:]
}
