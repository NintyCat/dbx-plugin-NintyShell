package main

import (
	"os"
	"strings"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

// Sizes used until the UI reports the real xterm.js window via shell/resize.
const (
	localPtyDefaultCols = 80
	localPtyDefaultRows = 24
)

// eventEmitter is the slice of the SDK emitter the PTY paths need. A small
// interface so tests can capture events without a live bridge.
type eventEmitter interface {
	Event(method string, params any) *dbxpluginsdk.PluginError
}

// localPTYArgv builds the interactive shell invocation. A PTY session runs a
// login shell so profiles load and the prompt behaves like a real terminal,
// which is deliberately unlike the per-command exec fallback.
func localPTYArgv(shellPath string) []string {
	switch shellStyleFor(shellPath) {
	case powershellShell:
		return []string{shellPath, "-NoLogo"}
	case cmdShell:
		return []string{shellPath}
	default:
		return []string{shellPath, "-l"}
	}
}

// localPTYEnv replaces the inherited terminal type: the host process often
// has no TERM at all, and without one every interactive program (vim, top,
// ssh) degrades to dumb mode.
func localPTYEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "TERM=") || strings.HasPrefix(entry, "COLORTERM=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "TERM=xterm-256color", "COLORTERM=truecolor")
}

// openLocalPTY starts the configured shell on a pseudo terminal and streams
// raw output to the UI, mirroring the SSH PTY path: keystrokes arrive via
// shell/input, resizes via shell/resize, and the read loop emits
// shell/pty-closed once the shell exits.
func openLocalPTY(s *shellSession, emitter eventEmitter) error {
	pty, err := startLocalPTY(s.shellPath, s.cwd, localPtyDefaultCols, localPtyDefaultRows)
	if err != nil {
		return err
	}
	s.localPty = pty
	sessionID := s.id
	go func() {
		defer guardPanic("local-pty-read")
		buf := make([]byte, 8192)
		for {
			n, readErr := pty.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				_ = emitter.Event("shell/output", map[string]any{
					"connectionId": sessionID,
					"data":         chunk,
				})
			}
			if readErr != nil {
				s.mutex.Lock()
				stopping := s.stopping
				if !stopping {
					s.ptyClosed = true
				}
				s.mutex.Unlock()
				if !stopping {
					_ = emitter.Event("shell/pty-closed", map[string]any{"connectionId": sessionID})
				}
				return
			}
		}
	}()
	return nil
}
