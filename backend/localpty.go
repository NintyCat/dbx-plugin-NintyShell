package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
	env = append(env, "TERM=xterm-256color", "COLORTERM=truecolor")
	if runtime.GOOS == "windows" {
		env = supplementWindowsEnv(env)
	}
	return env
}

// ptyLogf appends a line to pty.log next to the panic log. Unlike a Unix
// pty, a Windows pseudo console never reports EOF when the shell process
// dies, so this log is the only window into start failures and crashes on
// that platform. Kept small: a few lines per session, truncated at 1 MB.
func ptyLogf(format string, args ...any) {
	dir := pluginLogDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, "pty.log")
	if info, err := os.Stat(path); err == nil && info.Size() > 1<<20 {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, time.Now().Format("2006-01-02 15:04:05.000 ")+" "+format+"\n", args...)
}

// openLocalPTY starts the configured shell on a pseudo terminal and streams
// raw output to the UI, mirroring the SSH PTY path: keystrokes arrive via
// shell/input, resizes via shell/resize, and the read loop emits
// shell/pty-closed once the shell exits.
func openLocalPTY(s *shellSession, emitter eventEmitter) error {
	pty, err := startLocalPTY(s.shellPath, s.cwd, localPtyDefaultCols, localPtyDefaultRows)
	if err != nil {
		ptyLogf("start failed shell=%q: %v", s.shellPath, err)
		return err
	}
	ptyLogf("started shell=%q dir=%q", s.shellPath, s.cwd)
	s.localPty = pty
	sessionID := s.id
	go func() {
		defer guardPanic("local-pty-read")
		buf := make([]byte, 8192)
		firstOutput := true
		for {
			n, readErr := pty.Read(buf)
			if n > 0 {
				if firstOutput {
					ptyLogf("first output: %d bytes", n)
					firstOutput = false
				}
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				_ = emitter.Event("shell/output", map[string]any{
					"connectionId": sessionID,
					"data":         chunk,
				})
			}
			if readErr != nil {
				ptyLogf("read ended: %v (got output=%v)", readErr, !firstOutput)
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
