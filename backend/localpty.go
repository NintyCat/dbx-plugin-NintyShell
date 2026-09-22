package main

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
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
		// -NoExit keeps the session interactive; the init pins UTF-8 and
		// wraps the prompt so it reports the cwd via OSC 7 (see osc7Scanner).
		return []string{shellPath, "-NoLogo", "-NoExit", "-EncodedCommand", encodePowerShellScript(powershellOsc7Init())}
	case cmdShell:
		return []string{shellPath, "/K", "chcp 65001 >nul"}
	default:
		return []string{shellPath, "-l"}
	}
}

// powershellOsc7Init is fed to -EncodedCommand for PTY sessions: UTF-8
// output for the UI's decoder, plus a prompt wrapper that emits an OSC 7
// cwd report while preserving the profile's own prompt function.
func powershellOsc7Init() string {
	return strings.Join([]string{
		"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
		"$OutputEncoding = [System.Text.Encoding]::UTF8",
		"$global:__dbxPrompt = $function:prompt",
		"function global:prompt {",
		`  [Console]::Write([char]27 + "]7;file://" + [uri]::EscapeDataString($PWD.Path) + [char]7)`,
		"  if ($global:__dbxPrompt) { & $global:__dbxPrompt } else { \"PS $($PWD.Path)> \" }",
		"}",
	}, "\n")
}

// osc7Scanner extracts OSC 7 cwd reports ("ESC ] 7 ; file://URI BEL" or
// "... ESC \") from a PTY byte stream. Sequences can split across reads, so
// a small carry buffer bridges the chunks.
type osc7Scanner struct {
	pending []byte
}

func (s *osc7Scanner) feed(chunk []byte) string {
	s.pending = append(s.pending, chunk...)
	var last string
	for {
		start := bytes.Index(s.pending, []byte("\x1b]7;"))
		if start < 0 {
			// keep a short tail so a marker split across chunks survives
			if len(s.pending) > 64 {
				s.pending = s.pending[len(s.pending)-64:]
			}
			return last
		}
		rest := s.pending[start+4:]
		end, termLen := -1, 0
		for i := 0; i < len(rest); i++ {
			if rest[i] == 7 {
				end, termLen = i, 1
				break
			}
			if rest[i] == 0x1b && i+1 < len(rest) && rest[i+1] == '\\' {
				end, termLen = i, 2
				break
			}
		}
		if end < 0 {
			// payload still arriving; cap the accumulation to bound memory
			if len(rest) > 8192 {
				s.pending = nil
			} else {
				s.pending = s.pending[start:]
			}
			return last
		}
		last = string(rest[:end])
		s.pending = rest[end+termLen:]
	}
}

// osc7URIToPath converts an OSC 7 payload (file://host/path, fully
// percent-encoded, or a raw path) into a native absolute path for goos.
func osc7URIToPath(uri, goos string) string {
	raw := strings.TrimSpace(uri)
	raw = strings.TrimPrefix(raw, "file://")
	if !strings.HasPrefix(raw, "/") {
		// drop the authority component of file://host/path
		if i := strings.Index(raw, "/"); i >= 0 {
			raw = raw[i:]
		}
	}
	if dec, err := url.PathUnescape(raw); err == nil {
		raw = dec
	}
	if goos == "windows" {
		raw = strings.ReplaceAll(raw, "/", "\\")
		if len(raw) >= 2 && raw[0] == '\\' && raw[1] != '\\' {
			raw = raw[1:] // "/C:\Users" → "C:\Users"
		}
		if len(raw) < 3 || raw[1] != ':' {
			return ""
		}
	} else if !strings.HasPrefix(raw, "/") {
		return ""
	}
	return raw
}

// emitOsc7Cwd updates the session cwd from an OSC 7 report and notifies the
// UI when it actually changed.
func emitOsc7Cwd(s *shellSession, emitter eventEmitter, uri string) {
	// An SSH session reports the remote shell's POSIX paths, which must not
	// be parsed with the client's GOOS: on a Windows client every /home/...
	// report used to come back empty and the file panel never followed the
	// terminal. Local sessions keep runtime.GOOS (PowerShell emits
	// file:///C:/... there).
	goos := runtime.GOOS
	if s.kind == "ssh" {
		goos = "linux"
	}
	cwd := osc7URIToPath(uri, goos)
	if cwd == "" {
		return
	}
	s.mutex.Lock()
	changed := cwd != s.cwd
	if changed {
		s.cwd = cwd
	}
	s.mutex.Unlock()
	if changed {
		_ = emitter.Event("shell/cwd-changed", map[string]any{
			"connectionId": s.id,
			"cwd":          cwd,
		})
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
func openLocalPTY(p *plugin, s *shellSession, emitter eventEmitter) error {
	pty, err := startLocalPTY(s.shellPath, s.cwd, localPtyDefaultCols, localPtyDefaultRows)
	if err != nil {
		ptyLogf("start failed shell=%q: %v", s.shellPath, err)
		return err
	}
	ptyLogf("started v%s shell=%q dir=%q", pluginVersion, s.shellPath, s.cwd)
	s.localPty = pty
	sessionID := s.id
	var outputSeen atomic.Bool
	scanner := &osc7Scanner{}
	go func() {
		defer guardPanic("local-pty-read")
		buf := make([]byte, 8192)
		for {
			n, readErr := pty.Read(buf)
			if n > 0 {
				if !outputSeen.Swap(true) {
					ptyLogf("first output: %d bytes", n)
				}
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if uri := scanner.feed(chunk); uri != "" {
					emitOsc7Cwd(s, emitter, uri)
				}
				_ = emitter.Event("shell/output", map[string]any{
					"connectionId": sessionID,
					"data":         chunk,
				})
			}
			if readErr != nil {
				ptyLogf("read ended: %v (got output=%v)", readErr, outputSeen.Load())
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
	// A live session with zero output is the Windows failure mode; tear the
	// pseudo console down and switch the connection to per-command mode while
	// the session is still open, instead of showing a dead terminal forever.
	go func() {
		defer guardPanic("local-pty-silent-watch")
		time.Sleep(4 * time.Second)
		if outputSeen.Load() {
			return
		}
		s.mutex.Lock()
		stopping := s.stopping
		s.mutex.Unlock()
		if stopping {
			return
		}
		p.fallbackSession(s, emitter)
	}()
	return nil
}
