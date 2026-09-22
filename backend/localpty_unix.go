//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// localPTY is an interactive local shell attached to a pseudo terminal. The
// file is the slave side: reads return the shell's output, writes feed its
// keyboard.
type localPTY struct {
	file    *os.File
	cmd     *exec.Cmd
	cleanup func() // release per-session injection files
	once    sync.Once
}

func startLocalPTY(shellPath, dir string, cols, rows uint16) (*localPTY, error) {
	argv := localPTYArgv(shellPath)
	env := localPTYEnv()
	var cleanup func()
	// Prompt-level OSC 7 injection per shell so the SFTP panel can follow
	// the cwd; shims wrap the user's own configuration (VS Code style).
	switch strings.ToLower(filepath.Base(shellPath)) {
	case "zsh":
		if shimDir, err := writeZshOsc7Shim(); err == nil {
			env = append(env, "ZDOTDIR="+shimDir)
			cleanup = func() { _ = os.RemoveAll(shimDir) }
		}
	case "bash":
		if rc, err := writeBashOsc7Rc(); err == nil {
			argv = append(argv, "--rcfile", rc)
			cleanup = func() { _ = os.Remove(rc) }
		}
	}
	cmd := exec.Command(shellPath)
	cmd.Args = argv
	cmd.Dir = dir
	cmd.Env = env
	// StartWithSize makes the shell a session leader with the terminal as its
	// controlling device, so job control and ^C behave like a real tty.
	file, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	return &localPTY{file: file, cmd: cmd, cleanup: cleanup}, nil
}

func (l *localPTY) Read(p []byte) (int, error)  { return l.file.Read(p) }
func (l *localPTY) Write(p []byte) (int, error) { return l.file.Write(p) }

func (l *localPTY) Resize(cols, rows uint16) error {
	return pty.Setsize(l.file, &pty.Winsize{Cols: cols, Rows: rows})
}

// supplementWindowsEnv is a no-op outside Windows; see localpty_windows.go.
func supplementWindowsEnv(env []string) []string { return env }

// noteSilentExit is a no-op outside Windows; see ptydiag_windows.go.
func (l *localPTY) noteSilentExit() {}

// Close hangs up the controlling terminal so the shell exits on its own and
// reaps it shortly after; closing the file also unblocks the plugin's read
// loop.
func (l *localPTY) Close() error {
	var err error
	l.once.Do(func() {
		if l.cleanup != nil {
			l.cleanup()
		}
		if l.cmd.Process != nil {
			_ = syscall.Kill(-l.cmd.Process.Pid, syscall.SIGHUP)
		}
		err = l.file.Close()
		go func() {
			time.Sleep(1500 * time.Millisecond)
			if l.cmd.Process != nil {
				_ = syscall.Kill(-l.cmd.Process.Pid, syscall.SIGKILL)
			}
			_ = l.cmd.Wait()
		}()
	})
	return err
}

const osc7POSIX = `printf '\033]7;file://%s\007' "$PWD"`

// writeBashOsc7Rc creates an rcfile that sources the user's configuration
// and prepends an OSC 7 cwd report to PROMPT_COMMAND.
func writeBashOsc7Rc() (string, error) {
	f, err := os.CreateTemp("", "dbx-osc7-*.sh")
	if err != nil {
		return "", err
	}
	content := `[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"` + "\n" +
		`PROMPT_COMMAND="` + osc7POSIX + `${PROMPT_COMMAND:+; $PROMPT_COMMAND}"` + "\n"
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// writeZshOsc7Shim creates a ZDOTDIR whose startup files source the user's
// configuration and register an OSC 7 precmd hook.
func writeZshOsc7Shim() (string, error) {
	dir, err := os.MkdirTemp("", "dbx-osc7-zsh-")
	if err != nil {
		return "", err
	}
	shim := `[ -f "$HOME/.zshenv" ] && . "$HOME/.zshenv"` + "\n" +
		`[ -f "$HOME/.zshrc" ] && . "$HOME/.zshrc"` + "\n" +
		`__dbx_osc7() { ` + osc7POSIX + ` }` + "\n" +
		`precmd_functions+=(__dbx_osc7)` + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(shim), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, ".zshenv"), []byte(`[ -f "$HOME/.zshenv" ] && . "$HOME/.zshenv"`+"\n"), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}
