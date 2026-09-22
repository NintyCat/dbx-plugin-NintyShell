//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	gopt "github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/windows/registry"
)

// supplementWindowsEnv restores variables that console hosts (PowerShell,
// cmd) require for DLL initialization but that a sandboxed sidecar
// environment may have lost. Without SystemRoot, powershell.exe fails with
// STATUS_DLL_INIT_FAILED (0xC0000142) before writing a single byte of
// output.
func supplementWindowsEnv(env []string) []string {
	have := make(map[string]bool, len(env))
	for _, entry := range env {
		if name, _, found := strings.Cut(entry, "="); found {
			have[strings.ToUpper(name)] = true
		}
	}
	if have["SYSTEMROOT"] {
		return env
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
			if value, _, regErr := key.GetStringValue("SystemRoot"); regErr == nil && value != "" {
				root = value
			}
			key.Close()
		}
	}
	if root == "" {
		root = `C:\Windows`
	}
	ptyLogf("sidecar env lacks SystemRoot; supplementing %q", root)
	return append(env, "SystemRoot="+root)
}

// localPTY is an interactive local shell attached to a Windows pseudo
// console (ConPTY) through github.com/aymanbagabas/go-pty. Reads return the
// shell's VT rendered output, writes feed its keyboard.
//
// The previous hand-rolled CreatePseudoConsole sequence produced a live but
// completely silent shell on Windows 11 25H2 (build 26200): the child
// process ran, yet not a single byte reached our output pipe. go-pty's
// spawn path (STARTF_USESTDHANDLES plus its pipe/attribute handling) works
// on the same machine, so the whole lifecycle is delegated to the library.
type localPTY struct {
	pty       gopt.Pty
	cmd       *gopt.Cmd
	shellPath string
	dir       string
	startedAt time.Time
	once      sync.Once
}

func startLocalPTY(shellPath, dir string, cols, rows uint16) (*localPTY, error) {
	p, err := gopt.New()
	if err != nil {
		return nil, err
	}
	argv := localPTYArgv(shellPath)
	cmd := p.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = localPTYEnv()
	if err := cmd.Start(); err != nil {
		_ = p.Close()
		return nil, err
	}
	if err := p.Resize(int(cols), int(rows)); err != nil {
		ptyLogf("initial resize %dx%d failed: %v", cols, rows, err)
	}
	l := &localPTY{pty: p, cmd: cmd, shellPath: shellPath, dir: dir, startedAt: time.Now()}
	l.watchExit()
	return l, nil
}

func (l *localPTY) Read(p []byte) (int, error)  { return l.pty.Read(p) }
func (l *localPTY) Write(p []byte) (int, error) { return l.pty.Write(p) }

func (l *localPTY) Resize(cols, rows uint16) error {
	return l.pty.Resize(int(cols), int(rows))
}

// watchExit closes the pseudo console once the shell process exits. Unlike a
// Unix pty, ConPTY pipes never report EOF on their own, so a shell that dies
// on startup (or after typing exit) would otherwise leave the terminal
// frozen on a blank screen forever. The short drain delay lets the console
// flush its final VT output before the pipes go away. A shell that dies
// within seconds of start also triggers the automatic failure probes in
// ptydiag_windows.go.
func (l *localPTY) watchExit() {
	go func() {
		waitErr := l.cmd.Wait()
		code := -1
		if l.cmd.ProcessState != nil {
			code = l.cmd.ProcessState.ExitCode()
		}
		ptyLogf("shell process exited, code=%d (%v)", code, waitErr)
		if code != 0 && time.Since(l.startedAt) < 3*time.Second {
			diagnoseConPTYFailure(l.shellPath, l.dir, uint32(code))
		}
		time.Sleep(400 * time.Millisecond)
		_ = l.Close()
	}()
}

// Close terminates the shell and releases the pseudo console. Killing the
// process first makes the concurrent Wait in watchExit return promptly.
func (l *localPTY) Close() error {
	var err error
	l.once.Do(func() {
		if l.cmd.Process != nil {
			_ = l.cmd.Process.Kill()
		}
		err = l.pty.Close()
	})
	return err
}

// fmtExit renders a wait result for the logs: an NTSTATUS code is far more
// readable in hex (0xC0000142 = STATUS_DLL_INIT_FAILED).
func fmtExit(code uint32, alive bool, waited time.Duration) string {
	if alive {
		return fmt.Sprintf("alive after %s", waited)
	}
	return fmt.Sprintf("exit %d (0x%08X)", code, code)
}
