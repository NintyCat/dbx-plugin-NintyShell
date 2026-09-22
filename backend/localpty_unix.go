//go:build unix

package main

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// localPTY is an interactive local shell attached to a pseudo terminal. The
// file is the slave side: reads return the shell's output, writes feed its
// keyboard.
type localPTY struct {
	file *os.File
	cmd  *exec.Cmd
	once sync.Once
}

func startLocalPTY(shellPath, dir string, cols, rows uint16) (*localPTY, error) {
	cmd := exec.Command(shellPath)
	cmd.Args = localPTYArgv(shellPath)
	cmd.Dir = dir
	cmd.Env = localPTYEnv()
	// StartWithSize makes the shell a session leader with the terminal as its
	// controlling device, so job control and ^C behave like a real tty.
	file, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, err
	}
	return &localPTY{file: file, cmd: cmd}, nil
}

func (l *localPTY) Read(p []byte) (int, error)  { return l.file.Read(p) }
func (l *localPTY) Write(p []byte) (int, error) { return l.file.Write(p) }

func (l *localPTY) Resize(cols, rows uint16) error {
	return pty.Setsize(l.file, &pty.Winsize{Cols: cols, Rows: rows})
}

// supplementWindowsEnv is a no-op outside Windows; see localpty_windows.go.
func supplementWindowsEnv(env []string) []string { return env }

// Close hangs up the controlling terminal so the shell exits on its own and
// reaps it shortly after; closing the file also unblocks the plugin's read
// loop.
func (l *localPTY) Close() error {
	var err error
	l.once.Do(func() {
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
