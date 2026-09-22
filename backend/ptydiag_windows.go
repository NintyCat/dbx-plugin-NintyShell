//go:build windows

package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	gopt "github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/windows"
)

// diagnoseConPTYFailure runs controlled probes inside the sidecar's own
// process and environment when a PTY shell dies within seconds of start, and
// writes the results to pty.log. The probes isolate the failing layer:
//   - go-pty with our environment vs. inherited: does a fresh ConPTY
//     session produce bytes at all? (spawn path broken vs. env broken)
//   - go-pty with cmd.exe: is conhost itself broken?
//   - plain CreateProcess (no pseudo console): is it the session/token
//     rather than ConPTY?
//
// Runs at most once per sidecar process.
var diagOnce sync.Once

func diagnoseConPTYFailure(shellPath, dir string, exitCode uint32) {
	diagOnce.Do(func() {
		runDiagnoseConPTYFailure(shellPath, dir, exitCode)
	})
}

// noteSilentExit runs the same probes for a session that never produced
// output at all — the signature of the child never attaching to the
// pseudoconsole (every byte then goes to a console we never read).
func (l *localPTY) noteSilentExit() {
	diagOnce.Do(func() {
		runDiagnoseConPTYFailure(l.shellPath, l.dir, 0)
	})
}

func runDiagnoseConPTYFailure(shellPath, dir string, exitCode uint32) {
	_ = rtlGetVersionForLog()
	argv := localPTYArgv(shellPath)
	ours := localPTYEnv()
	ptyLogf("diag: failing shell exit=%d (0x%08X)", exitCode, exitCode)

	conptyProbe(argv, dir, ours, "go-pty shell env=ours")
	conptyProbe(argv, dir, nil, "go-pty shell env=inherit")
	if cmd, err := exec.LookPath("cmd.exe"); err == nil {
		conptyProbe([]string{cmd, "/c", "echo diag_ok"}, dir, nil, "go-pty cmd /c echo")
	}

	code, alive := spawnPlainWait(argv, dir, ours)
	ptyLogf("diag: plain shell env=ours -> %s", fmtExit(code, alive, 2*time.Second))
	ptyLogf("diag: probes done")
}

// conptyProbe starts argv on a fresh pseudo console through go-pty, collects
// output for d, then tears the session down. A hard timeout keeps a blocked
// probe from silencing the remaining log lines.
func conptyProbe(argv []string, dir string, env []string, label string) {
	done := make(chan string, 1)
	go func() {
		p, err := gopt.New()
		if err != nil {
			done <- fmt.Sprintf("new err %v", err)
			return
		}
		c := p.Command(argv[0], argv[1:]...)
		c.Dir = dir
		c.Env = env
		if err := c.Start(); err != nil {
			_ = p.Close()
			done <- fmt.Sprintf("start err %v", err)
			return
		}
		n, out := readFor(p, func() { _ = p.Close() }, 2*time.Second)
		if c.Process != nil {
			_ = c.Process.Kill()
		}
		_ = c.Wait()
		done <- fmt.Sprintf("%d bytes%s", n, previewSuffix(out))
	}()
	select {
	case msg := <-done:
		ptyLogf("diag: %s -> %s", label, msg)
	case <-time.After(8 * time.Second):
		ptyLogf("diag: %s -> PROBE TIMED OUT (blocked)", label)
	}
}

// spawnPlainWait starts a console process without a pseudo console (hidden
// window), waits up to 2s, and reports the exit code or liveness. A plain
// spawn also spins up conhost, so a failure here points at the session or
// job context rather than at the pseudo console.
func spawnPlainWait(argv []string, dir string, env []string) (uint32, bool) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		ptyLogf("diag: plain start err %v", err)
		return 0, false
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		return uint32(code), false
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return 0, true
	}
}

// readFor collects reader output for d, invokes closeFn to unblock the
// reader (ConPTY pipes never hit EOF on their own), and waits for it to
// drain.
func readFor(r io.Reader, closeFn func(), d time.Duration) (int, []byte) {
	var mu sync.Mutex
	var all []byte
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				mu.Lock()
				all = append(all, buf[:n]...)
				mu.Unlock()
			}
			if err != nil {
				close(done)
				return
			}
		}
	}()
	time.Sleep(d)
	closeFn()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return len(all), all
}

// rtlGetVersionForLog records the Windows build the sidecar runs on so
// ConPTY behavior can be correlated with the OS version.
func rtlGetVersionForLog() error {
	vi := windows.RtlGetVersion()
	ptyLogf("diag: windows %d.%d build %d | sizeof STARTUPINFO=%d STARTUPINFOEX=%d",
		vi.MajorVersion, vi.MinorVersion, vi.BuildNumber,
		unsafe.Sizeof(windows.StartupInfo{}), unsafe.Sizeof(windows.StartupInfoEx{}))
	return nil
}

func previewSuffix(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := strings.ReplaceAll(string(b), "\x1b", "\\e")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return fmt.Sprintf(` out="%s"`, s)
}
