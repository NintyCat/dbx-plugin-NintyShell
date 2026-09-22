//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// diagnoseConPTYFailure runs controlled probes inside the sidecar's own
// process and environment when a PTY shell dies within seconds of start, and
// writes the results to pty.log. The probes isolate the failing layer:
//   - plain CreateProcess (no pseudo console) with the inherited environment
//     vs. ours: does the shell die even without ConPTY? (env/session issue)
//   - ConPTY with the inherited environment vs. ours: is our env block bad?
//   - ConPTY without STARTF_USESTDHANDLES: is the startup-info flag the
//     trigger on this Windows build?
//   - ConPTY with cmd.exe: is conhost itself broken?
//
// Runs at most once per sidecar process.
var diagOnce sync.Once

func diagnoseConPTYFailure(shellPath, dir string, exitCode uint32) {
	diagOnce.Do(func() {
		runDiagnoseConPTYFailure(shellPath, dir, exitCode)
	})
}

// diagnoseSilentSession runs the same probes for a session that never
// produced output at all — the signature of the pseudoconsole attribute not
// being applied (the child then opens its own console window and every byte
// goes there instead of our pipe).
func (l *localPTY) noteSilentExit() {
	diagOnce.Do(func() {
		runDiagnoseConPTYFailure(l.shellPath, l.dir, 0)
	})
}

func runDiagnoseConPTYFailure(shellPath, dir string, exitCode uint32) {
	_ = rtlGetVersionForLog()
	argv := localPTYArgv(shellPath)
	ours := localPTYEnv()

	// Decisive first: close the pseudo console 0.8s after spawn - if the
	// child survives, it was never attached (own console) and every output
	// byte went there instead of our pipe.
	attachedProbe(argv, dir, ours, "attach-test powershell env=ours")

	code, alive := spawnPlainWait(argv, dir, nil)
	ptyLogf("diag: plain powershell env=inherit -> %s", fmtExit(code, alive, 2*time.Second))
	code, alive = spawnPlainWait(argv, dir, ours)
	ptyLogf("diag: plain powershell env=ours -> %s", fmtExit(code, alive, 2*time.Second))

	conptyProbe(argv, dir, nil, false, "conpty powershell env=inherit")
	conptyProbe(argv, dir, ours, false, "conpty powershell env=ours")
	conptyProbe(argv, dir, ours, true, "conpty powershell env=ours USESTDHANDLES")
	if cmd, err := exec.LookPath("cmd.exe"); err == nil {
		conptyProbe([]string{cmd, "/c", "echo diag_ok"}, dir, nil, false, "conpty cmd /c echo env=inherit")
	}
	ptyLogf("diag: probes done")
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

// attachedProbe closes the pseudo console shortly after spawn and reports
// whether the child died with it. Surviving the close means the
// PSEUDOCONSOLE attribute never reached the child.
func attachedProbe(argv []string, dir string, env []string, label string) {
	c, err := spawnConPTY(argv, dir, 80, 24, env, false)
	if err != nil {
		ptyLogf("diag: %s -> spawn err %v", label, err)
		return
	}
	time.Sleep(800 * time.Millisecond)
	c.closeConsole()
	event, _ := windows.WaitForSingleObject(c.process, 1500)
	stillAlive := uint32(event) == uint32(windows.WAIT_TIMEOUT)
	var code uint32
	_ = windows.GetExitCodeProcess(c.process, &code)
	if stillAlive {
		_ = windows.TerminateProcess(c.process, 1)
		_, _ = windows.WaitForSingleObject(c.process, 1000)
	}
	_ = c.release()
	ptyLogf("diag: %s -> attached=%v %s", label, !stillAlive, fmtExit(code, stillAlive, 1500*time.Millisecond))
}

// conptyProbe runs one spawn with a hard timeout so a blocked probe cannot
// silence the remaining log lines.
func conptyProbe(argv []string, dir string, env []string, useStdHandles bool, label string) {
	done := make(chan string, 1)
	go func() {
		c, err := spawnConPTY(argv, dir, 80, 24, env, useStdHandles)
		if err != nil {
			done <- fmt.Sprintf("spawn err %v", err)
			return
		}
		n, out := readFor(c, 2000)
		code := exitCodeOf(c)
		msg := fmt.Sprintf("%d bytes, %s%s", n, fmtExit(code, false, 0), previewSuffix(out))
		_ = c.release()
		done <- msg
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
	commandLine, err := windows.UTF16PtrFromString(windowsCommandLine(argv))
	if err != nil {
		return 0, false
	}
	var dirPtr *uint16
	if dir != "" {
		if dirPtr, err = windows.UTF16PtrFromString(dir); err != nil {
			return 0, false
		}
	}
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	pi := &windows.ProcessInformation{}
	flags := uint32(windows.CREATE_NO_WINDOW)
	var envBlock *uint16
	if env != nil {
		flags |= windows.CREATE_UNICODE_ENVIRONMENT
		envBlock = envBlockUTF16(env)
	}
	if err := windows.CreateProcess(nil, commandLine, nil, nil, false, flags, envBlock, dirPtr, si, pi); err != nil {
		ptyLogf("diag: plain CreateProcess err %v", err)
		return 0, false
	}
	event, _ := windows.WaitForSingleObject(pi.Process, 2000)
	alive := uint32(event) == uint32(windows.WAIT_TIMEOUT)
	var code uint32
	_ = windows.GetExitCodeProcess(pi.Process, &code)
	if alive {
		_ = windows.TerminateProcess(pi.Process, 1)
		_, _ = windows.WaitForSingleObject(pi.Process, 1000)
	}
	_ = windows.CloseHandle(pi.Process)
	_ = windows.CloseHandle(pi.Thread)
	return code, alive
}

// readFor collects pseudo console output for d, then closes the console so
// the blocking reader unblocks.
func readFor(c *conptyProc, d time.Duration) (int, []byte) {
	var mu sync.Mutex
	var all []byte
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
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
	c.closeConsole()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return len(all), all
}

func exitCodeOf(c *conptyProc) uint32 {
	_, _ = windows.WaitForSingleObject(c.process, 3000)
	var code uint32
	_ = windows.GetExitCodeProcess(c.process, &code)
	return code
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
