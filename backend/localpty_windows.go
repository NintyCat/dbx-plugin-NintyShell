//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// errConPtyUnsupported is returned on Windows releases older than 10 1809,
// where the ConPTY APIs are missing; connectLocal falls back to per-command
// exec mode.
var errConPtyUnsupported = errors.New("ConPTY is not available on this version of Windows")

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

// conptyProc is a raw pseudo console with an attached process. The caller
// owns the lifecycle: closeConsole() terminates the shell and unblocks the
// output pipe, release() frees every handle.
type conptyProc struct {
	con           windows.Handle
	ptyIn         windows.Handle // pseudoconsole end of the input pipe
	ptyOut        windows.Handle // pseudoconsole end of the output pipe
	cmdIn         windows.Handle // shell keyboard (we write)
	cmdOut        windows.Handle // shell output (we read)
	process       windows.Handle
	thread        windows.Handle
	attrs         *windows.ProcThreadAttributeListContainer
	consoleClosed bool
}

// spawnConPTY attaches argv to a new pseudo console. The process-attachment
// sequence follows github.com/UserExistsError/conpty (MIT), built directly
// on x/sys/windows.
func spawnConPTY(argv []string, dir string, cols, rows uint16, env []string, useStdHandles bool) (*conptyProc, error) {
	var ptyIn, ptyOut, cmdIn, cmdOut windows.Handle
	if err := windows.CreatePipe(&ptyIn, &cmdIn, nil, 0); err != nil {
		return nil, err
	}
	if err := windows.CreatePipe(&cmdOut, &ptyOut, nil, 0); err != nil {
		closeHandles(ptyIn, cmdIn)
		return nil, err
	}
	var con windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, ptyIn, ptyOut, 0, &con); err != nil {
		closeHandles(ptyIn, ptyOut, cmdIn, cmdOut)
		return nil, err
	}

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeConsoleAndPipes(con, ptyIn, ptyOut, cmdIn, cmdOut)
		return nil, err
	}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(&con), unsafe.Sizeof(con)); err != nil {
		attrs.Delete()
		closeConsoleAndPipes(con, ptyIn, ptyOut, cmdIn, cmdOut)
		return nil, err
	}

	commandLine, err := windows.UTF16PtrFromString(windowsCommandLine(argv))
	if err != nil {
		attrs.Delete()
		closeConsoleAndPipes(con, ptyIn, ptyOut, cmdIn, cmdOut)
		return nil, err
	}
	var dirPtr *uint16
	if dir != "" {
		if dirPtr, err = windows.UTF16PtrFromString(dir); err != nil {
			attrs.Delete()
			closeConsoleAndPipes(con, ptyIn, ptyOut, cmdIn, cmdOut)
			return nil, err
		}
	}

	si := &windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(*si))
	if useStdHandles {
		si.Flags = windows.STARTF_USESTDHANDLES
	}
	si.ProcThreadAttributeList = attrs.List()
	pi := &windows.ProcessInformation{}
	var envBlock *uint16
	creationFlags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT)
	if env != nil {
		creationFlags |= windows.CREATE_UNICODE_ENVIRONMENT
		envBlock = envBlockUTF16(env)
	}
	if err := windows.CreateProcess(nil, commandLine, nil, nil, false,
		creationFlags, envBlock, dirPtr, &si.StartupInfo, pi); err != nil {
		attrs.Delete()
		closeConsoleAndPipes(con, ptyIn, ptyOut, cmdIn, cmdOut)
		return nil, err
	}

	return &conptyProc{
		con:     con,
		ptyIn:   ptyIn,
		ptyOut:  ptyOut,
		cmdIn:   cmdIn,
		cmdOut:  cmdOut,
		process: pi.Process,
		thread:  pi.Thread,
		attrs:   attrs,
	}, nil
}

func closeConsoleAndPipes(con windows.Handle, pipes ...windows.Handle) {
	windows.ClosePseudoConsole(con)
	closeHandles(pipes...)
}

func (c *conptyProc) Read(p []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(c.cmdOut, p, &n, nil)
	return int(n), err
}

func (c *conptyProc) Write(p []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(c.cmdIn, p, &n, nil)
	return int(n), err
}

func (c *conptyProc) Resize(cols, rows uint16) error {
	return windows.ResizePseudoConsole(c.con, windows.Coord{X: int16(cols), Y: int16(rows)})
}

// closeConsole shuts the pseudo console down, which terminates the attached
// shell and makes the output pipe report EOF.
func (c *conptyProc) closeConsole() {
	if c.consoleClosed {
		return
	}
	c.consoleClosed = true
	windows.ClosePseudoConsole(c.con)
}

// release tears down the pseudo console and frees every handle.
func (c *conptyProc) release() error {
	c.closeConsole()
	if c.attrs != nil {
		c.attrs.Delete()
	}
	return closeHandles(c.process, c.thread, c.ptyIn, c.ptyOut, c.cmdIn, c.cmdOut)
}

func closeHandles(handles ...windows.Handle) error {
	var first error
	for _, h := range handles {
		if h == 0 || h == windows.InvalidHandle {
			continue
		}
		if err := windows.CloseHandle(h); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// envBlockUTF16 builds the double-NUL-terminated UTF-16 environment block
// CreateProcess expects when CREATE_UNICODE_ENVIRONMENT is set.
func envBlockUTF16(env []string) *uint16 {
	if len(env) == 0 {
		return nil
	}
	block := make([]uint16, 0, 256)
	for _, entry := range env {
		block = append(block, utf16.Encode([]rune(entry))...)
		block = append(block, 0)
	}
	block = append(block, 0)
	return &block[0]
}

// windowsCommandLine quotes argv the way CreateProcess expects: one
// command-line string following the C runtime rules (backslash runs before a
// quote are doubled, embedded quotes are escaped).
func windowsCommandLine(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		if !strings.ContainsAny(arg, " \t\"") {
			quoted[i] = arg
			continue
		}
		var b strings.Builder
		b.WriteByte('"')
		backslashes := 0
		for _, ch := range arg {
			switch ch {
			case '\\':
				backslashes++
			case '"':
				b.WriteString(strings.Repeat(`\`, backslashes*2+1))
				backslashes = 0
				b.WriteByte('"')
			default:
				b.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
				b.WriteRune(ch)
			}
		}
		b.WriteString(strings.Repeat(`\`, backslashes*2))
		b.WriteByte('"')
		quoted[i] = b.String()
	}
	return strings.Join(quoted, " ")
}

// localPTY is an interactive local shell attached to a Windows pseudo
// console (ConPTY). Reads return the shell's VT rendered output, writes feed
// its keyboard.
type localPTY struct {
	*conptyProc
	shellPath string
	dir       string
	startedAt time.Time
	once      sync.Once
}

func startLocalPTY(shellPath, dir string, cols, rows uint16) (*localPTY, error) {
	c, err := spawnConPTY(localPTYArgv(shellPath), dir, cols, rows, localPTYEnv(), true)
	if err != nil {
		return nil, err
	}
	pty := &localPTY{conptyProc: c, shellPath: shellPath, dir: dir, startedAt: time.Now()}
	pty.watchExit()
	return pty, nil
}

// watchExit closes the pseudo console once the shell process exits. Unlike a
// Unix pty, the ConPTY pipes never report EOF on their own, so a shell that
// dies on startup (or after typing exit) would otherwise leave the terminal
// frozen on a blank screen forever. The short drain delay lets the console
// flush its final VT output before the pipes go away. A shell that dies
// within seconds of start also triggers the automatic failure probes in
// ptydiag_windows.go.
func (l *localPTY) watchExit() {
	go func() {
		_, _ = windows.WaitForSingleObject(l.process, windows.INFINITE)
		var code uint32
		_ = windows.GetExitCodeProcess(l.process, &code)
		ptyLogf("shell process exited, code=%d (0x%08X)", code, code)
		if code != 0 && time.Since(l.startedAt) < 3*time.Second {
			diagnoseConPTYFailure(l.shellPath, l.dir, code)
		}
		time.Sleep(400 * time.Millisecond)
		_ = l.Close()
	}()
}

func (l *localPTY) Close() error {
	var err error
	l.once.Do(func() { err = l.release() })
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
