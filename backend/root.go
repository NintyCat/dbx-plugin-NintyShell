package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const rootProbeCommand = `printf '%s\n' "__DBX_ROOT_HOME__$HOME"
if command -v sftp-server >/dev/null 2>&1; then
	printf '%s\n' "__DBX_ROOT_SFTP__$(command -v sftp-server)"
else
	for __dbx_sftp_path in \
		/usr/lib/openssh/sftp-server \
		/usr/libexec/openssh/sftp-server \
		/usr/lib/sftp-server \
		/usr/lib/ssh/sftp-server \
		/usr/libexec/sftp-server
	do
		if [ -x "$__dbx_sftp_path" ]; then
			printf '%s\n' "__DBX_ROOT_SFTP__$__dbx_sftp_path"
			break
		fi
	done
fi`

// rootSettings reads the optional root escalation configuration. Root mode is
// deliberately explicit: it is enabled only when the connection asks for
// password escalation and supplies a root password.
func rootSettings(values map[string]any) (bool, string, error) {
	mode := configString(values, "root_login")
	password := configSecret(values, "root_password")
	if mode != "password" {
		if password != "" {
			return false, "", errors.New("Root login mode must be set to Password when a root password is configured")
		}
		return false, "", nil
	}
	if password == "" {
		return false, "", errors.New("Root password is required when root login mode is Password")
	}
	return true, password, nil
}

// configureRootEscalation only validates and stores the connection settings.
// The host gives connection/connect a 10-second deadline, so no remote su
// probe is performed here. Root credentials are verified lazily the first time
// the terminal, Docker, or SFTP actually needs elevated privileges.
func configureRootEscalation(s *shellSession, values map[string]any) error {
	enabled, password, err := rootSettings(values)
	if err != nil {
		return err
	}
	s.rootEnabled = false
	s.rootUser = ""
	s.rootPassword = ""
	s.rootHome = ""
	s.rootSFTPPath = ""
	if !enabled {
		return nil
	}
	s.rootEnabled = true
	s.rootUser = "root"
	s.rootPassword = password
	return nil
}

// discoverRootSFTPPath runs when the file panel is first opened. The probe is
// executed as the normal SSH user only to locate the external sftp-server
// executable; opening the resulting server still authenticates as root.
func discoverRootSFTPPath(s *shellSession) error {
	result := runSSHCommandWithTimeout(s, rootProbeCommand, 2*time.Second)
	if result.err != nil {
		return fmt.Errorf("Cannot locate the external sftp-server: %w", result.err)
	}
	if result.exitCode != 0 {
		detail := strings.TrimSpace(result.stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.stdout)
		}
		if detail == "" {
			detail = fmt.Sprintf("probe exited with code %d", result.exitCode)
		}
		return fmt.Errorf("Cannot locate the external sftp-server: %s", detail)
	}
	_, sftpPath := parseRootProbe(result.stdout)
	if sftpPath == "" {
		return errors.New("The external sftp-server executable was not found. Install the OpenSSH SFTP server or disable root login mode.")
	}
	s.rootSFTPPath = sftpPath
	if s.rootHome == "" {
		s.rootHome = "/root"
	}
	return nil
}

func parseRootProbe(output string) (home string, sftpPath string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		if value, ok := strings.CutPrefix(line, "__DBX_ROOT_HOME__"); ok && home == "" {
			home = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "__DBX_ROOT_SFTP__"); ok && sftpPath == "" {
			sftpPath = strings.TrimSpace(value)
		}
	}
	return home, sftpPath
}

func rootFailureMessage(result commandResult) string {
	detail := strings.TrimSpace(result.stderr)
	if detail == "" {
		detail = strings.TrimSpace(result.stdout)
	}
	if detail == "" {
		detail = fmt.Sprintf("su exited with code %d", result.exitCode)
	}
	return "Root escalation failed: " + detail +
		". Check the configured root password and make sure the SSH user is allowed to run su root."
}

// buildRootScript prints unforgeable markers around the requested command so
// the password prompt and any login banners cannot be mistaken for command
// output. The password itself is sent only through the PTY input pipe and is
// never interpolated into the remote command.
func buildRootScript(command, readyMarker, doneMarker string) string {
	return "printf '%s\\n' " + shellQuote(readyMarker) + "\n" +
		command + "\n" +
		"__dbx_root_rc=$?\n" +
		"printf '\\n%s %s\\n' " + shellQuote(doneMarker) + " \"$__dbx_root_rc\"\n" +
		"exit \"$__dbx_root_rc\""
}

func parseRootScriptOutput(output, readyMarker, doneMarker string) (string, int, bool) {
	ready := strings.Index(output, readyMarker)
	if ready < 0 {
		return "", -1, false
	}
	body := output[ready+len(readyMarker):]
	done := strings.Index(body, doneMarker)
	if done < 0 {
		return "", -1, false
	}
	commandOutput := strings.Trim(body[:done], "\r\n")
	remainder := strings.Fields(body[done+len(doneMarker):])
	if len(remainder) == 0 {
		return commandOutput, -1, true
	}
	exitCode := -1
	for _, field := range remainder {
		if value, err := strconvAtoi(field); err == nil {
			exitCode = value
			break
		}
	}
	return commandOutput, exitCode, true
}

// strconvAtoi is kept tiny and local so parseRootScriptOutput can be tested
// without pulling parsing concerns into the SSH code.
func strconvAtoi(value string) (int, error) {
	if value == "" {
		return 0, errors.New("empty integer")
	}
	result := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, errors.New("not an integer")
		}
		result = result*10 + int(char-'0')
		if result > 1<<30 {
			return 0, errors.New("integer overflow")
		}
	}
	return result, nil
}

// runRootCommand runs one non-interactive command through su in its own PTY.
// The PTY starts with echo disabled, the root password is queued as input,
// and su reads it when its localized prompt appears. A separate channel keeps
// this escalation out of the user's interactive terminal.
func runRootCommand(s *shellSession, command string, timeout time.Duration) commandResult {
	if s == nil || s.kind != "ssh" {
		return commandResult{err: errors.New("root escalation requires an SSH connection")}
	}
	if !s.rootEnabled {
		return runSSHCommandWithTimeout(s, command, timeout)
	}
	if s.rootPassword == "" {
		return commandResult{err: errors.New("root password is not configured")}
	}
	if s.isDead() {
		return commandResult{err: errors.New(s.deadError())}
	}
	if s.sshClient == nil {
		return commandResult{err: errors.New("SSH client is closed")}
	}
	session, sessionErr := withTimeout(sshSessionOpenTimeout, func() (*ssh.Session, error) {
		return s.sshClient.NewSession()
	})
	if sessionErr != nil {
		s.markDead()
		return commandResult{err: fmt.Errorf("open SSH session: %w", sessionErr)}
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.ICRNL: 1}
	if ptyErr := session.RequestPty("xterm-256color", 24, 80, modes); ptyErr != nil {
		return commandResult{err: fmt.Errorf("request root PTY: %w", ptyErr)}
	}
	stdin, stdinErr := session.StdinPipe()
	if stdinErr != nil {
		return commandResult{err: fmt.Errorf("open root input: %w", stdinErr)}
	}
	stdout := &limitedBuffer{limit: dockerCommandOutputLimit}
	stderr := &limitedBuffer{limit: dockerErrorOutputLimit}
	session.Stdout = stdout
	session.Stderr = stderr

	readyMarker := "__DBX_ROOT_READY__" + randomHex(8)
	doneMarker := "__DBX_ROOT_DONE__" + randomHex(8)
	script := buildRootScript(command, readyMarker, doneMarker)
	remoteCommand := "exec su - " + shellQuote(s.rootUser) + " -c " + shellQuote(script)
	if startErr := session.Start(remoteCommand); startErr != nil {
		return commandResult{err: fmt.Errorf("start root command: %w", startErr)}
	}
	// Queue the password before su reaches its prompt. Echo is disabled for
	// the lifetime of authentication, so it is never rendered by the PTY.
	// LF is the canonical line delimiter on the non-raw PTY used by su and
	// does not depend on the remote ICRNL setting accepting a carriage return.
	if _, writeErr := io.WriteString(stdin, s.rootPassword+"\n"); writeErr != nil {
		_ = session.Close()
		return commandResult{err: fmt.Errorf("send root password: %w", writeErr)}
	}
	_ = stdin.Close()

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		_ = session.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		return commandResult{
			stdout: stdout.String(),
			stderr: stderr.String(),
			err: fmt.Errorf(
				"root escalation command timed out after %s: %w",
				timeout,
				errRemoteCommandTimeout,
			),
		}
	}

	result := commandResult{stdout: stdout.String(), stderr: stderr.String()}
	if stdout.truncated {
		result.err = errors.New("root command output exceeded 4 MB")
		return result
	}
	body, exitCode, found := parseRootScriptOutput(result.stdout, readyMarker, doneMarker)
	if !found {
		if waitErr == nil {
			result.err = errors.New(rootFailureMessage(result))
			return result
		}
		result.exitCode = -1
		if errors.Is(waitErr, errRemoteCommandTimeout) {
			result.err = waitErr
		} else {
			result.err = errors.New(rootFailureMessage(result))
		}
		return result
	}
	result.stdout = body
	result.exitCode = exitCode
	if waitErr != nil && exitCode < 0 {
		var exitErr *ssh.ExitError
		if errors.As(waitErr, &exitErr) {
			result.exitCode = exitErr.ExitStatus()
		} else {
			s.markDead()
			result.err = fmt.Errorf("run root command: %w", waitErr)
		}
	}
	return result
}

type markerResult struct {
	prefix []byte
	tail   []byte
	err    error
}

type rootMarkerState struct {
	mutex  sync.Mutex
	prefix []byte
}

func (state *rootMarkerState) store(prefix []byte) {
	state.mutex.Lock()
	state.prefix = append([]byte(nil), prefix...)
	state.mutex.Unlock()
}

func (state *rootMarkerState) snapshot() []byte {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	return append([]byte(nil), state.prefix...)
}

// waitForOutputMarker reads until an unforgeable marker is observed. It
// returns everything before the marker for diagnostics and preserves any
// bytes already read after it, so no protocol data is lost when the marker and
// following payload arrive in one SSH packet.
func waitForOutputMarker(reader io.Reader, marker string, timeout time.Duration) ([]byte, []byte, error) {
	if marker == "" {
		return nil, nil, errors.New("output marker is empty")
	}
	state := &rootMarkerState{}
	done := make(chan markerResult, 1)
	go func() {
		prefix, tail, err := readUntilOutputMarker(reader, marker, state)
		done <- markerResult{prefix: prefix, tail: tail, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.prefix, result.tail, result.err
	case <-timer.C:
		return state.snapshot(), nil, fmt.Errorf("remote output marker %q was not received within %s", marker, timeout)
	}
}

func readUntilOutputMarker(reader io.Reader, marker string, state *rootMarkerState) ([]byte, []byte, error) {
	needle := []byte(marker)
	var output bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		n, readErr := reader.Read(chunk)
		if n > 0 {
			_, _ = output.Write(chunk[:n])
			if index := bytes.Index(output.Bytes(), needle); index >= 0 {
				all := append([]byte(nil), output.Bytes()...)
				return all[:index], all[index+len(needle):], nil
			}
			// Keep enough recent bytes to recognize a marker split across reads
			// while preventing a noisy login banner from growing without bound.
			if output.Len() > dockerErrorOutputLimit {
				data := output.Bytes()
				keep := len(needle)
				if keep < 1 {
					keep = 1
				}
				trimmed := append([]byte(nil), data[len(data)-keep:]...)
				output.Reset()
				_, _ = output.Write(trimmed)
			}
			state.store(output.Bytes())
		}
		if readErr != nil {
			state.store(output.Bytes())
			return output.Bytes(), nil, fmt.Errorf("remote output ended before marker %q: %w", marker, readErr)
		}
	}
}

// openRootSFTPClient starts the external SFTP server as root over a PTY and
// performs an explicit two-stage handshake:
//
//  1. wait until the outer shell has started su, then send the root password;
//  2. wait until su has authenticated and raw sftp-server mode is ready, then
//     send the binary SFTP INIT packet.
//
// This ordering prevents password-prompt text or a queued newline from being
// interpreted as part of the SFTP protocol.
func openRootSFTPClient(s *shellSession) (*sftp.Client, *ssh.Session, error) {
	if s.rootSFTPPath == "" {
		if err := discoverRootSFTPPath(s); err != nil {
			return nil, nil, err
		}
	}
	session, sessionErr := withTimeout(sshSessionOpenTimeout, func() (*ssh.Session, error) {
		return s.sshClient.NewSession()
	})
	if sessionErr != nil {
		s.markDead()
		return nil, nil, fmt.Errorf("open root SFTP session: %w", sessionErr)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.ICRNL: 1}
	if ptyErr := session.RequestPty("xterm-256color", 24, 80, modes); ptyErr != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("request root SFTP PTY: %w", ptyErr)
	}
	stdin, stdinErr := session.StdinPipe()
	if stdinErr != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("open root SFTP input: %w", stdinErr)
	}
	stdout, stdoutErr := session.StdoutPipe()
	if stdoutErr != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("open root SFTP output: %w", stdoutErr)
	}

	authMarker := "__DBX_ROOT_SFTP_AUTH__" + randomHex(8)
	serverMarker := "__DBX_ROOT_SFTP_READY__" + randomHex(8)
	// In raw mode the marker is emitted without a newline so no terminator
	// can be mistaken for the first byte of an SFTP protocol packet.
	rootScript := "stty raw -echo 2>/dev/null || true\n" +
		"printf '%s' " + shellQuote(serverMarker) + "\n" +
		"exec " + shellQuote(s.rootSFTPPath)
	remoteCommand := "stty icrnl -echo 2>/dev/null || true; " +
		"printf '%s\\n' " + shellQuote(authMarker) + "; " +
		"exec su - " + shellQuote(s.rootUser) + " -c " + shellQuote(rootScript)
	if startErr := session.Start(remoteCommand); startErr != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("start root SFTP server: %w", startErr)
	}

	handshakeDeadline := time.Now().Add(4 * time.Second)
	remaining := func() time.Duration {
		left := time.Until(handshakeDeadline)
		if left < 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return left
	}

	authPrefix, authTail, authErr := waitForOutputMarker(stdout, authMarker, remaining())
	if authErr != nil {
		_ = session.Close()
		detail := strings.TrimSpace(string(authPrefix))
		if detail != "" {
			return nil, nil, fmt.Errorf("root SFTP authentication did not start: %w; remote output: %s", authErr, detail)
		}
		return nil, nil, fmt.Errorf("root SFTP authentication did not start: %w", authErr)
	}
	// LF is the canonical line delimiter on the non-raw PTY used by su.
	if _, writeErr := io.WriteString(stdin, s.rootPassword+"\n"); writeErr != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("send root SFTP password: %w", writeErr)
	}

	serverInput := io.Reader(stdout)
	if len(authTail) > 0 {
		serverInput = io.MultiReader(bytes.NewReader(authTail), stdout)
	}
	serverPrefix, serverTail, serverErr := waitForOutputMarker(serverInput, serverMarker, remaining())
	if serverErr != nil {
		_ = session.Close()
		detail := strings.TrimSpace(string(serverPrefix))
		if detail != "" {
			return nil, nil, fmt.Errorf("root SFTP server did not become ready: %w; remote output: %s", serverErr, detail)
		}
		return nil, nil, fmt.Errorf("root SFTP server did not become ready: %w", serverErr)
	}

	protocolInput := io.Reader(stdout)
	if len(serverTail) > 0 {
		protocolInput = io.MultiReader(bytes.NewReader(serverTail), stdout)
	}
	client, clientErr := withTimeout(remaining(), func() (*sftp.Client, error) {
		return sftp.NewClientPipe(protocolInput, stdin)
	})
	if clientErr != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("root SFTP setup failed: %w", clientErr)
	}
	return client, session, nil
}
