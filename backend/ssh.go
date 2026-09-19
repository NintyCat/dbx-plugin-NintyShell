package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

var errTimeout = errors.New("operation timed out")

// buildRemoteScript composes the remote shell payload: restore the session's
// working directory, run the command, then print a marker line carrying the
// exit code and new directory on stdout. The UI filters marker lines out of
// the terminal view; the marker also lands in the stream tail ring for parsing.
func buildRemoteScript(sid, cwd, command string) string {
	rcVar := "__dbx_rc_" + sid
	var builder strings.Builder
	if cwd != "" {
		builder.WriteString("cd " + shellQuote(cwd) + " 2>/dev/null\n")
	}
	builder.WriteString(command)
	builder.WriteString("\n")
	builder.WriteString(rcVar + "=$?\n")
	builder.WriteString("printf '\\n" + metaTag + sid + "__ %s %s\\n' \"$" + rcVar + "\" \"$(pwd)\"\n")
	return builder.String()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func (p *plugin) testSSH(values map[string]any) any {
	message, ok := sshProbe(values)
	return map[string]any{"success": ok, "message": message}
}

func sshProbe(values map[string]any) (string, bool) {
	host := strings.TrimSpace(configString(values, "host"))
	if host == "" {
		return "Host is required", false
	}
	user := strings.TrimSpace(configString(values, "username"))
	if user == "" {
		return "Username is required", false
	}
	port := configPort(values)
	auth, authErr := sshAuthMethods(values)
	if authErr != "" {
		return authErr, false
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // v1: host key verification is not persisted yet
		Timeout:         sshDialTimeout,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return fmt.Sprintf("SSH connect failed: %v", err), false
	}
	_ = client.Close()
	return fmt.Sprintf("SSH ready: %s@%s:%d", user, host, port), true
}

func sshAuthMethods(values map[string]any) ([]ssh.AuthMethod, string) {
	authType := configString(values, "auth_type")
	if authType == "" {
		authType = "password"
	}
	var methods []ssh.AuthMethod
	switch authType {
	case "password":
		secret := configSecret(values, "password")
		if secret == "" {
			return nil, "Password is required for password authentication"
		}
		methods = append(methods, ssh.Password(secret))
	case "private_key":
		keyPath := configString(values, "key_path")
		if keyPath == "" {
			return nil, "Private key path is required for key authentication"
		}
		if expanded, ok := expandHome(keyPath); ok {
			keyPath = expanded
		}
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, "Cannot read private key: " + err.Error()
		}
		var signer ssh.Signer
		if passphrase := configSecret(values, "key_passphrase"); passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, "Cannot parse private key: " + err.Error()
		}
		methods = append(methods, ssh.PublicKeys(signer))
	default:
		return nil, "Unknown auth type: " + authType
	}
	// Try password as a fallback when a key is configured but password exists.
	if authType != "password" {
		if secret := configSecret(values, "password"); secret != "" {
			methods = append(methods, ssh.Password(secret))
		}
	}
	return methods, ""
}

func (p *plugin) connectSSH(values map[string]any, connectionID string, emitter *dbxpluginsdk.Emitter) (*shellSession, any, *dbxpluginsdk.PluginError) {
	host := strings.TrimSpace(configString(values, "host"))
	if host == "" {
		return nil, map[string]any{"success": false, "message": "Host is required"}, nil
	}
	user := strings.TrimSpace(configString(values, "username"))
	if user == "" {
		return nil, map[string]any{"success": false, "message": "Username is required"}, nil
	}
	port := configPort(values)
	auth, authErr := sshAuthMethods(values)
	if authErr != "" {
		return nil, map[string]any{"success": false, "message": authErr}, nil
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // v1: host key verification is not persisted yet
		Timeout:         sshDialTimeout,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return nil, map[string]any{"success": false, "message": "SSH connect failed: " + err.Error()}, nil
	}
	home := fetchRemoteHome(client)
	session := &shellSession{
		id:        connectionID,
		kind:      "ssh",
		sid:       randomHex(8),
		sshClient: client,
		cwd:       home,
		home:      home,
	}
	// Open the interactive PTY shell immediately: this is the "real SSH
	// client" mode where keystrokes stream to the remote shell and output
	// streams back live.
	if err := openPTYShell(session, emitter); err != nil {
		_ = client.Close()
		return nil, map[string]any{"success": false, "message": "PTY shell failed: " + err.Error()}, nil
	}
	go keepaliveLoop(session)
	return session, map[string]any{
		"success": true,
		"message": fmt.Sprintf("SSH connected: %s@%s:%d", user, host, port),
		"cwd":     home,
		"sid":     session.sid,
	}, nil
}

func fetchRemoteHome(client *ssh.Client) string {
	session, sessionErr := withTimeout(sshDialTimeout, func() (*ssh.Session, error) {
		return client.NewSession()
	})
	if sessionErr != nil {
		return "/"
	}
	defer session.Close()
	out, outputErr := withTimeout(sshDialTimeout, func() ([]byte, error) {
		return session.Output("pwd")
	})
	if outputErr != nil {
		return "/"
	}
	home := strings.TrimSpace(string(out))
	if home == "" {
		return "/"
	}
	return home
}

func keepaliveLoop(s *shellSession) {
	defer guardPanic("keepalive")
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for range ticker.C {
		if s.isDead() {
			return
		}
		s.ptyMutex.Lock()
		client := s.sshClient
		s.ptyMutex.Unlock()
		if client == nil {
			return
		}
		if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			s.markDead()
			return
		}
	}
}

// openPTYShell starts an interactive remote shell with a PTY and streams raw
// output to the UI. Keystrokes arrive via shell/input.
func openPTYShell(s *shellSession, emitter *dbxpluginsdk.Emitter) error {
	if s.isDead() {
		return errors.New(s.deadError())
	}
	if s.sshClient == nil {
		return errors.New("SSH client is closed")
	}
	session, sessionErr := withTimeout(sshOpTimeout, func() (*ssh.Session, error) {
		return s.sshClient.NewSession()
	})
	if sessionErr != nil {
		s.markDead()
		return sessionErr
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		session.Close()
		return fmt.Errorf("request pty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return err
	}
	if err := session.Shell(); err != nil {
		session.Close()
		return fmt.Errorf("start remote shell: %v", err)
	}
	s.ptyMutex.Lock()
	s.ptySession = session
	s.ptyStdin = stdin
	s.ptyMutex.Unlock()

	sessionID := s.id
	go func() {
		defer guardPanic("pty-read")
		buf := make([]byte, 8192)
		for {
			n, readErr := stdout.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				_ = emitter.Event("shell/output", map[string]any{
					"connectionId": sessionID,
					"data":         chunk,
				})
			}
			if readErr != nil {
				_ = emitter.Event("shell/pty-closed", map[string]any{"connectionId": sessionID})
				return
			}
		}
	}()
	return nil
}

func (p *plugin) ptyInput(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return nil, dbxpluginsdk.NewError(-32000, "shell/input requires an SSH connection")
	}
	data, err := base64.StdEncoding.DecodeString(stringField(values, "data"))
	if err != nil {
		return nil, dbxpluginsdk.NewError(-32602, "Invalid input encoding")
	}
	current.ptyMutex.Lock()
	stdin := current.ptyStdin
	current.ptyMutex.Unlock()
	if stdin == nil {
		return fail("PTY shell is not open")
	}
	current.ptyWriteMu.Lock()
	_, writeErr := stdin.Write(data)
	current.ptyWriteMu.Unlock()
	if writeErr != nil {
		return fail("Input failed: " + writeErr.Error())
	}
	return map[string]any{"success": true}, nil
}

func (p *plugin) ptyResize(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": true}, nil
	}
	cols, _ := values["cols"].(float64)
	rows, _ := values["rows"].(float64)
	if cols < 2 || rows < 2 || cols > 1000 || rows > 1000 {
		return map[string]any{"success": true}, nil
	}
	current.ptyMutex.Lock()
	session := current.ptySession
	current.ptyMutex.Unlock()
	if session == nil {
		return map[string]any{"success": true}, nil
	}
	if err := session.WindowChange(int(rows), int(cols)); err != nil {
		return map[string]any{"success": true, "message": err.Error()}, nil
	}
	return map[string]any{"success": true}, nil
}

func (s *shellSession) remoteHome() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.home != "" {
		return s.home
	}
	return "/"
}

func (s *shellSession) startSSHExec(command string, emitter *dbxpluginsdk.Emitter) (*execRun, error) {
	if s.isDead() {
		return nil, errors.New(s.deadError())
	}
	if s.sshClient == nil {
		return nil, errors.New("SSH client is closed")
	}
	session, newSessionErr := withTimeout(sshOpTimeout, func() (*ssh.Session, error) {
		return s.sshClient.NewSession()
	})
	if newSessionErr != nil {
		s.markDead()
		return nil, fmt.Errorf("open SSH session: %v", newSessionErr)
	}
	stdout := &streamWriter{emitter: emitter, connectionID: s.id, limit: maxPtyOutputBytes, ringSize: 8192}
	stderr := &streamWriter{emitter: emitter, connectionID: s.id, limit: maxPtyOutputBytes}
	session.Stdout = stdout
	session.Stderr = stderr
	_, startErr := withTimeout(sshOpTimeout, func() (struct{}, error) {
		return struct{}{}, session.Start(buildRemoteScript(s.sid, s.currentCwd(), command))
	})
	if startErr != nil {
		session.Close()
		s.markDead()
		return nil, fmt.Errorf("start remote command: %v", startErr)
	}
	done := make(chan struct{})
	sessionID := s.id
	sid := s.sid

	cancel := func() { _ = session.Close() }
	wait := func() {
		defer guardPanic("wait-ssh")
		defer close(done)
		waitErr := session.Wait()
		exitCode := -1
		if waitErr == nil {
			exitCode = 0
		} else if exitErr, ok := waitErr.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		}
		metaCode, metaCwd, hasMeta := parseRingMeta(stdout.tail, sid)
		if hasMeta {
			exitCode = metaCode
		}
		signalName := ""
		var missing *ssh.ExitMissingError
		if errors.As(waitErr, &missing) {
			signalName = "killed"
		}

		s.mutex.Lock()
		s.busy = false
		s.cancelFn = nil
		cancelled := s.cancelled && waitErr != nil
		if hasMeta && metaCwd != "" {
			s.cwd = metaCwd
		}
		cwd := s.cwd
		s.mutex.Unlock()

		emitExit(emitter, sessionID, exitCode, cwd, signalName, cancelled, stdout.truncated || stderr.truncated)
	}
	return &execRun{cancel: cancel, wait: wait, done: done}, nil
}

// ensureRemoteData lazily caches the remote PATH executable names and
// environment variable names so Tab completion works against the remote host.
func (s *shellSession) ensureRemoteData() {
	s.remoteMutex.Lock()
	defer s.remoteMutex.Unlock()
	if s.remoteLoaded {
		return
	}
	s.remoteLoaded = true
	if s.isDead() || s.sshClient == nil {
		return
	}
	session, sessionErr := withTimeout(sshOpTimeout, func() (*ssh.Session, error) {
		return s.sshClient.NewSession()
	})
	if sessionErr != nil {
		s.markDead()
		return
	}
	out, outputErr := withTimeout(sshOpTimeout, func() ([]byte, error) {
		return session.Output("printf '__DBX_PATH__%s\\n' \"$PATH\"; printenv | cut -d= -f1")
	})
	session.Close()
	if outputErr != nil {
		if errors.Is(outputErr, errTimeout) {
			s.markDead()
		}
		return
	}
	lines := strings.Split(string(out), "\n")
	for index, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "__DBX_PATH__") {
			s.remotePathDirs = strings.Split(strings.TrimPrefix(line, "__DBX_PATH__"), ":")
			lines = append(lines[:index], lines[index+1:]...)
			break
		}
	}
	envSet := make(map[string]bool, 64)
	for _, line := range lines {
		if name := strings.TrimSpace(line); name != "" && !envSet[name] {
			envSet[name] = true
			s.remoteEnvNames = append(s.remoteEnvNames, name)
		}
	}
	sort.Strings(s.remoteEnvNames)

	client, err := s.sftpClient()
	if err != nil {
		return
	}
	commandSet := make(map[string]bool, 256)
	for _, dir := range s.remotePathDirs {
		entries, err := client.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || commandSet[entry.Name()] {
				continue
			}
			if entry.Mode().Perm()&0111 != 0 {
				commandSet[entry.Name()] = true
			}
		}
	}
	for name := range commandSet {
		s.remoteCommands = append(s.remoteCommands, name)
	}
	sort.Strings(s.remoteCommands)
}

func (s *shellSession) remoteCommandCompletions(token string) []string {
	s.ensureRemoteData()
	builtinSet := make(map[string]bool, len(shellBuiltins))
	for _, name := range shellBuiltins {
		builtinSet[name] = true
	}
	remoteSet := make(map[string]bool, len(s.remoteCommands))
	for _, name := range s.remoteCommands {
		remoteSet[name] = true
	}
	seen := make(map[string]bool, 32)
	out := make([]string, 0, 16)
	add := func(name string) bool {
		if name == "" || !strings.HasPrefix(name, token) || seen[name] {
			return false
		}
		seen[name] = true
		out = append(out, name)
		return len(out) >= maxCommandItems
	}
	// Curated everyday commands first, filtered to those the remote actually has.
	for _, name := range commonCommands {
		if !builtinSet[name] && !remoteSet[name] {
			continue
		}
		if add(name) {
			return out
		}
	}
	for _, name := range s.remoteCommands {
		if add(name) {
			return out
		}
	}
	return out
}

func (s *shellSession) remoteEnvCompletions(token string) []string {
	s.ensureRemoteData()
	prefix := strings.TrimPrefix(token, "$")
	var out []string
	for _, name := range s.remoteEnvNames {
		if strings.HasPrefix(name, prefix) {
			out = append(out, "$"+name)
		}
		if len(out) >= maxCompletionItems {
			break
		}
	}
	return out
}

func (s *shellSession) remotePathCompletions(token string) []string {
	client, err := s.sftpClient()
	if err != nil {
		return nil
	}
	dirPart := ""
	namePrefix := token
	if index := strings.LastIndex(token, "/"); index >= 0 {
		dirPart = token[:index+1]
		namePrefix = token[index+1:]
	}
	home := s.remoteHome()
	base := s.currentCwd()
	switch {
	case dirPart == "~":
		return nil
	case dirPart == "":
		// complete entries of the current directory
	case strings.HasPrefix(dirPart, "~/"):
		base = home + strings.TrimPrefix(dirPart, "~")
	case strings.HasPrefix(dirPart, "/"):
		base = dirPart
	default:
		base = path.Join(s.currentCwd(), dirPart)
	}
	if base != "/" {
		base = strings.TrimSuffix(base, "/")
	}
	entries, err := client.ReadDir(base)
	if err != nil {
		return nil
	}
	out := make([]string, 0, 16)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, namePrefix) {
			continue
		}
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(namePrefix, ".") {
			continue
		}
		candidate := dirPart + name
		switch {
		case entry.IsDir():
			candidate += "/"
		case entry.Mode().Type()&os.ModeSymlink != 0:
			if info, err := client.Stat(path.Join(base, name)); err == nil && info.IsDir() {
				candidate += "/"
			}
		}
		out = append(out, candidate)
		if len(out) >= maxCompletionItems {
			break
		}
	}
	sort.Strings(out)
	return out
}

func (s *shellSession) sftpClient() (*sftp.Client, error) {
	if s.kind != "ssh" {
		return nil, errors.New("SFTP requires an SSH connection")
	}
	s.sftpMutex.Lock()
	defer s.sftpMutex.Unlock()
	if s.sftpConn != nil {
		return s.sftpConn, nil
	}
	if s.isDead() {
		return nil, errors.New(s.deadError())
	}
	if s.sshClient == nil {
		return nil, errors.New("SSH client is closed")
	}
	client, clientErr := withTimeout(sshOpTimeout, func() (*sftp.Client, error) {
		return sftp.NewClient(s.sshClient)
	})
	if clientErr != nil {
		if errors.Is(clientErr, errTimeout) {
			s.markDead()
		}
		return nil, fmt.Errorf("SFTP setup failed: %v", clientErr)
	}
	s.sftpConn = client
	return client, nil
}

func resolveRemotePath(s *shellSession, path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "~" {
		return s.remoteHome()
	}
	if strings.HasPrefix(trimmed, "~/") {
		return s.remoteHome() + strings.TrimPrefix(trimmed, "~")
	}
	return trimmed
}

func fail(message string) (map[string]any, *dbxpluginsdk.PluginError) {
	return map[string]any{"success": false, "message": message}, nil
}
