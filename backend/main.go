package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

const (
	defaultShell        = "/bin/zsh"
	metaTag             = "__DBX_META__"
	maxOutputBytes      = 4 * 1024 * 1024
	maxPtyOutputBytes   = 1 << 30
	cancelGracePeriod   = 3 * time.Second
	metaReadGracePeriod = 1500 * time.Millisecond
	maxCompletionItems  = 200
	maxCommandItems     = 12
	sshDialTimeout      = 10 * time.Second
	sshOpTimeout        = 10 * time.Second
	keepaliveInterval   = 30 * time.Second
	sftpListLimit       = 500
	providerLocal       = "com.nintycat.shell.connection"
	providerSSH         = "com.nintycat.ssh.connection"
)

// metaStatement is appended to every local command. The child shell reports the
// command's exit code and the resulting working directory on fd 3, a pipe that
// belongs to this plugin alone, so the terminal stream stays clean.
const metaStatement = "printf '__DBX_META__ %s %s\\n' \"$?\" \"$(pwd)\" >&3\n"

// shellSession is one connection's execution context, either a local shell
// (directory persistence via per-command processes) or a remote SSH host.
type shellSession struct {
	id        string
	kind      string // "local" or "ssh"
	shellPath string // local only
	sid       string // random salt for SSH meta markers
	home      string // remote home (SSH)

	sshClient *ssh.Client
	sftpMutex sync.Mutex
	sftpConn  *sftp.Client

	ptyMutex   sync.Mutex
	ptySession *ssh.Session
	ptyStdin   io.WriteCloser
	ptyWriteMu sync.Mutex

	remoteMutex    sync.Mutex
	remoteLoaded   bool
	remoteCommands []string
	remoteEnvNames []string
	remotePathDirs []string

	deadMutex sync.RWMutex
	dead      bool

	mutex     sync.Mutex
	cwd       string
	busy      bool
	cancelled bool
	cancelFn  func()
	done      chan struct{}
}

func (s *shellSession) currentCwd() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.cwd
}

// markDead flags a broken SSH connection and closes the client, which
// unblocks every pending network call on that session.
func (s *shellSession) markDead() {
	s.deadMutex.Lock()
	wasDead := s.dead
	s.dead = true
	s.deadMutex.Unlock()
	if !wasDead && s.sshClient != nil {
		_ = s.sshClient.Close()
	}
}

func (s *shellSession) isDead() bool {
	s.deadMutex.RLock()
	defer s.deadMutex.RUnlock()
	return s.dead
}

func (s *shellSession) deadError() string {
	return "SSH connection lost. Please reconnect from the connection list."
}

// guardPanic recovers panics in background goroutines and dumps the trace to
// a file, because the dev host swallows sidecar stderr.
func guardPanic(where string) {
	if r := recover(); r != nil {
		message := fmt.Sprintf("[%s] panic: %v\n%s\n", where, r, debug.Stack())
		_ = os.WriteFile("/tmp/nintyshell-panic.log", []byte(message), 0o644)
		log.Printf("panic in %s: %v", where, r)
	}
}

// withTimeout bounds a network call so a dead connection fails fast instead of
// hanging the whole session.
func withTimeout[T any](d time.Duration, f func() (T, error)) (T, error) {
	type outcome struct {
		value T
		err   error
	}
	ch := make(chan outcome, 1)
	go func() {
		value, err := f()
		ch <- outcome{value, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case result := <-ch:
		return result.value, result.err
	case <-timer.C:
		var zero T
		return zero, errors.New("operation timed out")
	}
}

func (s *shellSession) shutdown() {
	s.mutex.Lock()
	cancel := s.cancelFn
	s.cancelFn = nil
	s.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
	if s.kind == "ssh" {
		s.ptyMutex.Lock()
		if s.ptySession != nil {
			_ = s.ptySession.Close()
			s.ptySession = nil
			s.ptyStdin = nil
		}
		s.ptyMutex.Unlock()
		s.sftpMutex.Lock()
		if s.sftpConn != nil {
			_ = s.sftpConn.Close()
			s.sftpConn = nil
		}
		s.sftpMutex.Unlock()
		s.markDead()
	}
}

// execRun is one running command: a cancel hook and a wait function that
// updates session state and emits the shell/exit event.
type execRun struct {
	cancel func()
	wait   func()
	done   chan struct{}
}

type plugin struct {
	mutex    sync.Mutex
	sessions map[string]*shellSession
}

func (p *plugin) Handle(ctx dbxpluginsdk.RequestContext, method string, params json.RawMessage, emitter *dbxpluginsdk.Emitter) (any, *dbxpluginsdk.PluginError) {
	defer guardPanic("handle:" + method)
	return p.handle(ctx, method, params, emitter)
}

func (p *plugin) handle(_ dbxpluginsdk.RequestContext, method string, params json.RawMessage, emitter *dbxpluginsdk.Emitter) (any, *dbxpluginsdk.PluginError) {
	values := map[string]any{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &values); err != nil {
			return nil, dbxpluginsdk.NewError(-32602, "Invalid request parameters")
		}
	}
	switch method {
	case "connection/test":
		return p.testConnection(values), nil
	case "connection/connect":
		return p.connect(values, emitter)
	case "connection/disconnect":
		return p.disconnect(values)
	case "shell/exec":
		return p.execCommand(values, emitter)
	case "shell/cancel":
		return p.cancelCommand(values)
	case "shell/cwd":
		return p.workingDir(values)
	case "shell/complete":
		return p.complete(values)
	case "shell/input":
		return p.ptyInput(values)
	case "shell/resize":
		return p.ptyResize(values)
	case "sftp/list":
		return p.sftpList(values)
	case "sftp/mkdir":
		return p.sftpMkdir(values)
	case "sftp/delete":
		return p.sftpDelete(values)
	case "sftp/rename":
		return p.sftpRename(values)
	case "sftp/uploadBegin":
		return p.sftpUploadBegin(values)
	case "sftp/uploadChunk":
		return p.sftpUploadChunk(values)
	case "sftp/uploadEnd":
		return p.sftpUploadEnd(values)
	case "sftp/download":
		return p.sftpDownload(values)
	case "filesystem/list":
		return p.fsList(values)
	case "filesystem/read":
		return p.fsRead(values)
	case "filesystem/write":
		return p.fsWrite(values)
	case "filesystem/createDirectory":
		return p.fsCreateDirectory(values)
	case "filesystem/delete":
		return p.fsDelete(values)
	case "filesystem/rename":
		return p.fsRename(values)
	default:
		return nil, dbxpluginsdk.MethodNotFound(method)
	}
}

func (p *plugin) sessionFor(values map[string]any) (*shellSession, *dbxpluginsdk.PluginError) {
	sessionID := requestSessionID(values)
	if sessionID == "" {
		return nil, dbxpluginsdk.NewError(-32602, "Missing connectionId")
	}
	p.mutex.Lock()
	current := p.sessions[sessionID]
	p.mutex.Unlock()
	if current == nil {
		return nil, dbxpluginsdk.NewError(-32000, "Session is not connected")
	}
	return current, nil
}

func (p *plugin) testConnection(values map[string]any) any {
	if providerID(values) == providerSSH {
		return p.testSSH(values)
	}
	shellPath, shellErr := resolveShell(configString(values, "shell_path"))
	if shellErr != "" {
		return map[string]any{"success": false, "message": shellErr}
	}
	dir, dirErr := resolveWorkingDir(configString(values, "working_dir"))
	if dirErr != "" {
		return map[string]any{"success": false, "message": dirErr}
	}
	return map[string]any{
		"success": true,
		"message": fmt.Sprintf("Shell ready: %s", shellPath),
		"shell":   shellPath,
		"cwd":     dir,
	}
}

func (p *plugin) connect(values map[string]any, emitter *dbxpluginsdk.Emitter) (any, *dbxpluginsdk.PluginError) {
	connectionID, pluginErr := requestConnectionID(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	var newSession *shellSession
	var result any
	var pluginErr2 *dbxpluginsdk.PluginError
	if providerID(values) == providerSSH {
		newSession, result, pluginErr2 = p.connectSSH(values, connectionID, emitter)
	} else {
		newSession, result, pluginErr2 = p.connectLocal(values, connectionID)
	}
	if pluginErr2 != nil {
		return nil, pluginErr2
	}
	if newSession != nil {
		p.mutex.Lock()
		previous := p.sessions[connectionID]
		p.sessions[connectionID] = newSession
		p.mutex.Unlock()
		if previous != nil {
			previous.shutdown()
		}
	}
	return result, nil
}

func (p *plugin) connectLocal(values map[string]any, connectionID string) (*shellSession, any, *dbxpluginsdk.PluginError) {
	shellPath, shellErr := resolveShell(configString(values, "shell_path"))
	if shellErr != "" {
		return nil, map[string]any{"success": false, "message": shellErr}, nil
	}
	dir, dirErr := resolveWorkingDir(configString(values, "working_dir"))
	if dirErr != "" {
		return nil, map[string]any{"success": false, "message": dirErr}, nil
	}
	session := &shellSession{id: connectionID, kind: "local", shellPath: shellPath, cwd: dir}
	return session, map[string]any{
		"success": true,
		"message": "Shell session started",
		"shell":   shellPath,
		"cwd":     dir,
	}, nil
}

func (p *plugin) disconnect(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	connectionID, pluginErr := requestConnectionID(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	p.mutex.Lock()
	current := p.sessions[connectionID]
	delete(p.sessions, connectionID)
	p.mutex.Unlock()
	if current != nil {
		current.shutdown()
	}
	return map[string]any{"success": true}, nil
}

func (p *plugin) execCommand(values map[string]any, emitter *dbxpluginsdk.Emitter) (any, *dbxpluginsdk.PluginError) {
	sessionID := requestSessionID(values)
	if sessionID == "" {
		return nil, dbxpluginsdk.NewError(-32602, "Missing connectionId")
	}
	command, _ := values["command"].(string)
	if strings.TrimSpace(command) == "" {
		return nil, dbxpluginsdk.NewError(-32602, "Empty command")
	}
	p.mutex.Lock()
	current := p.sessions[sessionID]
	p.mutex.Unlock()
	if current == nil {
		return nil, dbxpluginsdk.NewError(-32000, "Session is not connected")
	}
	if current.kind == "ssh" && current.isDead() {
		return nil, dbxpluginsdk.NewError(-32000, current.deadError())
	}

	current.mutex.Lock()
	if current.busy {
		current.mutex.Unlock()
		return nil, dbxpluginsdk.NewError(-32000, "Another command is still running")
	}
	current.cancelled = false
	// Claim the busy slot before any network call: a stalled SSH connection
	// must not hold the session lock and block cancel/cwd requests.
	current.busy = true
	current.mutex.Unlock()

	var handle *execRun
	var err error
	if current.kind == "ssh" {
		handle, err = current.startSSHExec(command, emitter)
	} else {
		handle, err = current.startLocalExec(command, emitter)
	}
	if err != nil {
		current.mutex.Lock()
		current.busy = false
		current.mutex.Unlock()
		return nil, dbxpluginsdk.NewError(-32000, "Failed to start command: "+err.Error())
	}

	current.mutex.Lock()
	current.cancelFn = handle.cancel
	current.done = handle.done
	current.mutex.Unlock()

	go handle.wait()

	return map[string]any{"started": true, "connectionId": sessionID}, nil
}

func emitExit(emitter *dbxpluginsdk.Emitter, sessionID string, exitCode int, cwd, signal string, cancelled, truncated bool) {
	result := map[string]any{
		"connectionId": sessionID,
		"exitCode":     exitCode,
		"cwd":          cwd,
	}
	if signal != "" {
		result["signal"] = signal
	}
	if cancelled {
		result["cancelled"] = true
	}
	if truncated {
		result["truncated"] = true
	}
	_ = emitter.Event("shell/exit", result)
}

func (p *plugin) cancelCommand(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	current.mutex.Lock()
	if !current.busy || current.cancelFn == nil {
		current.mutex.Unlock()
		return map[string]any{"cancelled": false, "message": "No command is running"}, nil
	}
	cancel := current.cancelFn
	done := current.done
	current.cancelled = true
	current.mutex.Unlock()

	cancel()
	go func() {
		timer := time.NewTimer(cancelGracePeriod)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			// Local commands escalate to SIGKILL via their own cancel path.
			current.mutex.Lock()
			cancel := current.cancelFn
			current.mutex.Unlock()
			if cancel != nil {
				cancel()
			}
		}
	}()
	return map[string]any{"cancelled": true}, nil
}

func (p *plugin) workingDir(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind == "ssh" && current.isDead() {
		return nil, dbxpluginsdk.NewError(-32000, current.deadError())
	}
	current.mutex.Lock()
	defer current.mutex.Unlock()
	result := map[string]any{"cwd": current.cwd, "kind": current.kind}
	if current.kind == "local" {
		home, _ := os.UserHomeDir()
		result["shell"] = current.shellPath
		result["home"] = home
	} else {
		result["home"] = current.home
		result["sid"] = current.sid
	}
	return result, nil
}

// ---- local execution ----

type runningCommand struct {
	*exec.Cmd
	metaReader *os.File
	stdout     *streamWriter
	stderr     *streamWriter
}

func (s *shellSession) startLocalExec(command string, emitter *dbxpluginsdk.Emitter) (*execRun, error) {
	cmd, err := startCommand(s.shellPath, command, s.cwd, emitter, s.id)
	if err != nil && s.cwd != "" {
		// The previous working directory may have been deleted; fall back to home.
		if home, homeErr := os.UserHomeDir(); homeErr == nil {
			cmd, err = startCommand(s.shellPath, command, home, emitter, s.id)
			if err == nil {
				s.cwd = home
			}
		}
	}
	if err != nil {
		return nil, err
	}
	stdout, stderr := cmd.stdout, cmd.stderr
	metaLines := make(chan string, 4)
	go readMeta(cmd.metaReader, metaLines)
	done := make(chan struct{})
	sessionID := s.id

	cancel := func() { interruptGroup(cmd.Cmd) }
	wait := func() {
		defer guardPanic("wait-local")
		defer close(done)
		waitErr := cmd.Cmd.Wait()
		meta := ""
		select {
		case meta = <-metaLines:
		case <-time.After(metaReadGracePeriod):
		}
		metaReader := cmd.metaReader
		metaReader.Close()

		exitCode, metaCwd, hasMeta := parseMetaLine(meta)
		if !hasMeta {
			exitCode = exitStatus(waitErr)
		}
		signalName, _ := exitSignal(waitErr)

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

func startCommand(shellPath, command, dir string, emitter *dbxpluginsdk.Emitter, sessionID string) (*runningCommand, error) {
	cmd := exec.Command(shellPath, "-c", command+"\n"+metaStatement)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	configureProcessGroup(cmd)

	stdout := &streamWriter{emitter: emitter, connectionID: sessionID, limit: maxOutputBytes}
	stderr := &streamWriter{emitter: emitter, connectionID: sessionID, limit: maxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	metaReader, metaWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{metaWriter}
	if err := cmd.Start(); err != nil {
		metaWriter.Close()
		metaReader.Close()
		return nil, err
	}
	// Drop the parent's copy so the read end sees EOF once the child exits.
	metaWriter.Close()
	return &runningCommand{Cmd: cmd, metaReader: metaReader, stdout: stdout, stderr: stderr}, nil
}

// ---- output streaming ----

// streamWriter forwards command output to the UI as shell/output events and
// enforces a per-stream cap so huge outputs cannot flood the bridge. When
// ringSize > 0 it also keeps the stream tail for marker parsing (SSH meta).
type streamWriter struct {
	emitter      *dbxpluginsdk.Emitter
	connectionID string
	limit        int
	written      int
	truncated    bool
	ringSize     int
	tail         []byte
}

func (w *streamWriter) Write(p []byte) (int, error) {
	total := len(p)
	if w.ringSize > 0 {
		w.tail = append(w.tail, p...)
		if len(w.tail) > w.ringSize {
			w.tail = w.tail[len(w.tail)-w.ringSize:]
		}
	}
	if w.written < w.limit {
		chunk := p
		if remaining := w.limit - w.written; len(p) > remaining {
			chunk = p[:remaining]
		}
		_ = w.emitter.Event("shell/output", map[string]any{
			"connectionId": w.connectionID,
			"data":         chunk,
		})
		w.written += len(chunk)
		if w.written >= w.limit {
			w.truncated = true
		}
	}
	return total, nil
}

func readMeta(file *os.File, lines chan<- string) {
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			select {
			case lines <- line:
			default:
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func parseMetaLine(raw string) (exitCode int, cwd string, ok bool) {
	line := strings.TrimRight(raw, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 || parts[0] != metaTag {
		return 0, "", false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, "", false
	}
	return code, parts[2], true
}

// parseRingMeta reads the trailing meta marker from an SSH stdout tail. The
// marker must be the final line of the stream.
func parseRingMeta(tail []byte, sid string) (exitCode int, cwd string, ok bool) {
	tag := metaTag + sid + "__ "
	trimmed := strings.TrimRight(string(tail), "\r\n")
	idx := strings.LastIndex(trimmed, tag)
	if idx < 0 {
		return 0, "", false
	}
	if lineStart := strings.LastIndex(trimmed, "\n") + 1; lineStart != idx {
		return 0, "", false
	}
	parts := strings.SplitN(trimmed[idx+len(tag):], " ", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	code, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", false
	}
	return code, parts[1], true
}

// ---- completion ----

var shellBuiltins = []string{
	"cd", "echo", "printf", "pwd", "export", "unset", "alias", "unalias",
	"source", "set", "type", "true", "false", "test", "exit", "return",
	"readonly", "wait", "umask", "history", "fc", "getopts", "hash",
}

// commonCommands ranks everyday commands first so short prefixes produce a
// meaningful menu instead of an alphabetical dump of every PATH executable.
var commonCommands = []string{
	"ls", "cd", "pwd", "cat", "echo", "mkdir", "rm", "cp", "mv", "touch",
	"grep", "find", "git", "curl", "ssh", "tar", "open", "brew", "python3", "node",
	"npm", "go", "docker", "ps", "top", "kill", "man", "which", "head", "tail",
	"less", "chmod", "chown", "nano", "vim", "diff", "sort", "uniq", "wc", "df",
	"du", "whoami", "date", "env", "history", "clear", "sudo", "wget", "zip", "unzip",
}

func (p *plugin) complete(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	sessionID := requestSessionID(values)
	if sessionID == "" {
		return nil, dbxpluginsdk.NewError(-32602, "Missing connectionId")
	}
	token, _ := values["token"].(string)
	commandPosition, _ := values["commandPosition"].(bool)
	directoryOnly, _ := values["directoryOnly"].(bool)
	p.mutex.Lock()
	current := p.sessions[sessionID]
	p.mutex.Unlock()
	if current == nil {
		return nil, dbxpluginsdk.NewError(-32000, "Session is not connected")
	}
	var candidates []string
	if current.kind == "ssh" {
		// Complete against the REMOTE machine: paths via SFTP, commands and
		// env names from the remote environment.
		if !directoryOnly && strings.HasPrefix(token, "$") && !strings.Contains(token, "/") {
			candidates = current.remoteEnvCompletions(token)
		} else if commandPosition && !strings.Contains(token, "/") {
			candidates = current.remoteCommandCompletions(token)
		} else {
			candidates = current.remotePathCompletions(token)
		}
	} else {
		current.mutex.Lock()
		cwd := current.cwd
		current.mutex.Unlock()
		candidates = completionsFor(token, commandPosition, directoryOnly, cwd)
	}
	return map[string]any{"candidates": candidates}, nil
}

func completionsFor(token string, commandPosition, directoryOnly bool, cwd string) []string {
	if !directoryOnly && strings.HasPrefix(token, "$") && !strings.Contains(token, "/") {
		return envCompletions(token)
	}
	if commandPosition && !strings.Contains(token, "/") {
		return commandCompletions(token)
	}
	return pathCompletions(token, cwd)
}

func envCompletions(token string) []string {
	prefix := strings.TrimPrefix(token, "$")
	var out []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name != "" && strings.HasPrefix(name, prefix) {
			out = append(out, "$"+name)
		}
	}
	sort.Strings(out)
	if len(out) > maxCompletionItems {
		out = out[:maxCompletionItems]
	}
	return out
}

func commandCompletions(token string) []string {
	builtinSet := make(map[string]bool, len(shellBuiltins))
	for _, name := range shellBuiltins {
		builtinSet[name] = true
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
	// Curated everyday commands first; externals must exist on this machine.
	for _, name := range commonCommands {
		if _, err := exec.LookPath(name); err != nil && !builtinSet[name] {
			continue
		}
		if add(name) {
			return out
		}
	}
	// Then the rest of PATH, alphabetically.
	dirs := filepath.SplitList(os.Getenv("PATH"))
	sort.Strings(dirs)
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if info, err := entry.Info(); err != nil || info.Mode()&0111 == 0 {
				continue
			}
			if add(entry.Name()) {
				return out
			}
		}
	}
	return out
}

func pathCompletions(token string, cwd string) []string {
	dirPart := ""
	namePrefix := token
	if index := strings.LastIndex(token, "/"); index >= 0 {
		dirPart = token[:index+1]
		namePrefix = token[index+1:]
	}
	base := cwd
	if expanded, ok := expandHome(dirPart); ok {
		base = expanded
	} else if dirPart != "" {
		if filepath.IsAbs(dirPart) {
			base = dirPart
		} else {
			base = filepath.Join(cwd, dirPart)
		}
	}
	entries, err := os.ReadDir(base)
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
		case entry.Type()&os.ModeSymlink != 0:
			if info, err := os.Stat(filepath.Join(base, name)); err == nil && info.IsDir() {
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

// ---- config parsing ----

func configString(values map[string]any, key string) string {
	for _, root := range []any{values["connection"], values} {
		rootObject, ok := root.(map[string]any)
		if !ok {
			continue
		}
		for _, container := range []string{"external_config", "config", "values"} {
			node, ok := rootObject[container].(map[string]any)
			if !ok {
				continue
			}
			if value, ok := node[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
		if value, ok := rootObject[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func configSecret(values map[string]any, key string) string {
	for _, root := range []any{values["connection"], values} {
		rootObject, ok := root.(map[string]any)
		if !ok {
			continue
		}
		for _, container := range []string{"connection_secrets", "secrets"} {
			node, ok := rootObject[container].(map[string]any)
			if !ok {
				continue
			}
			if value, ok := node[key].(string); ok && value != "" {
				return value
			}
		}
		if value, ok := rootObject[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func configPort(values map[string]any) int {
	connection, _ := values["connection"].(map[string]any)
	if connection != nil {
		if port, ok := connection["port"].(float64); ok && port > 0 && port < 65536 {
			return int(port)
		}
	}
	if port, ok := values["port"].(float64); ok && port > 0 && port < 65536 {
		return int(port)
	}
	return 22
}

func providerID(values map[string]any) string {
	provider, _ := values["provider"].(map[string]any)
	if id, _ := provider["id"].(string); id != "" {
		return id
	}
	connection, _ := values["connection"].(map[string]any)
	if connection != nil {
		if id, _ := connection["plugin_connection_provider"].(string); id != "" {
			return id
		}
	}
	return providerLocal
}

func requestSessionID(values map[string]any) string {
	if id, ok := values["connectionId"].(string); ok && id != "" {
		return id
	}
	connection, _ := values["connection"].(map[string]any)
	id, _ := connection["id"].(string)
	return id
}

func requestConnectionID(values map[string]any) (string, *dbxpluginsdk.PluginError) {
	connection, _ := values["connection"].(map[string]any)
	connectionID, _ := connection["id"].(string)
	if connectionID == "" {
		return "", dbxpluginsdk.NewError(-32602, "Missing connection id")
	}
	return connectionID, nil
}

func expandHome(path string) (string, bool) {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path, false
		}
		return home, true
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path, false
		}
		return filepath.Join(home, path[2:]), true
	}
	return path, false
}

func resolveShell(path string) (string, string) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		trimmed = defaultShell
	}
	if expanded, ok := expandHome(trimmed); ok {
		trimmed = expanded
	}
	resolved, err := exec.LookPath(trimmed)
	if err != nil {
		return "", fmt.Sprintf("Shell not found or not executable: %s", trimmed)
	}
	return resolved, ""
}

func resolveWorkingDir(path string) (string, string) {
	trimmed := strings.TrimSpace(path)
	if expanded, ok := expandHome(trimmed); ok {
		trimmed = expanded
	}
	if trimmed == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "Cannot determine home directory: " + err.Error()
		}
		trimmed = home
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", "Invalid working directory: " + err.Error()
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Sprintf("Working directory not accessible: %s", absolute)
	}
	if !info.IsDir() {
		return "", fmt.Sprintf("Not a directory: %s", absolute)
	}
	return absolute, ""
}

func randomHex(bytesCount int) string {
	buffer := make([]byte, bytesCount)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

// Sidecar 身份必须与包根 manifest.json 完全一致（由 version_test.go 守护）
const (
	pluginID      = "com.nintycat.shell"
	pluginVersion = "0.5.0"
)

func main() {
	metadata := dbxpluginsdk.Metadata{
		ID:           pluginID,
		Version:      pluginVersion,
		Capabilities: []string{"connections", "events"},
	}
	server := dbxpluginsdk.NewServer(metadata, &plugin{sessions: map[string]*shellSession{}})
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
