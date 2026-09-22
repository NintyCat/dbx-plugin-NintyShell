//go:build unix

package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

// fakeEmitter records PTY events so the test can assert on the byte stream
// the UI would receive.
type fakeEmitter struct {
	mutex  sync.Mutex
	events []ptyEvent
}

type ptyEvent struct {
	method string
	data   string
}

func (f *fakeEmitter) Event(method string, params any) *dbxpluginsdk.PluginError {
	record, _ := params.(map[string]any)
	data, _ := record["data"].([]byte)
	f.mutex.Lock()
	f.events = append(f.events, ptyEvent{method: method, data: string(data)})
	f.mutex.Unlock()
	return nil
}

func (f *fakeEmitter) output() string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var b strings.Builder
	for _, event := range f.events {
		if event.method == "shell/output" {
			b.WriteString(event.data)
		}
	}
	return b.String()
}

func (f *fakeEmitter) sawClosed() bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, event := range f.events {
		if event.method == "shell/pty-closed" {
			return true
		}
	}
	return false
}

// waitOutput polls the accumulated stream until want matches or the deadline
// passes; PTY output arrives asynchronously.
func waitOutput(t *testing.T, emitter *fakeEmitter, want func(string) bool, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		blob := emitter.output()
		if want(blob) {
			return blob
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for PTY output; got %q", truncate(blob, 2000))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func truncate(value string, n int) string {
	if len(value) > n {
		return value[len(value)-n:]
	}
	return value
}

// TestLocalPTYSession drives a whole local session over the plugin methods:
// connect starts a login shell on a PTY, keystrokes echo back with the
// inherited TERM, resize takes effect, and disconnect tears everything down.
func TestLocalPTYSession(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{}}
	emitter := &fakeEmitter{}
	home := t.TempDir()
	values := map[string]any{
		"connection": map[string]any{"id": "pty-e2e"},
		"config": map[string]any{
			"shell_path":  "/bin/sh",
			"working_dir": home,
		},
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	rawResult, pluginErr := plug.connect(decoded, emitter)
	if pluginErr != nil {
		t.Fatalf("connect: %v", pluginErr)
	}
	result, ok := rawResult.(map[string]any)
	if !ok {
		t.Fatalf("connect returned %T", rawResult)
	}
	if result["pty"] != true {
		t.Fatalf("pty = %v, want true", result["pty"])
	}
	session := plug.sessions["pty-e2e"]
	if session == nil || session.localPty == nil {
		t.Fatal("connect did not register a PTY session")
	}
	defer session.shutdown()

	// The login shell prints its prompt on the PTY.
	waitOutput(t, emitter, func(blob string) bool { return strings.Contains(blob, "$") || strings.Contains(blob, "#") }, 10*time.Second)

	// Type a command: the expanded result must come back through the stream.
	type_ := func(s string) {
		t.Helper()
		if _, pluginErr := plug.ptyInput(map[string]any{
			"connectionId": "pty-e2e",
			"data":         base64.StdEncoding.EncodeToString([]byte(s)),
		}); pluginErr != nil {
			t.Fatalf("ptyInput(%q): %v", s, pluginErr)
		}
	}
	type_("echo dbxpty_$((40+2))\r")
	waitOutput(t, emitter, func(blob string) bool { return strings.Contains(blob, "dbxpty_42") }, 10*time.Second)

	type_("echo dbxterm_$TERM\r")
	waitOutput(t, emitter, func(blob string) bool { return strings.Contains(blob, "dbxterm_xterm-256color") }, 10*time.Second)

	if _, pluginErr := plug.ptyResize(map[string]any{
		"connectionId": "pty-e2e",
		"cols":         float64(100),
		"rows":         float64(30),
	}); pluginErr != nil {
		t.Fatalf("ptyResize: %v", pluginErr)
	}
	type_("echo dbxsize_$(stty size)\r")
	waitOutput(t, emitter, func(blob string) bool { return strings.Contains(blob, "dbxsize_30 100") }, 10*time.Second)

	// shell/cwd reports the interactive session so the UI switches to xterm.
	info, pluginErr := plug.workingDir(map[string]any{"connectionId": "pty-e2e"})
	if pluginErr != nil {
		t.Fatalf("workingDir: %v", pluginErr)
	}
	infoMap, ok := info.(map[string]any)
	if !ok {
		t.Fatalf("workingDir returned %T", info)
	}
	if infoMap["pty"] != true || infoMap["kind"] != "local" {
		t.Fatalf("shell/cwd = %v, want pty=true kind=local", infoMap)
	}

	// A graceful disconnect removes the session and must NOT emit
	// shell/pty-closed: the UI already knows the connection is gone.
	if _, pluginErr := plug.disconnect(map[string]any{
		"connection": map[string]any{"id": "pty-e2e"},
	}); pluginErr != nil {
		t.Fatalf("disconnect: %v", pluginErr)
	}
	time.Sleep(300 * time.Millisecond)
	if emitter.sawClosed() {
		t.Error("shell/pty-closed emitted for a deliberately disconnected session")
	}
	if _, pluginErr := plug.ptyInput(map[string]any{
		"connectionId": "pty-e2e",
		"data":         base64.StdEncoding.EncodeToString([]byte("echo hi\r")),
	}); pluginErr == nil {
		t.Error("ptyInput after disconnect succeeded, want error")
	}
}

// Typing "exit" into the PTY ends the shell; the session must report closure
// so the UI shows the disconnected state.
func TestLocalPTYExitClosesSession(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{}}
	emitter := &fakeEmitter{}
	values := map[string]any{
		"connection": map[string]any{"id": "pty-exit"},
		"config":     map[string]any{"shell_path": "/bin/sh"},
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	rawResult, pluginErr := plug.connect(decoded, emitter)
	if pluginErr != nil {
		t.Fatalf("connect: %v", pluginErr)
	}
	result, ok := rawResult.(map[string]any)
	if !ok {
		t.Fatalf("connect returned %T", rawResult)
	}
	if result["pty"] != true {
		t.Fatalf("pty = %v, want true", result["pty"])
	}
	session := plug.sessions["pty-exit"]
	if session == nil || session.localPty == nil {
		t.Fatal("connect did not register a PTY session")
	}
	defer session.shutdown()
	waitOutput(t, emitter, func(blob string) bool { return strings.Contains(blob, "$") }, 10*time.Second)

	if _, pluginErr := plug.ptyInput(map[string]any{
		"connectionId": "pty-exit",
		"data":         base64.StdEncoding.EncodeToString([]byte("exit\r")),
	}); pluginErr != nil {
		t.Fatalf("ptyInput(exit): %v", pluginErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		session.mutex.Lock()
		closed := session.ptyClosed
		session.mutex.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session not marked closed after typing exit")
		}
		if emitter.sawClosed() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !emitter.sawClosed() {
		t.Error("shell/pty-closed not emitted after the shell exited")
	}
	// Further input fails softly (success=false), matching the SSH dead-path.
	replay, pluginErr := plug.ptyInput(map[string]any{
		"connectionId": "pty-exit",
		"data":         base64.StdEncoding.EncodeToString([]byte("echo hi\r")),
	})
	if pluginErr != nil {
		t.Fatalf("ptyInput after exit: %v", pluginErr)
	}
	replayMap, ok := replay.(map[string]any)
	if !ok || replayMap["success"] != false {
		t.Errorf("ptyInput after shell exit = %v, want success=false", replay)
	}
}
