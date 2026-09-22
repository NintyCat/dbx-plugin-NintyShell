//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

// captureEmitter records every event the UI would receive so the test can
// tell a live session (shell/output bytes) from a silent one.
type captureEmitter struct {
	mutex   sync.Mutex
	methods []string
	text    []string
	bytes   int
}

func (c *captureEmitter) Event(method string, params any) *dbxpluginsdk.PluginError {
	c.mutex.Lock()
	c.methods = append(c.methods, method)
	if record, ok := params.(map[string]any); ok {
		if data, ok := record["data"].([]byte); ok {
			c.bytes += len(data)
			if method == "shell/output" {
				c.text = append(c.text, string(data))
			}
		}
	}
	c.mutex.Unlock()
	return nil
}

func (c *captureEmitter) snapshot() ([]string, int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]string(nil), c.methods...), c.bytes
}

// captureText concatenates every shell/output payload seen so far.
func captureText(c *captureEmitter) string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var b strings.Builder
	for _, s := range c.text {
		b.WriteString(s)
	}
	return b.String()
}

func truncateForLog(s string) string {
	if len(s) > 400 {
		return "..." + s[len(s)-400:]
	}
	return s
}

// TestLocalPTYWindowsInteractive is the regression test for the field
// failure where a local PowerShell session on ConPTY stayed completely
// silent (zero output within 4s) and fell back to per-command mode. It
// asserts output arrives, no fallback fires, typed commands echo back, and
// teardown does not hang.
func TestLocalPTYWindowsInteractive(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{}, fallbacks: map[string]bool{}}
	emitter := &captureEmitter{}
	values := map[string]any{
		"connection": map[string]any{"id": "repro"},
		"config":     map[string]any{"shell_path": defaultShellPath()},
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
	result, _ := rawResult.(map[string]any)
	t.Logf("connect result: pty=%v", result["pty"])

	session := plug.sessions["repro"]
	if session == nil {
		t.Fatal("no session registered")
	}
	defer session.shutdown()

	// The silent watcher fires at 4s; give it time and snapshot.
	time.Sleep(6 * time.Second)
	methods, bytes := emitter.snapshot()
	t.Logf("after 6s: bytes=%d events=%v", bytes, methods)
	if bytes == 0 {
		t.Fatal("REPRODUCED: silent session (zero output within 6s)")
	}
	for _, m := range methods {
		if m == "shell/legacy-fallback" {
			t.Fatal("session fell back to per-command mode: PTY still silent")
		}
	}

	// Interactive round trip: keystrokes must reach the shell and echo back
	// through the stream (this is what the xterm.js UI depends on).
	encoded := base64.StdEncoding.EncodeToString([]byte("echo dbxpty_$((40+2))\r"))
	if _, pluginErr := plug.ptyInput(map[string]any{
		"connectionId": "repro",
		"data":         encoded,
	}); pluginErr != nil {
		t.Fatalf("ptyInput: %v", pluginErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := captureText(emitter); strings.Contains(got, "dbxpty_42") {
			t.Logf("echo round trip ok: %q", truncateForLog(got))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no echo of typed command within 10s; stream=%q", truncateForLog(captureText(emitter)))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// noteSilentExit only runs when the session fell back; here we assert
	// the healthy path instead: keep the session alive briefly and confirm
	// output keeps flowing rather than dying after the first chunk.
	beforeBytes := func() int { _, n := emitter.snapshot(); return n }()
	time.Sleep(2 * time.Second)
	methods, bytes = emitter.snapshot()
	t.Logf("steady state: bytes=%d->%d events=%v", beforeBytes, bytes, methods)

	// Teardown must not wedge the test: a hang here means ClosePseudoConsole
	// is blocked (the field failure signature), which we want reported rather
	// than a stack-dump timeout.
	done := make(chan struct{}, 1)
	go func() {
		session.shutdown()
		done <- struct{}{}
	}()
	select {
	case <-done:
		t.Log("shutdown completed")
	case <-time.After(10 * time.Second):
		t.Error("shutdown hung for 10s: Close/release is blocked")
	}

	// Echo the probe log so the run output carries the diagnosis.
	if data, err := os.ReadFile(filepath.Join(pluginLogDir(), "pty.log")); err == nil {
		t.Logf("pty.log:\n%s", string(data))
	} else {
		t.Logf("pty.log unreadable: %v", err)
	}
}
