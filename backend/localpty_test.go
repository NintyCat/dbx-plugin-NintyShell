package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

// The PTY shell must get exactly one TERM entry (ours), never the host's —
// the host GUI process usually has none or a wrong one.
func TestLocalPTYEnv(t *testing.T) {
	t.Setenv("TERM", "dumb")
	t.Setenv("COLORTERM", "24bit")
	env := localPTYEnv()
	terms := 0
	colors := 0
	for _, entry := range env {
		switch {
		case strings.HasPrefix(entry, "TERM="):
			terms++
			if entry != "TERM=xterm-256color" {
				t.Errorf("TERM entry = %q, want TERM=xterm-256color", entry)
			}
		case strings.HasPrefix(entry, "COLORTERM="):
			colors++
		}
	}
	if terms != 1 || colors != 1 {
		t.Errorf("localPTYEnv() terms=%d colors=%d, want 1 and 1", terms, colors)
	}
}

// A local connection with an unusable shell must fail the form validation
// instead of starting a half-broken session.
func TestConnectLocalRejectsBadShell(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{}}
	values := map[string]any{
		"connection": map[string]any{"id": "bad-shell"},
		"config":     map[string]any{"shell_path": "/nonexistent/shell-xyz"},
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	session, rawResult, pluginErr := plug.connectLocal(decoded, "bad-shell", nil)
	if pluginErr != nil {
		t.Fatalf("connectLocal returned protocol error: %v", pluginErr)
	}
	if session != nil {
		t.Fatal("connectLocal returned a session for an invalid shell")
	}
	result, ok := rawResult.(map[string]any)
	if !ok {
		t.Fatalf("connectLocal returned %T", rawResult)
	}
	if result["success"] != false {
		t.Errorf("success = %v, want false", result["success"])
	}
	if message, _ := result["message"].(string); !strings.Contains(message, "Shell not found") {
		t.Errorf("message = %q, want shell resolution failure", message)
	}
}

// A working local connection over the real handle path: connectLocal must
// report pty=true and register the session (unix runs the real PTY, windows
// runs ConPTY).
func TestConnectLocalStartsPty(t *testing.T) {
	if _, err := os.Stat(defaultShellPath()); err != nil {
		t.Skipf("default shell unavailable: %v", err)
	}
	plug := &plugin{sessions: map[string]*shellSession{}}
	values := map[string]any{
		"connection": map[string]any{"id": "pty-connect"},
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
	session, rawResult, pluginErr := plug.connectLocal(decoded, "pty-connect", &discardEmitter{})
	if pluginErr != nil {
		t.Fatalf("connectLocal returned protocol error: %v", pluginErr)
	}
	result, ok := rawResult.(map[string]any)
	if !ok {
		t.Fatalf("connectLocal returned %T", rawResult)
	}
	if result["pty"] != true {
		t.Fatalf("pty = %v, want true", result["pty"])
	}
	if session.localPty == nil {
		t.Fatal("session has no localPty after connect")
	}
	session.shutdown()
}

// discardEmitter swallows PTY output for tests that only exercise connect and
// teardown; use the fake emitter in localpty_session_test.go to assert on
// stream contents.
type discardEmitter struct{}

func (discardEmitter) Event(string, any) *dbxpluginsdk.PluginError { return nil }
