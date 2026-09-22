package main

import (
	"testing"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

// cwdRecorder captures shell/cwd-changed notifications for assertions.
type cwdRecorder struct {
	methods []string
	params  []map[string]any
}

func (r *cwdRecorder) Event(method string, params any) *dbxpluginsdk.PluginError {
	r.methods = append(r.methods, method)
	if record, ok := params.(map[string]any); ok {
		r.params = append(r.params, record)
	}
	return nil
}

// A Windows client must still accept the POSIX cwd reports of an SSH remote
// shell. Parsing them with runtime.GOOS used to drop every /home/... path,
// which silently disabled the terminal → file-panel follow on Windows.
func TestEmitOsc7CwdSSHKeepsRemotePath(t *testing.T) {
	s := &shellSession{id: "conn-1", kind: "ssh", cwd: "/home/u"}
	rec := &cwdRecorder{}

	emitOsc7Cwd(s, rec, "file://host/home/u/proj")
	if s.cwd != "/home/u/proj" {
		t.Fatalf("session cwd = %q, want %q", s.cwd, "/home/u/proj")
	}
	if len(rec.methods) != 1 || rec.methods[0] != "shell/cwd-changed" {
		t.Fatalf("events = %v, want one shell/cwd-changed", rec.methods)
	}
	if rec.params[0]["cwd"] != "/home/u/proj" || rec.params[0]["connectionId"] != "conn-1" {
		t.Fatalf("event params = %v, want cwd=/home/u/proj connectionId=conn-1", rec.params[0])
	}

	// An unchanged path must not re-notify the UI (follow loop guard).
	emitOsc7Cwd(s, rec, "file://host/home/u/proj")
	if len(rec.methods) != 1 {
		t.Fatalf("duplicate event for unchanged cwd: %v", rec.methods)
	}
}

func TestOsc7Scanner(t *testing.T) {
	s := &osc7Scanner{}
	if uri := s.feed([]byte("prompt \x1b]7;file:///home/u\x1b\\ rest")); uri != "file:///home/u" {
		t.Fatalf("ST-terminated uri = %q", uri)
	}

	// payload split across two reads
	split := &osc7Scanner{}
	if uri := split.feed([]byte("out\x1b]7;file:///ho")); uri != "" {
		t.Fatalf("premature uri = %q", uri)
	}
	if uri := split.feed([]byte("me/u\x07tail")); uri != "file:///home/u" {
		t.Fatalf("split uri = %q", uri)
	}

	// multiple reports in one chunk: the last one wins
	s3 := &osc7Scanner{}
	uri := s3.feed([]byte("\x1b]0;title\x07\x1b]7;file:///a\x07text\x1b]7;file:///b\x07"))
	if uri != "file:///b" {
		t.Fatalf("multi uri = %q", uri)
	}

	// unterminated payload must not wedge the scanner
	s4 := &osc7Scanner{}
	if uri := s4.feed([]byte("\x1b]7;file:///runaway")); uri != "" {
		t.Fatalf("unterminated uri = %q", uri)
	}
	if uri := s4.feed(make([]byte, 20000)); uri != "" && len(s4.pending) > 8192 {
		t.Fatalf("runaway payload not bounded: %d", len(s4.pending))
	}
}

func TestOsc7URIToPath(t *testing.T) {
	cases := []struct {
		uri, goos, want string
	}{
		{"file:///home/u", "linux", "/home/u"},
		{"file://host/home/u", "linux", "/home/u"},
		{"file://%2Fhome%2Fu%20name", "linux", "/home/u name"},
		{"/home/u", "linux", "/home/u"},
		{"file://relative", "linux", ""},
		{"", "linux", ""},
		{"file://C%3A%5CUsers%5Cx", "windows", `C:\Users\x`},
		{"file:///C%3A/Users/x", "windows", `C:\Users\x`},
		{"file:///home/u", "windows", ""},
	}
	for _, tc := range cases {
		if got := osc7URIToPath(tc.uri, tc.goos); got != tc.want {
			t.Errorf("osc7URIToPath(%q, %s) = %q, want %q", tc.uri, tc.goos, got, tc.want)
		}
	}
}
