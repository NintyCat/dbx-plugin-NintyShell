package main

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestRootSettings(t *testing.T) {
	cases := []struct {
		name        string
		values      map[string]any
		wantEnabled bool
		wantErr     string
	}{
		{
			name:   "disabled by default",
			values: map[string]any{},
		},
		{
			name: "password mode",
			values: map[string]any{
				"root_login":    "password",
				"root_password": "secret",
			},
			wantEnabled: true,
		},
		{
			name: "password mode requires password",
			values: map[string]any{
				"root_login": "password",
			},
			wantErr: "Root password is required",
		},
		{
			name: "disabled mode rejects stored password",
			values: map[string]any{
				"root_login":    "disabled",
				"root_password": "secret",
			},
			wantErr: "Root login mode must be set to Password",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enabled, password, err := rootSettings(c.values)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("rootSettings: %v", err)
			}
			if enabled != c.wantEnabled {
				t.Errorf("enabled = %v, want %v", enabled, c.wantEnabled)
			}
			if enabled && password != "secret" {
				t.Errorf("password = %q, want configured secret", password)
			}
		})
	}
}

func TestParseRootProbe(t *testing.T) {
	home, sftpPath := parseRootProbe("__DBX_ROOT_HOME__/root\r\n__DBX_ROOT_SFTP__/usr/lib/openssh/sftp-server\r\n")
	if home != "/root" {
		t.Errorf("home = %q, want /root", home)
	}
	if sftpPath != "/usr/lib/openssh/sftp-server" {
		t.Errorf("sftpPath = %q", sftpPath)
	}

	home, sftpPath = parseRootProbe("login banner\n__DBX_ROOT_HOME__/root\n")
	if home != "/root" || sftpPath != "" {
		t.Errorf("probe without server = (%q, %q)", home, sftpPath)
	}
}

func TestRootScriptRoundTrip(t *testing.T) {
	const ready = "__DBX_ROOT_READY__1234"
	const done = "__DBX_ROOT_DONE__5678"
	script := buildRootScript("printf 'hello\\n'", ready, done)
	if strings.Contains(script, "secret") {
		t.Fatal("root script unexpectedly contains a password")
	}
	if !strings.Contains(script, ready) || !strings.Contains(script, done) {
		t.Fatalf("script does not contain both markers: %q", script)
	}

	output := "Password prompt\r\n" + ready + "\r\nhello\n\r\n" + done + " 7\r\n"
	body, exitCode, found := parseRootScriptOutput(output, ready, done)
	if !found {
		t.Fatal("parseRootScriptOutput did not find markers")
	}
	if !strings.Contains(body, "hello") || strings.Contains(body, "Password prompt") {
		t.Errorf("body = %q, want command output without login prompt", body)
	}
	if exitCode != 7 {
		t.Errorf("exitCode = %d, want 7", exitCode)
	}

	if _, _, found := parseRootScriptOutput("authentication failure", ready, done); found {
		t.Error("parseRootScriptOutput accepted output without markers")
	}
}

func TestWaitForOutputMarkerPreservesTail(t *testing.T) {
	const marker = "__ROOT_READY_1234__"
	// strings.Reader returns the marker and following protocol bytes in one
	// read, covering the SSH packet case where tail data must not be dropped.
	prefix, tail, err := waitForOutputMarker(
		strings.NewReader("login banner\n"+marker+"binary-tail"),
		marker,
		time.Second,
	)
	if err != nil {
		t.Fatalf("waitForOutputMarker: %v", err)
	}
	if string(prefix) != "login banner\n" {
		t.Errorf("prefix = %q, want login banner", prefix)
	}
	if string(tail) != "binary-tail" {
		t.Errorf("tail = %q, want protocol bytes after marker", tail)
	}
}

func TestWaitForOutputMarkerHandlesSplitReads(t *testing.T) {
	const marker = "__ROOT_READY_1234__"
	prefix, _, err := waitForOutputMarker(
		iotest.OneByteReader(strings.NewReader("login banner\n"+marker)),
		marker,
		time.Second,
	)
	if err != nil {
		t.Fatalf("waitForOutputMarker: %v", err)
	}
	if string(prefix) != "login banner\n" {
		t.Errorf("prefix = %q, want login banner", prefix)
	}
}

func TestWaitForOutputMarkerReportsEOFOutput(t *testing.T) {
	const marker = "__ROOT_READY_1234__"
	prefix, tail, err := waitForOutputMarker(strings.NewReader("Authentication failure"), marker, time.Second)
	if err == nil {
		t.Fatal("waitForOutputMarker accepted EOF before marker")
	}
	if tail != nil || string(prefix) != "Authentication failure" {
		t.Errorf("prefix/tail = %q/%q, want remote failure output", prefix, tail)
	}
	if !strings.Contains(err.Error(), marker) {
		t.Errorf("error = %q, want missing marker", err)
	}
}

func TestWaitForOutputMarkerTimesOut(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	prefix, tail, err := waitForOutputMarker(reader, "__ROOT_READY_1234__", 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "was not received") {
		t.Fatalf("error = %v, want marker timeout", err)
	}
	if prefix != nil || tail != nil {
		t.Errorf("prefix/tail = %q/%q, want no completed marker payload", prefix, tail)
	}
}
