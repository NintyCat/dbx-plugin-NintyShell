package main

import "testing"

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
