package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMetaFileValue(t *testing.T) {
	cases := []struct {
		raw  string
		code int
		cwd  string
		ok   bool
	}{
		{"0|/home/nintycat", 0, "/home/nintycat", true},
		{"130|/tmp", 130, "/tmp", true},
		{"1|C:\\Users\\nintycat", 1, "C:\\Users\\nintycat", true},
		{" 2 | /opt ", 2, "/opt", true},
		{"", 0, "", false},
		{"garbage", 0, "", false},
		{"x|/tmp", 0, "", false},
	}
	for _, c := range cases {
		code, cwd, ok := parseMetaFileValue(c.raw)
		if ok != c.ok || (ok && (code != c.code || cwd != c.cwd)) {
			t.Errorf("parseMetaFileValue(%q) = (%d,%q,%v), want (%d,%q,%v)", c.raw, code, cwd, ok, c.code, c.cwd, c.ok)
		}
	}
}

func TestEncodePowerShellScript(t *testing.T) {
	// "hi" in UTF-16LE is 68 00 69 00.
	if got := encodePowerShellScript("hi"); got != "aABpAA==" {
		t.Errorf("encodePowerShellScript(%q) = %q", "hi", got)
	}
}

func TestPowershellWrapper(t *testing.T) {
	script := powershellWrapper("Get-ChildItem", `C:\tmp\dbx's meta\x.meta`)
	if !strings.Contains(script, "Get-ChildItem") {
		t.Error("wrapper must embed the user command")
	}
	// PowerShell single-quote escaping: ' doubles inside literal strings.
	if !strings.Contains(script, `'C:\tmp\dbx''s meta\x.meta'`) {
		t.Errorf("wrapper must escape single quotes in the meta path, got:\n%s", script)
	}
	for _, want := range []string{"$rc = 0", "$LASTEXITCODE", "[System.IO.File]::WriteAllText", "UTF8Encoding($false)", "try {", "} catch {", "[Console]::OutputEncoding"} {
		if !strings.Contains(script, want) {
			t.Errorf("wrapper missing %q", want)
		}
	}
	// Set-Content would use the ANSI codepage and mangle non-ASCII paths;
	// -Encoding UTF8 would prepend a BOM that breaks exit-code parsing.
	if strings.Contains(script, "Set-Content") {
		t.Error("wrapper must not use Set-Content (ANSI encoding mangles non-ASCII paths)")
	}
}

func TestReadMetaFileStripsBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.meta")
	if err := os.WriteFile(path, []byte("\ufeff3|C:\\Users\\张三\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, cwd, ok := parseMetaFileValue(readMetaFile(path))
	if !ok || code != 3 || cwd != `C:\Users\张三` {
		t.Errorf("readMetaFile+parse = (%d,%q,%v), want (3, C:\\Users\\张三, true)", code, cwd, ok)
	}
}

func TestShellStyleFor(t *testing.T) {
	if shellStyleFor("/bin/zsh") != posixShell {
		t.Error("unix shells must be posix style")
	}
}
