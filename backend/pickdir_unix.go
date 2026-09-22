//go:build unix

package main

import (
	"os/exec"
	"runtime"
	"strings"
)

// pickDownloadDir opens a native folder chooser and returns the chosen
// directory. macOS uses the built-in osascript folder picker; Linux tries
// zenity, then kdialog. ok is false when unavailable or cancelled.
func pickDownloadDir() (string, bool) {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("osascript", "-e",
			`POSIX path of (choose folder with prompt "选择下载目录")`).Output()
		if err != nil {
			return "", false
		}
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir, true
		}
		return "", false
	}
	if out, err := exec.Command("zenity", "--file-selection", "--directory", "--title", "选择下载目录").Output(); err == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir, true
		}
	}
	if out, err := exec.Command("kdialog", "--getexistingdirectory", "~", "--title", "选择下载目录").Output(); err == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir, true
		}
	}
	return "", false
}
