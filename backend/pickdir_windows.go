//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// pickDownloadDir opens the native folder chooser via Windows Forms and
// returns the selected directory. ok is false when unavailable or cancelled.
func pickDownloadDir() (string, bool) {
	script := "Add-Type -AssemblyName System.Windows.Forms; " +
		"$f = New-Object System.Windows.Forms.FolderBrowserDialog; " +
		"$f.Description = '选择下载目录'; " +
		"if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $f.SelectedPath }"
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", script).Output()
	if err != nil {
		return "", false
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", false
	}
	return dir, true
}
