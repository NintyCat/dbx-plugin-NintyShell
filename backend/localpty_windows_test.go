//go:build windows

package main

import "testing"

func TestWindowsCommandLine(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"powershell.exe", "-NoLogo"}, `powershell.exe -NoLogo`},
		{[]string{`C:\Program Files\PowerShell\7\pwsh.exe`, "-NoLogo"}, `"C:\Program Files\PowerShell\7\pwsh.exe" -NoLogo`},
		{[]string{`C:\trailing\path\`, "arg"}, `"C:\trailing\path\\" arg`},
		{[]string{`C:\we"ird\shell.exe`}, `"C:\we\"ird\shell.exe"`},
	}
	for _, tc := range cases {
		if got := windowsCommandLine(tc.argv); got != tc.want {
			t.Errorf("windowsCommandLine(%v) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}
