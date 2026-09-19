//go:build windows

package main

import (
	"errors"
	"os/exec"
)

func configureProcessGroup(cmd *exec.Cmd) {}

func interruptGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func exitStatus(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func exitSignal(waitErr error) (string, bool) {
	return "", false
}
