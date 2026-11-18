// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// killGroup starts cmd in its own process group and, when its context
// ends, kills the group, so a child such as aws in "aws ... | base64 -d"
// goes with the shell.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
