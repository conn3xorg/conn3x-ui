// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build !unix

package main

import "os/exec"

// killGroup leaves cmd as it is: there's no process group to kill here,
// and WaitDelay still bounds the wait.
func killGroup(*exec.Cmd) {}
