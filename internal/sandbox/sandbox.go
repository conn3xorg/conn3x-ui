// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package sandbox runs a program that can reach only the files it's
// given, with Linux Landlock. conn3x-ui starts itself with the policy in
// its environment; Exec, first thing in main, applies it and then
// replaces itself with the program, which keeps the policy, as does
// everything it starts.
package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

const envKey = "CONN3X_UI_SANDBOX"

// System is what any program needs to read: its libraries, the kernel's
// views, and the parts of /etc that name hosts, users, certificates and
// time zones. Not all of /etc, where a credentials key may live.
var System = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/nix/store", "/proc", "/sys", "/dev", "/run/systemd/resolve",
	"/etc/alternatives", "/etc/ca-certificates", "/etc/ca-certificates.conf", "/etc/crypto-policies", "/etc/gai.conf",
	"/etc/gitconfig", "/etc/group", "/etc/host.conf", "/etc/hostname", "/etc/hosts", "/etc/ld.so.cache", "/etc/ld.so.conf",
	"/etc/ld.so.conf.d", "/etc/localtime", "/etc/mime.types", "/etc/nsswitch.conf", "/etc/os-release", "/etc/passwd",
	"/etc/pki", "/etc/protocols", "/etc/resolv.conf", "/etc/services", "/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d",
	"/etc/ssh/ssh_known_hosts", "/etc/ssl", "/etc/timezone",
}

// Policy is what a program may reach, files or directories. Paths that
// don't exist are skipped.
type Policy struct {
	Program string   `json:"program"`
	Read    []string `json:"read"`
	// Write can be read, written and run from.
	Write []string `json:"write"`
}

// Available is the kernel's Landlock ABI version, or why there's none.
func Available() (int, error) {
	v, err := llsys.LandlockGetABIVersion()
	if err == nil && v < 1 {
		err = errors.New("Landlock isn't enabled")
	}
	return v, err
}

// Command is how to start program under p: the path to start instead,
// and a variable to add to its environment.
func Command(program string, p Policy) (path, env string, err error) {
	self, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	p.Program = program
	b, err := json.Marshal(p)
	return self, envKey + "=" + string(b), err
}

// Exec returns at once unless Command started this process. Then it
// applies the policy and execs the program with this process's arguments,
// or exits 126 saying why it couldn't.
func Exec() {
	v, ok := os.LookupEnv(envKey)
	if !ok {
		return
	}
	os.Unsetenv(envKey)
	if err := apply(v); err != nil {
		fmt.Fprintln(os.Stderr, "conn3x-ui sandbox:", err)
		os.Exit(126)
	}
}

// grant gives each path that exists the directory or the file rights, as
// fits it; Landlock refuses directory rights on a file.
func grant(paths []string, dirs, files func(...string) landlock.FSRule) []landlock.Rule {
	var d, f []string
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			d = append(d, p)
		} else if err == nil {
			f = append(f, p)
		}
	}
	return []landlock.Rule{dirs(d...).IgnoreIfMissing(), files(f...).IgnoreIfMissing()}
}

func apply(v string) error {
	var p Policy
	if err := json.Unmarshal([]byte(v), &p); err != nil {
		return err
	}
	// Found before the policy hides PATH's other directories.
	prog, err := exec.LookPath(p.Program)
	if err != nil {
		return err
	}
	if prog, err = filepath.Abs(prog); err != nil {
		return err
	}
	if _, err := Available(); err != nil {
		return fmt.Errorf("can't sandbox the run: %w", err)
	}
	// Best effort only lets an older kernel enforce the rights it knows.
	cfg := landlock.V11.BestEffort()
	rules := append(grant(append(append(System, p.Read...), prog), landlock.RODirs, landlock.ROFiles),
		grant(append(p.Write, "/dev/null", "/dev/tty"), landlock.RWDirs, landlock.RWFiles)...)
	err = cfg.RestrictPaths(rules...)
	if err != nil {
		return err
	}
	// Nor may it signal, or reach the abstract sockets of, anything
	// outside, conn3x-ui included.
	if err := cfg.RestrictScoped(); err != nil {
		return err
	}
	return syscall.Exec(prog, append([]string{p.Program}, os.Args[1:]...), os.Environ())
}
