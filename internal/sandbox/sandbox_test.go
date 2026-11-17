// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMain lets the test binary be the sandboxed program's starter, as
// conn3x-ui is.
func TestMain(m *testing.M) {
	Exec()
	os.Exit(m.Run())
}

func TestSandbox(t *testing.T) {
	if _, err := Available(); err != nil {
		t.Skip("no Landlock here:", err)
	}
	dir := t.TempDir()
	run, secret := filepath.Join(dir, "run"), filepath.Join(dir, "data", "secret")
	os.MkdirAll(run, 0o700)
	os.MkdirAll(filepath.Dir(secret), 0o700)
	os.WriteFile(secret, []byte("key"), 0o600)
	cred := filepath.Join(dir, "cred")
	os.WriteFile(cred, []byte("cred"), 0o600)

	sh := func(script string) error {
		path, env, err := Command("sh", Policy{Write: []string{run}, Read: []string{cred}})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(path, "-c", script)
		cmd.Env = append(os.Environ(), env)
		out, err := cmd.CombinedOutput()
		t.Logf("%s: %s", script, out)
		return err
	}
	for _, ok := range []string{"cat " + cred, "cat /etc/hosts >/dev/null", "echo hi > " + run + "/f && cat " + run + "/f", "ls /usr/bin >/dev/null"} {
		if err := sh(ok); err != nil {
			t.Errorf("%q: %v, want it allowed", ok, err)
		}
	}
	for _, denied := range []string{"cat " + secret, "ls " + filepath.Dir(secret), "echo x > " + dir + "/g", "ls " + os.TempDir(), "ls /etc"} {
		if err := sh(denied); err == nil {
			t.Errorf("%q worked, want it denied", denied)
		}
	}
}
