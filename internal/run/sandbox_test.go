// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

func TestConn3xSandboxed(t *testing.T) {
	env := []string{"A=1", "CONN3X_CRED_KEY=/data/credentials/cred-1/key"}
	p := store.Project{Conn3xPath: "/opt/conn3x"}

	c, err := (&Runner{}).conn3x(1, p, "/tmp/run", "/tmp/run/repo", env)
	if err != nil || c.Path != "/opt/conn3x" || !slices.Equal(c.Env, env) {
		t.Fatalf("unsandboxed: %v %q %q", err, c.Path, c.Env)
	}

	c, err = (&Runner{Sandbox: true}).conn3x(1, p, "/tmp/run", "/tmp/run/repo", env)
	if err != nil {
		t.Fatal(err)
	}
	if self, _ := os.Executable(); c.Path != self || c.Dir != "/tmp/run/repo" {
		t.Errorf("path %q dir %q, want this program in the checkout", c.Path, c.Dir)
	}
	pol := c.Env[len(c.Env)-1]
	for _, want := range []string{`CONN3X_UI_SANDBOX=`, `"program":"/opt/conn3x"`, `"write":["/tmp/run"]`, `"/data/credentials/cred-1/key"`} {
		if !strings.Contains(pol, want) {
			t.Errorf("policy %s lacks %s", pol, want)
		}
	}
	if !slices.Contains(c.Env, "TMPDIR=/tmp/run/tmp") || len(env) != 2 {
		t.Errorf("env %q: want TMPDIR in the run, and the caller's env untouched", c.Env)
	}
}
