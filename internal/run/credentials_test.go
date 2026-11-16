// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

func TestWriteCredentials(t *testing.T) {
	parent := t.TempDir()
	dir, env, err := writeCredentials(parent, []store.Secret{
		{Name: "ssh_key", Kind: store.CredFile, Value: []byte("key\n")},
		{Name: "AWS_SECRET_ACCESS_KEY", Kind: store.CredEnv, Value: []byte("aws")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if filepath.Dir(dir) != parent {
		t.Errorf("dir %s isn't in %s", dir, parent)
	}
	path := filepath.Join(dir, "ssh_key")
	if !slices.Equal(env, []string{"CONN3X_CRED_SSH_KEY=" + path, "AWS_SECRET_ACCESS_KEY=aws"}) {
		t.Errorf("env %q", env)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("dir %v %v", st.Mode(), err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("file %v %v", st.Mode(), err)
	}
	if b, _ := os.ReadFile(path); string(b) != "key\n" {
		t.Errorf("file holds %q", b)
	}
	if _, _, err := writeCredentials(parent, []store.Secret{{Name: "../x", Kind: store.CredFile}}); err == nil {
		t.Error("a name with a path in it was written")
	}
}

func TestHider(t *testing.T) {
	key := "-----BEGIN KEY-----\nAAAAsecret<&>\n-----END KEY-----\n"
	h := hider([]store.Secret{{Name: "k", Value: []byte(key)}, {Name: "t", Value: []byte(`tok"en`)}})
	quoted, _ := json.Marshal("got " + key + " and tok\"en")
	for _, in := range []string{key, string(quoted), "line: AAAAsecret<&>", `{"@message":"tok\"en"}`} {
		if out := h.Replace(in); strings.Contains(out, "AAAAsecret") || strings.Contains(out, "tok") || !strings.Contains(out, "<hidden>") {
			t.Errorf("%q became %q", in, out)
		}
	}
}

func TestRemoveLeftovers(t *testing.T) {
	data, outside := t.TempDir(), t.TempDir()
	r := &Runner{DataDir: data}
	if n, err := r.RemoveLeftovers(); n != 0 || err != nil {
		t.Errorf("no credentials directory yet: %d %v", n, err)
	}
	// Two runs that died with their credentials still on disk.
	for range 2 {
		if _, _, err := writeCredentials(r.credentialsDir(), []store.Secret{{Name: "k", Kind: store.CredFile, Value: []byte("v")}}); err != nil {
			t.Fatal(err)
		}
	}
	// And what the UI didn't make: a file and a directory without the
	// prefix, a link with it, and a credentials-named directory outside.
	keep := []string{
		filepath.Join(r.credentialsDir(), "notes"),
		filepath.Join(r.credentialsDir(), "other-dir"),
		filepath.Join(r.credentialsDir(), credPrefix+"link"),
		filepath.Join(data, credPrefix+"x"),
		filepath.Join(outside, credPrefix+"y"),
	}
	os.WriteFile(keep[0], nil, 0o600)
	os.Mkdir(keep[1], 0o700)
	os.Symlink(outside, keep[2])
	os.Mkdir(keep[3], 0o700)
	os.Mkdir(keep[4], 0o700)

	if n, err := r.RemoveLeftovers(); n != 2 || err != nil {
		t.Errorf("removed %d: %v", n, err)
	}
	entries, _ := os.ReadDir(r.credentialsDir())
	if len(entries) != 3 {
		t.Errorf("left %v", entries)
	}
	for _, k := range keep {
		if _, err := os.Lstat(k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}
