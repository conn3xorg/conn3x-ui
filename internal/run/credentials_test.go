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
	dir, env, err := writeCredentials([]store.Secret{
		{Name: "ssh_key", Kind: store.CredFile, Value: []byte("key\n")},
		{Name: "AWS_SECRET_ACCESS_KEY", Kind: store.CredEnv, Value: []byte("aws")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
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
	if _, _, err := writeCredentials([]store.Secret{{Name: "../x", Kind: store.CredFile}}); err == nil {
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
