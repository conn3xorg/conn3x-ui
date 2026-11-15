// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkDirStaysInTheRepo(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "infra", "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("infra", filepath.Join(repo, "inside")); err != nil {
		t.Fatal(err)
	}
	for path, ok := range map[string]bool{"infra/web": true, "": true, "inside/web": true, "escape": false, "../": false, "missing": false} {
		if _, err := workDir(repo, path); (err == nil) != ok {
			t.Errorf("%q: %v", path, err)
		}
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://x:tok3n@git.example.com/r.git": "https://redacted@git.example.com/r.git",
		"https://git.example.com/r.git":         "https://git.example.com/r.git",
		"git@github.com:o/r.git":                "git@github.com:o/r.git",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
