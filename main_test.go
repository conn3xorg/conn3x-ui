// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

func TestRotateKeyCommand(t *testing.T) {
	data, keys := t.TempDir(), t.TempDir()
	keyFile := func(name string) (string, string) {
		k := make([]byte, 32)
		rand.Read(k)
		b64 := base64.StdEncoding.EncodeToString(k)
		path := filepath.Join(keys, name)
		os.WriteFile(path, []byte(b64+"\n"), 0o600)
		return path, b64
	}
	oldFile, oldB64 := keyFile("old")
	newFile, newB64 := keyFile("new")
	wrongFile, _ := keyFile("wrong")
	if err := rotateKey(data, oldFile, newFile); err == nil {
		t.Error("rotated a database that isn't there")
	}
	if _, err := os.Stat(filepath.Join(data, "conn3x-ui.db")); err == nil {
		t.Error("rotate-key made a database")
	}

	st, _ := store.Open(filepath.Join(data, "conn3x-ui.db"))
	key, _ := loadKey(oldFile, keyEnv)
	st.SetKey(key)
	ctx := context.Background()
	pid, _ := st.CreateProject(ctx, store.Project{Name: "p"})
	st.SetCredential(ctx, pid, "TOKEN", store.CredEnv, []byte("tok-Very$ecret"))
	st.Close()

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	err := rotateKey(data, wrongFile, newFile)
	if err == nil {
		t.Error("rotated with the wrong old key")
	}
	if err := rotateKey(data, oldFile, newFile); err != nil {
		t.Fatal(err)
	}
	if err := rotateKey(data, oldFile, newFile); err == nil {
		t.Error("the old key still rotates")
	}
	out := logged.String() + err.Error()
	if !strings.Contains(out, "re-sealed 1 credentials") {
		t.Errorf("log: %s", out)
	}
	for _, secret := range []string{oldB64, newB64, "tok-Very"} {
		if strings.Contains(out, secret) {
			t.Errorf("a key or value in the log: %s", out)
		}
	}
}

// GitHub teams are named by ID: a slug in a flag is refused at startup,
// since any member can create a team with a free slug.
func TestSetupGitHubRefusesTeamSlugs(t *testing.T) {
	t.Setenv(githubSecretEnv, "s")
	base := githubConfig{clientID: "c", redirectURL: "https://ui/cb", org: "acme", url: "https://github.com"}
	admin := base
	admin.adminTeam = "platform"
	role := base
	role.roles = roleFlags{{Group: "ops", Project: "web", Role: "planner"}}
	for name, gc := range map[string]githubConfig{"-github-admin-team": admin, "-github-role": role} {
		if _, err := setupGitHub(gc); err == nil || !strings.Contains(err.Error(), "numeric ID") {
			t.Errorf("%s with a slug: %v", name, err)
		}
	}
	ok := base
	ok.adminTeam = "4185301"
	ok.roles = roleFlags{{Group: "4185302", Project: "web", Role: "planner"}}
	t.Setenv(githubSecretEnv, "s")
	if _, err := setupGitHub(ok); err != nil {
		t.Errorf("team IDs: %v", err)
	}
}
