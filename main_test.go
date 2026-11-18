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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

func TestRotateKeyCommand(t *testing.T) {
	data, keys := t.TempDir(), t.TempDir()
	keyFile := func(name string) (keySource, string) {
		k := make([]byte, 32)
		rand.Read(k)
		b64 := base64.StdEncoding.EncodeToString(k)
		path := filepath.Join(keys, name)
		os.WriteFile(path, []byte(b64+"\n"), 0o600)
		return keySource{file: path}, b64
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

func TestKeyCommand(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	b64 := base64.StdEncoding.EncodeToString(k)
	t.Setenv(newKeyEnv, "not-for-the-command")
	got, err := loadKey(keySource{command: "echo " + b64}, keyEnv)
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("got %x, %v", got, err)
	}
	if _, err := loadKey(keySource{file: "f", command: "echo " + b64}, keyEnv); err == nil {
		t.Error("took a file and a command both")
	}
	if _, err := loadKey(keySource{command: "exit 3"}, keyEnv); err == nil || !strings.Contains(err.Error(), "key command failed") {
		t.Errorf("failing command: %v", err)
	}
	if runtime.GOOS != "windows" {
		t.Setenv(oidcSecretEnv, "not-for-the-command")
		out, _ := keyCommandOutput("echo \"[$" + newKeyEnv + "$" + oidcSecretEnv + "]\"")
		if string(out) != "[]\n" {
			t.Errorf("the command saw a CONN3X_UI_ secret: %q", out)
		}

		// A pipeline whose first command hangs, as a KMS call on a dead
		// network would, still ends at the timeout.
		was := keyCommandTimeout
		keyCommandTimeout = time.Second
		defer func() { keyCommandTimeout = was }()
		start := time.Now()
		if _, err := keyCommandOutput("sleep 60 | cat"); err == nil {
			t.Error("a hung command succeeded")
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("a hung pipeline held for %s", d)
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
	padded := base
	padded.adminTeam = "00123"
	padded.roles = roleFlags{{Group: "0456", Project: "web", Role: "planner"}}
	t.Setenv(githubSecretEnv, "s")
	if g, err := setupGitHub(padded); err != nil || g.AdminTeam != "123" || g.TeamRoles[0].Group != "456" {
		t.Errorf("leading zeros: %+v, %v", g, err)
	}
}
