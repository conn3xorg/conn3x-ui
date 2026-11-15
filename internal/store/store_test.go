// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	s, err := Open(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestProjects(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id, err := s.CreateProject(ctx, Project{Name: "web", GitURL: "https://example.com/r.git", GitRef: "main", Path: ".", Conn3xPath: "conn3x", Env: "A=1\n\nB=2\n"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Project(ctx, id)
	if err != nil || p.Name != "web" || len(p.EnvList()) != 2 || p.EnvList()[1] != "B=2" {
		t.Fatalf("%+v %v", p, err)
	}
	p.Name = "web2"
	if err := s.UpdateProject(ctx, p); err != nil {
		t.Fatal(err)
	}
	all, err := s.Projects(ctx)
	if err != nil || len(all) != 1 || all[0].Name != "web2" {
		t.Fatalf("%+v %v", all, err)
	}
	if _, err := s.CreateProject(ctx, Project{Name: "web2"}); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := s.DeleteProject(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Project(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	if err := s.UpdateProject(ctx, p); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing: %v", err)
	}
}

func TestRunsAndEvents(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pid, _ := s.CreateProject(ctx, Project{Name: "p"})
	uid, _ := s.CreateUser(ctx, "admin", "pw")
	id, err := s.CreateRun(ctx, pid, "plan", uid)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := s.Run(ctx, id)
	if r.Status != StatusQueued || r.Finished() || r.CreatedBy.Int64 != uid {
		t.Fatalf("%+v", r)
	}
	s.StartRun(ctx, id)
	s.SetRunCommit(ctx, id, "abc")
	s.SetRunVersion(ctx, id, "0.21.0")
	for _, l := range []string{`{"type":"version"}`, `{"type":"change_summary"}`} {
		if _, err := s.AppendEvent(ctx, id, []byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	s.FinishRun(ctx, id, StatusFailed, "boom")
	r, _ = s.Run(ctx, id)
	if !r.Finished() || r.CommitSHA != "abc" || r.Conn3xVersion != "0.21.0" || r.Error != "boom" || !r.StartedAt.Valid || !r.FinishedAt.Valid {
		t.Fatalf("%+v", r)
	}
	lines, last, err := s.Events(ctx, id)
	if err != nil || last != 2 || len(lines) != 2 || string(lines[1]) != `{"type":"change_summary"}` {
		t.Fatalf("%q %d %v", lines, last, err)
	}
	runs, _ := s.Runs(ctx, pid)
	if len(runs) != 1 {
		t.Fatalf("%+v", runs)
	}
	// Deleting the project takes its runs and events with it.
	s.DeleteProject(ctx, pid)
	if _, err := s.Run(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("run outlived project: %v", err)
	}
}

func TestSessions(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Login(ctx, "admin", "wrong", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong password: %v", err)
	}
	if _, _, err := s.Login(ctx, "nobody", "secret", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}
	tok, csrf, err := s.Login(ctx, "admin", "secret", time.Hour)
	if err != nil || len(tok) != 64 || len(csrf) != 64 {
		t.Fatal(tok, csrf, err)
	}
	u, c, err := s.Session(ctx, tok)
	if err != nil || u.Name != "admin" || c != csrf {
		t.Fatal(u, c, err)
	}
	if _, _, err := s.Session(ctx, "bad"); !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	expired, _, _ := s.Login(ctx, "admin", "secret", -time.Second)
	if _, _, err := s.Session(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Error("expired session accepted")
	}
	s.Logout(ctx, tok)
	if _, _, err := s.Session(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Error("session outlived logout")
	}
}

func TestMigrateTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui.db")
	for range 2 {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
}
