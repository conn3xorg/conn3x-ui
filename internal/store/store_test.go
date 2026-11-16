// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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

func TestApplyRuns(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pid, _ := s.CreateProject(ctx, Project{Name: "p"})
	uid, _ := s.CreateUser(ctx, "admin", "pw")
	plan, _ := s.CreateRun(ctx, pid, KindPlan, uid)
	if ok, _ := s.Applicable(ctx, plan); ok {
		t.Error("a queued plan is applicable")
	}
	if _, err := s.CreateApply(ctx, plan, uid); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("apply of a queued plan: %v", err)
	}
	s.FinishRun(ctx, plan, StatusSucceeded, "")
	if ok, err := s.Applicable(ctx, plan); !ok || err != nil {
		t.Errorf("succeeded plan not applicable: %v", err)
	}
	id, err := s.CreateApply(ctx, plan, uid)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := s.Run(ctx, id)
	if r.Kind != KindApply || r.Status != StatusQueued || r.ProjectID != pid || r.PlanRunID.Int64 != plan || r.ApprovedBy.Int64 != uid || r.ApprovedByName.String != "admin" || !r.ApprovedAt.Valid || r.CreatedBy.Int64 != uid {
		t.Fatalf("%+v", r)
	}
	if _, err := s.CreateApply(ctx, plan, uid); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("second apply: %v", err)
	}
	if ok, _ := s.Applicable(ctx, plan); ok {
		t.Error("an applied plan is applicable")
	}
	if _, err := s.CreateApply(ctx, id, uid); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("apply of an apply: %v", err)
	}
	plan2, _ := s.CreateRun(ctx, pid, KindPlan, uid)
	s.FinishRun(ctx, plan2, StatusSucceeded, "")
	s.CreateRun(ctx, pid, KindPlan, uid) // newer, still queued
	if ok, _ := s.Applicable(ctx, plan2); ok {
		t.Error("a superseded plan is applicable")
	}
	s.FinishRun(ctx, id, StatusCancelled, "")
	if r, _ = s.Run(ctx, id); !r.Finished() || r.Status != StatusCancelled {
		t.Errorf("%+v", r)
	}
	if runs, _ := s.Runs(ctx, pid); len(runs) != 4 || runs[0].Kind != KindPlan || runs[2].Kind != KindApply {
		t.Errorf("%+v", runs)
	}
}

func TestHistory(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	web, _ := s.CreateProject(ctx, Project{Name: "web"})
	db, _ := s.CreateProject(ctx, Project{Name: "db"})
	uid, _ := s.CreateUser(ctx, "admin", "pw")
	r1, _ := s.CreateRun(ctx, web, KindPlan, uid)
	r2, _ := s.CreateRun(ctx, db, KindPlan, uid)
	r3, _ := s.CreateRun(ctx, web, KindPlan, uid)
	s.FinishRun(ctx, r1, StatusSucceeded, "")
	s.FinishRun(ctx, r2, StatusFailed, "boom")
	s.SetRunHosts(ctx, r1, map[string]string{"web1": "changes", "web2": "changes"})
	s.SetRunHosts(ctx, r3, map[string]string{"web1": "failed"})
	s.SetRunHosts(ctx, r3, map[string]string{"web1": "ok"}) // replaces
	ids := func(f Filter, limit, offset int) []int64 {
		t.Helper()
		runs, err := s.History(ctx, f, limit, offset)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, r := range runs {
			out = append(out, r.ID)
		}
		return out
	}
	for _, c := range []struct {
		f             Filter
		limit, offset int
		want          []int64
	}{
		{Filter{}, 10, 0, []int64{r3, r2, r1}},
		{Filter{}, 2, 1, []int64{r2, r1}},
		{Filter{ProjectID: web}, 10, 0, []int64{r3, r1}},
		{Filter{Status: StatusFailed}, 10, 0, []int64{r2}},
		{Filter{Host: "web1"}, 10, 0, []int64{r3, r1}},
		{Filter{Host: "web2", ProjectID: web, Status: StatusSucceeded}, 10, 0, []int64{r1}},
		{Filter{Host: "web3"}, 10, 0, nil},
	} {
		if got := ids(c.f, c.limit, c.offset); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%+v %d %d: %v, want %v", c.f, c.limit, c.offset, got, c.want)
		}
	}
	runs, _ := s.History(ctx, Filter{Host: "web1"}, 10, 0)
	if runs[0].HostOutcome != "ok" || runs[1].HostOutcome != "changes" || runs[0].ProjectName != "web" || runs[0].CreatedByName.String != "admin" {
		t.Errorf("%+v", runs)
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

func TestCredentials(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pid, _ := s.CreateProject(ctx, Project{Name: "p"})
	other, _ := s.CreateProject(ctx, Project{Name: "q"})
	if err := s.SetCredential(ctx, pid, "token", CredEnv, []byte("x")); !errors.Is(err, ErrNoKey) {
		t.Errorf("set without a key: %v", err)
	}
	if err := s.SetKey([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
	key := make([]byte, 32)
	rand.Read(key)
	if err := s.SetKey(key); err != nil {
		t.Fatal(err)
	}
	s.SetCredential(ctx, pid, "ssh_key", CredFile, []byte("old key\n"))
	s.SetCredential(ctx, pid, "SSH_KEY", CredFile, []byte("key one\n")) // same name, other case: replaces
	s.SetCredential(ctx, pid, "TOKEN", CredEnv, []byte("tok-1"))
	s.SetCredential(ctx, other, "TOKEN", CredEnv, []byte("tok-2"))

	creds, err := s.Credentials(ctx, pid)
	if err != nil || len(creds) != 2 || creds[0].Name != "SSH_KEY" || creds[0].Kind != CredFile || creds[0].SetAt == "" {
		t.Fatalf("%+v %v", creds, err)
	}
	secrets, err := s.Secrets(ctx, pid)
	if err != nil || len(secrets) != 2 || string(secrets[0].Value) != "key one\n" || string(secrets[1].Value) != "tok-1" {
		t.Fatalf("%+v %v", secrets, err)
	}
	var raw []byte
	s.db.QueryRow("SELECT value FROM credentials WHERE project_id=? AND name='TOKEN'", pid).Scan(&raw)
	if bytes.Contains(raw, []byte("tok-1")) {
		t.Error("value stored in plain text")
	}

	// A value moved to another project's row doesn't open there.
	s.db.Exec("UPDATE credentials SET value=? WHERE project_id=? AND name='TOKEN'", raw, other)
	if _, err := s.Secrets(ctx, other); err == nil || strings.Contains(err.Error(), "tok") {
		t.Errorf("swapped value: %v", err)
	}
	s.DeleteCredential(ctx, other, "token")

	// Nor does anything under a different key, and no key at all says how
	// to make one.
	rand.Read(key)
	s.SetKey(key)
	if _, err := s.Secrets(ctx, pid); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Errorf("wrong key: %v", err)
	}
	s.aead = nil
	if _, err := s.Secrets(ctx, pid); !errors.Is(err, ErrNoKey) || !strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("no key: %v", err)
	}
	if secrets, err := s.Secrets(ctx, other); err != nil || len(secrets) != 0 {
		t.Errorf("a project without credentials needs no key: %v", err)
	}

	if err := s.DeleteCredential(ctx, pid, "token"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCredential(ctx, pid, "token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing: %v", err)
	}
	s.DeleteProject(ctx, pid)
	if creds, _ := s.Credentials(ctx, pid); len(creds) != 0 {
		t.Errorf("credentials outlived their project: %+v", creds)
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

func TestDriftChecks(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pid, _ := s.CreateProject(ctx, Project{Name: "web", Schedule: "6h", WebhookURL: "https://hooks.example.com:8443/T000/SECRET"})
	p, err := s.Project(ctx, pid)
	if err != nil || p.Schedule != "6h" || p.WebhookURL != "https://hooks.example.com:8443/T000/SECRET" || p.WebhookHost() != "hooks.example.com:8443" {
		t.Fatalf("%+v %v", p, err)
	}
	p.Schedule, p.WebhookURL = "0 3 * * *", ""
	s.UpdateProject(ctx, p)
	if p, _ = s.Project(ctx, pid); p.Schedule != "0 3 * * *" || p.WebhookURL != "" || p.WebhookHost() != "" {
		t.Errorf("%+v", p)
	}

	if _, err := s.LastRun(ctx, pid, KindDrift); !errors.Is(err, ErrNotFound) {
		t.Errorf("no drift check yet: %v", err)
	}
	uid, _ := s.CreateUser(ctx, "admin", "pw")
	plan, _ := s.CreateRun(ctx, pid, KindPlan, uid)
	d1, err := s.CreateRun(ctx, pid, KindDrift, 0) // the schedule, nobody's
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := s.CreateRun(ctx, pid, KindDrift, 0)
	s.SetRunOutcome(ctx, d1, OutcomeClean)
	s.SetRunOutcome(ctx, d2, OutcomeDrift)
	s.FinishRun(ctx, d2, StatusSucceeded, "")
	last, err := s.LastRun(ctx, pid, KindDrift)
	if err != nil || last.ID != d2 || last.Outcome != OutcomeDrift || last.CreatedBy.Valid {
		t.Errorf("%+v %v", last, err)
	}
	// A drift check doesn't retire the plan before it.
	if ok, _ := s.Applicable(ctx, plan); ok {
		t.Error("an unfinished plan is applicable")
	}
	s.FinishRun(ctx, plan, StatusSucceeded, "")
	if ok, _ := s.Applicable(ctx, plan); !ok {
		t.Error("a drift check retired the plan")
	}
	for status, want := range map[string]int64{OutcomeDrift: d2, OutcomeClean: d1} {
		if runs, _ := s.History(ctx, Filter{Status: status}, 10, 0); len(runs) != 1 || runs[0].ID != want {
			t.Errorf("%s: %+v", status, runs)
		}
	}
}

// TestMigrateKeepsProjects opens a database from before schedules and
// finds its projects with none.
func TestMigrateKeepsProjects(t *testing.T) {
	path := openAt(t, 4, "INSERT INTO projects (name, git_url, git_ref, path, conn3x_path, env, created_at, updated_at) VALUES ('old', 'u', 'main', '.', 'conn3x', '', 't', 't')")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ps, err := s.Projects(context.Background())
	if err != nil || len(ps) != 1 || ps[0].Name != "old" || ps[0].Schedule != "" || ps[0].WebhookURL != "" {
		t.Errorf("%+v %v", ps, err)
	}
}

// openAt makes a database with only the first version migrations, runs
// query in it, and returns its path for Open to bring up to date.
func openAt(t *testing.T, version int, query string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ui.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, m := range migrations[:version] {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d; %s", version, query)); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUsers(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id, err := s.CreateUser(ctx, "alice", "first-password")
	if err != nil {
		t.Fatal(err)
	}
	if u, err := s.User(ctx, id); err != nil || u.Name != "alice" || u.Admin || u.Disabled {
		t.Fatalf("new user %+v %v", u, err)
	}
	if err := s.SetUser(ctx, id, true, false); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserNamed(ctx, "alice"); !u.Admin {
		t.Errorf("not made admin: %+v", u)
	}
	if _, err := s.UserNamed(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}

	// A new password works, the old one doesn't, and only the kept session
	// survives.
	keep, _, _ := s.Login(ctx, "alice", "first-password", time.Hour)
	other, _, _ := s.Login(ctx, "alice", "first-password", time.Hour)
	if err := s.SetPassword(ctx, id, "second-password", keep); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPassword(ctx, id, "first-password"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old password: %v", err)
	}
	if err := s.CheckPassword(ctx, id, "second-password"); err != nil {
		t.Errorf("new password: %v", err)
	}
	if _, _, err := s.Session(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Error("another session outlived the password change")
	}
	if _, _, err := s.Session(ctx, keep); err != nil {
		t.Errorf("kept session: %v", err)
	}

	// Disabled, the user's sessions end and they can't sign in.
	if err := s.SetUser(ctx, id, false, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, keep); !errors.Is(err, ErrNotFound) {
		t.Error("session outlived disabling")
	}
	if _, _, err := s.Login(ctx, "alice", "second-password", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("disabled user signed in: %v", err)
	}
	if err := s.SetUser(ctx, 999, false, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}
	if us, err := s.Users(ctx); err != nil || len(us) != 1 || !us[0].Disabled {
		t.Errorf("%+v %v", us, err)
	}
}

func TestRoles(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	web, _ := s.CreateProject(ctx, Project{Name: "web"})
	db, _ := s.CreateProject(ctx, Project{Name: "db"})
	alice, _ := s.CreateUser(ctx, "alice", "pw")
	bob, _ := s.CreateUser(ctx, "bob", "pw")
	if role, err := s.Role(ctx, web, alice); err != nil || role != "" {
		t.Errorf("no role: %q %v", role, err)
	}
	if err := s.SetRole(ctx, web, alice, RolePlanner); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, web, alice, RoleApprover); err != nil {
		t.Fatal(err)
	}
	s.SetRole(ctx, web, bob, RoleViewer)
	if err := s.SetRole(ctx, db, bob, "owner"); err == nil {
		t.Error("unknown role accepted")
	}
	if role, _ := s.Role(ctx, web, alice); role != RoleApprover {
		t.Errorf("role %q", role)
	}
	if ms, err := s.Members(ctx, web); err != nil || len(ms) != 2 || ms[0].Name != "alice" || ms[1].Role != RoleViewer {
		t.Errorf("%+v %v", ms, err)
	}
	if ps, err := s.MemberProjects(ctx, bob); err != nil || len(ps) != 1 || ps[0].ID != web {
		t.Errorf("%+v %v", ps, err)
	}

	// History keeps to the projects a user has a role on.
	r1, _ := s.CreateRun(ctx, web, KindPlan, alice)
	s.CreateRun(ctx, db, KindPlan, alice)
	if runs, _ := s.History(ctx, Filter{UserID: bob}, 10, 0); len(runs) != 1 || runs[0].ID != r1 {
		t.Errorf("bob's history %+v", runs)
	}
	s.SetRole(ctx, web, bob, "")
	if role, _ := s.Role(ctx, web, bob); role != "" {
		t.Errorf("role outlived its removal: %q", role)
	}

	for _, c := range []struct {
		have, want string
		ok         bool
	}{
		{RoleAdmin, RoleViewer, true}, {RoleApprover, RoleApprover, true}, {RolePlanner, RoleApprover, false},
		{RoleViewer, RolePlanner, false}, {"", RoleViewer, false}, {"owner", RoleViewer, false},
	} {
		if RoleAtLeast(c.have, c.want) != c.ok {
			t.Errorf("RoleAtLeast(%q, %q) = %v", c.have, c.want, !c.ok)
		}
	}
}

func TestAudit(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	alice, _ := s.CreateUser(ctx, "alice", "pw")
	web, _ := s.CreateProject(ctx, Project{Name: "web"})
	for _, e := range []Entry{
		{UserID: alice, UserName: "alice", Action: "sign-in"},
		{UserID: alice, UserName: "alice", ProjectID: web, ProjectName: "web", Action: "plan", Detail: "run 1"},
		{Action: "sign-in failed", Detail: "unknown name"},
	} {
		if err := s.Audit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got := func(f AuditFilter, limit, offset int) []string {
		es, err := s.AuditLog(ctx, f, limit, offset)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range es {
			out = append(out, e.Action)
		}
		return out
	}
	for _, c := range []struct {
		f             AuditFilter
		limit, offset int
		want          string
	}{
		{AuditFilter{}, 10, 0, "sign-in failed,plan,sign-in"},
		{AuditFilter{}, 1, 1, "plan"},
		{AuditFilter{UserID: alice}, 10, 0, "plan,sign-in"},
		{AuditFilter{ProjectID: web}, 10, 0, "plan"},
	} {
		if g := strings.Join(got(c.f, c.limit, c.offset), ","); g != c.want {
			t.Errorf("%+v: %s, want %s", c, g, c.want)
		}
	}

	// Deleting the project keeps its entries, and nothing edits or removes
	// one.
	s.DeleteProject(ctx, web)
	if es, _ := s.AuditLog(ctx, AuditFilter{ProjectID: web}, 10, 0); len(es) != 1 || es[0].ProjectName != "web" || es[0].UserName != "alice" || es[0].At == "" {
		t.Errorf("after delete %+v", es)
	}
	if _, err := s.db.Exec("UPDATE audit SET detail = 'x'"); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("update: %v", err)
	}
	if _, err := s.db.Exec("DELETE FROM audit"); err == nil {
		t.Error("delete allowed")
	}
}

// TestMigrateKeepsAdmin opens a database from before roles and finds its
// one user still an admin.
func TestMigrateKeepsAdmin(t *testing.T) {
	path := openAt(t, 5, "INSERT INTO users (name, password_hash, created_at) VALUES ('admin', 'x', 't')")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u, err := s.UserNamed(context.Background(), "admin"); err != nil || !u.Admin || u.Disabled {
		t.Errorf("%+v %v", u, err)
	}
	id, _ := s.CreateUser(context.Background(), "new", "pw")
	if u, _ := s.User(context.Background(), id); u.Admin {
		t.Error("a new user is an admin")
	}
}
