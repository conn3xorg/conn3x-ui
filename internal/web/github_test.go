// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// fakeGitHub is GitHub Enterprise Server's OAuth and REST API, as much as
// sign-in uses, for users by login: their ID, whether they're active in
// acme, and their teams.
type fakeGitHub struct {
	*httptest.Server
	mu     sync.Mutex
	codes  map[string]string // code: login
	tokens map[string]string // token: login
	users  map[string]ghUser
}

type ghUser struct {
	id     int64
	member string // acme membership state, or "" for none
	teams  map[string][]string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{codes: map[string]string{}, tokens: map[string]string{}, users: map[string]ghUser{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		g.mu.Lock()
		login, ok := g.codes[r.Form.Get("code")]
		delete(g.codes, r.Form.Get("code"))
		tok := store.Token(8)
		g.tokens[tok] = login
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": tok, "token_type": "bearer", "scope": "read:org"})
	})
	user := func(r *http.Request) (ghUser, string, bool) {
		g.mu.Lock()
		defer g.mu.Unlock()
		login, ok := g.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		return g.users[login], login, ok
	}
	mux.HandleFunc("GET /api/v3/user", func(w http.ResponseWriter, r *http.Request) {
		u, login, ok := user(r)
		if !ok {
			http.Error(w, "", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": u.id, "login": login})
	})
	mux.HandleFunc("GET /api/v3/user/memberships/orgs/{org}", func(w http.ResponseWriter, r *http.Request) {
		u, _, ok := user(r)
		if !ok || r.PathValue("org") != "acme" || u.member == "" {
			http.Error(w, "", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"state": u.member})
	})
	mux.HandleFunc("GET /api/v3/user/teams", func(w http.ResponseWriter, r *http.Request) {
		u, _, ok := user(r)
		if !ok {
			http.Error(w, "", 401)
			return
		}
		out := []map[string]any{}
		for org, slugs := range u.teams {
			for _, s := range slugs {
				out = append(out, map[string]any{"slug": s, "organization": map[string]string{"login": org}})
			}
		}
		json.NewEncoder(w).Encode(out)
	})
	g.Server = httptest.NewTLSServer(mux)
	t.Cleanup(g.Close)
	return g
}

type githubEnv struct {
	st  *store.Store
	srv *Server
	gh  *fakeGitHub
	*client
}

func setupGitHub(t *testing.T) githubEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	gh := newFakeGitHub(t)
	h := New(st, nil)
	srv := httptest.NewUnstartedServer(h)
	base := "http://" + srv.Listener.Addr().String()
	if h.GitHub, err = NewGitHub(gh.URL, "client", "secret", base+"/login/github/callback", "acme"); err != nil {
		t.Fatal(err)
	}
	h.GitHub.client = gh.Client()
	srv.Start()
	t.Cleanup(srv.Close)
	return githubEnv{st, h, gh, newClient(t, base)}
}

// signIn goes through the flow as login; edit can break the callback.
func (e githubEnv) signIn(t *testing.T, login string, edit func(url.Values)) *http.Response {
	t.Helper()
	resp, _ := e.get("/login/github")
	auth, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || err != nil || !strings.HasPrefix(auth.String(), e.gh.URL+"/login/oauth/authorize") {
		t.Fatalf("start: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if q := auth.Query(); q.Get("scope") != "read:org" || q.Get("client_id") != "client" || q.Get("state") == "" {
		t.Fatalf("authorize request: %v", q)
	}
	code := store.Token(8)
	e.gh.mu.Lock()
	e.gh.codes[code] = login
	e.gh.mu.Unlock()
	cb := url.Values{"code": {code}, "state": {auth.Query().Get("state")}}
	if edit != nil {
		edit(cb)
	}
	resp, _ = e.get("/login/github/callback?" + cb.Encode())
	return resp
}

func (e githubEnv) fresh() githubEnv { return githubEnv{e.st, e.srv, e.gh, newClient(e.t, e.base)} }

// Members of the org sign in, linked by their numeric ID; anyone else, a
// pending member, a bad state or a replayed code doesn't. Teams give roles
// as OIDC groups do.
func TestGitHubSignIn(t *testing.T) {
	e := setupGitHub(t)
	ctx := context.Background()
	pid, err := e.st.CreateProject(ctx, store.Project{Name: "web", GitURL: "https://example.com/w.git", GitRef: "main", Path: "."})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.GitHub.AdminTeam = "platform"
	e.srv.GitHub.TeamRoles = []GroupRole{{Group: "ops", Project: "web", Role: store.RolePlanner}}
	e.gh.users["octo"] = ghUser{id: 42, member: "active", teams: map[string][]string{"acme": {"ops"}, "other": {"platform"}}}
	e.gh.users["outsider"] = ghUser{id: 7}
	e.gh.users["invited"] = ghUser{id: 8, member: "pending"}

	if resp := e.signIn(t, "octo", nil); resp.StatusCode != 303 {
		t.Fatalf("member sign-in: %d", resp.StatusCode)
	}
	if _, body := e.get("/"); !strings.Contains(body, ">octo</small>") {
		t.Fatalf("home after sign-in:\n%s", body)
	}
	u, err := e.st.OIDCUser(ctx, e.gh.URL, "42")
	if err != nil || u.Admin {
		t.Fatalf("user %+v, %v: want linked by ID 42, not an admin (platform is another org's team)", u, err)
	}
	if role, _ := e.st.Role(ctx, pid, u.ID); role != store.RolePlanner {
		t.Errorf("role from team ops: %q", role)
	}

	for name, f := range map[string]func() *http.Response{
		"not a member":   func() *http.Response { return e.fresh().signIn(t, "outsider", nil) },
		"pending member": func() *http.Response { return e.fresh().signIn(t, "invited", nil) },
		"state mismatch": func() *http.Response {
			return e.fresh().signIn(t, "octo", func(q url.Values) { q.Set("state", "forged") })
		},
		"provider error": func() *http.Response {
			return e.fresh().signIn(t, "octo", func(q url.Values) { q.Set("error", "access_denied") })
		},
		"unknown code": func() *http.Response {
			return e.fresh().signIn(t, "octo", func(q url.Values) { q.Set("code", "nope") })
		},
	} {
		if resp := f(); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, resp.StatusCode)
		}
	}
	if n, _ := e.st.UserCount(ctx); n != 1 {
		t.Errorf("%d users, want only octo", n)
	}

	// A renamed login is the same user: the link is the ID.
	e.gh.users["octo-renamed"] = e.gh.users["octo"]
	if resp := e.fresh().signIn(t, "octo-renamed", nil); resp.StatusCode != 303 {
		t.Fatalf("renamed sign-in: %d", resp.StatusCode)
	}
	if n, _ := e.st.UserCount(ctx); n != 1 {
		t.Errorf("a renamed login made a second user")
	}
}

func TestNewGitHubChecks(t *testing.T) {
	for _, tc := range []struct{ base, org string }{{"http://github.example.com", "acme"}, {"https://github.com", ""}, {"github.com", "acme"}} {
		if _, err := NewGitHub(tc.base, "c", "s", "https://ui/cb", tc.org); err == nil {
			t.Errorf("%q, org %q: no error", tc.base, tc.org)
		}
	}
	g, err := NewGitHub("https://github.com/", "c", "s", "https://ui/cb", "acme")
	if err != nil || g.API != "https://api.github.com" || g.URL != "https://github.com" {
		t.Errorf("github.com: %+v, %v", g, err)
	}
	g, err = NewGitHub("https://ghe.example.com", "c", "s", "https://ui/cb", "acme")
	if err != nil || g.API != "https://ghe.example.com/api/v3" {
		t.Errorf("GHES: %+v, %v", g, err)
	}
}
