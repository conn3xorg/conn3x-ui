// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// postBody posts a form and returns the response and its body.
func (c *client) postBody(path string, form url.Values) (*http.Response, string) {
	c.t.Helper()
	resp, err := c.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// user makes a user with password pw-<name>-long and a role on project,
// and returns a client signed in as them.
func (e env) user(t *testing.T, name, project, role string) *client {
	t.Helper()
	id, err := e.st.CreateUser(context.Background(), name, "pw-"+name+"-long")
	if err != nil {
		t.Fatal(err)
	}
	if role != "" {
		if resp := e.post(project+"/roles", url.Values{"csrf": {e.csrf(project)}, "user": {strconv.FormatInt(id, 10)}, "role": {role}}); resp.StatusCode != 303 {
			t.Fatalf("role for %s: %d", name, resp.StatusCode)
		}
	}
	c := newClient(t, e.base)
	c.loginAs(t, name, "pw-"+name+"-long")
	return c
}

// auditLines is every audit entry, oldest first, as "user project action
// detail".
func auditLines(t *testing.T, st *store.Store) []string {
	t.Helper()
	es, err := st.AuditLog(context.Background(), store.AuditFilter{}, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(es) - 1; i >= 0; i-- {
		out = append(out, strings.Join([]string{es[i].UserName, es[i].ProjectName, es[i].Action, es[i].Detail}, " "))
	}
	return out
}

func TestRoles(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	e.login(t)
	project := e.createProject(t, "web", repo, ".", exe, "CONN3X_FAKE=plan\n")
	viewer := e.user(t, "vera", project, store.RoleViewer)
	planner := e.user(t, "pat", project, store.RolePlanner)
	approver := e.user(t, "april", project, store.RoleApprover)
	padmin := e.user(t, "adam", project, store.RoleAdmin)
	outsider := e.user(t, "olga", project, "")
	plan1, _ := e.plan(t, project)

	// Everyone with a role sees the project and its runs; nobody else does.
	for _, path := range []string{project, plan1, plan1 + "/status", plan1 + "/events", "/runs/1/report"} {
		for who, c := range map[string]*client{"viewer": viewer, "planner": planner, "approver": approver, "admin": padmin, "outsider": outsider} {
			resp, body := c.get(path)
			if forbidden := resp.StatusCode == 403; forbidden != (who == "outsider") {
				t.Errorf("%s GET %s: %d", who, path, resp.StatusCode)
			} else if forbidden && !strings.Contains(body, "Not allowed") {
				t.Errorf("%s GET %s: 403 page:\n%s", who, path, body)
			}
		}
	}
	if _, body := outsider.get("/"); strings.Contains(body, project) {
		t.Error("outsider's project list shows the project")
	}
	if _, body := outsider.get("/runs"); strings.Contains(body, `href="/runs/1"`) || strings.Contains(body, ">web</option>") {
		t.Errorf("outsider's history shows the run:\n%s", body)
	}
	if _, body := viewer.get("/runs"); !strings.Contains(body, `href="/runs/1"`) {
		t.Error("viewer's history lacks the run")
	}

	// Each change to the project needs its role, checked on the server.
	posts := []struct {
		path, need string
	}{
		{project + "/plan", store.RolePlanner},
		{plan1 + "/cancel", store.RolePlanner},
		{project, store.RoleAdmin},
		{project + "/credentials", store.RoleAdmin},
		{project + "/credentials/x/delete", store.RoleAdmin},
		{project + "/roles", store.RoleAdmin},
	}
	for _, p := range posts {
		for _, c := range []struct {
			role string
			*client
		}{{store.RoleViewer, viewer}, {store.RolePlanner, planner}, {store.RoleApprover, approver}, {store.RoleAdmin, padmin}, {"", outsider}} {
			resp := c.post(p.path, url.Values{"csrf": {c.csrf("/")}, "name": {"web"}, "git_url": {repo}, "conn3x_path": {exe}, "env": {"CONN3X_FAKE=plan"}})
			if forbidden := resp.StatusCode == 403; forbidden == store.RoleAtLeast(c.role, p.need) {
				t.Errorf("%q POST %s: %d", c.role, p.path, resp.StatusCode)
			}
		}
	}
	// Site-wide pages are for site admins, a project admin included.
	for _, path := range []string{"/users", "/audit"} {
		if resp, _ := padmin.get(path); resp.StatusCode != 403 {
			t.Errorf("project admin GET %s: %d", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/projects", "/users", "/users/1", "/users/1/password"} {
		if resp := padmin.post(path, url.Values{"csrf": {padmin.csrf("/")}, "name": {"x"}}); resp.StatusCode != 403 {
			t.Errorf("project admin POST %s: %d", path, resp.StatusCode)
		}
	}

	// Controls a role can't use aren't shown.
	_, vpage := viewer.get(project)
	_, ppage := planner.get(project)
	_, apage := padmin.get(project)
	if strings.Contains(vpage, "/plan\"") || strings.Contains(vpage, "Settings") || !strings.Contains(ppage, "/plan\"") || strings.Contains(ppage, "Settings") ||
		!strings.Contains(apage, "Settings") || !strings.Contains(apage, "/roles\"") || !strings.Contains(apage, "<td>vera</td><td>viewer</td>") {
		t.Errorf("project pages:\nviewer:\n%s\nplanner:\n%s\nadmin:\n%s", vpage, ppage, apage)
	}
	if _, body := viewer.get("/"); strings.Contains(body, "New project") {
		t.Error("viewer is offered New project")
	}

	// An approver applies a plan someone else made; a planner doesn't, and
	// applies their own only once the project allows it.
	plan, _ := planner.plan(t, project)
	if _, body := planner.get(plan); strings.Contains(body, "/apply\"") {
		t.Error("planner is offered Apply on their own plan")
	}
	if resp, body := planner.postBody(plan+"/apply", url.Values{"csrf": {planner.csrf("/")}}); resp.StatusCode != 403 || !strings.Contains(body, "Someone else has to approve your plan") {
		t.Errorf("planner applies own plan: %d", resp.StatusCode)
	}
	if resp := viewer.post(plan+"/apply", url.Values{"csrf": {viewer.csrf("/")}}); resp.StatusCode != 403 {
		t.Errorf("viewer applies: %d", resp.StatusCode)
	}
	if _, body := approver.get(plan); !strings.Contains(body, `action="`+plan+`/apply"`) {
		t.Error("approver isn't offered Apply")
	}
	if _, events := approver.apply(t, plan); !strings.Contains(strings.Join(events, "\n"), "Apply complete") {
		t.Errorf("approver's apply:\n%s", strings.Join(events, "\n"))
	}
	own, _ := approver.plan(t, project)
	if resp := approver.post(own+"/apply", url.Values{"csrf": {approver.csrf("/")}}); resp.StatusCode != 403 {
		t.Errorf("approver applies own plan: %d", resp.StatusCode)
	}
	if resp := padmin.post(project, url.Values{"csrf": {padmin.csrf(project)}, "name": {"web"}, "git_url": {repo}, "conn3x_path": {exe}, "env": {"CONN3X_FAKE=plan"}, "self_apply": {"1"}}); resp.StatusCode != 303 {
		t.Fatalf("self_apply: %d", resp.StatusCode)
	}
	plan, _ = planner.plan(t, project)
	if _, events := planner.apply(t, plan); !strings.Contains(strings.Join(events, "\n"), "Apply complete") {
		t.Errorf("planner's own apply with self_apply:\n%s", strings.Join(events, "\n"))
	}

	// A role taken away takes the project with it.
	e.post(project+"/roles", url.Values{"csrf": {e.csrf(project)}, "user": {"2"}, "role": {""}})
	if resp, _ := viewer.get(project); resp.StatusCode != 403 {
		t.Errorf("after the role went: %d", resp.StatusCode)
	}
	if resp := e.post(project+"/roles", url.Values{"csrf": {e.csrf(project)}, "user": {"2"}, "role": {"owner"}}); resp.StatusCode != 400 {
		t.Errorf("unknown role: %d", resp.StatusCode)
	}
	if resp := e.post(project+"/roles", url.Values{"user": {"2"}, "role": {"admin"}}); resp.StatusCode != 403 {
		t.Errorf("role without CSRF: %d", resp.StatusCode)
	}
}

var shownPassword = regexp.MustCompile(`The password for (\S+) is <code>([0-9a-f]+)</code>`)

func TestUsers(t *testing.T) {
	e := setup(t)
	e.login(t)
	form := func(kv ...string) url.Values {
		v := url.Values{"csrf": {e.csrf("/users")}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}

	// A blank password is generated and shown once, and not cached.
	resp, body := e.postBody("/users", form("name", "bob"))
	m := shownPassword.FindStringSubmatch(body)
	if resp.StatusCode != 200 || m == nil || m[1] != "bob" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %v\n%s", resp.StatusCode, resp.Header, body)
	}
	if _, body := e.get("/users"); strings.Contains(body, m[2]) {
		t.Error("the generated password is shown again")
	}
	bob := newClient(t, e.base)
	bob.loginAs(t, "bob", m[2])
	if resp, _ := bob.get("/users"); resp.StatusCode != 403 {
		t.Errorf("bob GET /users: %d", resp.StatusCode)
	}
	for _, bad := range []url.Values{form("name", "bob"), form("name", "carol", "password", "short"), form("name", "has space")} {
		if resp := e.post("/users", bad); resp.StatusCode != 400 {
			t.Errorf("%v: %d", bad, resp.StatusCode)
		}
	}
	if resp := e.post("/users", url.Values{"name": {"mallory"}, "admin": {"1"}}); resp.StatusCode != 403 {
		t.Errorf("create without CSRF: %d", resp.StatusCode)
	}
	if resp := e.post("/users", form("name", "carol", "password", "carols-own-password", "admin", "1")); resp.StatusCode != 303 {
		t.Errorf("create with a password: %d", resp.StatusCode)
	}
	if u, _ := e.st.UserNamed(context.Background(), "carol"); !u.Admin {
		t.Error("carol isn't a site admin")
	}

	// Everyone changes their own password, given the current one.
	if resp := bob.post("/account/password", url.Values{"csrf": {bob.csrf("/account")}, "current": {"wrong"}, "password": {"bobs-new-password"}}); resp.StatusCode != 400 {
		t.Errorf("wrong current password: %d", resp.StatusCode)
	}
	if resp := bob.post("/account/password", url.Values{"current": {m[2]}, "password": {"bobs-new-password"}}); resp.StatusCode != 403 {
		t.Errorf("change without CSRF: %d", resp.StatusCode)
	}
	if resp := bob.post("/account/password", url.Values{"csrf": {bob.csrf("/account")}, "current": {m[2]}, "password": {"bobs-new-password"}}); resp.StatusCode != 200 {
		t.Errorf("change: %d", resp.StatusCode)
	}
	if resp, _ := bob.get("/"); resp.StatusCode != 200 {
		t.Errorf("the changing session was signed out: %d", resp.StatusCode)
	}

	// A reset signs the user out; so does disabling, and then they can't
	// sign in.
	bobID := "2"
	resp, body = e.postBody("/users/"+bobID+"/password", form())
	m = shownPassword.FindStringSubmatch(body)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("reset: %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := bob.get("/"); resp.StatusCode != 303 {
		t.Errorf("bob's session outlived the reset: %d", resp.StatusCode)
	}
	if resp := e.post("/users/"+bobID+"/password", url.Values{}); resp.StatusCode != 403 {
		t.Errorf("reset without CSRF: %d", resp.StatusCode)
	}
	bob.loginAs(t, "bob", m[2])
	if resp := e.post("/users/"+bobID, url.Values{"disabled": {"1"}}); resp.StatusCode != 403 {
		t.Errorf("disable without CSRF: %d", resp.StatusCode)
	}
	if resp := e.post("/users/"+bobID, form("disabled", "1")); resp.StatusCode != 303 {
		t.Errorf("disable: %d", resp.StatusCode)
	}
	if resp, _ := bob.get("/"); resp.StatusCode != 303 {
		t.Errorf("a disabled user's session: %d", resp.StatusCode)
	}
	if resp := bob.post("/login", url.Values{"csrf": {bob.csrf("/login")}, "name": {"bob"}, "password": {m[2]}}); resp.StatusCode != 401 {
		t.Errorf("a disabled user signs in: %d", resp.StatusCode)
	}

	// Nobody locks themselves out.
	if resp := e.post("/users/1", form()); resp.StatusCode != 400 {
		t.Errorf("admin drops own admin: %d", resp.StatusCode)
	}
	if resp := e.post("/users/1", form("admin", "1", "disabled", "1")); resp.StatusCode != 400 {
		t.Errorf("admin disables self: %d", resp.StatusCode)
	}
}

func TestAudit(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	key := make([]byte, 32)
	rand.Read(key)
	e.st.SetKey(key)
	const secret, hookURL, password = "s3cret-Value-42", "https://hooks.example.com/services/TOKEN99", "the-users-password"

	if resp := e.post("/login", url.Values{"csrf": {e.csrf("/login")}, "name": {"typed-a-password"}, "password": {"x"}}); resp.StatusCode != 401 {
		t.Fatalf("unknown name: %d", resp.StatusCode)
	}
	e.post("/login", url.Values{"csrf": {e.csrf("/login")}, "name": {"admin"}, "password": {"wrong"}})
	e.login(t)
	project := e.createProject(t, "web", repo, ".", exe, "CONN3X_FAKE=plan\n")
	e.post("/users", url.Values{"csrf": {e.csrf("/users")}, "name": {"bob"}, "password": {password}})
	e.post(project+"/roles", url.Values{"csrf": {e.csrf(project)}, "user": {"2"}, "role": {"viewer"}})
	e.post(project+"/credentials", url.Values{"csrf": {e.csrf(project)}, "name": {"API_TOKEN"}, "kind": {"env"}, "value": {secret}})
	e.post(project, url.Values{"csrf": {e.csrf(project)}, "name": {"web"}, "git_url": {repo}, "conn3x_path": {exe}, "env": {"CONN3X_FAKE=plan"}, "schedule": {"6h"}, "webhook_url": {hookURL}})
	plan, _ := e.plan(t, project)
	e.apply(t, plan)
	e.post(project+"/credentials/API_TOKEN/delete", url.Values{"csrf": {e.csrf(project)}})
	e.post("/users/2/password", url.Values{"csrf": {e.csrf("/users")}, "password": {password + "2"}})
	e.post("/users/2", url.Values{"csrf": {e.csrf("/users")}, "disabled": {"1"}})
	e.post(project+"/delete", url.Values{"csrf": {e.csrf(project)}})
	e.post("/logout", url.Values{"csrf": {e.csrf("/")}})

	got := auditLines(t, e.st)
	want := []string{
		"  sign-in failed unknown name",
		"admin  sign-in failed wrong password",
		"admin  sign-in ",
		"admin web project create ",
		"admin  user create bob",
		"admin web role change bob: viewer",
		"admin web credential set API_TOKEN, as env",
		"admin web project edit ",
		`admin web schedule change "" to "6h"`,
		"admin web webhook change set, to hooks.example.com",
		"admin web plan run 1",
		"admin web apply run 2, of plan 1",
		"admin web credential delete API_TOKEN",
		"admin  password reset bob",
		"admin  user change bob: site admin no, disabled yes",
		"admin web project delete ",
		"admin  sign-out ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range got {
		for _, s := range []string{secret, "TOKEN99", password, "typed-a-password"} {
			if strings.Contains(l, s) {
				t.Errorf("audit entry %q holds %q", l, s)
			}
		}
	}

	// The page is newest first and filters by user and project.
	e.login(t)
	_, body := e.get("/audit")
	if !strings.Contains(body, "<td>sign-out</td>") || strings.Index(body, "<td>sign-in</td>") > strings.Index(body, "<td>sign-in failed</td>") || strings.Contains(body, secret) {
		t.Errorf("audit page:\n%s", body)
	}
	if _, body := e.get("/audit?project=1"); strings.Contains(body, "user create") || !strings.Contains(body, "<td>plan</td>") {
		t.Errorf("project filter:\n%s", body)
	}
	if _, body := e.get("/audit?user=1&page=2"); strings.Contains(body, "<td>plan</td>") || !strings.Contains(body, "Newer") {
		t.Errorf("page 2:\n%s", body)
	}
}
