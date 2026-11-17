// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"crypto/rand"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// What a run executes can run commands on this server and so reach every
// project's credentials, so only a site admin may change it: the Git URL,
// the Conn3x binary and the environment. A project admin keeps the rest of
// the settings, and no credential may be named for a variable that changes
// how a run's programs start.
func TestRunSettingsNeedASiteAdmin(t *testing.T) {
	e := setup(t)
	key := make([]byte, 32)
	rand.Read(key)
	e.st.SetKey(key)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	other, _ := gitServer(t, map[string]string{"main.tf": "# someone else's\n"})
	e.login(t)
	project := e.createProject(t, "web", repo, ".", exe, "CONN3X_FAKE=plan\n")
	padmin := e.user(t, "adam", project, store.RoleAdmin)
	form := func(c *client, change map[string]string) url.Values {
		v := url.Values{"csrf": {c.csrf(project)}, "name": {"web"}, "git_url": {repo}, "conn3x_path": {exe}, "env": {"CONN3X_FAKE=plan"}}
		for k, s := range change {
			v.Set(k, s)
		}
		return v
	}
	saved := func() store.Project {
		t.Helper()
		ps, err := e.st.Projects(context.Background())
		if err != nil || len(ps) != 1 {
			t.Fatalf("projects: %v, %v", ps, err)
		}
		return ps[0]
	}

	for field, value := range map[string]string{"git_url": other, "conn3x_path": "/bin/sh", "env": "CONN3X_FAKE=plan\nGIT_SSH_COMMAND=touch /tmp/x"} {
		resp, body := padmin.postBody(project, form(padmin, map[string]string{field: value}))
		if resp.StatusCode != 400 || !strings.Contains(body, "only a site admin can change") {
			t.Errorf("project admin changing %s: %d\n%s", field, resp.StatusCode, body)
		}
	}
	if p := saved(); p.GitURL != repo || p.Conn3xPath != exe || p.Env != "CONN3X_FAKE=plan" {
		t.Fatalf("a refused change was saved: %+v", p)
	}
	_, page := padmin.get(project)
	if !strings.Contains(page, `name="git_url" value="`+repo+`" placeholder="https://github.com/you/circuits.git" required readonly`) || !strings.Contains(page, "Only a site admin can change") {
		t.Errorf("project admin's form doesn't show the run settings as read-only:\n%s", page)
	}
	// The rest of the settings stay the project admin's.
	if resp := padmin.post(project, form(padmin, map[string]string{"schedule": "6h"})); resp.StatusCode != 303 {
		t.Errorf("project admin setting a schedule: %d", resp.StatusCode)
	}
	if p := saved(); p.Schedule != "6h" {
		t.Errorf("schedule = %q", p.Schedule)
	}
	// So is what a drift check does about drift, which lets the schedule
	// change hosts with nobody approving, and its limit.
	for field, value := range map[string]string{"schedule_mode": store.ModeConverge, "max_changes": "5"} {
		resp, body := padmin.postBody(project, form(padmin, map[string]string{field: value}))
		if resp.StatusCode != 400 || !strings.Contains(body, "only a site admin can change what a drift check does") {
			t.Errorf("project admin changing %s: %d\n%s", field, resp.StatusCode, body)
		}
	}
	if _, page := padmin.get(project); strings.Contains(page, `<select id="schedule_mode"`) || !strings.Contains(page, "Report it, and change nothing.") {
		t.Errorf("project admin's form offers the schedule mode:\n%s", page)
	}
	if resp := e.post(project, form(e.client, map[string]string{"schedule_mode": store.ModeCorrect, "max_changes": "5"})); resp.StatusCode != 303 {
		t.Errorf("site admin setting the schedule mode: %d", resp.StatusCode)
	}
	if p := saved(); p.ScheduleMode != store.ModeCorrect || p.MaxChanges != 5 {
		t.Errorf("schedule mode = %q, %d", p.ScheduleMode, p.MaxChanges)
	}
	// The project admin's form carries the saved mode back unchanged.
	if resp := padmin.post(project, form(padmin, map[string]string{"schedule_mode": store.ModeCorrect, "max_changes": "5", "schedule": "12h"})); resp.StatusCode != 303 {
		t.Errorf("project admin saving with the mode unchanged: %d", resp.StatusCode)
	}
	if resp, _ := e.postBody(project, form(e.client, map[string]string{"schedule_mode": "yolo"})); resp.StatusCode != 400 {
		t.Errorf("an unknown mode: %d", resp.StatusCode)
	}
	e.post(project, form(e.client, map[string]string{"schedule_mode": store.ModeReport, "max_changes": "0"}))

	// A site admin changes any of it.
	if resp := e.post(project, form(e.client, map[string]string{"git_url": other, "env": "CONN3X_FAKE=plan\nAWS_PROFILE=prod"})); resp.StatusCode != 303 {
		t.Errorf("site admin changing the run settings: %d", resp.StatusCode)
	}
	if p := saved(); p.GitURL != other || p.Env != "CONN3X_FAKE=plan\nAWS_PROFILE=prod" {
		t.Errorf("site admin's change not saved: %+v", p)
	}

	// Credentials named for those variables are refused for everyone,
	// whatever their case; an ordinary one, and a file credential with such
	// a name (it reaches the run as CONN3X_CRED_<NAME>), are fine.
	for _, c := range []*client{padmin, e.client} {
		for _, name := range []string{"GIT_SSH_COMMAND", "ld_preload", "PATH", "DYLD_INSERT_LIBRARIES", "TF_CLI_CONFIG_FILE", "CONN3X_AGENT", "PYTHONPATH"} {
			resp, body := c.postBody(project+"/credentials", url.Values{"csrf": {c.csrf(project)}, "name": {name}, "kind": {store.CredEnv}, "value": {"x"}})
			if resp.StatusCode != 400 || !strings.Contains(body, "can&#39;t be a credential") {
				t.Errorf("env credential %s: %d\n%s", name, resp.StatusCode, body)
			}
		}
	}
	for name, kind := range map[string]string{"AWS_SECRET_ACCESS_KEY": store.CredEnv, "git_ssh_command": store.CredFile} {
		if resp := padmin.post(project+"/credentials", url.Values{"csrf": {padmin.csrf(project)}, "name": {name}, "kind": {kind}, "value": {"x"}}); resp.StatusCode != 303 {
			t.Errorf("%s credential %s: %d", kind, name, resp.StatusCode)
		}
	}
}
