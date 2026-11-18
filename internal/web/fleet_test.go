// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// The hosts page lists what the fleet store knows, filtered by facts, and a
// host's page shows its facts and step results; neither shows a project
// the user can't view.
func TestFleetPages(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	web, err := e.st.CreateProject(ctx, store.Project{Name: "web", GitURL: "https://example.com/web.git", GitRef: "main", Path: "."})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := e.st.CreateProject(ctx, store.Project{Name: "secret", GitURL: "https://example.com/s.git", GitRef: "main", Path: "."})
	if err != nil {
		t.Fatal(err)
	}
	run, err := e.st.CreateRun(ctx, web, store.KindApply, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		project int64
		host    string
		source  string
		facts   map[string]any
	}{
		{web, "web1", "conn3x_host", map[string]any{"os_id": "rocky", "os_version": "10.0"}},
		{web, "web1", "conn3x_packages", map[string]any{"packages": map[string]any{"openssl": "3.2", "nginx": "1.26"}}},
		{web, "web2", "conn3x_host", map[string]any{"os_id": "ubuntu", "os_version": "24.04"}},
		{secret, "vault1", "conn3x_host", map[string]any{"os_id": "rocky", "os_version": "10.0"}},
	} {
		if err := e.st.SaveFacts(ctx, f.project, f.host, f.source, f.facts, run); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.st.SaveStepResults(ctx, run, web, []store.StepResult{{Host: "web1", Step: "conn3x_file.web__motd", Kind: store.ResultApplied, Action: "update", Outcome: "changed"}}); err != nil {
		t.Fatal(err)
	}

	e.login(t)
	_, page := e.get("/hosts")
	for _, want := range []string{`href="/hosts/web1"`, "rocky 10.0", "ubuntu 24.04", "vault1"} {
		if !strings.Contains(page, want) {
			t.Errorf("admin's hosts page has no %q", want)
		}
	}
	_, page = e.get("/hosts?facts=" + url.QueryEscape("os_id:rocky packages:openssl"))
	if !strings.Contains(page, "web1") || strings.Contains(page, "web2") || strings.Contains(page, "vault1") {
		t.Errorf("filtered page:\n%s", page)
	}
	if resp, _ := e.get("/hosts?facts=nocolon"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a filter without name:value: %d", resp.StatusCode)
	}
	_, page = e.get("/hosts/web1")
	for _, want := range []string{"conn3x_host", "openssl", "conn3x_file.web__motd", "changed"} {
		if !strings.Contains(page, want) {
			t.Errorf("web1's page has no %q", want)
		}
	}

	// A viewer of web sees web's hosts, and nothing of secret.
	uid, _ := e.st.CreateUser(ctx, "pat", "pw2")
	if err := e.st.SetRole(ctx, web, uid, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	pat := newClient(t, e.base)
	pat.loginAs(t, "pat", "pw2")
	_, page = pat.get("/hosts")
	if !strings.Contains(page, "web1") || strings.Contains(page, "vault1") {
		t.Errorf("viewer's hosts page:\n%s", page)
	}
	if resp, _ := pat.get("/hosts/vault1"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("viewer on another project's host: %d, want 404", resp.StatusCode)
	}
}
