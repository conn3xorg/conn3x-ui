// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"fmt"
	"testing"
)

func change(host, circuit, step, item, action string) []byte {
	addr := fmt.Sprintf(`conn3x_command.%s__%s[\"%s\"]`, circuit, step, host)
	conn3x := fmt.Sprintf(`,"conn3x":{"circuit":%q,"step":%q,"host":%q,"item":%q}`, circuit, step, host, item)
	if host == "" {
		addr, conn3x = "digitalocean_droplet.web", ""
	}
	return []byte(fmt.Sprintf(`{"type":"planned_change","change":{"resource":{"addr":"%s","resource_type":"x","resource_name":"y"%s},"action":%q}}`, addr, conn3x, action))
}

func TestGroup(t *testing.T) {
	lines := [][]byte{
		[]byte(`{"type":"version","conn3x":"0.21.0"}`),
		[]byte(`{"type":"conn3x_ui","@message":"git clone"}`),
		change("web2", "box", "build", "", "create"),
		change("web1", "box", "build", "", "update"),
		change("web1", "box", "deploy", "a", "create"),
		change("web1", "box", "deploy", "b", "replace"),
		change("web1", "box", "noop", "", "noop"),
		change("", "", "", "", "create"),
		[]byte(`{"type":"resource_drift","change":{"resource":{"addr":"r","conn3x":{"circuit":"box","step":"motd","host":"web1"}},"action":"update"}}`),
		[]byte(`{"type":"diagnostic","diagnostic":{"severity":"warning","summary":"careful"}}`),
		[]byte(`not json at all`),
		[]byte(`{"type":"change_summary","changes":{"add":3,"change":1,"remove":0,"operation":"plan"}}`),
	}
	res := Group(lines)
	if len(res.Hosts) != 3 || res.Hosts[0].Name != "web1" || res.Hosts[1].Name != "web2" || res.Hosts[2].Name != "" {
		t.Fatalf("hosts %+v", res.Hosts)
	}
	w1 := res.Hosts[0]
	if len(w1.Steps) != 2 || w1.Steps[0].Name != "box.build" || w1.Steps[1].Name != "box.deploy" {
		t.Fatalf("web1 steps %+v", w1.Steps)
	}
	if a := w1.Steps[1].Actions; len(a) != 2 || a[0].Item != "a" || a[1].Action != "replace" {
		t.Fatalf("deploy actions %+v", a)
	}
	if o := res.Hosts[2]; len(o.Steps) != 1 || o.Steps[0].Name != "digitalocean_droplet.web" {
		t.Fatalf("other resources %+v", o.Steps)
	}
	if res.Summary == nil || res.Summary.Add != 3 || len(res.Diagnostics) != 1 || len(res.Drift) != 1 || len(res.Notes) != 1 {
		t.Fatalf("%+v", res)
	}
}

func hook(typ, host, step, item, action string, elapsed float64) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"hook":{"resource":{"addr":"conn3x_command.box__%s","conn3x":{"circuit":"box","step":%q,"host":%q,"item":%q}},"action":%q,"elapsed_seconds":%g}}`, typ, step, step, host, item, action, elapsed))
}

func TestGroupApply(t *testing.T) {
	lines := [][]byte{
		hook("apply_start", "web1", "build", "", "create", 0),
		hook("apply_progress", "web1", "build", "", "create", 10),
		hook("apply_complete", "web1", "build", "", "create", 12.5),
		hook("apply_complete", "web1", "deploy", "a", "create", 1),
		hook("apply_errored", "web1", "build", "x", "create", 3), // back to an earlier step
		[]byte(`{"type":"change_summary","changes":{"add":2,"change":0,"remove":0,"operation":"apply"}}`),
	}
	res := Group(lines)
	if len(res.Hosts) != 1 || len(res.Hosts[0].Steps) != 2 || !res.HasChanges() {
		t.Fatalf("%+v", res)
	}
	build, deploy := res.Hosts[0].Steps[0], res.Hosts[0].Steps[1]
	if len(build.Actions) != 2 || build.Actions[0].Outcome != "ok" || build.Actions[0].Elapsed != 12.5 || build.Actions[1].Outcome != "failed" || build.Actions[1].Item != "x" {
		t.Errorf("build %+v", build.Actions)
	}
	if len(deploy.Actions) != 1 || deploy.Actions[0].Item != "a" {
		t.Errorf("deploy %+v", deploy.Actions)
	}
	if (Result{}).HasChanges() || Group(nil).HasChanges() {
		t.Error("an empty result has changes")
	}
}

func TestValidateGitURL(t *testing.T) {
	ok := []string{"https://github.com/conn3xorg/conn3x.git", "ssh://git@github.com/x/y.git", "git@github.com:x/y.git", "github.com:x/y", "http://127.0.0.1:8080/x.git", "http://localhost/x.git"}
	bad := []string{"", "-oProxyCommand=evil", "file:///etc", "ext::sh -c evil", "/tmp/repo.git", "http://example.com/x.git", "https://", "git@host:ext::x", `C:\repo`, "host:: x"}
	for _, u := range ok {
		if err := ValidateGitURL(u); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range bad {
		if ValidateGitURL(u) == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestHostOutcomes(t *testing.T) {
	hook := func(typ, host, step string) []byte {
		return []byte(fmt.Sprintf(`{"type":%q,"hook":{"resource":{"addr":"a.%s","conn3x":{"circuit":"box","step":%q,"host":%q}},"action":"create"}}`, typ, step, step, host))
	}
	plan := Group([][]byte{change("web1", "box", "build", "", "create"), change("", "", "", "", "create")}).HostOutcomes()
	if len(plan) != 1 || plan["web1"] != "changes" {
		t.Errorf("plan %v", plan)
	}
	apply := Group([][]byte{hook("apply_complete", "web1", "a"), hook("apply_errored", "web1", "b"), hook("apply_complete", "web2", "a")}).HostOutcomes()
	if len(apply) != 2 || apply["web1"] != "failed" || apply["web2"] != "ok" {
		t.Errorf("apply %v", apply)
	}
}
