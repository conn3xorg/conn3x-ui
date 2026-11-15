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
