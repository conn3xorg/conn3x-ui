// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"encoding/json"
	"slices"
	"sort"

	conn3xexec "github.com/conn3xorg/conn3x-exec"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// Result is a plan's or an apply's stream arranged for a page: hosts, then
// each host's steps, then what would happen, or happened, to each.
type Result struct {
	Hosts       []Host
	Summary     *conn3xexec.ChangeSummary
	Diagnostics []conn3xexec.Diagnostic
	// Drift is what changed on a host since the last apply.
	Drift []Action
	// Notes are conn3x-ui's own lines, such as the git clone.
	Notes []string
}

// Host is one host's planned steps. Name is "" for resources that aren't
// circuit steps, such as cloud servers.
type Host struct {
	Name  string
	Steps []Step
}

// Step is one circuit step on a host, as "circuit.step". A step with
// for_each has one action per item.
type Step struct {
	Name    string
	Actions []Action
}

// Action is one planned change, or one applied in an apply. Outcome is
// "ok" or "failed" for an apply, with how long the step took, and "" for
// a plan. Host is set for drift, which isn't grouped by host.
type Action struct {
	Host    string
	Addr    string
	Item    string
	Action  string
	Reason  string
	Outcome string
	Elapsed float64
}

// HasChanges is true when the summary counts anything to do.
func (r Result) HasChanges() bool {
	s := r.Summary
	return s != nil && s.Add+s.Change+s.Remove+s.Import+s.Forget > 0
}

// Outcome is how the run came out on the host: "failed" when a step
// failed there, "ok" when its applied steps all succeeded, and "changes"
// for a plan that would change it.
func (h Host) Outcome() string {
	out := "changes"
	for _, s := range h.Steps {
		for _, a := range s.Actions {
			switch a.Outcome {
			case "failed":
				return "failed"
			case "ok":
				out = "ok"
			}
		}
	}
	return out
}

// HostOutcomes is each named host's Outcome, for the run history, and
// "drift" for a host that only drifted.
func (r Result) HostOutcomes() map[string]string {
	out := map[string]string{}
	for _, h := range r.DriftedHosts() {
		out[h] = store.OutcomeDrift
	}
	for _, h := range r.Hosts {
		if h.Name != "" {
			out[h.Name] = h.Outcome()
		}
	}
	return out
}

// DriftedHosts is each named host with drift, by name.
func (r Result) DriftedHosts() []string {
	var out []string
	for _, a := range r.Drift {
		if a.Host != "" && !slices.Contains(out, a.Host) {
			out = append(out, a.Host)
		}
	}
	slices.Sort(out)
	return out
}

// Group arranges raw stream lines into a Result. Lines it doesn't know are
// ignored, so an older or newer Conn3x still gives a page.
func Group(lines [][]byte) Result {
	var res Result
	hosts := map[string]*Host{}
	steps := map[string]map[string]int{} // index into hosts[h].Steps; a pointer would go stale on append
	add := func(res conn3xexec.Resource, a Action) {
		host, step := "", res.Addr
		if s := res.Step; s != nil {
			host, step = s.Host, s.Circuit+"."+s.Step
		}
		h := hosts[host]
		if h == nil {
			h = &Host{Name: host}
			hosts[host] = h
			steps[host] = map[string]int{}
		}
		i, ok := steps[host][step]
		if !ok {
			i = len(h.Steps)
			h.Steps = append(h.Steps, Step{Name: step})
			steps[host][step] = i
		}
		h.Steps[i].Actions = append(h.Steps[i].Actions, a)
	}
	for _, line := range lines {
		var ev conn3xexec.Event
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch ev.Type {
		case "change_summary":
			res.Summary = ev.Changes
		case "diagnostic":
			if ev.Diagnostic != nil {
				res.Diagnostics = append(res.Diagnostics, *ev.Diagnostic)
			}
		case "conn3x_ui":
			res.Notes = append(res.Notes, ev.Message)
		case "resource_drift":
			if ev.Change != nil {
				res.Drift = append(res.Drift, action(ev.Change))
			}
		case "planned_change":
			if ev.Change == nil || ev.Change.Action == "noop" {
				continue
			}
			add(ev.Change.Resource, action(ev.Change))
		case "apply_complete", "apply_errored":
			if ev.Hook == nil {
				continue
			}
			a := Action{Addr: ev.Hook.Resource.Addr, Action: ev.Hook.Action, Outcome: "ok", Elapsed: ev.Hook.Elapsed}
			if ev.Type == "apply_errored" {
				a.Outcome = "failed"
			}
			if ev.Hook.Resource.Step != nil {
				a.Item = ev.Hook.Resource.Step.Item
			}
			add(ev.Hook.Resource, a)
		}
	}
	for _, h := range hosts {
		res.Hosts = append(res.Hosts, *h)
	}
	// Named hosts by name; the nameless "other resources" group last.
	sort.Slice(res.Hosts, func(i, j int) bool {
		a, b := res.Hosts[i].Name, res.Hosts[j].Name
		if (a == "") != (b == "") {
			return b == ""
		}
		return a < b
	})
	return res
}

func action(c *conn3xexec.Change) Action {
	a := Action{Addr: c.Resource.Addr, Action: c.Action, Reason: c.Reason}
	if c.Resource.Step != nil {
		a.Host, a.Item = c.Resource.Step.Host, c.Resource.Step.Item
	}
	return a
}
