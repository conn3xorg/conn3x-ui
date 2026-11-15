// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"encoding/json"
	"sort"

	conn3xexec "github.com/conn3xorg/conn3x-exec"
)

// Result is a plan's stream arranged for a page: hosts, then each host's
// steps, then what would happen to each.
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

// Action is one planned change.
type Action struct {
	Addr   string
	Item   string
	Action string
	Reason string
}

// Group arranges raw stream lines into a Result. Lines it doesn't know are
// ignored, so an older or newer Conn3x still gives a page.
func Group(lines [][]byte) Result {
	var res Result
	hosts := map[string]*Host{}
	steps := map[string]map[string]*Step{}
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
			host, step := "", ev.Change.Resource.Addr
			if s := ev.Change.Resource.Step; s != nil {
				host, step = s.Host, s.Circuit+"."+s.Step
			}
			h := hosts[host]
			if h == nil {
				h = &Host{Name: host}
				hosts[host] = h
				steps[host] = map[string]*Step{}
			}
			st := steps[host][step]
			if st == nil {
				h.Steps = append(h.Steps, Step{Name: step})
				st = &h.Steps[len(h.Steps)-1]
				steps[host][step] = st
			}
			st.Actions = append(st.Actions, action(ev.Change))
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
		a.Item = c.Resource.Step.Item
	}
	return a
}
