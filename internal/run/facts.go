// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// factSources are the data sources whose values are a host's facts, for
// the fleet store. Each is read with for_each over the hosts, so its
// instance key is the host.
var factSources = map[string]bool{"conn3x_host": true, "conn3x_packages": true, "conn3x_services": true}

// showJSON is conn3x show -json of the saved plan in work.
func showJSON(ctx context.Context, conn3x, work string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, conn3x, "show", "-json", "plan.bin")
	cmd.Dir, cmd.Env = work, append(cmd.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("show: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

type stateModule struct {
	Resources []struct {
		Mode      string          `json:"mode"`
		Type      string          `json:"type"`
		Index     any             `json:"index"`
		Values    map[string]any  `json:"values"`
		Sensitive json.RawMessage `json:"sensitive_values"`
	} `json:"resources"`
	ChildModules []stateModule `json:"child_modules"`
}

// planFacts reads the facts in a plan's prior state, which holds what each
// data source read at plan: by host, then by source.
func planFacts(plan []byte) (map[string]map[string]map[string]any, error) {
	var pl struct {
		PriorState struct {
			Values struct {
				RootModule stateModule `json:"root_module"`
			} `json:"values"`
		} `json:"prior_state"`
	}
	if err := json.Unmarshal(plan, &pl); err != nil {
		return nil, err
	}
	out := map[string]map[string]map[string]any{}
	var walk func(m stateModule)
	walk = func(m stateModule) {
		for _, r := range m.Resources {
			host, ok := r.Index.(string)
			if r.Mode != "data" || !factSources[r.Type] || !ok || host == "" {
				continue
			}
			var sens any
			_ = json.Unmarshal(r.Sensitive, &sens)
			facts := map[string]any{}
			for k, v := range r.Values {
				if k == "ssh" || k == "id" || strings.HasPrefix(k, "read_") || k == "allow_windows" {
					continue // how it was read, not about the host
				}
				if v = withoutSensitive(v, field(sens, k)); v != nil {
					facts[k] = v
				}
			}
			if out[host] == nil {
				out[host] = map[string]map[string]any{}
			}
			out[host][r.Type] = facts
		}
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(pl.PriorState.Values.RootModule)
	return out, nil
}

func field(sens any, k string) any {
	if m, ok := sens.(map[string]any); ok {
		return m[k]
	}
	return nil
}

// withoutSensitive drops whatever sens marks as sensitive in v: all of it
// when sens is true, or the parts it marks inside a map or list.
func withoutSensitive(v, sens any) any {
	switch s := sens.(type) {
	case bool:
		if s {
			return nil
		}
	case map[string]any:
		if m, ok := v.(map[string]any); ok {
			out := map[string]any{}
			for k, e := range m {
				if e = withoutSensitive(e, s[k]); e != nil {
					out[k] = e
				}
			}
			return out
		}
	case []any:
		if l, ok := v.([]any); ok {
			out := []any{}
			for i, e := range l {
				var si any
				if i < len(s) {
					si = s[i]
				}
				if e = withoutSensitive(e, si); e != nil {
					out = append(out, e)
				}
			}
			return out
		}
	}
	return v
}

// saveFacts stores the facts in the plan saved in work, for the fleet
// store. Not being able to doesn't fail the run; its log says why.
func (r *Runner) saveFacts(ctx context.Context, id int64, p store.Project, work string, env []string) {
	b, err := showJSON(ctx, p.Conn3xPath, work, env)
	var facts map[string]map[string]map[string]any
	if err == nil {
		facts, err = planFacts(b)
	}
	for host, bySource := range facts {
		for source, f := range bySource {
			if err == nil {
				err = r.Store.SaveFacts(context.Background(), p.ID, host, source, f, id)
			}
		}
	}
	if err != nil {
		r.note(id, "Facts weren't saved: "+r.scrub(id, err.Error()))
	}
}
