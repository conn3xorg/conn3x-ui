// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	conn3xexec "github.com/conn3xorg/conn3x-exec"
	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// After a drift check finds drift, a project whose schedule mode is correct
// or converge plans, and applies that plan with no one approving it only
// when the plan passes every guard below. Otherwise the plan waits for a
// person, the same as one somebody made by hand.

// planJSON is the part of conn3x show -json a scheduled apply reads.
type planJSON struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			Actions []string `json:"actions"`
		} `json:"change"`
	} `json:"resource_changes"`
	ResourceDrift []struct {
		Address string `json:"address"`
	} `json:"resource_drift"`
}

// unattended says whether a plan may be applied with no one approving it
// under mode, with at most max changes (0 for any number). It returns how
// many changes the plan makes, and when it may not, why, as a sentence.
func unattended(pl planJSON, mode string, max int) (changes int, why string) {
	drifted := map[string]bool{}
	for _, d := range pl.ResourceDrift {
		drifted[d.Address] = true
	}
	for _, rc := range pl.ResourceChanges {
		a := rc.Change.Actions
		if len(a) == 0 || slices.Equal(a, []string{"no-op"}) || slices.Equal(a, []string{"read"}) {
			continue
		}
		changes++
		switch {
		case slices.Contains(a, "delete"):
			// Never, in any mode: a delete or a replace always waits.
			if why == "" {
				what := "delete"
				if slices.Contains(a, "create") {
					what = "replace"
				}
				why = fmt.Sprintf("it would %s %s, and a schedule never deletes or replaces anything", what, rc.Address)
			}
		case mode == store.ModeCorrect && !slices.Equal(a, []string{"update"}):
			if why == "" {
				why = fmt.Sprintf("it would %s %s, and correcting drift only updates in place", strings.Join(a, " and "), rc.Address)
			}
		case mode == store.ModeCorrect && !drifted[rc.Address]:
			if why == "" {
				why = fmt.Sprintf("it would change %s, which didn't drift, and correcting drift only puts back what drifted", rc.Address)
			}
		}
	}
	if why == "" && max > 0 && changes > max {
		why = fmt.Sprintf("it makes %d changes, more than the %d this project allows a schedule", changes, max)
	}
	return changes, why
}

// showPlan reads the saved plan in work with conn3x show -json.
func showPlan(ctx context.Context, conn3x, work string, env []string) (planJSON, error) {
	var pl planJSON
	b, err := showJSON(ctx, conn3x, work, env)
	if err != nil {
		return pl, err
	}
	return pl, json.Unmarshal(b, &pl)
}

// correct follows a drift check, run driftID, that found drift: it plans,
// and applies the plan unattended when the guards allow, or leaves it for
// a person. Either way the webhook hears what happened.
func (r *Runner) correct(driftID int64, p store.Project) {
	bg := context.Background()
	if d, err := r.Store.Run(bg, driftID); err != nil || d.Status != store.StatusSucceeded || d.Outcome != store.OutcomeDrift {
		return
	}
	planID, err := r.Store.CreateRun(bg, p.ID, store.KindPlan, 0)
	if err != nil {
		r.Log.Printf("schedule: project %d: %v", p.ID, err)
		return
	}
	var why string
	changes := 0
	r.run(planID, p, func(ctx context.Context, env []string) error {
		r.note(planID, fmt.Sprintf("Planned by the schedule after drift check %d", driftID))
		return r.doPlan(ctx, planID, p, env, func(c *conn3xexec.Conn3x) error {
			pl, err := showPlan(ctx, c.Path, c.Dir, c.Env)
			if err != nil {
				return err
			}
			changes, why = unattended(pl, p.ScheduleMode, p.MaxChanges)
			return nil
		})
	})
	plan, err := r.Store.Run(bg, planID)
	if err != nil || plan.Status != store.StatusSucceeded {
		r.notifyScheduled(p, planID, store.StatusFailed, "", fmt.Sprintf("Conn3x: the schedule's plan of %s failed (run %d)", p.Name, planID))
		return
	}
	switch {
	case changes == 0:
		r.note(planID, "Nothing to change: the drift is in settings the configuration doesn't set.")
		return
	case why != "":
		r.note(planID, "Waits for a person to approve: "+why+".")
		r.notifyScheduled(p, planID, store.StatusSucceeded, "waiting", fmt.Sprintf("Conn3x: %s has a plan waiting for approval, since %s (run %d)", p.Name, why, planID))
		return
	}
	r.note(planID, fmt.Sprintf("The schedule applies this plan: %d changes, %s.", changes, map[string]string{
		store.ModeCorrect:  "each one putting back something that drifted",
		store.ModeConverge: "with no delete or replace",
	}[p.ScheduleMode]))
	applyID, err := r.Store.CreateApply(bg, planID, 0)
	if err != nil {
		r.Log.Printf("schedule: project %d: %v", p.ID, err)
		return
	}
	r.run(applyID, p, func(ctx context.Context, env []string) error { return r.doApply(ctx, applyID, p, plan, env) })
	a, err := r.Store.Run(bg, applyID)
	if err != nil {
		r.Log.Printf("run %d: %v", applyID, err)
		return
	}
	if a.Status == store.StatusSucceeded {
		r.notifyScheduled(p, applyID, a.Status, "corrected", fmt.Sprintf("Conn3x: the schedule applied %d changes to %s (run %d)", changes, p.Name, applyID))
	} else {
		r.notifyScheduled(p, applyID, a.Status, "", fmt.Sprintf("Conn3x: the schedule's apply to %s %s (run %d)", p.Name, a.Status, applyID))
	}
}

// notifyScheduled posts what a scheduled plan or apply came to.
func (r *Runner) notifyScheduled(p store.Project, id int64, status, outcome, text string) {
	if p.WebhookURL == "" && (p.NotifyEmail == "" || r.Mailer == nil) {
		return
	}
	var hosts []string
	if lines, _, err := r.Store.Events(context.Background(), id); err == nil {
		for _, h := range Group(lines).Hosts {
			if h.Name != "" {
				hosts = append(hosts, h.Name)
			}
		}
	}
	if hosts == nil {
		hosts = []string{}
	}
	n := Notification{Project: p.Name, RunID: id, Status: status, Outcome: outcome, Link: fmt.Sprintf("/runs/%d", id), Hosts: hosts, Time: time.Now().UTC(), Text: text}
	r.withURL(&n)
	r.deliver(p, n)
}
