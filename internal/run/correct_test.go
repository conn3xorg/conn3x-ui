// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

func TestUnattended(t *testing.T) {
	plan := func(changes string) planJSON {
		var pl planJSON
		if err := json.Unmarshal([]byte(`{"resource_changes":[`+changes+`],"resource_drift":[{"address":"a"}]}`), &pl); err != nil {
			t.Fatal(err)
		}
		return pl
	}
	ch := func(addr string, actions ...string) string {
		b, _ := json.Marshal(map[string]any{"address": addr, "change": map[string]any{"actions": actions}})
		return string(b)
	}
	for _, c := range []struct {
		name, changes, mode string
		max, n              int
		why                 string
	}{
		{"puts back drift", ch("a", "update") + "," + ch("b", "no-op"), store.ModeCorrect, 0, 1, ""},
		{"updates something that didn't drift", ch("b", "update"), store.ModeCorrect, 0, 1, "which didn't drift"},
		{"creates, when correcting", ch("a", "update") + "," + ch("c", "create"), store.ModeCorrect, 0, 2, "only updates in place"},
		{"creates, when converging", ch("a", "update") + "," + ch("c", "create"), store.ModeConverge, 0, 2, ""},
		{"deletes", ch("a", "delete"), store.ModeConverge, 0, 1, "would delete a"},
		{"replaces", ch("a", "delete", "create"), store.ModeConverge, 0, 1, "would replace a"},
		{"over the cap", ch("a", "update") + "," + ch("c", "create") + "," + ch("d", "create"), store.ModeConverge, 2, 3, "3 changes, more than the 2"},
		{"at the cap", ch("a", "update") + "," + ch("c", "create"), store.ModeConverge, 2, 2, ""},
		{"nothing to do", ch("a", "no-op") + "," + ch("e", "read"), store.ModeCorrect, 0, 0, ""},
	} {
		n, why := unattended(plan(c.changes), c.mode, c.max)
		if n != c.n || (c.why == "") != (why == "") || !strings.Contains(why, c.why) {
			t.Errorf("%s: %d changes, %q", c.name, n, why)
		}
	}
}

// A splay holds a due check back by a delay it picks once, then lets it
// start; a fresh delay is picked the next time.
func TestSplay(t *testing.T) {
	r := &Runner{splayed: map[int64]time.Time{}}
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	if !r.splay(store.Project{ID: 1}, now) {
		t.Error("no splay held a check back")
	}
	p := store.Project{ID: 2, SplayMinutes: 30}
	if r.splay(p, now) && r.splayed[2].IsZero() {
		// rand picked 0: allowed, and nothing is left pending.
		return
	}
	at := r.splayed[2]
	if at.Before(now) || !at.Before(now.Add(30*time.Minute)) {
		t.Fatalf("delay to %v", at)
	}
	if r.splay(p, at.Add(-time.Second)) {
		t.Error("started before its delay")
	}
	if r.splayed[2] != at {
		t.Error("the delay was picked again while waiting")
	}
	if !r.splay(p, at) {
		t.Error("didn't start once its delay passed")
	}
	if _, ok := r.splayed[2]; ok {
		t.Error("the delay stayed for next time")
	}
}
