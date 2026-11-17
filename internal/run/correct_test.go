// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"encoding/json"
	"strings"
	"testing"

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
