// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"strings"
)

// The fleet store answers questions across runs and projects: what changed
// on a host, which hosts a fact matches, which steps failed. Runs fill it
// as they finish; see run.Runner.

// StepResult is one step's result on one host in one run: applied, with
// an outcome of "ok" or "failed", or drift a check or plan found.
type StepResult struct {
	RunID     int64   `json:"run_id"`
	ProjectID int64   `json:"project_id"`
	Project   string  `json:"project"`
	Host      string  `json:"host"`
	Step      string  `json:"step"`
	Item      string  `json:"item,omitempty"`
	Kind      string  `json:"kind"`
	Action    string  `json:"action"`
	Outcome   string  `json:"outcome,omitempty"`
	Elapsed   float64 `json:"elapsed_seconds,omitempty"`
	At        string  `json:"at"`
}

// Kinds of step result.
const (
	ResultApplied = "applied"
	ResultDrift   = "drift"
)

// SaveStepResults records a finished run's results.
func (s *Store) SaveStepResults(ctx context.Context, runID, projectID int64, results []StepResult) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	t := now()
	for _, r := range results {
		if _, err := tx.ExecContext(ctx, "INSERT INTO step_results (run_id, project_id, host, step, item, kind, action, outcome, elapsed, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			runID, projectID, r.Host, r.Step, r.Item, r.Kind, r.Action, r.Outcome, r.Elapsed, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveFacts keeps what a data source of type source read about host, the
// latest for each project, in place of what it read before.
func (s *Store) SaveFacts(ctx context.Context, projectID int64, host, source string, facts map[string]any, runID int64) error {
	b, err := json.Marshal(facts)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO host_facts (project_id, host, source, facts, run_id, at) VALUES (?, ?, ?, ?, ?, ?) "+
		"ON CONFLICT (project_id, host, source) DO UPDATE SET facts=excluded.facts, run_id=excluded.run_id, at=excluded.at",
		projectID, host, source, string(b), runID, now())
	return err
}

// visible keeps a query to the projects userID can view; 0 is a site
// admin, who sees all of them.
const visible = "(?1 = 0 OR project_id IN (SELECT project_id FROM roles WHERE user_id = ?1))"

// FleetHost is what the store knows about one host in one project.
type FleetHost struct {
	Host      string                    `json:"host"`
	ProjectID int64                     `json:"project_id"`
	Project   string                    `json:"project"`
	Facts     map[string]map[string]any `json:"facts"`
	At        string                    `json:"at"`
}

// FactMatch is one fact a host must have, as name and value: os_id:rocky.
// Its value matches a fact's text, or one key of a map fact, so
// packages:openssl matches a host with openssl installed.
type FactMatch struct{ Name, Value string }

// Hosts lists the hosts userID can see whose facts match every one of
// match, by host and project.
func (s *Store) Hosts(ctx context.Context, userID int64, match []FactMatch) ([]FleetHost, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT host, project_id, (SELECT name FROM projects WHERE id = project_id), source, facts, at FROM host_facts WHERE "+visible+" ORDER BY host, project_id, source", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FleetHost
	for rows.Next() {
		var h FleetHost
		var source, facts string
		if err := rows.Scan(&h.Host, &h.ProjectID, &h.Project, &source, &facts, &h.At); err != nil {
			return nil, err
		}
		var f map[string]any
		if err := json.Unmarshal([]byte(facts), &f); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].Host == h.Host && out[n-1].ProjectID == h.ProjectID {
			out[n-1].Facts[source] = f
			out[n-1].At = max(out[n-1].At, h.At)
			continue
		}
		h.Facts = map[string]map[string]any{source: f}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	kept := []FleetHost{}
	for _, h := range out {
		if matchesAll(h, match) {
			kept = append(kept, h)
		}
	}
	return kept, nil
}

// matchesAll says whether h has every fact in match, in any of its sources.
func matchesAll(h FleetHost, match []FactMatch) bool {
	for _, m := range match {
		found := false
		for _, f := range h.Facts {
			switch v := f[m.Name].(type) {
			case string:
				found = found || v == m.Value
			case float64, bool:
				found = found || strings.TrimSpace(jsonText(v)) == m.Value
			case map[string]any:
				_, ok := v[m.Value]
				found = found || ok
			case []any:
				for _, e := range v {
					found = found || e == m.Value
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ResultFilter narrows StepResults. A zero field matches everything.
type ResultFilter struct {
	Host    string
	Circuit string
	Outcome string
	Kind    string
	Since   string // RFC 3339 or a date, compared as text
}

// StepResults lists the step results userID can see that match f, newest
// first, at most limit.
func (s *Store) StepResults(ctx context.Context, userID int64, f ResultFilter, limit int) ([]StepResult, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT run_id, project_id, (SELECT name FROM projects WHERE id = project_id), host, step, item, kind, action, outcome, elapsed, at FROM step_results WHERE "+visible+
		" AND (?2 = '' OR host = ?2) AND (?3 = '' OR step LIKE ?3 || '.%') AND (?4 = '' OR outcome = ?4) AND (?5 = '' OR kind = ?5) AND (?6 = '' OR at >= ?6) ORDER BY id DESC LIMIT ?7",
		userID, f.Host, f.Circuit, f.Outcome, f.Kind, f.Since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StepResult{}
	for rows.Next() {
		var r StepResult
		if err := rows.Scan(&r.RunID, &r.ProjectID, &r.Project, &r.Host, &r.Step, &r.Item, &r.Kind, &r.Action, &r.Outcome, &r.Elapsed, &r.At); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneStepResults removes step results from before cutoff, an RFC 3339
// time. Facts stay: the latest per host is kept for good.
func (s *Store) PruneStepResults(ctx context.Context, cutoff string) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM step_results WHERE at < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
