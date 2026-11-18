package store

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// EventRule starts a drift check of its project when a webhook signed with
// its secret arrives, or an Alertmanager alert it matches.
type EventRule struct {
	ID        int64
	ProjectID int64
	Name      string
	// Alertname and Labels are what an Alertmanager alert must have for the
	// rule to start a run: an alertname, and LABEL=VALUE lines. Both empty
	// matches any signed request.
	Alertname string
	Labels    string
	// LimitLabel is an alert label whose value is the host the run is
	// limited to, as -limit; "" runs on every host.
	LimitLabel string
	// Vars is VAR=LABEL lines: each variable the run gets from an alert
	// label, as TF_VAR_VAR.
	Vars string
	// Mode is what the run does about the drift it finds, as a schedule's
	// ScheduleMode.
	Mode string
	// DebounceMinutes is how long after a run the rule starts no other;
	// events in between are folded into that run.
	DebounceMinutes int
	LastStartedAt   string
	CreatedAt       string
}

// LabelPairs is Labels as name and value pairs, blank lines dropped.
func (e EventRule) LabelPairs() [][2]string { return pairs(e.Labels) }

// VarPairs is Vars as variable and label pairs, blank lines dropped.
func (e EventRule) VarPairs() [][2]string { return pairs(e.Vars) }

// pairs reads KEY=VALUE lines, blank lines dropped.
func pairs(lines string) [][2]string {
	var out [][2]string
	for _, l := range strings.Split(lines, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			out = append(out, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
		}
	}
	return out
}

const ruleCols = "id, project_id, name, alertname, labels, limit_label, vars, mode, debounce_minutes, last_started_at, created_at"

func scanRule(row interface{ Scan(...any) error }) (EventRule, error) {
	var e EventRule
	err := row.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Alertname, &e.Labels, &e.LimitLabel, &e.Vars, &e.Mode, &e.DebounceMinutes, &e.LastStartedAt, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return e, err
}

// ruleAD binds a rule's sealed secret to its project and name, as credAD
// does a credential's.
func ruleAD(projectID int64, name string) []byte {
	return fmt.Appendf(nil, "event\x00%d\x00%s", projectID, name)
}

// CreateEventRule adds a rule with a new random secret, sealed with the
// credentials key, and returns the rule and the secret. The secret isn't
// shown again.
func (s *Store) CreateEventRule(ctx context.Context, e EventRule) (EventRule, []byte, error) {
	if s.aead == nil {
		return e, nil, ErrNoKey
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	sealed := s.aead.Seal(nonce, nonce, secret, ruleAD(e.ProjectID, e.Name))
	e.CreatedAt = now()
	res, err := s.db.ExecContext(ctx, "INSERT INTO event_rules (project_id, name, secret, alertname, labels, limit_label, vars, mode, debounce_minutes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		e.ProjectID, e.Name, sealed, e.Alertname, e.Labels, e.LimitLabel, e.Vars, e.Mode, e.DebounceMinutes, e.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return e, nil, fmt.Errorf("this project already has an event rule called %s", e.Name)
		}
		return e, nil, err
	}
	e.ID, err = res.LastInsertId()
	return e, secret, err
}

// EventRules returns a project's rules, by name.
func (s *Store) EventRules(ctx context.Context, projectID int64) ([]EventRule, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+ruleCols+" FROM event_rules WHERE project_id=? ORDER BY name", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRule
	for rows.Next() {
		e, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EventRule returns a rule and its opened secret.
func (s *Store) EventRule(ctx context.Context, id int64) (EventRule, []byte, error) {
	var sealed []byte
	e, err := scanRule(s.db.QueryRowContext(ctx, "SELECT "+ruleCols+" FROM event_rules WHERE id=?", id))
	if err != nil {
		return e, nil, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT secret FROM event_rules WHERE id=?", id).Scan(&sealed); err != nil {
		return e, nil, err
	}
	if s.aead == nil {
		return e, nil, ErrNoKey
	}
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return e, nil, fmt.Errorf("event rule %s is damaged", e.Name)
	}
	secret, err := s.aead.Open(nil, sealed[:n], sealed[n:], ruleAD(e.ProjectID, e.Name))
	if err != nil {
		return e, nil, fmt.Errorf("event rule %s won't open: the credentials key %s", e.Name, errWrongKey)
	}
	return e, secret, nil
}

// DeleteEventRule removes a project's rule. Runs it started keep its name.
func (s *Store) DeleteEventRule(ctx context.Context, projectID, id int64) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, "DELETE FROM event_rules WHERE project_id=? AND id=? RETURNING name", projectID, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return name, err
}

// SeeDelivery records a delivery ID for a rule, and says false if the rule
// has seen it before. IDs older than a day are forgotten, which is safe
// since a signed request older than the timestamp window is refused anyway.
func (s *Store) SeeDelivery(ctx context.Context, ruleID int64, delivery string) (bool, error) {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM event_deliveries WHERE received_at < ?", time.Now().UTC().Add(-24*time.Hour).Format(time.RFC3339)); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, "INSERT INTO event_deliveries (rule_id, delivery, received_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING", ruleID, delivery, now())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ClaimEventRun marks the rule as having started a run now, unless it
// started one within its debounce time, and says whether it did. One
// update checks and claims, so two events at once start one run.
func (s *Store) ClaimEventRun(ctx context.Context, ruleID int64) (bool, error) {
	t := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, "UPDATE event_rules SET last_started_at=? WHERE id=? AND (last_started_at = '' OR last_started_at <= strftime('%Y-%m-%dT%H:%M:%SZ', ?, '-' || debounce_minutes || ' minutes'))",
		t.Format(time.RFC3339), ruleID, t.Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// EventInput is what a run takes from the event that started it: the
// host it's limited to, as -limit, and TF_VAR_ variables.
type EventInput struct {
	Limit string
	Env   []string
}

// CreateEventRun adds a queued drift check that rule started, keeping the
// event's body and what the run takes from it, and returns its ID.
func (s *Store) CreateEventRun(ctx context.Context, rule EventRule, body string, in EventInput) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO runs (project_id, kind, status, created_at, event_rule_id, event_rule_name, event_body, event_limit, event_env) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		rule.ProjectID, KindDrift, StatusQueued, now(), rule.ID, rule.Name, body, in.Limit, strings.Join(in.Env, "\n"))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// InheritEvent gives run id the event rule of run from, and what it took
// from the event, so the plan and apply that follow an event's drift check
// say what started them and plan the same hosts with the same variables.
func (s *Store) InheritEvent(ctx context.Context, id, from int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE runs SET (event_rule_id, event_rule_name, event_limit, event_env) = (SELECT event_rule_id, event_rule_name, event_limit, event_env FROM runs WHERE id=?) WHERE id=?", from, id)
	return err
}

// RunEventInput is what a run took from the event that started it, empty
// for a run no event started.
func (s *Store) RunEventInput(ctx context.Context, runID int64) (EventInput, error) {
	var in EventInput
	var env string
	err := s.db.QueryRowContext(ctx, "SELECT event_limit, event_env FROM runs WHERE id=?", runID).Scan(&in.Limit, &env)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if env != "" {
		in.Env = strings.Split(env, "\n")
	}
	return in, err
}

// EventBody is the event that started a run, or "" for a run no event
// started.
func (s *Store) EventBody(ctx context.Context, runID int64) (string, error) {
	var b string
	err := s.db.QueryRowContext(ctx, "SELECT event_body FROM runs WHERE id=?", runID).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return b, err
}

// resealRules re-seals every event rule's secret from old to next, inside
// RotateKey's transaction, and returns how many there were.
func resealRules(ctx context.Context, tx *sql.Tx, old, next cipher.AEAD) (int, error) {
	type row struct {
		id, projectID int64
		name          string
		sealed        []byte
	}
	var all []row
	rows, err := tx.QueryContext(ctx, "SELECT id, project_id, name, secret FROM event_rules")
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.projectID, &r.name, &r.sealed); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range all {
		n := old.NonceSize()
		if len(r.sealed) < n {
			return 0, fmt.Errorf("event rule %s is damaged", r.name)
		}
		plain, err := old.Open(nil, r.sealed[:n], r.sealed[n:], ruleAD(r.projectID, r.name))
		if err != nil {
			return 0, fmt.Errorf("event rule %s won't open: the old key %s", r.name, errWrongKey)
		}
		nonce := make([]byte, next.NonceSize())
		rand.Read(nonce)
		sealed := next.Seal(nonce, nonce, plain, ruleAD(r.projectID, r.name))
		clear(plain)
		if _, err := tx.ExecContext(ctx, "UPDATE event_rules SET secret=? WHERE id=?", sealed, r.id); err != nil {
			return 0, err
		}
	}
	return len(all), nil
}
