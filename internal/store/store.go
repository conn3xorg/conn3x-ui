// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package store keeps projects, runs, users, roles, sessions, credentials
// and the audit log in one SQLite file.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is a row that isn't there.
var ErrNotFound = errors.New("not found")

// migrations run in order; each entry is one schema version. Add to the
// end, never edit an entry that shipped.
var migrations = []string{
	`CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE TABLE sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		csrf TEXT NOT NULL,
		expires_at TEXT NOT NULL
	);
	CREATE TABLE projects (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		git_url TEXT NOT NULL,
		git_ref TEXT NOT NULL,
		path TEXT NOT NULL,
		conn3x_path TEXT NOT NULL,
		env TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE runs (
		id INTEGER PRIMARY KEY,
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		kind TEXT NOT NULL,
		status TEXT NOT NULL,
		commit_sha TEXT NOT NULL DEFAULT '',
		conn3x_version TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
		created_at TEXT NOT NULL,
		started_at TEXT,
		finished_at TEXT
	);
	CREATE INDEX runs_project ON runs(project_id, id);
	CREATE TABLE run_events (
		run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
		seq INTEGER NOT NULL,
		line BLOB NOT NULL,
		PRIMARY KEY (run_id, seq)
	);`,
	// 2: an apply points at the plan it runs and records who approved it.
	`ALTER TABLE runs ADD COLUMN plan_run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL;
	ALTER TABLE runs ADD COLUMN approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL;
	ALTER TABLE runs ADD COLUMN approved_at TEXT;
	CREATE INDEX runs_plan ON runs(plan_run_id);`,
	// 3: the hosts each run touched and how each came out, so the history
	// can be filtered by host.
	`CREATE TABLE run_hosts (
		run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
		host TEXT NOT NULL,
		outcome TEXT NOT NULL,
		PRIMARY KEY (run_id, host)
	);
	CREATE INDEX run_hosts_host ON run_hosts(host, run_id);`,
	// 4: each project's credentials, sealed with the key the UI reads at
	// start. Names are unique whatever their case, since a file credential
	// becomes an upper-case variable.
	`CREATE TABLE credentials (
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL COLLATE NOCASE,
		kind TEXT NOT NULL,
		value BLOB NOT NULL,
		set_at TEXT NOT NULL,
		PRIMARY KEY (project_id, name)
	);`,
	// 5: a drift check schedule and a webhook per project, and how a drift
	// check came out.
	`ALTER TABLE projects ADD COLUMN schedule TEXT NOT NULL DEFAULT '';
	ALTER TABLE projects ADD COLUMN webhook_url TEXT NOT NULL DEFAULT '';
	ALTER TABLE runs ADD COLUMN outcome TEXT NOT NULL DEFAULT '';`,
	// 6: site admins, disabled users, a role per user per project, the
	// setting that lets planners apply their own plans, and the audit log.
	// Until now the only user was the admin made at first start, so every
	// existing user stays an admin. The audit log keeps names as text and
	// has no foreign keys, so deleting a project or user never touches it,
	// and its triggers refuse any UPDATE or DELETE.
	`ALTER TABLE users ADD COLUMN admin INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
	UPDATE users SET admin = 1;
	ALTER TABLE projects ADD COLUMN self_apply INTEGER NOT NULL DEFAULT 0;
	CREATE TABLE roles (
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		role TEXT NOT NULL,
		PRIMARY KEY (project_id, user_id)
	);
	CREATE INDEX roles_user ON roles(user_id);
	CREATE TABLE audit (
		id INTEGER PRIMARY KEY,
		at TEXT NOT NULL,
		user_id INTEGER,
		user_name TEXT NOT NULL,
		project_id INTEGER,
		project_name TEXT NOT NULL,
		action TEXT NOT NULL,
		detail TEXT NOT NULL
	);
	CREATE INDEX audit_user ON audit(user_id, id);
	CREATE INDEX audit_project ON audit(project_id, id);
	CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
	CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;`,
	// 7: the OIDC account a user signs in with, by issuer and subject. A
	// user made from OIDC has no password: an empty hash matches none.
	`ALTER TABLE users ADD COLUMN oidc_issuer TEXT;
	ALTER TABLE users ADD COLUMN oidc_subject TEXT;
	CREATE UNIQUE INDEX users_oidc ON users(oidc_issuer, oidc_subject);`,
	// 8: what a drift check may do about the drift it finds, the most
	// changes it may make unattended, and which runs the schedule started.
	// Every drift check so far was the schedule's.
	`ALTER TABLE projects ADD COLUMN schedule_mode TEXT NOT NULL DEFAULT 'report';
	ALTER TABLE projects ADD COLUMN max_changes INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE runs ADD COLUMN by_schedule INTEGER NOT NULL DEFAULT 0;
	UPDATE runs SET by_schedule = 1 WHERE kind = 'drift';`,
	// 9: a random delay, up to this many minutes, before a due drift check
	// starts.
	`ALTER TABLE projects ADD COLUMN splay_minutes INTEGER NOT NULL DEFAULT 0;`,
	// 10: who gets an email when a drift check finds drift or fails.
	`ALTER TABLE projects ADD COLUMN notify_email TEXT NOT NULL DEFAULT '';`,
	// 11: which roles came from a user's OIDC groups, so a sign-in can
	// change them without touching the ones an admin gave by hand.
	`ALTER TABLE roles ADD COLUMN from_group INTEGER NOT NULL DEFAULT 0;`,
	// 12: the fleet store: each step's result on each host, from applies
	// and drift checks, and the latest facts each project's data sources
	// read about each host.
	`CREATE TABLE step_results (
		id INTEGER PRIMARY KEY,
		run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		host TEXT NOT NULL,
		step TEXT NOT NULL,
		item TEXT NOT NULL,
		kind TEXT NOT NULL,
		action TEXT NOT NULL,
		outcome TEXT NOT NULL,
		elapsed REAL NOT NULL,
		at TEXT NOT NULL
	);
	CREATE INDEX step_results_host ON step_results(host, at);
	CREATE INDEX step_results_at ON step_results(at);
	CREATE TABLE host_facts (
		project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		host TEXT NOT NULL,
		source TEXT NOT NULL,
		facts TEXT NOT NULL,
		run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
		at TEXT NOT NULL,
		PRIMARY KEY (project_id, host, source)
	);`,
}

// Store is the database.
type Store struct {
	db *sql.DB
	// aead seals credentials; nil until SetKey.
	aead cipher.AEAD
}

// Open opens or creates the database at path and brings its schema up to
// date.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serialises writers anyway, and this keeps a
	// write from ever seeing SQLITE_BUSY from our own reads.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Project is a Git repo and a path in it that Conn3x runs from.
type Project struct {
	ID         int64
	Name       string
	GitURL     string
	GitRef     string
	Path       string
	Conn3xPath string
	// Env is KEY=VALUE lines the runs get, in plain text. Secrets go in
	// the project's credentials instead.
	Env string
	// Schedule is when drift checks run, "" for never: an interval or
	// five cron fields, as run.ParseSchedule reads them.
	Schedule string
	// WebhookURL gets a POST when a drift check finds drift or fails. It
	// may hold a token, so pages show only its host.
	WebhookURL string
	// SelfApply lets a planner apply a plan they made themselves.
	SelfApply bool
	// ScheduleMode is what a drift check does when it finds drift: one of
	// ModeReport, ModeCorrect and ModeConverge.
	ScheduleMode string
	// MaxChanges is the most changes a scheduled apply may make, 0 for no
	// cap. A plan with more waits for a person.
	MaxChanges int
	// SplayMinutes delays each due drift check by a random time up to this
	// many minutes, picked fresh each time, so projects on one schedule
	// don't all start at once. 0 starts it as soon as it's due.
	SplayMinutes int
	// NotifyEmail is the comma-separated addresses that get an email
	// whenever the webhook would get a POST.
	NotifyEmail string
	CreatedAt   string
	UpdatedAt   string
}

// WebhookHost is the webhook URL's host, all a page shows of it.
func (p Project) WebhookHost() string {
	if u, err := url.Parse(p.WebhookURL); err == nil {
		return u.Host
	}
	return ""
}

// EnvList is Env as the []string os/exec wants, blank lines dropped.
func (p Project) EnvList() []string {
	var out []string
	for _, l := range strings.Split(p.Env, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

const projectCols = "id, name, git_url, git_ref, path, conn3x_path, env, schedule, webhook_url, self_apply, schedule_mode, max_changes, splay_minutes, notify_email, created_at, updated_at"

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Name, &p.GitURL, &p.GitRef, &p.Path, &p.Conn3xPath, &p.Env, &p.Schedule, &p.WebhookURL, &p.SelfApply, &p.ScheduleMode, &p.MaxChanges, &p.SplayMinutes, &p.NotifyEmail, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return p, err
}

// CreateProject adds p and returns its ID.
func (s *Store) CreateProject(ctx context.Context, p Project) (int64, error) {
	t := now()
	if p.ScheduleMode == "" {
		p.ScheduleMode = ModeReport
	}
	res, err := s.db.ExecContext(ctx, "INSERT INTO projects ("+projectCols+") VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		p.Name, p.GitURL, p.GitRef, p.Path, p.Conn3xPath, p.Env, p.Schedule, p.WebhookURL, p.SelfApply, p.ScheduleMode, p.MaxChanges, p.SplayMinutes, p.NotifyEmail, t, t)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateProject saves p's fields over the project with p.ID.
func (s *Store) UpdateProject(ctx context.Context, p Project) error {
	if p.ScheduleMode == "" {
		p.ScheduleMode = ModeReport
	}
	res, err := s.db.ExecContext(ctx, "UPDATE projects SET name=?, git_url=?, git_ref=?, path=?, conn3x_path=?, env=?, schedule=?, webhook_url=?, self_apply=?, schedule_mode=?, max_changes=?, splay_minutes=?, notify_email=?, updated_at=? WHERE id=?",
		p.Name, p.GitURL, p.GitRef, p.Path, p.Conn3xPath, p.Env, p.Schedule, p.WebhookURL, p.SelfApply, p.ScheduleMode, p.MaxChanges, p.SplayMinutes, p.NotifyEmail, now(), p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteProject removes a project and its runs.
func (s *Store) DeleteProject(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM projects WHERE id=?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Project returns one project.
func (s *Store) Project(ctx context.Context, id int64) (Project, error) {
	return scanProject(s.db.QueryRowContext(ctx, "SELECT "+projectCols+" FROM projects WHERE id=?", id))
}

// Projects returns every project, by name.
func (s *Store) Projects(ctx context.Context) ([]Project, error) {
	return s.projects(ctx, "SELECT "+projectCols+" FROM projects ORDER BY name")
}

// MemberProjects returns the projects userID has a role on, by name.
func (s *Store) MemberProjects(ctx context.Context, userID int64) ([]Project, error) {
	return s.projects(ctx, "SELECT "+projectCols+" FROM projects WHERE id IN (SELECT project_id FROM roles WHERE user_id=?) ORDER BY name", userID)
}

func (s *Store) projects(ctx context.Context, query string, args ...any) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Run statuses. Queued waits for the project's lock; the rest follow.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Run kinds. A drift check is a plan -refresh-only that its project's
// schedule starts.
const (
	KindPlan  = "plan"
	KindApply = "apply"
	KindDrift = "drift"
)

// What a drift check does about drift it finds. Report changes nothing.
// Correct applies a plan only when every change in it puts back something
// the same plan saw drift. Converge applies any plan. Neither ever deletes
// or replaces unattended.
const (
	ModeReport   = "report"
	ModeCorrect  = "correct"
	ModeConverge = "converge"
)

// Drift check outcomes: drift when a host no longer matches the state.
const (
	OutcomeDrift = "drift"
	OutcomeClean = "clean"
)

// Run is one conn3x run: a plan, or an apply of a plan run's saved plan.
type Run struct {
	ID            int64
	ProjectID     int64
	Kind          string
	Status        string
	CommitSHA     string
	Conn3xVersion string
	Error         string
	CreatedBy     sql.NullInt64
	CreatedByName sql.NullString
	ProjectName   string
	CreatedAt     string
	StartedAt     sql.NullString
	FinishedAt    sql.NullString
	// PlanRunID is the plan an apply runs, and who approved it when.
	PlanRunID      sql.NullInt64
	ApprovedBy     sql.NullInt64
	ApprovedByName sql.NullString
	ApprovedAt     sql.NullString
	// Outcome is a finished drift check's OutcomeDrift or OutcomeClean, and
	// "" for anything else.
	Outcome string
	// HostOutcome is how the run came out on the host History was asked
	// about, and "" from anything else.
	HostOutcome string
	// BySchedule is a run the schedule started, or an apply it approved.
	BySchedule bool
}

// Finished is true once the run has a final status.
func (r Run) Finished() bool {
	return r.Status == StatusSucceeded || r.Status == StatusFailed || r.Status == StatusCancelled
}

const runCols = "id, project_id, kind, status, commit_sha, conn3x_version, error, created_by, " +
	"(SELECT name FROM users WHERE users.id = runs.created_by), (SELECT name FROM projects WHERE projects.id = runs.project_id), created_at, started_at, finished_at, " +
	"plan_run_id, approved_by, (SELECT name FROM users WHERE users.id = runs.approved_by), approved_at, outcome, by_schedule"

// scanRun reads runCols, then any extra columns into extra.
func scanRun(row interface{ Scan(...any) error }, extra ...any) (Run, error) {
	var r Run
	err := row.Scan(append([]any{&r.ID, &r.ProjectID, &r.Kind, &r.Status, &r.CommitSHA, &r.Conn3xVersion, &r.Error, &r.CreatedBy, &r.CreatedByName, &r.ProjectName, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		&r.PlanRunID, &r.ApprovedBy, &r.ApprovedByName, &r.ApprovedAt, &r.Outcome, &r.BySchedule}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

// CreateRun adds a queued run and returns its ID. userID 0 is the
// schedule, not a person.
func (s *Store) CreateRun(ctx context.Context, projectID int64, kind string, userID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO runs (project_id, kind, status, created_by, created_at, by_schedule) VALUES (?, ?, ?, ?, ?, ?)",
		projectID, kind, StatusQueued, sql.NullInt64{Int64: userID, Valid: userID != 0}, now(), userID == 0)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ErrNotApplicable is a plan that can't be applied: it hasn't succeeded,
// it was applied already, or the project has a newer plan.
var ErrNotApplicable = errors.New("this plan can't be applied any more: it has been applied, or a newer plan has been made since")

// applicable is the plan row p that CreateApply accepts.
const applicable = `FROM runs p WHERE p.id = ? AND p.kind = 'plan' AND p.status = 'succeeded'
	AND NOT EXISTS (SELECT 1 FROM runs a WHERE a.plan_run_id = p.id)
	AND NOT EXISTS (SELECT 1 FROM runs n WHERE n.project_id = p.project_id AND n.kind = 'plan' AND n.id > p.id)`

// Applicable says whether CreateApply would accept the plan run.
func (s *Store) Applicable(ctx context.Context, planID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) "+applicable, planID).Scan(&n)
	return n == 1, err
}

// CreateApply adds a queued apply of a plan run, approved by userID now,
// or by the schedule when userID is 0, and returns its ID. One insert checks and claims the plan, so two
// approvers can't both apply it.
func (s *Store) CreateApply(ctx context.Context, planID, userID int64) (int64, error) {
	t := now()
	user := sql.NullInt64{Int64: userID, Valid: userID != 0}
	res, err := s.db.ExecContext(ctx, "INSERT INTO runs (project_id, kind, status, created_by, created_at, plan_run_id, approved_by, approved_at, by_schedule) "+
		"SELECT p.project_id, ?, ?, ?, ?, p.id, ?, ?, ? "+applicable, KindApply, StatusQueued, user, t, user, t, userID == 0, planID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotApplicable
	}
	return res.LastInsertId()
}

// StartRun marks a run running.
func (s *Store) StartRun(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE runs SET status=?, started_at=? WHERE id=?", StatusRunning, now(), id)
	return err
}

// SetRunCommit records what the run checked out.
func (s *Store) SetRunCommit(ctx context.Context, id int64, sha string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE runs SET commit_sha=? WHERE id=?", sha, id)
	return err
}

// SetRunVersion records the Conn3x release from the version event.
func (s *Store) SetRunVersion(ctx context.Context, id int64, version string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE runs SET conn3x_version=? WHERE id=?", version, id)
	return err
}

// FinishRun records the final status. errMsg is empty on success.
func (s *Store) FinishRun(ctx context.Context, id int64, status, errMsg string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE runs SET status=?, error=?, finished_at=? WHERE id=?", status, errMsg, now(), id)
	return err
}

// SetRunOutcome records how a drift check came out.
func (s *Store) SetRunOutcome(ctx context.Context, id int64, outcome string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE runs SET outcome=? WHERE id=?", outcome, id)
	return err
}

// LastRun returns a project's newest run of kind.
func (s *Store) LastRun(ctx context.Context, projectID int64, kind string) (Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, "SELECT "+runCols+" FROM runs WHERE project_id=? AND kind=? ORDER BY id DESC LIMIT 1", projectID, kind))
}

// Run returns one run.
func (s *Store) Run(ctx context.Context, id int64) (Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, "SELECT "+runCols+" FROM runs WHERE id=?", id))
}

// Runs returns a project's runs, newest first.
func (s *Store) Runs(ctx context.Context, projectID int64) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+runCols+" FROM runs WHERE project_id=? ORDER BY id DESC", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetRunHosts records each host a run touched and how it came out there,
// replacing what was recorded before.
func (s *Store) SetRunHosts(ctx context.Context, id int64, outcomes map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM run_hosts WHERE run_id=?", id); err != nil {
		return err
	}
	for host, outcome := range outcomes {
		if _, err := tx.ExecContext(ctx, "INSERT INTO run_hosts (run_id, host, outcome) VALUES (?, ?, ?)", id, host, outcome); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Filter narrows History. A zero field matches every run. Status matches
// a run's status or its drift check outcome. UserID keeps to the projects
// that user has a role on.
type Filter struct {
	ProjectID int64
	Host      string
	Status    string
	UserID    int64
}

// History returns runs across projects that match f, newest first,
// skipping the first offset and returning at most limit. With f.Host set,
// each run's HostOutcome is how it came out on that host.
func (s *Store) History(ctx context.Context, f Filter, limit, offset int) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+runCols+", COALESCE((SELECT outcome FROM run_hosts h WHERE h.run_id = runs.id AND h.host = ?3), '') FROM runs "+
		"WHERE (?1 = 0 OR project_id = ?1) AND (?2 = '' OR status = ?2 OR outcome = ?2) AND (?3 = '' OR EXISTS (SELECT 1 FROM run_hosts h WHERE h.run_id = runs.id AND h.host = ?3)) "+
		"AND (?6 = 0 OR project_id IN (SELECT project_id FROM roles WHERE user_id = ?6)) "+
		"ORDER BY id DESC LIMIT ?4 OFFSET ?5", f.ProjectID, f.Status, f.Host, limit, offset, f.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var outcome string
		r, err := scanRun(rows, &outcome)
		if err != nil {
			return nil, err
		}
		r.HostOutcome = outcome
		out = append(out, r)
	}
	return out, rows.Err()
}

// AppendEvent stores one raw line of a run's stream and returns its seq,
// counting from 1.
func (s *Store) AppendEvent(ctx context.Context, runID int64, line []byte) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx,
		"INSERT INTO run_events (run_id, seq, line) VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM run_events WHERE run_id = ?), ?) RETURNING seq",
		runID, runID, line).Scan(&seq)
	return seq, err
}

// Events returns a run's raw lines in order, with the seq of the last.
func (s *Store) Events(ctx context.Context, runID int64) ([][]byte, int64, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT seq, line FROM run_events WHERE run_id=? ORDER BY seq", runID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out [][]byte
	var last int64
	for rows.Next() {
		var line []byte
		if err := rows.Scan(&last, &line); err != nil {
			return nil, 0, err
		}
		out = append(out, line)
	}
	return out, last, rows.Err()
}

// Credential kinds. A file credential reaches a run as a file in a private
// temp directory, an env credential as an environment variable.
const (
	CredFile = "file"
	CredEnv  = "env"
)

// Credential is a project's credential as the UI shows it: never its value.
type Credential struct {
	Name  string
	Kind  string
	SetAt string
}

// Secret is a credential with its value, for a run and nothing else.
type Secret struct {
	Name  string
	Kind  string
	Value []byte
}

// ErrNoKey is a credential read or written while the UI has no key.
var ErrNoKey = errors.New("credentials need the key conn3x-ui reads at start. " +
	"Make one with openssl rand -base64 32, then pass its file with -key-file or its value in CONN3X_UI_KEY")

// SetKey sets the 32-byte key that seals credentials with AES-256-GCM.
func (s *Store) SetKey(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil || len(key) != 32 {
		return errors.New("the credentials key must be 32 bytes")
	}
	s.aead, err = cipher.NewGCM(block)
	return err
}

// HasKey says whether credentials can be saved and read.
func (s *Store) HasKey() bool { return s.aead != nil }

// credAD binds a sealed value to its row, so a value copied to another
// project or name won't open.
func credAD(projectID int64, name string) []byte {
	return fmt.Appendf(nil, "%d\x00%s", projectID, name)
}

// SetCredential adds a credential to a project, or replaces the one with
// that name, whatever its case.
func (s *Store) SetCredential(ctx context.Context, projectID int64, name, kind string, value []byte) error {
	if s.aead == nil {
		return ErrNoKey
	}
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	sealed := s.aead.Seal(nonce, nonce, value, credAD(projectID, name))
	_, err := s.db.ExecContext(ctx, "INSERT INTO credentials (project_id, name, kind, value, set_at) VALUES (?, ?, ?, ?, ?) "+
		"ON CONFLICT (project_id, name) DO UPDATE SET name=excluded.name, kind=excluded.kind, value=excluded.value, set_at=excluded.set_at",
		projectID, name, kind, sealed, now())
	return err
}

// DeleteCredential removes a project's credential.
func (s *Store) DeleteCredential(ctx context.Context, projectID int64, name string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM credentials WHERE project_id=? AND name=?", projectID, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Credentials returns a project's credentials by name, without values.
func (s *Store) Credentials(ctx context.Context, projectID int64) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT name, kind, set_at FROM credentials WHERE project_id=? ORDER BY name", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.Name, &c.Kind, &c.SetAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Secrets returns a project's credentials with their values opened, for a
// run. A project with credentials and a UI without its key is ErrNoKey.
func (s *Store) Secrets(ctx context.Context, projectID int64) ([]Secret, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT name, kind, value FROM credentials WHERE project_id=? ORDER BY name", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var c Secret
		var sealed []byte
		if err := rows.Scan(&c.Name, &c.Kind, &sealed); err != nil {
			return nil, err
		}
		if s.aead == nil {
			return nil, ErrNoKey
		}
		if len(sealed) < s.aead.NonceSize() {
			return nil, fmt.Errorf("credential %s is damaged", c.Name)
		}
		if c.Value, err = s.open(projectID, c.Name, sealed); err != nil {
			return nil, fmt.Errorf("credential %s won't open: conn3x-ui was started with a different key from the one it was saved with, or the row was changed", c.Name)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// errWrongKey is a sealed value the key doesn't open.
const errWrongKey = "isn't the key the credentials were saved with. Start with that key, or rotate to a new one with conn3x-ui rotate-key"

// CheckKey opens one saved credential, so a wrong key stops conn3x-ui at
// start rather than at the first run that needs it. It returns how many
// credentials are saved; with none, or no key, there's nothing to open.
func (s *Store) CheckKey(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM credentials").Scan(&n); err != nil || n == 0 || s.aead == nil {
		return n, err
	}
	var projectID int64
	var name string
	var sealed []byte
	if err := s.db.QueryRowContext(ctx, "SELECT project_id, name, value FROM credentials LIMIT 1").Scan(&projectID, &name, &sealed); err != nil {
		return n, err
	}
	plain, err := s.open(projectID, name, sealed)
	if err != nil {
		return n, errors.New("the credentials key " + errWrongKey)
	}
	clear(plain)
	return n, nil
}

// open opens a credential's sealed value with the store's key.
func (s *Store) open(projectID int64, name string, sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("damaged")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], credAD(projectID, name))
}

// RotateKey re-seals every credential under newKey in one transaction, and
// records it in the audit log by count. If the store's key doesn't open
// every one, nothing changes. From then on the store uses newKey.
func (s *Store) RotateKey(ctx context.Context, newKey []byte) (int, error) {
	if s.aead == nil {
		return 0, ErrNoKey
	}
	next := &Store{}
	if err := next.SetKey(newKey); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	type row struct {
		projectID int64
		name      string
		sealed    []byte
	}
	var all []row
	rows, err := tx.QueryContext(ctx, "SELECT project_id, name, value FROM credentials")
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.projectID, &r.name, &r.sealed); err != nil {
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
		plain, err := s.open(r.projectID, r.name, r.sealed)
		if err != nil {
			return 0, fmt.Errorf("credential %s won't open: the old key %s", r.name, errWrongKey)
		}
		nonce := make([]byte, next.aead.NonceSize())
		rand.Read(nonce)
		sealed := next.aead.Seal(nonce, nonce, plain, credAD(r.projectID, r.name))
		clear(plain)
		if _, err := tx.ExecContext(ctx, "UPDATE credentials SET value=? WHERE project_id=? AND name=?", sealed, r.projectID, r.name); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, auditInsert, now(), 0, "", 0, "", "credentials key rotated", fmt.Sprintf("%d credentials", len(all))); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.aead = next.aead
	return len(all), nil
}

// User is someone who can sign in.
// shortcut: roles per person only; roles for OIDC groups are the rest of
// #892.
type User struct {
	ID   int64
	Name string
	// Admin manages users, reads the audit log, and is admin on every
	// project.
	Admin bool
	// Disabled can't sign in.
	Disabled bool
	// OIDC is true when the user signs in with OIDC.
	OIDC bool
}

const userCols = "id, name, admin, disabled, oidc_subject IS NOT NULL"

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Name, &u.Admin, &u.Disabled, &u.OIDC)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return u, err
}

// Token returns n random bytes as hex.
func Token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

const pbkdf2Rounds = 600_000

func hashPassword(password, salt string) string {
	key, err := pbkdf2.Key(sha256.New, password, []byte(salt), pbkdf2Rounds, 32)
	if err != nil {
		panic(err)
	}
	return "pbkdf2-sha256$" + salt + "$" + hex.EncodeToString(key)
}

// matches says whether password is the one hash was made from.
func matches(hash, password string) bool {
	parts := strings.Split(hash, "$")
	return len(parts) == 3 && hmac.Equal([]byte(hashPassword(password, parts[1])), []byte(hash))
}

// CreateUser adds a user with a password. They aren't an admin and have no
// role on any project until given one.
func (s *Store) CreateUser(ctx context.Context, name, password string) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO users (name, password_hash, created_at) VALUES (?, ?, ?)",
		name, hashPassword(password, Token(16)), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetUser makes a user an admin or not, and disabled or not. Disabling
// ends their sessions.
func (s *Store) SetUser(ctx context.Context, id int64, admin, disabled bool) error {
	res, err := s.db.ExecContext(ctx, "UPDATE users SET admin=?, disabled=? WHERE id=?", admin, disabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if disabled {
		_, err = s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", id)
	}
	return err
}

// SetPassword replaces a user's password and ends their sessions, all but
// the one with token keep.
func (s *Store) SetPassword(ctx context.Context, id int64, password, keep string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE users SET password_hash=? WHERE id=?", hashPassword(password, Token(16)), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=? AND token<>?", id, keep)
	return err
}

// CheckPassword is ErrNotFound unless password is the user's.
func (s *Store) CheckPassword(ctx context.Context, id int64, password string) error {
	var hash string
	if err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id=?", id).Scan(&hash); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if !matches(hash, password) {
		return ErrNotFound
	}
	return nil
}

// User returns one user.
func (s *Store) User(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id=?", id))
}

// UserNamed returns the user with that name.
func (s *Store) UserNamed(ctx context.Context, name string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE name=?", name))
}

// Users returns every user, by name.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserCount says how many users exist, so the first start can make one.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// Login checks a password and, when it's right and the user isn't
// disabled, opens a session. It returns the session token and its CSRF
// token.
func (s *Store) Login(ctx context.Context, name, password string, ttl time.Duration) (token, csrf string, err error) {
	var id int64
	var hash string
	var disabled bool
	err = s.db.QueryRowContext(ctx, "SELECT id, password_hash, disabled FROM users WHERE name=?", name).Scan(&id, &hash, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		// Hash anyway, so a missing user takes as long as a wrong password.
		hashPassword(password, "x")
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	if !matches(hash, password) || disabled {
		return "", "", ErrNotFound
	}
	return s.OpenSession(ctx, id, ttl)
}

// OpenSession opens a session for a user who has signed in. It returns the
// session token and its CSRF token.
func (s *Store) OpenSession(ctx context.Context, userID int64, ttl time.Duration) (token, csrf string, err error) {
	token, csrf = Token(32), Token(32)
	_, err = s.db.ExecContext(ctx, "INSERT INTO sessions (token, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)",
		token, userID, csrf, time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return token, csrf, err
}

// OIDCUser returns the user linked to an OIDC issuer and subject.
func (s *Store) OIDCUser(ctx context.Context, issuer, subject string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE oidc_issuer=? AND oidc_subject=?", issuer, subject))
}

// CreateOIDCUser adds a user who signs in with OIDC as issuer and subject.
// Like CreateUser, they aren't an admin and have no role on any project.
func (s *Store) CreateOIDCUser(ctx context.Context, name, issuer, subject string) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO users (name, password_hash, created_at, oidc_issuer, oidc_subject) VALUES (?, '', ?, ?, ?)",
		name, now(), issuer, subject)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EndPasswordSessions ends every session of a user with no OIDC link,
// since only a password opens one, and says how many it ended.
func (s *Store) EndPasswordSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE oidc_subject IS NULL)")
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// OIDCAdmins says how many site admins who aren't disabled sign in with
// OIDC from issuer.
func (s *Store) OIDCAdmins(ctx context.Context, issuer string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE admin = 1 AND disabled = 0 AND oidc_issuer=?", issuer).Scan(&n)
	return n, err
}

// Session returns the user and CSRF token of a live session of a user who
// isn't disabled.
func (s *Store) Session(ctx context.Context, token string) (User, string, error) {
	var u User
	var csrf string
	err := s.db.QueryRowContext(ctx, "SELECT u.id, u.name, u.admin, u.disabled, u.oidc_subject IS NOT NULL, s.csrf FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=? AND s.expires_at > ? AND u.disabled = 0",
		token, now()).Scan(&u.ID, &u.Name, &u.Admin, &u.Disabled, &u.OIDC, &csrf)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return u, csrf, err
}

// Logout ends a session.
func (s *Store) Logout(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token=?", token)
	return err
}

// Roles on a project, each allowed what the ones before it are: a viewer
// sees runs and history, a planner starts plans, an approver applies a
// plan someone else made, and an admin edits the project, its credentials
// and its roles.
const (
	RoleViewer   = "viewer"
	RolePlanner  = "planner"
	RoleApprover = "approver"
	RoleAdmin    = "admin"
)

// Roles is every role, least first.
var Roles = []string{RoleViewer, RolePlanner, RoleApprover, RoleAdmin}

// RoleAtLeast says whether have allows what want does. No role, or one
// that isn't in Roles, allows nothing.
func RoleAtLeast(have, want string) bool {
	h := slices.Index(Roles, have)
	return h >= 0 && h >= slices.Index(Roles, want)
}

// Member is a user's role on a project.
type Member struct {
	UserID int64
	Name   string
	Role   string
	// FromGroup is a role the user's OIDC groups gave them.
	FromGroup bool
}

// Role returns a user's role on a project, "" for none.
func (s *Store) Role(ctx context.Context, projectID, userID int64) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, "SELECT role FROM roles WHERE project_id=? AND user_id=?", projectID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return role, err
}

// SetRole gives a user a role on a project, replacing the one they had.
// Role "" takes it away.
func (s *Store) SetRole(ctx context.Context, projectID, userID int64, role string) error {
	if role == "" {
		_, err := s.db.ExecContext(ctx, "DELETE FROM roles WHERE project_id=? AND user_id=?", projectID, userID)
		return err
	}
	if !slices.Contains(Roles, role) {
		return fmt.Errorf("%q isn't a role; a role is one of %s", role, strings.Join(Roles, ", "))
	}
	// A role set by hand is the admin's from then on, whatever groups say.
	_, err := s.db.ExecContext(ctx, "INSERT INTO roles (project_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT (project_id, user_id) DO UPDATE SET role=excluded.role, from_group=0",
		projectID, userID, role)
	return err
}

// SyncGroupRoles makes userID's roles from OIDC groups exactly want, by
// project. A role an admin set by hand stays as it is: groups never
// replace or remove it. It returns what changed, for the audit log.
func (s *Store) SyncGroupRoles(ctx context.Context, userID int64, want map[int64]string) ([]string, error) {
	for _, r := range want {
		if !slices.Contains(Roles, r) {
			return nil, fmt.Errorf("%q isn't a role", r)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	had := map[int64]string{}
	rows, err := tx.QueryContext(ctx, "SELECT project_id, role FROM roles WHERE user_id=? AND from_group=1", userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pid int64
		var r string
		if err := rows.Scan(&pid, &r); err != nil {
			rows.Close()
			return nil, err
		}
		had[pid] = r
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, "DELETE FROM roles WHERE user_id=? AND from_group=1", userID); err != nil {
		return nil, err
	}
	got := map[int64]string{}
	for pid, r := range want {
		res, err := tx.ExecContext(ctx, "INSERT INTO roles (project_id, user_id, role, from_group) VALUES (?, ?, ?, 1) ON CONFLICT (project_id, user_id) DO NOTHING", pid, userID, r)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			got[pid] = r
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	var changes []string
	for pid, r := range got {
		if had[pid] != r {
			changes = append(changes, fmt.Sprintf("project %d: %s", pid, r))
		}
	}
	for pid := range had {
		if _, ok := got[pid]; !ok {
			changes = append(changes, fmt.Sprintf("project %d: none", pid))
		}
	}
	slices.Sort(changes)
	return changes, nil
}

// ErrLastAdmin is a change that would leave no site admin who can sign in.
var ErrLastAdmin = errors.New("that would leave no site admin")

// SetAdmin makes a user a site admin or not, unless taking it away would
// leave no site admin who isn't disabled.
func (s *Store) SetAdmin(ctx context.Context, id int64, admin bool) error {
	if !admin {
		var others int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE admin=1 AND disabled=0 AND id<>?", id).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrLastAdmin
		}
	}
	_, err := s.db.ExecContext(ctx, "UPDATE users SET admin=? WHERE id=?", admin, id)
	return err
}

// Members returns who has a role on a project, by name.
func (s *Store) Members(ctx context.Context, projectID int64) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT u.id, u.name, r.role, r.from_group FROM roles r JOIN users u ON u.id = r.user_id WHERE r.project_id=? ORDER BY u.name", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Name, &m.Role, &m.FromGroup); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Entry is one line of the audit log. It copies the user's and project's
// names, so it still reads right once either is gone. It never holds a
// password or a credential's value.
type Entry struct {
	ID int64
	At string
	// UserID is 0 for a failed sign-in with a name nobody has.
	UserID   int64
	UserName string
	// ProjectID is 0 for an action that isn't on a project.
	ProjectID   int64
	ProjectName string
	Action      string
	Detail      string
}

const auditInsert = "INSERT INTO audit (at, user_id, user_name, project_id, project_name, action, detail) VALUES (?, NULLIF(?, 0), ?, NULLIF(?, 0), ?, ?, ?)"

// Audit appends e to the audit log, at now.
func (s *Store) Audit(ctx context.Context, e Entry) error {
	_, err := s.db.ExecContext(ctx, auditInsert,
		now(), e.UserID, e.UserName, e.ProjectID, e.ProjectName, e.Action, e.Detail)
	return err
}

// AuditFilter narrows AuditLog. A zero field matches every entry.
type AuditFilter struct {
	UserID    int64
	ProjectID int64
}

// AuditEach calls fn with each entry that matches f and comes after the
// entry with ID after, oldest first, for an export.
func (s *Store) AuditEach(ctx context.Context, f AuditFilter, after int64, fn func(Entry) error) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id, at, COALESCE(user_id, 0), user_name, COALESCE(project_id, 0), project_name, action, detail FROM audit "+
		"WHERE (?1 = 0 OR user_id = ?1) AND (?2 = 0 OR project_id = ?2) AND id > ?3 ORDER BY id", f.UserID, f.ProjectID, after)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.UserName, &e.ProjectID, &e.ProjectName, &e.Action, &e.Detail); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// AuditLog returns the entries that match f, newest first, skipping the
// first offset and returning at most limit.
func (s *Store) AuditLog(ctx context.Context, f AuditFilter, limit, offset int) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, at, COALESCE(user_id, 0), user_name, COALESCE(project_id, 0), project_name, action, detail FROM audit "+
		"WHERE (?1 = 0 OR user_id = ?1) AND (?2 = 0 OR project_id = ?2) ORDER BY id DESC LIMIT ?3 OFFSET ?4", f.UserID, f.ProjectID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.UserName, &e.ProjectID, &e.ProjectName, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
