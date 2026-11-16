// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package store keeps projects, runs, users, sessions and credentials in
// one SQLite file.
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
	Env       string
	CreatedAt string
	UpdatedAt string
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

const projectCols = "id, name, git_url, git_ref, path, conn3x_path, env, created_at, updated_at"

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Name, &p.GitURL, &p.GitRef, &p.Path, &p.Conn3xPath, &p.Env, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return p, err
}

// CreateProject adds p and returns its ID.
func (s *Store) CreateProject(ctx context.Context, p Project) (int64, error) {
	t := now()
	res, err := s.db.ExecContext(ctx, "INSERT INTO projects ("+projectCols+") VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
		p.Name, p.GitURL, p.GitRef, p.Path, p.Conn3xPath, p.Env, t, t)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateProject saves p's fields over the project with p.ID.
func (s *Store) UpdateProject(ctx context.Context, p Project) error {
	res, err := s.db.ExecContext(ctx, "UPDATE projects SET name=?, git_url=?, git_ref=?, path=?, conn3x_path=?, env=?, updated_at=? WHERE id=?",
		p.Name, p.GitURL, p.GitRef, p.Path, p.Conn3xPath, p.Env, now(), p.ID)
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
	rows, err := s.db.QueryContext(ctx, "SELECT "+projectCols+" FROM projects ORDER BY name")
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

// Run kinds.
const (
	KindPlan  = "plan"
	KindApply = "apply"
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
	// HostOutcome is how the run came out on the host History was asked
	// about, and "" from anything else.
	HostOutcome string
}

// Finished is true once the run has a final status.
func (r Run) Finished() bool {
	return r.Status == StatusSucceeded || r.Status == StatusFailed || r.Status == StatusCancelled
}

const runCols = "id, project_id, kind, status, commit_sha, conn3x_version, error, created_by, " +
	"(SELECT name FROM users WHERE users.id = runs.created_by), (SELECT name FROM projects WHERE projects.id = runs.project_id), created_at, started_at, finished_at, " +
	"plan_run_id, approved_by, (SELECT name FROM users WHERE users.id = runs.approved_by), approved_at"

// scanRun reads runCols, then any extra columns into extra.
func scanRun(row interface{ Scan(...any) error }, extra ...any) (Run, error) {
	var r Run
	err := row.Scan(append([]any{&r.ID, &r.ProjectID, &r.Kind, &r.Status, &r.CommitSHA, &r.Conn3xVersion, &r.Error, &r.CreatedBy, &r.CreatedByName, &r.ProjectName, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		&r.PlanRunID, &r.ApprovedBy, &r.ApprovedByName, &r.ApprovedAt}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

// CreateRun adds a queued run and returns its ID.
func (s *Store) CreateRun(ctx context.Context, projectID int64, kind string, userID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO runs (project_id, kind, status, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
		projectID, kind, StatusQueued, userID, now())
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
// and returns its ID. One insert checks and claims the plan, so two
// approvers can't both apply it.
func (s *Store) CreateApply(ctx context.Context, planID, userID int64) (int64, error) {
	t := now()
	res, err := s.db.ExecContext(ctx, "INSERT INTO runs (project_id, kind, status, created_by, created_at, plan_run_id, approved_by, approved_at) "+
		"SELECT p.project_id, ?, ?, ?, ?, p.id, ?, ? "+applicable, KindApply, StatusQueued, userID, t, userID, t, planID)
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

// Filter narrows History. A zero field matches every run.
type Filter struct {
	ProjectID int64
	Host      string
	Status    string
}

// History returns runs across projects that match f, newest first,
// skipping the first offset and returning at most limit. With f.Host set,
// each run's HostOutcome is how it came out on that host.
func (s *Store) History(ctx context.Context, f Filter, limit, offset int) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+runCols+", COALESCE((SELECT outcome FROM run_hosts h WHERE h.run_id = runs.id AND h.host = ?3), '') FROM runs "+
		"WHERE (?1 = 0 OR project_id = ?1) AND (?2 = '' OR status = ?2) AND (?3 = '' OR EXISTS (SELECT 1 FROM run_hosts h WHERE h.run_id = runs.id AND h.host = ?3)) "+
		"ORDER BY id DESC LIMIT ?4 OFFSET ?5", f.ProjectID, f.Status, f.Host, limit, offset)
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
		n := s.aead.NonceSize()
		if len(sealed) < n {
			return nil, fmt.Errorf("credential %s is damaged", c.Name)
		}
		if c.Value, err = s.aead.Open(nil, sealed[:n], sealed[n:], credAD(projectID, c.Name)); err != nil {
			return nil, fmt.Errorf("credential %s won't open: conn3x-ui was started with a different key from the one it was saved with, or the row was changed", c.Name)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// User is someone who can sign in.
// shortcut: local accounts only, one admin made at first start; #892 brings
// OIDC and roles.
type User struct {
	ID   int64
	Name string
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

// CreateUser adds a user with a password.
func (s *Store) CreateUser(ctx context.Context, name, password string) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO users (name, password_hash, created_at) VALUES (?, ?, ?)",
		name, hashPassword(password, Token(16)), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UserCount says how many users exist, so the first start can make one.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// Login checks a password and, when it's right, opens a session. It
// returns the session token and its CSRF token.
func (s *Store) Login(ctx context.Context, name, password string, ttl time.Duration) (token, csrf string, err error) {
	var id int64
	var hash string
	err = s.db.QueryRowContext(ctx, "SELECT id, password_hash FROM users WHERE name=?", name).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		// Hash anyway, so a missing user takes as long as a wrong password.
		hashPassword(password, "x")
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 3 || !hmac.Equal([]byte(hashPassword(password, parts[1])), []byte(hash)) {
		return "", "", ErrNotFound
	}
	token, csrf = Token(32), Token(32)
	_, err = s.db.ExecContext(ctx, "INSERT INTO sessions (token, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)",
		token, id, csrf, time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return token, csrf, err
}

// Session returns the user and CSRF token of a live session.
func (s *Store) Session(ctx context.Context, token string) (User, string, error) {
	var u User
	var csrf string
	err := s.db.QueryRowContext(ctx, "SELECT u.id, u.name, s.csrf FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=? AND s.expires_at > ?",
		token, now()).Scan(&u.ID, &u.Name, &csrf)
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
