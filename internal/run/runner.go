// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package run fetches a project's repo and drives conn3x through it,
// recording the -json stream and handing it to anyone watching.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	conn3xexec "github.com/conn3xorg/conn3x-exec"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// Line is one stored stream line, or Done when the run has finished.
type Line struct {
	Seq  int64
	Data []byte
	Done bool
}

// Runner runs plans. One at a time per project; the rest queue.
type Runner struct {
	Store   *store.Store
	DataDir string
	// Git is the git binary. Empty means "git" on PATH.
	Git string
	Log *log.Logger

	ctx   context.Context
	wg    sync.WaitGroup
	mu    sync.Mutex
	locks map[int64]*sync.Mutex
	subs  map[int64]map[chan Line]struct{}
}

// New makes a Runner. Cancelling ctx interrupts every running conn3x.
func New(ctx context.Context, st *store.Store, dataDir string) *Runner {
	return &Runner{Store: st, DataDir: dataDir, Log: log.Default(), ctx: ctx,
		locks: map[int64]*sync.Mutex{}, subs: map[int64]map[chan Line]struct{}{}}
}

// Wait blocks until every run has finished.
func (r *Runner) Wait() { r.wg.Wait() }

// PlanFile is where a run's saved plan lives, for #889 to apply.
func (r *Runner) PlanFile(runID int64) string {
	return filepath.Join(r.DataDir, "runs", fmt.Sprint(runID), "plan.bin")
}

// StartPlan queues a plan of p and returns the run's ID at once.
func (r *Runner) StartPlan(ctx context.Context, p store.Project, userID int64) (int64, error) {
	id, err := r.Store.CreateRun(ctx, p.ID, "plan", userID)
	if err != nil {
		return 0, err
	}
	r.wg.Go(func() { r.plan(id, p) })
	return id, nil
}

func (r *Runner) lock(projectID int64) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.locks[projectID]
	if m == nil {
		m = &sync.Mutex{}
		r.locks[projectID] = m
	}
	return m
}

func (r *Runner) plan(id int64, p store.Project) {
	m := r.lock(p.ID)
	m.Lock()
	defer m.Unlock()
	ctx := context.Background()
	if err := r.Store.StartRun(ctx, id); err != nil {
		r.Log.Printf("run %d: %v", id, err)
	}
	status, msg := store.StatusSucceeded, ""
	if err := r.doPlan(id, p); err != nil {
		status, msg = store.StatusFailed, err.Error()
		r.note(id, "Error: "+msg)
	}
	if err := r.Store.FinishRun(ctx, id, status, msg); err != nil {
		r.Log.Printf("run %d: %v", id, err)
	}
	r.mu.Lock()
	for ch := range r.subs[id] {
		ch <- Line{Done: true}
		close(ch)
	}
	delete(r.subs, id)
	r.mu.Unlock()
}

// ErrLocalState is a configuration without a remote backend.
var ErrLocalState = errors.New("this configuration keeps its state in a local file, which would be lost with the run's temp directory. " +
	"conn3x-ui needs a remote backend, such as s3, azurerm, gcs, pg or http. Add a backend block to the configuration and plan again")

func (r *Runner) doPlan(id int64, p store.Project) error {
	ctx := r.ctx
	tmp, err := os.MkdirTemp("", "conn3x-ui-run-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	repo := filepath.Join(tmp, "repo")

	r.note(id, fmt.Sprintf("git clone --depth 1 --branch %s %s", p.GitRef, redactURL(p.GitURL)))
	if out, err := r.git(ctx, "clone", "--quiet", "--depth", "1", "--branch", p.GitRef, "--", p.GitURL, repo); err != nil {
		return fmt.Errorf("git clone: %v: %s", err, strings.TrimSpace(string(out)))
	}
	sha, err := r.git(ctx, "-C", repo, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("git rev-parse: %v", err)
	}
	r.Store.SetRunCommit(context.Background(), id, strings.TrimSpace(string(sha)))
	r.note(id, "at commit "+strings.TrimSpace(string(sha)))

	work, err := workDir(repo, p.Path)
	if err != nil {
		return err
	}

	c := &conn3xexec.Conn3x{Path: p.Conn3xPath, Dir: work, Env: p.EnvList(), Stderr: noteWriter{r, id}}
	r.note(id, "conn3x init -input=false")
	if err := c.Run(ctx, r.record(id), "init", "-input=false"); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	// init writes the backend it configured here; no file means the default,
	// local state. Checking it beats guessing from the configuration, which
	// may put its backend in any .tf file or a module.
	if t, err := backendType(work); err != nil {
		return err
	} else if t == "local" {
		return ErrLocalState
	}
	r.note(id, "conn3x plan -input=false -out=plan.bin")
	planErr := c.Run(ctx, r.record(id), "plan", "-input=false", "-out=plan.bin")
	if planErr != nil {
		return fmt.Errorf("plan: %w", planErr)
	}
	dir := filepath.Dir(r.PlanFile(id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return copyFile(filepath.Join(work, "plan.bin"), r.PlanFile(id))
}

// redactURL hides a password or token in a URL, for the run's log.
func redactURL(u string) string {
	if p, err := url.Parse(u); err == nil && p.User != nil {
		p.User = url.User("redacted")
		return p.String()
	}
	return u
}

// workDir is path inside the clone at repo. Symlinks are followed before
// the check, since the repo is untrusted and a link could point anywhere,
// and the run writes its plan file there.
func workDir(repo, path string) (string, error) {
	root, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return "", err
	}
	work, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", fmt.Errorf("path %q is not a directory in the repository", path)
	}
	if rel, err := filepath.Rel(root, work); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q leaves the repository", path)
	}
	if st, err := os.Stat(work); err != nil || !st.IsDir() {
		return "", fmt.Errorf("path %q is not a directory in the repository", path)
	}
	return work, nil
}

func (r *Runner) git(ctx context.Context, args ...string) ([]byte, error) {
	git := r.Git
	if git == "" {
		git = "git"
	}
	cmd := exec.CommandContext(ctx, git, args...)
	// Never hang on a password or host-key prompt nobody can answer.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes", "GIT_ALLOW_PROTOCOL=https:ssh:http")
	return cmd.CombinedOutput()
}

func backendType(work string) (string, error) {
	b, err := os.ReadFile(filepath.Join(work, ".terraform", "terraform.tfstate"))
	if errors.Is(err, fs.ErrNotExist) {
		return "local", nil
	}
	if err != nil {
		return "", err
	}
	var s struct {
		Backend struct{ Type string } `json:"backend"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", fmt.Errorf(".terraform/terraform.tfstate: %w", err)
	}
	if s.Backend.Type == "" {
		return "local", nil
	}
	return s.Backend.Type, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// record stores each event and notes the Conn3x version.
func (r *Runner) record(id int64) func(conn3xexec.Event) error {
	return func(ev conn3xexec.Event) error {
		if ev.Type == "version" && ev.Conn3x != "" {
			r.Store.SetRunVersion(context.Background(), id, ev.Conn3x)
		}
		return r.emit(id, ev.Raw)
	}
}

// note adds a line of conn3x-ui's own to the run, as a conn3x_ui event, so
// the log reads in order and Group can show it.
func (r *Runner) note(id int64, msg string) {
	line, _ := json.Marshal(map[string]any{"@level": "info", "@message": msg, "@timestamp": time.Now(), "type": "conn3x_ui"})
	r.emit(id, line)
}

func (r *Runner) emit(id int64, line []byte) error {
	seq, err := r.Store.AppendEvent(context.Background(), id, line)
	if err != nil {
		r.Log.Printf("run %d: %v", id, err)
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for ch := range r.subs[id] {
		select {
		case ch <- Line{Seq: seq, Data: line}:
		default:
			// A reader this far behind reconnects and catches up from the
			// database, so drop it rather than block the run.
			delete(r.subs[id], ch)
			close(ch)
		}
	}
	return nil
}

// Subscribe returns a channel of the run's lines from now on, closed after
// Done. Call stop when done reading.
func (r *Runner) Subscribe(runID int64) (lines <-chan Line, stop func()) {
	ch := make(chan Line, 256)
	r.mu.Lock()
	if r.subs[runID] == nil {
		r.subs[runID] = map[chan Line]struct{}{}
	}
	r.subs[runID][ch] = struct{}{}
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, ok := r.subs[runID][ch]; ok {
			delete(r.subs[runID], ch)
			close(ch)
		}
	}
}

// noteWriter turns conn3x's stderr into conn3x_ui lines.
type noteWriter struct {
	r  *Runner
	id int64
}

func (w noteWriter) Write(b []byte) (int, error) {
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			w.r.note(w.id, "stderr: "+l)
		}
	}
	return len(b), nil
}

var scpLike = regexp.MustCompile(`^(?:[\w.-]+@)?[\w.-]+:[\w./~-][^\s:]*$`)

// ValidateGitURL accepts https://, ssh:// and user@host:path, plus http://
// to this machine for a lab Git server. file:// and ext:: would run or
// read what the UI's host has, so they're out, as is anything git could
// take for an option.
func ValidateGitURL(u string) error {
	switch {
	case u == "":
		return errors.New("a Git URL is needed")
	case strings.HasPrefix(u, "-"):
		return errors.New("a Git URL can't start with -")
	case strings.HasPrefix(u, "https://"), strings.HasPrefix(u, "ssh://"), strings.HasPrefix(u, "http://"):
		p, err := url.Parse(u)
		if err != nil || p.Host == "" {
			return errors.New("that isn't a URL git can clone")
		}
		if p.Scheme == "http" {
			if ip := net.ParseIP(p.Hostname()); p.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
				return errors.New("http:// is allowed only to localhost; use https:// or ssh")
			}
		}
		return nil
	case strings.Contains(u, "://"), !scpLike.MatchString(u):
		return errors.New("use https://host/repo, ssh://host/repo or user@host:repo")
	}
	return nil
}
