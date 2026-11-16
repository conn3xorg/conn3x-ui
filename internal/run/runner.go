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

// Runner runs plans and applies. One at a time per project; the rest
// queue.
type Runner struct {
	Store   *store.Store
	DataDir string
	// Git is the git binary. Empty means "git" on PATH.
	Git string
	Log *log.Logger

	ctx     context.Context
	wg      sync.WaitGroup
	mu      sync.Mutex
	locks   map[int64]*sync.Mutex
	subs    map[int64]map[chan Line]struct{}
	cancels map[int64]context.CancelCauseFunc
}

// New makes a Runner. Cancelling ctx interrupts every running conn3x.
func New(ctx context.Context, st *store.Store, dataDir string) *Runner {
	return &Runner{Store: st, DataDir: dataDir, Log: log.Default(), ctx: ctx,
		locks: map[int64]*sync.Mutex{}, subs: map[int64]map[chan Line]struct{}{}, cancels: map[int64]context.CancelCauseFunc{}}
}

// Wait blocks until every run has finished.
func (r *Runner) Wait() { r.wg.Wait() }

// PlanFile is where a plan run's saved plan lives, for an apply.
func (r *Runner) PlanFile(runID int64) string {
	return filepath.Join(r.DataDir, "runs", fmt.Sprint(runID), "plan.bin")
}

// ReportFile is where an apply run's -report file lives.
func (r *Runner) ReportFile(runID int64) string {
	return filepath.Join(r.DataDir, "runs", fmt.Sprint(runID), "report.json")
}

// StartPlan queues a plan of p and returns the run's ID at once.
func (r *Runner) StartPlan(ctx context.Context, p store.Project, userID int64) (int64, error) {
	id, err := r.Store.CreateRun(ctx, p.ID, store.KindPlan, userID)
	if err != nil {
		return 0, err
	}
	r.wg.Go(func() { r.run(id, p, func(ctx context.Context) error { return r.doPlan(ctx, id, p) }) })
	return id, nil
}

// StartApply queues an apply of plan, approved by userID, and returns the
// run's ID at once. The plan must still be the project's newest and not
// yet applied, or the error is store.ErrNotApplicable.
func (r *Runner) StartApply(ctx context.Context, plan store.Run, p store.Project, userID int64) (int64, error) {
	id, err := r.Store.CreateApply(ctx, plan.ID, userID)
	if err != nil {
		return 0, err
	}
	r.wg.Go(func() { r.run(id, p, func(ctx context.Context) error { return r.doApply(ctx, id, p, plan) }) })
	return id, nil
}

// ErrCancelled is why a run's context ended when somebody pressed Cancel.
var ErrCancelled = errors.New("cancelled")

// Cancel interrupts a queued or running run. conn3x gets an interrupt, as
// Ctrl-C would, so it releases its state lock. A run that isn't running
// is store.ErrNotFound.
func (r *Runner) Cancel(runID int64) error {
	r.mu.Lock()
	cancel := r.cancels[runID]
	r.mu.Unlock()
	if cancel == nil {
		return store.ErrNotFound
	}
	cancel(ErrCancelled)
	return nil
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

// run takes the project's turn, runs do, and records how it ended.
func (r *Runner) run(id int64, p store.Project, do func(context.Context) error) {
	ctx, cancel := context.WithCancelCause(r.ctx)
	r.mu.Lock()
	r.cancels[id] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.cancels, id)
		r.mu.Unlock()
		cancel(nil)
	}()
	m := r.lock(p.ID)
	m.Lock()
	defer m.Unlock()
	bg := context.Background()
	if err := r.Store.StartRun(bg, id); err != nil {
		r.Log.Printf("run %d: %v", id, err)
	}
	status, msg := store.StatusSucceeded, ""
	if err := do(ctx); err != nil && context.Cause(ctx) == ErrCancelled {
		status = store.StatusCancelled
		r.note(id, "Cancelled")
	} else if err != nil {
		status, msg = store.StatusFailed, err.Error()
		r.note(id, "Error: "+msg)
	}
	lines, _, err := r.Store.Events(bg, id)
	if err == nil {
		err = r.Store.SetRunHosts(bg, id, Group(lines).HostOutcomes())
	}
	if err != nil {
		r.Log.Printf("run %d: %v", id, err)
	}
	if err := r.Store.FinishRun(bg, id, status, msg); err != nil {
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

// checkout clones p's ref into a fresh temp directory and, when sha is
// set, moves to that commit instead of the ref's current head. It returns
// the directory conn3x runs in, the commit, and how to remove it all.
func (r *Runner) checkout(ctx context.Context, id int64, p store.Project, sha string) (work, commit string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "conn3x-ui-run-")
	if err != nil {
		return "", "", nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmp)
		}
	}()
	repo := filepath.Join(tmp, "repo")

	r.note(id, fmt.Sprintf("git clone --depth 1 --branch %s %s", p.GitRef, redactURL(p.GitURL)))
	if out, err := r.git(ctx, "clone", "--quiet", "--depth", "1", "--branch", p.GitRef, "--", p.GitURL, repo); err != nil {
		return "", "", nil, fmt.Errorf("git clone: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if sha != "" {
		if !commitSHA.MatchString(sha) {
			return "", "", nil, fmt.Errorf("the plan's commit %q isn't a commit ID", sha)
		}
		r.note(id, "git fetch --depth 1 origin "+sha)
		if out, err := r.git(ctx, "-C", repo, "fetch", "--quiet", "--depth", "1", "origin", sha); err != nil {
			return "", "", nil, fmt.Errorf("git fetch %s: %v: %s", sha, err, strings.TrimSpace(string(out)))
		}
		if out, err := r.git(ctx, "-C", repo, "checkout", "--quiet", "--detach", sha); err != nil {
			return "", "", nil, fmt.Errorf("git checkout %s: %v: %s", sha, err, strings.TrimSpace(string(out)))
		}
	}
	head, err := r.git(ctx, "-C", repo, "rev-parse", "HEAD")
	if err != nil {
		return "", "", nil, fmt.Errorf("git rev-parse: %v", err)
	}
	commit = strings.TrimSpace(string(head))
	r.Store.SetRunCommit(context.Background(), id, commit)
	r.note(id, "at commit "+commit)

	if work, err = workDir(repo, p.Path); err != nil {
		return "", "", nil, err
	}
	return work, commit, func() { os.RemoveAll(tmp) }, nil
}

func (r *Runner) doPlan(ctx context.Context, id int64, p store.Project) error {
	work, _, cleanup, err := r.checkout(ctx, id, p, "")
	if err != nil {
		return err
	}
	defer cleanup()

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

// doApply checks out the commit plan was made from and applies its saved
// plan file. A plan that no longer matches the state is refused by conn3x
// itself, and that error ends the run.
func (r *Runner) doApply(ctx context.Context, id int64, p store.Project, plan store.Run) error {
	work, _, cleanup, err := r.checkout(ctx, id, p, plan.CommitSHA)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := copyFile(r.PlanFile(plan.ID), filepath.Join(work, "plan.bin")); err != nil {
		return fmt.Errorf("plan %d has no saved plan file: %w", plan.ID, err)
	}
	c := &conn3xexec.Conn3x{Path: p.Conn3xPath, Dir: work, Env: p.EnvList(), Stderr: noteWriter{r, id}}
	r.note(id, "conn3x init -input=false")
	if err := c.Run(ctx, r.record(id), "init", "-input=false"); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.ReportFile(id)), 0o700); err != nil {
		return err
	}
	r.note(id, fmt.Sprintf("conn3x apply -input=false -report=report.json plan.bin (plan %d)", plan.ID))
	if err := r.applyWithReport(ctx, id, p, work); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	return nil
}

// applyWithReport runs conn3x apply with -report. -report doesn't go with
// -json, so the stream goes to a file through -json-into and is followed
// as conn3x writes it, which conn3xexec.Conn3x.Run can't do. Cancelling
// ctx interrupts conn3x, as Run does.
func (r *Runner) applyWithReport(ctx context.Context, id int64, p store.Project, work string) error {
	stream := filepath.Join(work, "stream.json")
	f, err := os.Create(stream)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	path := p.Conn3xPath
	if path == "" {
		path = "conn3x"
	}
	cmd := exec.CommandContext(ctx, path, "apply", "-input=false", "-json-into="+stream, "-report="+r.ReportFile(id), "plan.bin")
	cmd.Dir = work
	cmd.Env = append(os.Environ(), p.EnvList()...)
	cmd.Stderr = noteWriter{r, id} // stdout is the human output, which the stream repeats
	cmd.Cancel = func() error {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return cmd.Process.Kill() // Windows can't interrupt
		}
		return nil
	}
	cmd.WaitDelay = 30 * time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	record := r.record(id)
	var diags []conn3xexec.Diagnostic
	var fnErr error
	readErr := conn3xexec.Read(follow{f, exited}, func(ev conn3xexec.Event) error {
		if ev.Diagnostic != nil && ev.Diagnostic.Severity == "error" {
			diags = append(diags, *ev.Diagnostic)
		}
		if fnErr == nil {
			if fnErr = record(ev); fnErr != nil {
				cancel()
			}
		}
		return nil
	})
	<-exited
	if fnErr != nil {
		return fnErr
	}
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) && ctx.Err() == nil {
		return &conn3xexec.ExitError{Code: exit.ExitCode(), Diagnostics: diags}
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), waitErr)
		}
		return waitErr
	}
	return readErr
}

// follow reads a file another process is still writing, waiting at its
// end until done is closed.
type follow struct {
	f    *os.File
	done <-chan struct{}
}

func (fl follow) Read(b []byte) (int, error) {
	for {
		n, err := fl.f.Read(b)
		if n > 0 || err != io.EOF {
			return n, err
		}
		select {
		case <-fl.done:
			return fl.f.Read(b) // whatever came before it exited
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// commitSHA is a full SHA-1 or SHA-256 commit ID, all git takes here.
var commitSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

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
