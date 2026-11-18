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
	"slices"
	"strings"
	"sync"
	"time"

	conn3xexec "github.com/conn3xorg/conn3x-exec"

	"github.com/conn3xorg/conn3x-ui/internal/sandbox"
	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// Line is one stored stream line, or Done when the run has finished.
type Line struct {
	Seq  int64
	Data []byte
	Done bool
}

// Runner runs plans, applies and drift checks. One at a time per project;
// the rest queue.
type Runner struct {
	Store   *store.Store
	DataDir string
	// Git is the git binary. Empty means "git" on PATH.
	Git string
	// Sandbox runs conn3x with only its run's checkout and credentials,
	// not the UI's data or other runs. Linux only.
	Sandbox bool
	Log     *log.Logger
	// PublicURL is the UI's address, such as https://conn3x.example.com,
	// for full links in webhooks. Empty leaves them as paths.
	PublicURL string
	// Mailer sends a project's notifications to its email addresses; nil
	// when the UI has no SMTP server.
	Mailer interface {
		Send(to []string, subject, body string) error
	}

	ctx     context.Context
	wg      sync.WaitGroup
	mu      sync.Mutex
	locks   map[int64]*sync.Mutex
	subs    map[int64]map[chan Line]struct{}
	cancels map[int64]context.CancelCauseFunc
	// hide replaces each running run's credential values in its log.
	hide map[int64]*strings.Replacer
	// splayed is when each project's due drift check starts, once its
	// splay has picked a delay.
	splayed map[int64]time.Time
	// pruned is when step results past Retention were last removed.
	pruned time.Time
	// Retention is how long the fleet store keeps step results. The latest
	// facts per host are kept for good.
	Retention time.Duration
}

// New makes a Runner. Cancelling ctx interrupts every running conn3x.
func New(ctx context.Context, st *store.Store, dataDir string) *Runner {
	return &Runner{Store: st, DataDir: dataDir, Log: log.Default(), ctx: ctx,
		locks: map[int64]*sync.Mutex{}, subs: map[int64]map[chan Line]struct{}{}, cancels: map[int64]context.CancelCauseFunc{}, hide: map[int64]*strings.Replacer{}, splayed: map[int64]time.Time{}, Retention: 90 * 24 * time.Hour}
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
	r.wg.Go(func() {
		r.run(id, p, func(ctx context.Context, env []string) error { return r.doPlan(ctx, id, p, env, nil) })
	})
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
	r.wg.Go(func() {
		r.run(id, p, func(ctx context.Context, env []string) error { return r.doApply(ctx, id, p, plan, env) })
	})
	return id, nil
}

// StartDrift queues a drift check of p, started by userID, or by its
// schedule when userID is 0, and returns the run's ID at once. When the
// check finds drift or fails, p's webhook hears about it. Only a check the
// schedule started goes on to correct or converge: one somebody started
// is for looking.
func (r *Runner) StartDrift(ctx context.Context, p store.Project, userID int64) (int64, error) {
	id, err := r.Store.CreateRun(ctx, p.ID, store.KindDrift, userID)
	if err != nil {
		return 0, err
	}
	r.wg.Go(func() {
		r.run(id, p, func(ctx context.Context, env []string) error { return r.doDrift(ctx, id, p, env) })
		r.notify(id, p)
		if userID == 0 && (p.ScheduleMode == store.ModeCorrect || p.ScheduleMode == store.ModeConverge) {
			r.correct(id, p)
		}
	})
	return id, nil
}

// StartEvent queues a drift check of p that rule started, with the event's
// body kept beside it, and returns the run's ID at once. It goes on to
// correct or converge as the rule's mode says, under the same guards as a
// schedule's.
func (r *Runner) StartEvent(ctx context.Context, p store.Project, rule store.EventRule, body string) (int64, error) {
	id, err := r.Store.CreateEventRun(ctx, rule, body)
	if err != nil {
		return 0, err
	}
	p.ScheduleMode = rule.Mode
	r.wg.Go(func() {
		r.run(id, p, func(ctx context.Context, env []string) error { return r.doDrift(ctx, id, p, env) })
		r.notify(id, p)
		if p.ScheduleMode == store.ModeCorrect || p.ScheduleMode == store.ModeConverge {
			r.correct(id, p)
		}
	})
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

// run takes the project's turn, hands the project's credentials to do
// with its environment, and records how it ended.
func (r *Runner) run(id int64, p store.Project, do func(ctx context.Context, env []string) error) {
	ctx, cancel := context.WithCancelCause(r.ctx)
	r.mu.Lock()
	r.cancels[id] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.cancels, id)
		delete(r.hide, id)
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
	env, cleanup, err := r.credentials(id, p)
	if err == nil {
		err = do(ctx, append(p.EnvList(), env...))
		cleanup() // success, failure and cancel alike, before anyone hears it's done
	}
	if err != nil && context.Cause(ctx) == ErrCancelled {
		status = store.StatusCancelled
		r.note(id, "Cancelled")
	} else if err != nil {
		status, msg = store.StatusFailed, r.scrub(id, err.Error())
		r.note(id, "Error: "+msg)
	}
	lines, _, err := r.Store.Events(bg, id)
	if err == nil {
		res := Group(lines)
		if err = r.Store.SetRunHosts(bg, id, res.HostOutcomes()); err == nil {
			err = r.Store.SaveStepResults(bg, id, p.ID, res.StepResults())
		}
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

// credentials opens p's credentials, hides their values in the run's log
// from now on, and writes the file ones into a fresh private directory. It
// returns the environment the run gets for them and how to remove the
// directory.
func (r *Runner) credentials(id int64, p store.Project) (env []string, cleanup func(), err error) {
	secrets, err := r.Store.Secrets(context.Background(), p.ID)
	if err != nil || len(secrets) == 0 {
		return nil, func() {}, err
	}
	r.mu.Lock()
	r.hide[id] = hider(secrets)
	r.mu.Unlock()
	dir, env, err := writeCredentials(r.credentialsDir(), secrets)
	if err != nil {
		return nil, nil, err
	}
	return env, func() { os.RemoveAll(dir) }, nil
}

var credName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateCredentialName accepts a name that is an environment variable's,
// so it works as a variable, a file name and in CredentialEnv.
func ValidateCredentialName(name string) error {
	if !credName.MatchString(name) {
		return fmt.Errorf("credential name %q needs letters, digits and _ only, not starting with a digit", name)
	}
	return nil
}

// reservedEnv are variables that change how a run's programs start, load
// code or reach a host: git, ssh, the dynamic loader, the shell, conn3x and
// the language runtimes a provider or hook may start. An env credential
// named for one could run commands on this server, so none may be one.
var (
	reservedEnv       = []string{"PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "IFS", "PS4", "PROMPT_COMMAND", "CDPATH", "TMPDIR", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GCONV_PATH", "LOCPATH", "OPENSSL_CONF", "OPENSSL_ENGINES", "GLIBC_TUNABLES"}
	reservedEnvPrefix = []string{"LD_", "DYLD_", "GIT_", "SSH_", "TF_", "CONN3X_", "OPENTOFU_", "PYTHON", "PERL", "RUBY", "MALLOC_"}
)

// ValidateCredentialEnv refuses an env credential name that's one of
// reservedEnv, whatever its case.
func ValidateCredentialEnv(name string) error {
	up := strings.ToUpper(name)
	reserved := slices.Contains(reservedEnv, up)
	for _, p := range reservedEnvPrefix {
		reserved = reserved || strings.HasPrefix(up, p)
	}
	if reserved {
		return fmt.Errorf("%s changes how a run's programs start, so it can't be a credential; set it in the project's environment, which a site admin controls", name)
	}
	return nil
}

// CredentialEnv is the variable a file credential's path comes in:
// CONN3X_CRED_ and the name in upper case, so ssh_key is
// CONN3X_CRED_SSH_KEY.
func CredentialEnv(name string) string { return "CONN3X_CRED_" + strings.ToUpper(name) }

// credPrefix starts the name of each run's credentials directory.
const credPrefix = "conn3x-ui-cred-"

// credentialsDir is the one parent of every run's credentials directory,
// so a start can find what a crash left behind.
func (r *Runner) credentialsDir() string { return filepath.Join(r.DataDir, "credentials") }

// RemoveLeftovers removes the credentials directories that runs which died
// with conn3x-ui left behind, and returns how many. Call it at start,
// before any run. It removes nothing but credPrefix directories in
// credentialsDir.
func (r *Runner) RemoveLeftovers() (int, error) {
	entries, err := os.ReadDir(r.credentialsDir())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), credPrefix) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(r.credentialsDir(), e.Name())); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// writeCredentials writes each file credential into a fresh directory in
// parent that only this user can read, and returns the directory and the
// environment: NAME=value for an env credential, CredentialEnv(NAME)=path
// for a file one.
func writeCredentials(parent string, secrets []store.Secret) (dir string, env []string, err error) {
	// Absolute, as conn3x runs in the checkout.
	if parent, err = filepath.Abs(parent); err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, err
	}
	dir, err = os.MkdirTemp(parent, credPrefix) // 0700
	if err != nil {
		return "", nil, err
	}
	for _, s := range secrets {
		if err := ValidateCredentialName(s.Name); err != nil {
			os.RemoveAll(dir)
			return "", nil, err
		}
		if s.Kind == store.CredEnv {
			if err := ValidateCredentialEnv(s.Name); err != nil {
				os.RemoveAll(dir)
				return "", nil, err
			}
			env = append(env, s.Name+"="+string(s.Value))
			continue
		}
		path := filepath.Join(dir, s.Name)
		if err := os.WriteFile(path, s.Value, 0o600); err != nil {
			os.RemoveAll(dir)
			return "", nil, err
		}
		env = append(env, CredentialEnv(s.Name)+"="+path)
	}
	return dir, env, nil
}

// hider replaces each credential value with <hidden>: as it is, as JSON
// writes it, and line by line, so a key printed in part is caught too.
// It's a backstop; nothing in conn3x-ui prints a value on purpose.
func hider(secrets []store.Secret) *strings.Replacer {
	var olds []string
	for _, s := range secrets {
		v := string(s.Value)
		olds = append(olds, v, jsonString(v, true), jsonString(v, false))
		for _, l := range strings.Split(v, "\n") {
			olds = append(olds, strings.TrimSpace(l))
		}
	}
	// Longest first, so a whole value wins over one of its lines.
	slices.SortFunc(olds, func(a, b string) int { return len(b) - len(a) })
	var pairs []string
	for _, o := range olds {
		if o != "" {
			pairs = append(pairs, o, "<hidden>")
		}
	}
	return strings.NewReplacer(pairs...)
}

// jsonString is v as it appears inside a JSON string, with <, > and &
// escaped as Go's encoding/json does by default, or not.
func jsonString(v string, escapeHTML bool) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	enc.Encode(v)
	q := strings.TrimSuffix(b.String(), "\n")
	return q[1 : len(q)-1]
}

// scrub hides the run's credential values in s.
func (r *Runner) scrub(id int64, s string) string {
	r.mu.Lock()
	h := r.hide[id]
	r.mu.Unlock()
	if h == nil {
		return s
	}
	return h.Replace(s)
}

// ErrLocalState is a configuration without a remote backend.
var ErrLocalState = errors.New("this configuration keeps its state in a local file, which would be lost with the run's temp directory. " +
	"conn3x-ui needs a remote backend, such as s3, azurerm, gcs, pg or http. Add a backend block to the configuration and plan again")

// checkout clones p's ref into a fresh temp directory and, when sha is
// set, moves to that commit instead of the ref's current head. It returns
// the directory conn3x runs in, the commit, and the run's own directory,
// which holds it all and is for the caller to remove.
func (r *Runner) checkout(ctx context.Context, id int64, p store.Project, sha string, env []string) (work, commit, tmp string, err error) {
	tmp, err = os.MkdirTemp("", "conn3x-ui-run-")
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmp)
		}
	}()
	repo := filepath.Join(tmp, "repo")
	if err = os.Mkdir(filepath.Join(tmp, "tmp"), 0o700); err != nil {
		return "", "", "", err
	}

	r.note(id, fmt.Sprintf("git clone --depth 1 --branch %s %s", p.GitRef, redactURL(p.GitURL)))
	if out, err := r.git(ctx, env, "clone", "--quiet", "--depth", "1", "--branch", p.GitRef, "--", p.GitURL, repo); err != nil {
		return "", "", "", fmt.Errorf("git clone: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if sha != "" {
		if !commitSHA.MatchString(sha) {
			return "", "", "", fmt.Errorf("the plan's commit %q isn't a commit ID", sha)
		}
		r.note(id, "git fetch --depth 1 origin "+sha)
		if out, err := r.git(ctx, env, "-C", repo, "fetch", "--quiet", "--depth", "1", "origin", sha); err != nil {
			return "", "", "", fmt.Errorf("git fetch %s: %v: %s", sha, err, strings.TrimSpace(string(out)))
		}
		if out, err := r.git(ctx, env, "-C", repo, "checkout", "--quiet", "--detach", sha); err != nil {
			return "", "", "", fmt.Errorf("git checkout %s: %v: %s", sha, err, strings.TrimSpace(string(out)))
		}
	}
	head, err := r.git(ctx, env, "-C", repo, "rev-parse", "HEAD")
	if err != nil {
		return "", "", "", fmt.Errorf("git rev-parse: %v", err)
	}
	commit = strings.TrimSpace(string(head))
	r.Store.SetRunCommit(context.Background(), id, commit)
	r.note(id, "at commit "+commit)

	if work, err = workDir(repo, p.Path); err != nil {
		return "", "", "", err
	}
	return work, commit, tmp, nil
}

// doPlan plans and saves the plan file. after, when set, reads the plan in
// the checkout, c.Dir, before it's removed.
func (r *Runner) doPlan(ctx context.Context, id int64, p store.Project, env []string, after func(c *conn3xexec.Conn3x) error) error {
	work, _, tmp, err := r.checkout(ctx, id, p, "", env)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	c, err := r.conn3x(id, p, tmp, work, env)
	if err != nil {
		return err
	}
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
	if err := copyFile(filepath.Join(work, "plan.bin"), r.PlanFile(id)); err != nil {
		return err
	}
	r.saveFacts(ctx, id, p, c)
	if after != nil {
		return after(c)
	}
	return nil
}

// doDrift refreshes the state against the hosts without planning any
// change. -detailed-exitcode makes conn3x exit 2 when something drifted.
func (r *Runner) doDrift(ctx context.Context, id int64, p store.Project, env []string) error {
	work, _, tmp, err := r.checkout(ctx, id, p, "", env)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	c, err := r.conn3x(id, p, tmp, work, env)
	if err != nil {
		return err
	}
	r.note(id, "conn3x init -input=false")
	if err := c.Run(ctx, r.record(id), "init", "-input=false"); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if t, err := backendType(work); err != nil {
		return err
	} else if t == "local" {
		return ErrLocalState
	}
	r.note(id, "conn3x plan -refresh-only -detailed-exitcode -input=false -out=plan.bin")
	outcome := store.OutcomeClean
	err = c.Run(ctx, r.record(id), "plan", "-refresh-only", "-detailed-exitcode", "-input=false", "-out=plan.bin")
	var exit *conn3xexec.ExitError
	if errors.As(err, &exit) && exit.Code == 2 {
		outcome, err = store.OutcomeDrift, nil
	}
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	r.saveFacts(ctx, id, p, c)
	return r.Store.SetRunOutcome(context.Background(), id, outcome)
}

// doApply checks out the commit plan was made from and applies its saved
// plan file. A plan that no longer matches the state is refused by conn3x
// itself, and that error ends the run.
func (r *Runner) doApply(ctx context.Context, id int64, p store.Project, plan store.Run, env []string) error {
	work, _, tmp, err := r.checkout(ctx, id, p, plan.CommitSHA, env)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := copyFile(r.PlanFile(plan.ID), filepath.Join(work, "plan.bin")); err != nil {
		return fmt.Errorf("plan %d has no saved plan file: %w", plan.ID, err)
	}
	c, err := r.conn3x(id, p, tmp, work, env)
	if err != nil {
		return err
	}
	r.note(id, "conn3x init -input=false")
	if err := c.Run(ctx, r.record(id), "init", "-input=false"); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.ReportFile(id)), 0o700); err != nil {
		return err
	}
	r.note(id, fmt.Sprintf("conn3x apply -input=false -report=report.json plan.bin (plan %d)", plan.ID))
	// -report doesn't go with -json, so the stream goes to a file instead.
	// The report is written in the checkout, since a sandboxed run can't
	// write to the data directory, and copied there after, even when the
	// apply failed part way.
	applyErr := c.RunInto(ctx, r.record(id), filepath.Join(work, "stream.json"), "apply", "-input=false", "-report=report.json", "plan.bin")
	if err := copyFile(filepath.Join(work, "report.json"), r.ReportFile(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if applyErr != nil {
		return fmt.Errorf("apply: %w", applyErr)
	}
	return nil
}

// conn3x is how a run starts conn3x in work. When the runner sandboxes
// runs, conn3x can write only in tmp, the run's own directory, and read
// only the system's directories, its credential files and a few of the
// home directory's settings.
func (r *Runner) conn3x(id int64, p store.Project, tmp, work string, env []string) (*conn3xexec.Conn3x, error) {
	c := &conn3xexec.Conn3x{Path: p.Conn3xPath, Dir: work, Env: env, Stderr: noteWriter{r, id}}
	if !r.Sandbox {
		return c, nil
	}
	prog := p.Conn3xPath
	if prog == "" {
		prog = "conn3x"
	}
	pol := sandbox.Policy{Write: []string{tmp}}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, "CONN3X_CRED_"):
			pol.Read = append(pol.Read, v)
		case k == "TF_PLUGIN_CACHE_DIR":
			pol.Write = append(pol.Write, v)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, f := range []string{".ssh", ".terraform.d", ".terraformrc", ".tofurc"} {
			pol.Read = append(pol.Read, filepath.Join(home, f))
		}
	}
	path, v, err := sandbox.Command(prog, pol)
	if err != nil {
		return nil, err
	}
	// Last, so neither wins over the project's own variables' names.
	c.Path, c.Env = path, append(slices.Clip(env), "TMPDIR="+filepath.Join(tmp, "tmp"), v)
	return c, nil
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

// git runs git with the run's environment, so a project's credentials can
// set GIT_SSH_COMMAND or GIT_CONFIG_* for its own repository.
func (r *Runner) git(ctx context.Context, env []string, args ...string) ([]byte, error) {
	git := r.Git
	if git == "" {
		git = "git"
	}
	cmd := exec.CommandContext(ctx, git, args...)
	// Never hang on a password or host-key prompt nobody can answer, and
	// never let the environment widen the protocols, which ext:: would.
	// The UI's own settings come last, so nothing in env replaces them.
	cmd.Env = append(append(os.Environ(), env...), "GIT_SSH_COMMAND=ssh -o BatchMode=yes", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https:ssh:http")
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
	line = []byte(r.scrub(id, string(line)))
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
