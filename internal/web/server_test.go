// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/conn3xorg/conn3x-ui/internal/run"
	"github.com/conn3xorg/conn3x-ui/internal/store"
)

const versionLine = `{"@level":"info","@message":"Conn3x v0.21.0","conn3x":"0.21.0","tofu":"1.13.9","type":"version","ui":"1.2"}`

func changeLine(host, step, action string) string {
	return fmt.Sprintf(`{"@level":"info","@message":"planned","type":"planned_change","change":{"resource":{"addr":"conn3x_command.box__%s[\"%s\"]","resource_type":"conn3x_command","resource_name":"box__%s","conn3x":{"circuit":"box","step":"%s","host":"%s"}},"action":"%s"}}`, step, host, step, step, host, action)
}

func hookLine(typ, host, step, action string, elapsed float64) string {
	return fmt.Sprintf(`{"@level":"info","@message":"%s %s","type":"%s","hook":{"resource":{"addr":"conn3x_command.box__%s[\"%s\"]","resource_type":"conn3x_command","resource_name":"box__%s","conn3x":{"circuit":"box","step":"%s","host":"%s"}},"action":"%s","elapsed_seconds":%g}}`, host, step, typ, step, host, step, step, host, action, elapsed)
}

// waitForInterrupt blocks until SIGINT, as conn3x does mid-step, then
// exits 1 the way an interrupted conn3x does.
func waitForInterrupt(ch chan os.Signal) {
	<-ch
	fmt.Println(`{"@level":"error","@message":"Error: Interrupted","type":"diagnostic","diagnostic":{"severity":"error","summary":"Interrupted","detail":"the run was stopped"}}`)
	os.Exit(1)
}

// TestMain lets the test binary stand in for conn3x. CONN3X_FAKE, which
// reaches it through the project's environment, picks what it does:
// "plan" configures an http backend and plans and applies, "local" leaves
// state local, "stale" refuses the apply the way a stale plan is refused,
// "hang" makes the plan wait for an interrupt.
func TestMain(m *testing.M) {
	mode := os.Getenv("CONN3X_FAKE")
	if mode == "" {
		os.Exit(m.Run())
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt) // before the version line, so a test that sees it can cancel
	fmt.Println(versionLine)
	switch os.Args[1] {
	case "init":
		if mode != "local" {
			os.MkdirAll(".terraform", 0o755)
			os.WriteFile(".terraform/terraform.tfstate", []byte(`{"version":3,"backend":{"type":"http"}}`), 0o644)
		}
	case "plan":
		if mode == "hang" {
			waitForInterrupt(interrupt)
		}
		fmt.Println(changeLine("web2", "build", "create"))
		fmt.Println(changeLine("web1", "build", "update"))
		fmt.Println(changeLine("web1", "deploy", "create"))
		fmt.Println(`{"type":"change_summary","@message":"Plan: 2 to add, 1 to change, 0 to destroy.","changes":{"add":2,"change":1,"remove":0,"operation":"plan"}}`)
		for _, a := range os.Args {
			if out, ok := strings.CutPrefix(a, "-out="); ok {
				os.WriteFile(out, []byte("plan"), 0o644)
			}
		}
	case "apply":
		if b, err := os.ReadFile(os.Args[len(os.Args)-1]); err != nil || string(b) != "plan" {
			fmt.Printf(`{"@level":"error","@message":"Error: no plan file","type":"diagnostic","diagnostic":{"severity":"error","summary":"no plan file","detail":%q}}`+"\n", fmt.Sprint(os.Args, err))
			os.Exit(1)
		}
		if mode == "stale" {
			fmt.Println(`{"@level":"error","@message":"Error: Saved plan is stale","type":"diagnostic","diagnostic":{"severity":"error","summary":"Saved plan is stale","detail":"The given plan file can no longer be applied because the state was changed by another operation after the plan was created."}}`)
			os.Exit(1)
		}
		// The checkout's marker says which commit the apply really ran on.
		marker, _ := os.ReadFile("marker.txt")
		fmt.Printf(`{"@level":"info","@message":"marker %s","type":"conn3x_fake"}`+"\n", strings.TrimSpace(string(marker)))
		fmt.Println(hookLine("apply_start", "web2", "build", "create", 0))
		fmt.Println(hookLine("apply_complete", "web2", "build", "create", 1.5))
		fmt.Println(hookLine("apply_complete", "web1", "build", "update", 0.5))
		fmt.Println(hookLine("apply_errored", "web1", "deploy", "create", 2))
		fmt.Println(`{"type":"change_summary","@message":"Apply complete! Resources: 1 added, 1 changed, 0 destroyed.","changes":{"add":1,"change":1,"remove":0,"operation":"apply"}}`)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitServer makes a bare repo with files on main and serves it over smart
// HTTP with git's own CGI, so a shallow clone works. It returns the clone
// URL and the commit.
func gitServer(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	work := filepath.Join(t.TempDir(), "work")
	for name, body := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(work, name)), 0o755)
		os.WriteFile(filepath.Join(work, name), []byte(body), 0o644)
	}
	git(t, work, "init", "-q", "-b", "main")
	git(t, work, "add", ".")
	git(t, work, "commit", "-q", "-m", "circuits")
	sha := git(t, work, "rev-parse", "HEAD")
	root := t.TempDir()
	git(t, work, "clone", "-q", "--bare", work, filepath.Join(root, "repo.git"))
	git(t, filepath.Join(root, "repo.git"), "config", "http.receivepack", "true") // so a test can push a second commit
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(&cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	})
	t.Cleanup(srv.Close)
	return srv.URL + "/repo.git", sha
}

// commit adds files to the served repo's main as a new commit and returns
// its SHA.
func commit(t *testing.T, repoURL string, files map[string]string) string {
	t.Helper()
	work := filepath.Join(t.TempDir(), "work2")
	git(t, t.TempDir(), "clone", "-q", repoURL, work)
	for name, body := range files {
		os.WriteFile(filepath.Join(work, name), []byte(body), 0o644)
	}
	git(t, work, "add", ".")
	git(t, work, "commit", "-q", "-m", "more")
	git(t, work, "push", "-q", "origin", "main")
	return git(t, work, "rev-parse", "HEAD")
}

type client struct {
	t    *testing.T
	base string
	*http.Client
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t, base, &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) get(path string) (*http.Response, string) {
	c.t.Helper()
	resp, err := c.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (c *client) csrf(path string) string {
	c.t.Helper()
	_, body := c.get(path)
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		c.t.Fatalf("no CSRF token on %s", path)
	}
	return m[1]
}

func (c *client) post(path string, form url.Values) *http.Response {
	c.t.Helper()
	resp, err := c.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (c *client) login(t *testing.T) {
	csrf := c.csrf("/login")
	if resp := c.post("/login", url.Values{"csrf": {csrf}, "name": {"admin"}, "password": {"pw"}}); resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func (c *client) createProject(t *testing.T, name, gitURL, path, conn3x, env string) string {
	t.Helper()
	form := url.Values{"csrf": {c.csrf("/")}, "name": {name}, "git_url": {gitURL}, "git_ref": {"main"}, "path": {path}, "conn3x_path": {conn3x}, "env": {env}}
	resp := c.post("/projects", form)
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/projects/") {
		t.Fatalf("create project: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return resp.Header.Get("Location")
}

// plan starts a plan and reads its event stream to the done event.
func (c *client) plan(t *testing.T, projectPath string) (runPath string, events []string) {
	t.Helper()
	return c.follow(t, projectPath+"/plan")
}

// apply applies a plan run and reads the apply's stream to the done event.
func (c *client) apply(t *testing.T, planPath string) (runPath string, events []string) {
	t.Helper()
	return c.follow(t, planPath+"/apply")
}

// follow posts to a path that starts a run and reads the run's event
// stream to the done event.
func (c *client) follow(t *testing.T, startPath string) (runPath string, events []string) {
	t.Helper()
	runPath, es := c.start(t, startPath)
	defer es.Body.Close()
	sc := bufio.NewScanner(es.Body)
	events, done := readEvents(sc, nil)
	if !done {
		t.Fatalf("stream ended without done: %v", sc.Err())
	}
	return runPath, events
}

// start posts to a path that starts a run and opens the run's stream.
func (c *client) start(t *testing.T, startPath string) (runPath string, es *http.Response) {
	t.Helper()
	resp := c.post(startPath, url.Values{"csrf": {c.csrf("/")}})
	runPath = resp.Header.Get("Location")
	if resp.StatusCode != 303 || !strings.HasPrefix(runPath, "/runs/") {
		t.Fatalf("%s: %d %s", startPath, resp.StatusCode, runPath)
	}
	es, err := c.Get(c.base + runPath + "/events")
	if err != nil {
		t.Fatal(err)
	}
	if ct := es.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("events content-type %q", ct)
	}
	return runPath, es
}

// readEvents reads data lines until the done event, or until one matches
// until. It says whether done was reached.
func readEvents(sc *bufio.Scanner, until func(string) bool) (events []string, done bool) {
	for sc.Scan() {
		if sc.Text() == "event: done" {
			return events, true
		}
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			events = append(events, data)
			if until != nil && until(data) {
				return events, false
			}
		}
	}
	return events, false
}

type env struct {
	st     *store.Store
	runner *run.Runner
	data   string
	*client
}

func setup(t *testing.T) env {
	t.Helper()
	data := t.TempDir()
	st, err := store.Open(filepath.Join(data, "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateUser(context.Background(), "admin", "pw"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runner := run.New(ctx, st, data)
	t.Cleanup(func() { cancel(); runner.Wait() })
	srv := httptest.NewServer(New(st, runner))
	t.Cleanup(srv.Close)
	return env{st, runner, data, newClient(t, srv.URL)}
}

func TestPlanFromBrowser(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, sha := gitServer(t, map[string]string{"circuits/main.tf": "# circuits\n"})

	if resp, _ := e.get("/"); resp.StatusCode != 303 || resp.Header.Get("Location") != "/login" {
		t.Fatalf("signed out: %d", resp.StatusCode)
	}
	e.login(t)
	if resp := e.post("/projects", url.Values{"name": {"x"}}); resp.StatusCode != 403 {
		t.Errorf("POST without CSRF: %d", resp.StatusCode)
	}
	if resp := e.post("/projects", url.Values{"csrf": {e.csrf("/")}, "name": {"x"}, "git_url": {"file:///etc"}}); resp.StatusCode != 400 {
		t.Errorf("file:// URL: %d", resp.StatusCode)
	}

	project := e.createProject(t, "web", repo, "circuits", exe, "CONN3X_FAKE=plan\n")
	runPath, events := e.plan(t, project)
	joined := strings.Join(events, "\n")
	if !strings.Contains(joined, "git clone --depth 1 --branch main") || !strings.Contains(joined, "Conn3x v0.21.0") || !strings.Contains(joined, "Plan: 2 to add") {
		t.Errorf("events:\n%s", joined)
	}

	_, body := e.get(runPath)
	for _, want := range []string{`class="status succeeded"`, "commit", sha[:10], "Conn3x 0.21.0", "<h3>web1</h3>", "<h3>web2</h3>", "box.build", "box.deploy", "2 to add, 1 to change"} {
		if !strings.Contains(body, want) {
			t.Errorf("run page lacks %q", want)
		}
	}
	if strings.Index(body, "<h3>web1</h3>") > strings.Index(body, "<h3>web2</h3>") {
		t.Error("hosts aren't in order")
	}
	if _, err := os.Stat(filepath.Join(e.data, "runs", strings.TrimPrefix(runPath, "/runs/"), "plan.bin")); err != nil {
		t.Errorf("plan.bin wasn't kept: %v", err)
	}

	// A finished run's stream replays and ends at once, from where asked.
	resp, body := e.get(runPath + "/events?after=3")
	if resp.StatusCode != 200 || strings.Contains(body, "id: 3\n") || !strings.Contains(body, "id: 4\n") || !strings.HasSuffix(body, "event: done\ndata: \n\n") {
		t.Errorf("replay:\n%s", body)
	}

	// Edit, then delete, and the runs go too.
	resp = e.post(project, url.Values{"csrf": {e.csrf(project)}, "name": {"web renamed"}, "git_url": {repo}, "conn3x_path": {exe}})
	if resp.StatusCode != 303 {
		t.Errorf("edit: %d", resp.StatusCode)
	}
	if _, body := e.get("/"); !strings.Contains(body, "web renamed") {
		t.Error("rename didn't stick")
	}
	e.post(project+"/delete", url.Values{"csrf": {e.csrf(project)}})
	if resp, _ := e.get(runPath); resp.StatusCode != 404 {
		t.Errorf("run outlived its project: %d", resp.StatusCode)
	}
}

func TestApplyFromBrowser(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, sha1 := gitServer(t, map[string]string{"circuits/main.tf": "# circuits\n", "circuits/marker.txt": "one\n"})
	e.login(t)
	project := e.createProject(t, "web", repo, "circuits", exe, "CONN3X_FAKE=plan\n")

	// A finished plan with changes offers Apply.
	planPath, _ := e.plan(t, project)
	if _, body := e.get(planPath); !strings.Contains(body, `action="`+planPath+`/apply"`) || strings.Contains(body, "/cancel") {
		t.Errorf("plan page:\n%s", body)
	}

	// The branch moves on; the apply still runs the plan's commit.
	sha2 := commit(t, repo, map[string]string{"circuits/marker.txt": "two\n"})
	applyPath, events := e.apply(t, planPath)
	joined := strings.Join(events, "\n")
	for _, want := range []string{"git fetch --depth 1 origin " + sha1, "at commit " + sha1, "marker one", "conn3x apply -input=false plan.bin (plan 1)", "web2 build", "Apply complete"} {
		if !strings.Contains(joined, want) {
			t.Errorf("apply events lack %q:\n%s", want, joined)
		}
	}
	rn, _ := e.st.Run(context.Background(), 2)
	if rn.Kind != "apply" || rn.Status != store.StatusSucceeded || rn.CommitSHA != sha1 || rn.CommitSHA == sha2 || rn.PlanRunID.Int64 != 1 || !rn.ApprovedAt.Valid || rn.ApprovedByName.String != "admin" {
		t.Errorf("apply run %+v", rn)
	}
	_, body := e.get(applyPath)
	for _, want := range []string{"<h1>Apply 2", `class="status succeeded"`, `<a href="/runs/1">plan 1</a>`, "approved by admin", "<h3>web1</h3>", "<h3>web2</h3>",
		`<span class="succeeded">ok</span> <small>1.5s</small>`, `<span class="failed">failed</span> <small>2.0s</small>`, "<strong>Apply:</strong> 1 added, 1 changed, 0 destroyed."} {
		if !strings.Contains(body, want) {
			t.Errorf("apply page lacks %q", want)
		}
	}
	if strings.Contains(body, "/apply\"") || strings.Contains(body, "No changes") {
		t.Errorf("apply page offers Apply or says no changes:\n%s", body)
	}

	// Applied once, the plan can't be applied again.
	if _, body := e.get(planPath); strings.Contains(body, "/apply\"") {
		t.Error("applied plan still offers Apply")
	}
	if resp := e.post(planPath+"/apply", url.Values{"csrf": {e.csrf("/")}}); resp.StatusCode != 409 {
		t.Errorf("second apply: %d", resp.StatusCode)
	}

	// A newer plan retires an older one.
	plan3, _ := e.plan(t, project)
	plan4, _ := e.plan(t, project)
	if resp := e.post(plan3+"/apply", url.Values{"csrf": {e.csrf("/")}}); resp.StatusCode != 409 {
		t.Errorf("apply of a superseded plan: %d", resp.StatusCode)
	}
	if _, body := e.get(plan3); strings.Contains(body, "/apply\"") {
		t.Error("superseded plan still offers Apply")
	}
	if _, body := e.get(plan4); !strings.Contains(body, `action="`+plan4+`/apply"`) {
		t.Error("newest plan doesn't offer Apply")
	}
	if resp := e.post(plan4+"/apply", url.Values{}); resp.StatusCode != 403 {
		t.Errorf("apply without CSRF: %d", resp.StatusCode)
	}
	if _, body := e.get(project); !strings.Contains(body, "<td>apply of 1</td>") {
		t.Errorf("project page lacks the apply:\n%s", body)
	}
}

func TestStalePlanRefused(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	e.login(t)
	planPath, _ := e.plan(t, e.createProject(t, "web", repo, ".", exe, "CONN3X_FAKE=stale"))
	applyPath, events := e.apply(t, planPath)
	if _, body := e.get(applyPath); !strings.Contains(body, `class="status failed"`) || !strings.Contains(body, "Saved plan is stale") || !strings.Contains(body, "state was changed by another operation") {
		t.Errorf("apply page:\n%s\n%s", body, strings.Join(events, "\n"))
	}
}

func TestCancel(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	e.login(t)
	project := e.createProject(t, "web", repo, ".", exe, "CONN3X_FAKE=hang")
	runPath, es := e.start(t, project+"/plan")
	defer es.Body.Close()
	sc := bufio.NewScanner(es.Body)
	versions := 0 // init prints one, then the hanging plan prints one
	if _, done := readEvents(sc, func(s string) bool { versions += strings.Count(s, "Conn3x v0.21.0"); return versions == 2 }); done {
		t.Fatal("plan finished on its own")
	}
	if _, body := e.get(runPath); !strings.Contains(body, `action="`+runPath+`/cancel"`) {
		t.Errorf("running plan has no Cancel:\n%s", body)
	}
	if resp := e.post(runPath+"/cancel", url.Values{"csrf": {e.csrf("/")}}); resp.StatusCode != 303 {
		t.Errorf("cancel: %d", resp.StatusCode)
	}
	events, done := readEvents(sc, nil)
	if !done {
		t.Fatalf("stream ended without done: %v", sc.Err())
	}
	rn, _ := e.st.Run(context.Background(), 1)
	if rn.Status != store.StatusCancelled || !rn.Finished() {
		t.Errorf("run %+v\n%s", rn, strings.Join(events, "\n"))
	}
	joined := strings.Join(events, "\n")
	if !strings.Contains(joined, "Interrupted") || !strings.Contains(joined, "Cancelled") {
		t.Errorf("events:\n%s", joined)
	}
	if _, body := e.get(runPath); !strings.Contains(body, `class="status cancelled"`) || strings.Contains(body, "/cancel\"") {
		t.Errorf("cancelled page:\n%s", body)
	}
	if resp := e.post(runPath+"/cancel", url.Values{"csrf": {e.csrf("/")}}); resp.StatusCode != 409 {
		t.Errorf("cancel of a finished run: %d", resp.StatusCode)
	}
}

func TestLocalStateRefused(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# no backend\n"})
	e.login(t)
	runPath, events := e.plan(t, e.createProject(t, "lab", repo, ".", exe, "CONN3X_FAKE=local"))
	_, body := e.get(runPath)
	if !strings.Contains(body, `class="status failed"`) || !strings.Contains(body, "needs a remote backend") {
		t.Errorf("run page:\n%s", body)
	}
	if !strings.Contains(strings.Join(events, "\n"), "needs a remote backend") {
		t.Errorf("events:\n%s", strings.Join(events, "\n"))
	}
}

func TestBadCloneFails(t *testing.T) {
	e := setup(t)
	e.login(t)
	runPath, _ := e.plan(t, e.createProject(t, "gone", "http://127.0.0.1:9/nothing.git", ".", "conn3x", ""))
	if _, body := e.get(runPath); !strings.Contains(body, `class="status failed"`) || !strings.Contains(body, "git clone") {
		t.Errorf("run page:\n%s", body)
	}
}

// TestRealConn3x plans a real configuration with the conn3x binary CONN3X_BIN
// names: one with an http backend, served from memory here, and one with
// local state, which is refused.
func TestRealConn3x(t *testing.T) {
	bin := os.Getenv("CONN3X_BIN")
	if bin == "" {
		t.Skip("CONN3X_BIN not set")
	}
	var mu sync.Mutex
	var state []byte
	stateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			if state == nil {
				w.WriteHeader(404)
				return
			}
			w.Write(state)
		case http.MethodPost:
			state, _ = io.ReadAll(r.Body)
		}
	}))
	defer stateSrv.Close()
	repo, _ := gitServer(t, map[string]string{
		"remote/main.tf": fmt.Sprintf("terraform {\n  backend \"http\" {\n    address = %q\n  }\n}\nresource \"terraform_data\" \"hello\" { input = \"world\" }\n", stateSrv.URL+"/state"),
		"local/main.tf":  "output \"hello\" { value = \"world\" }\n",
	})
	e := setup(t)
	e.login(t)

	runPath, events := e.plan(t, e.createProject(t, "remote", repo, "remote", bin, ""))
	rn, _ := e.st.Run(context.Background(), 1)
	if rn.Status != store.StatusSucceeded || rn.Conn3xVersion == "" {
		t.Errorf("remote run %+v:\n%s", rn, strings.Join(events, "\n"))
	}
	if _, body := e.get(runPath); !strings.Contains(body, "1 to add") || !strings.Contains(body, `action="`+runPath+`/apply"`) {
		t.Errorf("run page:\n%s", body)
	}
	if _, err := os.Stat(e.runner.PlanFile(1)); err != nil {
		t.Error(err)
	}
	applyPath, events := e.apply(t, runPath)
	rn, _ = e.st.Run(context.Background(), 2)
	if rn.Status != store.StatusSucceeded || rn.PlanRunID.Int64 != 1 {
		t.Errorf("apply run %+v:\n%s", rn, strings.Join(events, "\n"))
	}
	if _, body := e.get(applyPath); !strings.Contains(body, "1 added") || !strings.Contains(body, `<span class="succeeded">ok</span>`) {
		t.Errorf("apply page:\n%s", body)
	}
	if state == nil {
		t.Error("the apply wrote no state")
	}
	if resp := e.post(runPath+"/apply", url.Values{"csrf": {e.csrf("/")}}); resp.StatusCode != 409 {
		t.Errorf("second apply: %d", resp.StatusCode)
	}

	_, events = e.plan(t, e.createProject(t, "local", repo, "local", bin, ""))
	rn, _ = e.st.Run(context.Background(), 3)
	if rn.Status != store.StatusFailed || !strings.Contains(rn.Error, "remote backend") {
		t.Errorf("local run %+v:\n%s", rn, strings.Join(events, "\n"))
	}
}

func TestLineText(t *testing.T) {
	d, _ := json.Marshal(map[string]any{"@message": "Error: x", "diagnostic": map[string]string{"detail": "why"}})
	if got := lineText(d); got != "Error: x\nwhy" {
		t.Errorf("%q", got)
	}
	if got := lineText([]byte("panic: boom")); got != "panic: boom" {
		t.Errorf("%q", got)
	}
}

func TestPagesCantBeFramed(t *testing.T) {
	e := setup(t)
	resp, err := e.Get(e.base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("headers %v", resp.Header)
	}
}
