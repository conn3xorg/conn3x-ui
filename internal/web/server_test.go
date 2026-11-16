// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cgi"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
// "hang" makes the plan wait for an interrupt, "creds" prints the
// credentials it was given and fails with one in its error. An apply writes its stream
// to -json-into and a report to -report, as a real one does. A plan
// -refresh-only finds nothing, except in "drift", where web1 drifted and,
// with -detailed-exitcode, it exits 2.
func TestMain(m *testing.M) {
	mode := os.Getenv("CONN3X_FAKE")
	if mode == "" {
		os.Exit(m.Run())
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt) // before the version line, so a test that sees it can cancel
	out, report := os.Stdout, ""
	for _, a := range os.Args {
		if path, ok := strings.CutPrefix(a, "-json-into="); ok {
			out, _ = os.Create(path)
		}
		if path, ok := strings.CutPrefix(a, "-report="); ok {
			report = path
		}
		if a == "-json" && report != "" {
			fmt.Fprintln(os.Stderr, "Error: -report doesn't go with -json")
			os.Exit(1)
		}
	}
	fmt.Fprintln(out, versionLine)
	switch os.Args[1] {
	case "init":
		if mode != "local" {
			os.MkdirAll(".terraform", 0o755)
			os.WriteFile(".terraform/terraform.tfstate", []byte(`{"version":3,"backend":{"type":"http"}}`), 0o644)
		}
	case "plan":
		if slices.Contains(os.Args, "-refresh-only") {
			if mode == "drift" {
				fmt.Println(strings.Replace(changeLine("web1", "build", "update"), "planned_change", "resource_drift", 1))
				if slices.Contains(os.Args, "-detailed-exitcode") {
					os.Exit(2)
				}
			}
			return
		}
		if mode == "hang" {
			waitForInterrupt(interrupt)
		}
		if mode == "creds" {
			path := os.Getenv("CONN3X_CRED_SSH_KEY")
			key, _ := os.ReadFile(path)
			fileMode, dirMode := "missing", "missing"
			if st, err := os.Stat(path); err == nil {
				fileMode = st.Mode().Perm().String()
			}
			if st, err := os.Stat(filepath.Dir(path)); err == nil {
				dirMode = st.Mode().Perm().String()
			}
			line, _ := json.Marshal(map[string]string{"type": "conn3x_fake", "@message": fmt.Sprintf("file %s %s %s %s", path, fileMode, dirMode, key)})
			fmt.Println(string(line))
			fmt.Fprintln(os.Stderr, "token "+os.Getenv("API_TOKEN"))
			fmt.Printf(`{"@level":"error","@message":"Error: bad token","type":"diagnostic","diagnostic":{"severity":"error","summary":"bad token %s","detail":""}}`+"\n", os.Getenv("API_TOKEN"))
			os.Exit(1)
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
			fmt.Fprintf(out, `{"@level":"error","@message":"Error: no plan file","type":"diagnostic","diagnostic":{"severity":"error","summary":"no plan file","detail":%q}}`+"\n", fmt.Sprint(os.Args, err))
			os.Exit(1)
		}
		if mode == "stale" {
			fmt.Fprintln(out, `{"@level":"error","@message":"Error: Saved plan is stale","type":"diagnostic","diagnostic":{"severity":"error","summary":"Saved plan is stale","detail":"The given plan file can no longer be applied because the state was changed by another operation after the plan was created."}}`)
			os.Exit(1)
		}
		// The checkout's marker says which commit the apply really ran on.
		marker, _ := os.ReadFile("marker.txt")
		fmt.Fprintf(out, `{"@level":"info","@message":"marker %s","type":"conn3x_fake"}`+"\n", strings.TrimSpace(string(marker)))
		fmt.Fprintln(out, hookLine("apply_start", "web2", "build", "create", 0))
		fmt.Fprintln(out, hookLine("apply_complete", "web2", "build", "create", 1.5))
		fmt.Fprintln(out, hookLine("apply_complete", "web1", "build", "update", 0.5))
		fmt.Fprintln(out, hookLine("apply_errored", "web1", "deploy", "create", 2))
		fmt.Fprintln(out, `{"type":"change_summary","@message":"Apply complete! Resources: 1 added, 1 changed, 0 destroyed.","changes":{"add":1,"change":1,"remove":0,"operation":"apply"}}`)
		if report != "" {
			os.WriteFile(report, []byte(`{"format_version":"1","command":"apply","success":true,"hosts":{"web1":{"steps":[]}}}`), 0o600)
		}
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
	t.Helper()
	c.loginAs(t, "admin", "pw")
}

func (c *client) loginAs(t *testing.T, name, password string) {
	t.Helper()
	csrf := c.csrf("/login")
	if resp := c.post("/login", url.Values{"csrf": {csrf}, "name": {name}, "password": {password}}); resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("login as %s: %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
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
	if id, err := st.CreateUser(context.Background(), "admin", "pw"); err != nil || st.SetUser(context.Background(), id, true, false) != nil {
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
	for _, want := range []string{"git fetch --depth 1 origin " + sha1, "at commit " + sha1, "marker one", "conn3x apply -input=false -report=report.json plan.bin (plan 1)", "web2 build", "Apply complete"} {
		if !strings.Contains(joined, want) {
			t.Errorf("apply events lack %q:\n%s", want, joined)
		}
	}
	rn, _ := e.st.Run(context.Background(), 2)
	if rn.Kind != "apply" || rn.Status != store.StatusSucceeded || rn.CommitSHA != sha1 || rn.CommitSHA == sha2 || rn.PlanRunID.Int64 != 1 || !rn.ApprovedAt.Valid || rn.ApprovedByName.String != "admin" {
		t.Errorf("apply run %+v", rn)
	}
	_, body := e.get(applyPath)
	for _, want := range []string{"<h1>Apply 2", `class="status succeeded"`, "started by admin", `<a href="/runs/1">plan 1</a>`, "approved by admin",
		`<h3>web1 <span class="failed">failed</span></h3>`, `<h3>web2 <span class="succeeded">ok</span></h3>`, `href="/runs/2/report"`,
		`<span class="succeeded">ok</span> <small>1.5s</small>`, `<span class="failed">failed</span> <small>2.0s</small>`, "<strong>Apply:</strong> 1 added, 1 changed, 0 destroyed."} {
		if !strings.Contains(body, want) {
			t.Errorf("apply page lacks %q", want)
		}
	}
	if strings.Contains(body, "/apply\"") || strings.Contains(body, "No changes") {
		t.Errorf("apply page offers Apply or says no changes:\n%s", body)
	}

	resp, report := e.get(applyPath + "/report")
	if resp.StatusCode != 200 || !strings.Contains(report, `"format_version":"1"`) || !strings.Contains(resp.Header.Get("Content-Disposition"), "run-2-report.json") {
		t.Errorf("report: %d %v %s", resp.StatusCode, resp.Header, report)
	}
	if resp, _ := e.get(planPath + "/report"); resp.StatusCode != 404 {
		t.Errorf("a plan's report: %d", resp.StatusCode)
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

func TestHistory(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, sha := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	e.login(t)
	web := e.createProject(t, "web", repo, ".", exe, "CONN3X_FAKE=plan")
	planPath, _ := e.plan(t, web)
	e.apply(t, planPath)
	e.plan(t, e.createProject(t, "db", repo, ".", exe, "CONN3X_FAKE=local"))

	_, body := e.get("/")
	if !strings.Contains(body, `<a href="/runs">Runs</a>`) {
		t.Error("no Runs link")
	}
	_, body = e.get("/runs")
	for _, want := range []string{`<a href="/runs/3">3</a>`, `<a href="/runs/2">2</a>`, `<a href="/runs/1">1</a>`, ">db</a>", ">web</a>", "apply of 1", "<td>admin</td>", sha[:10], "0.21.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("history lacks %q:\n%s", want, body)
		}
	}
	if strings.Index(body, `"/runs/3"`) > strings.Index(body, `"/runs/1"`) {
		t.Error("history isn't newest first")
	}
	for query, want := range map[string][]string{
		"?status=failed":                {"3"},
		"?project=" + path.Base(web):    {"2", "1"},
		"?host=web1":                    {"2", "1"},
		"?host=web1&status=succeeded&x": {"2", "1"},
		"?host=nowhere":                 nil,
	} {
		_, body := e.get("/runs" + query)
		for _, n := range []string{"1", "2", "3"} {
			if got := strings.Contains(body, `<a href="/runs/`+n+`">`); got != slices.Contains(want, n) {
				t.Errorf("%s: run %s listed %v:\n%s", query, n, got, body)
			}
		}
	}
	if _, body := e.get("/runs?host=web1"); !strings.Contains(body, "<th>On web1</th>") || !strings.Contains(body, "<td>failed</td>") || !strings.Contains(body, "<td>changes</td>") {
		t.Errorf("host outcomes:\n%s", body)
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
	if got := auditLines(t, e.st); !slices.Contains(got, "admin web cancel run 1") {
		t.Errorf("audit log lacks the cancel:\n%s", strings.Join(got, "\n"))
	}
}

func TestCredentials(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	e.login(t)
	project := e.createProject(t, "creds", repo, ".", exe, "CONN3X_FAKE=creds")
	const sshKey, token = "-----BEGIN KEY-----\nAAAAsecretline\n-----END KEY-----", "tok-Very$ecret-123"
	add := func(name, kind, value string) *http.Response {
		return e.post(project+"/credentials", url.Values{"csrf": {e.csrf(project)}, "name": {name}, "kind": {kind}, "value": {value}})
	}

	// Without a key there's no form, the page says how to make one, and a
	// save is refused.
	if _, body := e.get(project); !strings.Contains(body, "openssl rand -base64 32") || strings.Contains(body, `name="value"`) {
		t.Errorf("project page without a key:\n%s", body)
	}
	if resp := add("API_TOKEN", "env", token); resp.StatusCode != 400 {
		t.Errorf("save without a key: %d", resp.StatusCode)
	}

	key := make([]byte, 32)
	rand.Read(key)
	e.st.SetKey(key)
	if resp := e.post(project+"/credentials", url.Values{"name": {"API_TOKEN"}, "kind": {"env"}, "value": {token}}); resp.StatusCode != 403 {
		t.Errorf("save without CSRF: %d", resp.StatusCode)
	}
	if resp := add("ssh_key", "file", strings.ReplaceAll(sshKey, "\n", "\r\n")); resp.StatusCode != 303 {
		t.Fatalf("save file: %d", resp.StatusCode)
	}
	if resp := add("API_TOKEN", "env", token+"\r\n"); resp.StatusCode != 303 {
		t.Fatalf("save env: %d", resp.StatusCode)
	}
	resp, err := e.PostForm(e.base+project+"/credentials", url.Values{"csrf": {e.csrf(project)}, "name": {"bad-name"}, "kind": {"env"}, "value": {token}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || strings.Contains(string(body), token) {
		t.Errorf("bad name: %d, and the value came back: %v", resp.StatusCode, strings.Contains(string(body), token))
	}
	_, page := e.get(project)
	for _, want := range []string{"ssh_key", "$CONN3X_CRED_SSH_KEY", "API_TOKEN"} {
		if !strings.Contains(page, want) {
			t.Errorf("project page lacks %q", want)
		}
	}
	if strings.Contains(page, "AAAAsecretline") || strings.Contains(page, token) {
		t.Error("project page shows a saved value")
	}

	// The run gets them, and its log, its stored lines and its error don't.
	runPath, events := e.plan(t, project)
	joined := strings.Join(events, "\n")
	if strings.Contains(joined, "AAAAsecretline") || strings.Contains(joined, token) || !strings.Contains(joined, "token <hidden>") {
		t.Errorf("events:\n%s", joined)
	}
	m := regexp.MustCompile(`file (\S+) (\S+) (\S+) <hidden>`).FindStringSubmatch(joined)
	if m == nil || m[2] != "-rw-------" || m[3] != "-rwx------" {
		t.Fatalf("file credential: %q in\n%s", m, joined)
	}
	if _, err := os.Stat(filepath.Dir(m[1])); !os.IsNotExist(err) {
		t.Errorf("credentials directory outlived the run: %v", err)
	}
	rn, _ := e.st.Run(context.Background(), runID(t, runPath))
	lines, _, _ := e.st.Events(context.Background(), rn.ID)
	stored := string(slices.Concat(lines...))
	if strings.Contains(stored, "AAAAsecret") || strings.Contains(stored, token) || strings.Contains(rn.Error, token) || !strings.Contains(rn.Error, "bad token <hidden>") {
		t.Errorf("stored lines or error hold a secret: %q", rn.Error)
	}

	e.post(project+"/credentials/API_TOKEN/delete", url.Values{"csrf": {e.csrf(project)}})
	if _, page := e.get(project); strings.Contains(page, "API_TOKEN") {
		t.Error("deleted credential still listed")
	}
}

func runID(t *testing.T, runPath string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(path.Base(runPath), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
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
	if b, err := os.ReadFile(e.runner.ReportFile(2)); err != nil || !strings.Contains(string(b), "format_version") {
		t.Errorf("report: %v %s", err, b)
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

func TestDriftChecks(t *testing.T) {
	e := setup(t)
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	var mu sync.Mutex
	got := map[string]run.Notification{}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n run.Notification
		json.NewDecoder(r.Body).Decode(&n)
		mu.Lock()
		got[n.Project] = n
		mu.Unlock()
		if strings.Contains(r.URL.Path, "fail") {
			w.WriteHeader(500)
		}
	}))
	defer hook.Close()
	var logged strings.Builder
	e.runner.Log = log.New(&syncWriter{w: &logged}, "", 0)
	ctx := context.Background()
	add := func(name, fake, schedule, hookPath string) int64 {
		id, err := e.st.CreateProject(ctx, store.Project{Name: name, GitURL: repo, GitRef: "main", Path: ".", Conn3xPath: exe, Env: "CONN3X_FAKE=" + fake,
			Schedule: schedule, WebhookURL: hook.URL + hookPath})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	drifted := add("drifted", "drift", "1h", "/T000/SECRET")
	steady := add("steady", "plan", "1h", "/T000/SECRET")
	broken := add("broken", "local", "0 * * * *", "/fail/SECRET")
	unscheduled := add("unscheduled", "drift", "", "/T000/SECRET")

	e.runner.Tick(ctx, time.Now().Add(2*time.Hour))
	e.runner.Wait()
	last := func(pid int64) store.Run {
		t.Helper()
		rn, err := e.st.LastRun(ctx, pid, store.KindDrift)
		if err != nil {
			t.Fatalf("project %d: %v", pid, err)
		}
		return rn
	}
	if rn := last(drifted); rn.Status != store.StatusSucceeded || rn.Outcome != store.OutcomeDrift || rn.CreatedBy.Valid {
		t.Errorf("drifted: %+v", rn)
	}
	if rn := last(steady); rn.Status != store.StatusSucceeded || rn.Outcome != store.OutcomeClean {
		t.Errorf("steady: %+v", rn)
	}
	if rn := last(broken); rn.Status != store.StatusFailed || rn.Outcome != "" {
		t.Errorf("broken: %+v", rn)
	}
	if _, err := e.st.LastRun(ctx, unscheduled, store.KindDrift); err == nil {
		t.Error("a project without a schedule was checked")
	}

	// Drift and a failed check are posted; a clean one isn't. A webhook
	// that fails is logged without its URL.
	driftRun := last(drifted).ID
	if n := got["drifted"]; n.RunID != driftRun || n.Outcome != "drift" || n.Status != "succeeded" || n.Link != fmt.Sprintf("/runs/%d", driftRun) ||
		fmt.Sprint(n.Hosts) != "[web1]" || n.Time.IsZero() || !strings.Contains(n.Text, "drifted on web1") {
		t.Errorf("drift notification %+v", n)
	}
	if n := got["broken"]; n.Status != "failed" || n.RunID != last(broken).ID {
		t.Errorf("failure notification %+v", n)
	}
	if _, ok := got["steady"]; ok || len(got) != 2 {
		t.Errorf("notifications %+v", got)
	}
	if l := logged.String(); !strings.Contains(l, "webhook answered 500") || strings.Contains(l, "SECRET") {
		t.Errorf("log:\n%s", l)
	}

	// Just checked, so nothing is due now.
	e.runner.Tick(ctx, time.Now())
	e.runner.Wait()
	if rn := last(drifted); rn.ID != driftRun {
		t.Errorf("checked again at once: %+v", rn)
	}

	e.login(t)
	_, body := e.get(fmt.Sprintf("/runs/%d", driftRun))
	for _, want := range []string{"<h1>Drift check", "started by the schedule", `<span class="status drift">drift</span>`, "Drift since the last apply", "<td>web1</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("drift run page lacks %q:\n%s", want, body)
		}
	}
	if _, body := e.get(fmt.Sprintf("/runs/%d", last(steady).ID)); !strings.Contains(body, "No drift.") {
		t.Errorf("clean run page:\n%s", body)
	}
	for query, want := range map[string]int64{"?status=drift": driftRun, "?status=clean": last(steady).ID, "?host=web1&status=drift": driftRun} {
		_, body := e.get("/runs" + query)
		if n := strings.Count(body, `<a href="/runs/`); n != 1 || !strings.Contains(body, fmt.Sprintf(`<a href="/runs/%d">`, want)) {
			t.Errorf("%s: %d runs:\n%s", query, n, body)
		}
	}
}

// syncWriter lets runs log from their goroutines while a test reads.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(b)
}

func TestDriftSettings(t *testing.T) {
	e := setup(t)
	e.login(t)
	project := e.createProject(t, "web", "https://example.com/r.git", ".", "conn3x", "")
	const hookURL = "https://hooks.example.com/services/T000/SECRET"
	save := func(extra url.Values) (*http.Response, string) {
		form := url.Values{"csrf": {e.csrf(project)}, "name": {"web"}, "git_url": {"https://example.com/r.git"}}
		for k, v := range extra {
			form[k] = v
		}
		resp, err := e.PostForm(e.base+project, form)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}
	saved := func() store.Project {
		p, _ := e.st.Project(context.Background(), runID(t, project))
		return p
	}

	if resp, _ := save(url.Values{"schedule": {" 0  3 * * 1-5 "}, "webhook_url": {hookURL}}); resp.StatusCode != 303 {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	if p := saved(); p.Schedule != "0 3 * * 1-5" || p.WebhookURL != hookURL {
		t.Errorf("%+v", p)
	}
	_, body := e.get(project)
	if !strings.Contains(body, `value="0 3 * * 1-5"`) || !strings.Contains(body, "One is set, to hooks.example.com") || strings.Contains(body, "SECRET") {
		t.Errorf("project page:\n%s", body)
	}

	// A blank field keeps the webhook; bad values are refused and the
	// page that says so doesn't show it either.
	if resp, _ := save(url.Values{"schedule": {"6h"}}); resp.StatusCode != 303 || saved().WebhookURL != hookURL || saved().Schedule != "6h" {
		t.Errorf("blank webhook: %d %+v", resp.StatusCode, saved())
	}
	for _, bad := range []url.Values{{"schedule": {"daily"}}, {"schedule": {"10s"}}, {"webhook_url": {"ftp://example.com/x"}}} {
		if resp, body := save(bad); resp.StatusCode != 400 || strings.Contains(body, "SECRET") {
			t.Errorf("%v: %d", bad, resp.StatusCode)
		}
	}
	if resp, _ := save(url.Values{"webhook_clear": {"1"}}); resp.StatusCode != 303 || saved().WebhookURL != "" || saved().Schedule != "" {
		t.Errorf("clear: %d %+v", resp.StatusCode, saved())
	}
	if resp := e.post(project, url.Values{"name": {"web"}, "git_url": {"https://example.com/r.git"}, "schedule": {"1h"}}); resp.StatusCode != 403 {
		t.Errorf("save without CSRF: %d", resp.StatusCode)
	}
}
