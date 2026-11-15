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

// TestMain lets the test binary stand in for conn3x. CONN3X_FAKE, which
// reaches it through the project's environment, picks what it does:
// "plan" configures an http backend, "local" leaves state local.
func TestMain(m *testing.M) {
	mode := os.Getenv("CONN3X_FAKE")
	if mode == "" {
		os.Exit(m.Run())
	}
	fmt.Println(versionLine)
	switch os.Args[1] {
	case "init":
		if mode == "plan" {
			os.MkdirAll(".terraform", 0o755)
			os.WriteFile(".terraform/terraform.tfstate", []byte(`{"version":3,"backend":{"type":"http"}}`), 0o644)
		}
	case "plan":
		fmt.Println(changeLine("web2", "build", "create"))
		fmt.Println(changeLine("web1", "build", "update"))
		fmt.Println(changeLine("web1", "deploy", "create"))
		fmt.Println(`{"type":"change_summary","@message":"Plan: 2 to add, 1 to change, 0 to destroy.","changes":{"add":2,"change":1,"remove":0,"operation":"plan"}}`)
		for _, a := range os.Args {
			if out, ok := strings.CutPrefix(a, "-out="); ok {
				os.WriteFile(out, []byte("plan"), 0o644)
			}
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
	resp := c.post(projectPath+"/plan", url.Values{"csrf": {c.csrf(projectPath)}})
	runPath = resp.Header.Get("Location")
	if resp.StatusCode != 303 || !strings.HasPrefix(runPath, "/runs/") {
		t.Fatalf("plan: %d %s", resp.StatusCode, runPath)
	}
	es, err := c.Get(c.base + runPath + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer es.Body.Close()
	if ct := es.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("events content-type %q", ct)
	}
	sc := bufio.NewScanner(es.Body)
	for sc.Scan() {
		if sc.Text() == "event: done" {
			return runPath, events
		}
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			events = append(events, data)
		}
	}
	t.Fatalf("stream ended without done: %v", sc.Err())
	return
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
		"remote/main.tf": fmt.Sprintf("terraform {\n  backend \"http\" {\n    address = %q\n  }\n}\noutput \"hello\" { value = \"world\" }\n", stateSrv.URL+"/state"),
		"local/main.tf":  "output \"hello\" { value = \"world\" }\n",
	})
	e := setup(t)
	e.login(t)

	runPath, events := e.plan(t, e.createProject(t, "remote", repo, "remote", bin, ""))
	rn, _ := e.st.Run(context.Background(), 1)
	if rn.Status != store.StatusSucceeded || rn.Conn3xVersion == "" {
		t.Errorf("remote run %+v:\n%s", rn, strings.Join(events, "\n"))
	}
	if _, body := e.get(runPath); !strings.Contains(body, "No changes") && !strings.Contains(body, "0 to add") {
		t.Errorf("run page:\n%s", body)
	}
	if _, err := os.Stat(e.runner.PlanFile(1)); err != nil {
		t.Error(err)
	}

	_, events = e.plan(t, e.createProject(t, "local", repo, "local", bin, ""))
	rn, _ = e.st.Run(context.Background(), 2)
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
