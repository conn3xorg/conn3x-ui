// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package web is the HTTP side: pages, forms, sign-in and the event stream.
package web

import (
	"context"
	"crypto/hmac"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/run"
	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// static/htmx.min.js is htmx 2.0.8 from
// https://unpkg.com/htmx.org@2.0.8/dist/htmx.min.js, unchanged,
// sha256 22283ef68cb7545914f0a88a1bdedc7256a703d1d580c1d255217d0a50d31313.
//
//go:embed templates static
var files embed.FS

const sessionTTL = 7 * 24 * time.Hour

// Server serves the UI.
type Server struct {
	Store  *store.Store
	Runner *run.Runner
	Log    *log.Logger
	pages  map[string]*template.Template
	mux    *http.ServeMux
	// cop rejects cross-site POSTs by their Sec-Fetch-Site and Origin
	// headers, a second guard beside the CSRF tokens.
	cop http.CrossOriginProtection
}

type ctxKey int

const sessionKey ctxKey = 0

type session struct {
	token string
	user  store.User
	csrf  string
}

// page is what every template gets.
type page struct {
	User  store.User
	CSRF  string
	Error string
	Data  any
}

// New builds the handler.
func New(st *store.Store, rn *run.Runner) *Server {
	s := &Server{Store: st, Runner: rn, Log: log.Default(), pages: map[string]*template.Template{}, mux: http.NewServeMux()}
	for _, name := range []string{"login", "projects", "project", "run", "runs"} {
		s.pages[name] = template.Must(template.New("").Funcs(template.FuncMap{"lineText": lineText}).
			ParseFS(files, "templates/layout.html", "templates/project_form.html", "templates/"+name+".html"))
	}
	s.mux.Handle("GET /static/", http.FileServerFS(files))
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("POST /logout", s.logout)
	s.mux.HandleFunc("GET /{$}", s.projects)
	s.mux.HandleFunc("POST /projects", s.createProject)
	s.mux.HandleFunc("GET /projects/{id}", s.project)
	s.mux.HandleFunc("POST /projects/{id}", s.updateProject)
	s.mux.HandleFunc("POST /projects/{id}/delete", s.deleteProject)
	s.mux.HandleFunc("POST /projects/{id}/plan", s.startPlan)
	s.mux.HandleFunc("GET /runs", s.history)
	s.mux.HandleFunc("GET /runs/{id}", s.runPage)
	s.mux.HandleFunc("GET /runs/{id}/report", s.runReport)
	s.mux.HandleFunc("POST /runs/{id}/apply", s.startApply)
	s.mux.HandleFunc("POST /runs/{id}/cancel", s.cancelRun)
	s.mux.HandleFunc("GET /runs/{id}/status", s.runStatus)
	s.mux.HandleFunc("GET /runs/{id}/events", s.runEvents)
	return s
}

// ServeHTTP signs the request in and checks CSRF, then routes it.
// shortcut: one local admin and a session cookie stand in for #892's OIDC
// sign-in and roles.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No page may be framed, so a button can't be clicked through an overlay.
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.cop.Handler(http.HandlerFunc(s.serve)).ServeHTTP(w, r)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/login" {
		if r.Method == http.MethodPost && !sameToken(r.PostFormValue("csrf"), cookie(r, "csrf")) {
			http.Error(w, "the sign-in form expired; go back and try again", http.StatusForbidden)
			return
		}
		s.mux.ServeHTTP(w, r)
		return
	}
	sess, err := s.session(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost && !sameToken(r.PostFormValue("csrf"), sess.csrf) {
		http.Error(w, "this form has expired; reload the page and try again", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
}

func sameToken(a, b string) bool { return a != "" && hmac.Equal([]byte(a), []byte(b)) }

func cookie(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func (s *Server) session(r *http.Request) (session, error) {
	tok := cookie(r, "session")
	if tok == "" {
		return session{}, store.ErrNotFound
	}
	u, csrf, err := s.Store.Session(r.Context(), tok)
	return session{token: tok, user: u, csrf: csrf}, err
}

func sess(r *http.Request) session {
	s, _ := r.Context().Value(sessionKey).(session)
	return s
}

// setCookie sets a cookie the browser keeps to itself. Secure is off only
// on localhost, where browsers accept it over plain http anyway.
func setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	ip := net.ParseIP(host)
	local := host == "localhost" || (ip != nil && ip.IsLoopback())
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || !local, MaxAge: int(ttl / time.Second)})
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, status int, data any, errMsg string) {
	s.execute(w, r, name, "layout", status, data, errMsg)
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, page_, tmpl string, status int, data any, errMsg string) {
	se := sess(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages[page_].ExecuteTemplate(w, tmpl, page{User: se.user, CSRF: se.csrf, Error: errMsg, Data: data}); err != nil {
		s.Log.Printf("render %s: %v", page_, err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.Log.Print(err)
	http.Error(w, "something went wrong; the log has the details", http.StatusInternalServerError)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	csrf := store.Token(32)
	setCookie(w, r, "csrf", csrf, time.Hour)
	s.pages["login"].ExecuteTemplate(w, "layout", page{CSRF: csrf})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	tok, _, err := s.Store.Login(r.Context(), r.PostFormValue("name"), r.PostFormValue("password"), sessionTTL)
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusUnauthorized)
		s.pages["login"].ExecuteTemplate(w, "layout", page{CSRF: cookie(r, "csrf"), Error: "That name and password don't match."})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	setCookie(w, r, "session", tok, sessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Store.Logout(r.Context(), sess(r).token)
	setCookie(w, r, "session", "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.Projects(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "projects", http.StatusOK, map[string]any{"Projects": ps, "Form": store.Project{GitRef: "main", Path: ".", Conn3xPath: "conn3x"}}, "")
}

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// projectForm reads and checks the project form.
func projectForm(r *http.Request) (store.Project, error) {
	f := func(name, def string) string {
		v := strings.TrimSpace(r.PostFormValue(name))
		if v == "" {
			return def
		}
		return v
	}
	p := store.Project{Name: f("name", ""), GitURL: f("git_url", ""), GitRef: f("git_ref", "main"), Path: f("path", "."), Conn3xPath: f("conn3x_path", "conn3x")}
	if p.Name == "" {
		return p, errors.New("the project needs a name")
	}
	if err := run.ValidateGitURL(p.GitURL); err != nil {
		return p, err
	}
	if strings.HasPrefix(p.GitRef, "-") || strings.ContainsAny(p.GitRef, " \t\n") {
		return p, errors.New("that isn't a branch or tag name")
	}
	p.Path = path.Clean(strings.ReplaceAll(p.Path, "\\", "/"))
	if path.IsAbs(p.Path) || p.Path == ".." || strings.HasPrefix(p.Path, "../") {
		return p, errors.New("the path must be inside the repository, like circuits/web")
	}
	var env []string
	for _, l := range strings.Split(strings.ReplaceAll(r.PostFormValue("env"), "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		if !envKey.MatchString(l) {
			return p, fmt.Errorf("environment line %q isn't NAME=value", l)
		}
		env = append(env, l)
	}
	p.Env = strings.Join(env, "\n")
	return p, nil
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	p, err := projectForm(r)
	if err == nil {
		p.ID, err = s.Store.CreateProject(r.Context(), p)
	}
	if err != nil {
		ps, _ := s.Store.Projects(r.Context())
		s.render(w, r, "projects", http.StatusBadRequest, map[string]any{"Projects": ps, "Form": p}, saveError(err))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

func saveError(err error) string {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return "A project with that name already exists."
	}
	return err.Error()
}

func id(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

func (s *Server) project(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.Project(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	runs, err := s.Store.Runs(r.Context(), p.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "project", http.StatusOK, map[string]any{"Project": p, "Form": p, "Runs": runs}, "")
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.Project(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	form, err := projectForm(r)
	form.ID = p.ID
	if err == nil {
		err = s.Store.UpdateProject(r.Context(), form)
	}
	if err != nil {
		runs, _ := s.Store.Runs(r.Context(), p.ID)
		s.render(w, r, "project", http.StatusBadRequest, map[string]any{"Project": p, "Form": form, "Runs": runs}, saveError(err))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	runs, err := s.Store.Runs(r.Context(), id(r))
	if err == nil {
		err = s.Store.DeleteProject(r.Context(), id(r))
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, rn := range runs {
		os.RemoveAll(path.Dir(s.Runner.PlanFile(rn.ID)))
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) startPlan(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.Project(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	runID, err := s.Runner.StartPlan(r.Context(), p, sess(r).user.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", runID), http.StatusSeeOther)
}

// mayApply says whether u may approve and apply plan.
// shortcut: the one admin may apply any plan; #892 brings the approver
// role, and the setting that lets a planner apply their own plan belongs
// there too (TODO in #892, not here).
func mayApply(u store.User, plan store.Run) bool {
	return u.ID != 0
}

// runData is the run page and its status partial.
type runData struct {
	Run     store.Run
	Project store.Project
	Lines   [][]byte
	Last    int64
	Result  *run.Result
	// CanApply is true when the run is a plan this user may apply now.
	CanApply bool
	// HasReport is true when the run is an apply that left a -report file.
	HasReport bool
}

func (s *Server) loadRun(r *http.Request) (runData, error) {
	var d runData
	var err error
	if d.Run, err = s.Store.Run(r.Context(), id(r)); err != nil {
		return d, err
	}
	if d.Project, err = s.Store.Project(r.Context(), d.Run.ProjectID); err != nil {
		return d, err
	}
	if d.Lines, d.Last, err = s.Store.Events(r.Context(), d.Run.ID); err != nil {
		return d, err
	}
	if d.Run.Finished() {
		res := run.Group(d.Lines)
		d.Result = &res
	}
	if _, err := os.Stat(s.Runner.ReportFile(d.Run.ID)); err == nil {
		d.HasReport = true
	}
	if d.Run.Kind == store.KindPlan && d.Run.Status == store.StatusSucceeded && d.Result.HasChanges() && mayApply(sess(r).user, d.Run) {
		if d.CanApply, err = s.Store.Applicable(r.Context(), d.Run.ID); err != nil {
			return d, err
		}
	}
	return d, nil
}

func (s *Server) startApply(w http.ResponseWriter, r *http.Request) {
	d, err := s.loadRun(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !d.CanApply {
		http.Error(w, store.ErrNotApplicable.Error(), http.StatusConflict)
		return
	}
	runID, err := s.Runner.StartApply(r.Context(), d.Run, d.Project, sess(r).user.ID)
	if errors.Is(err, store.ErrNotApplicable) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", runID), http.StatusSeeOther)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	rn, err := s.Store.Run(r.Context(), id(r))
	if err == nil {
		err = s.Runner.Cancel(rn.ID)
	}
	if errors.Is(err, store.ErrNotFound) && rn.ID != 0 {
		http.Error(w, "this run isn't running", http.StatusConflict)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", rn.ID), http.StatusSeeOther)
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.loadRun(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "run", http.StatusOK, d, "")
}

// runReport serves an apply's -report file.
func (s *Server) runReport(w http.ResponseWriter, r *http.Request) {
	rn, err := s.Store.Run(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="run-%d-report.json"`, rn.ID))
	http.ServeFile(w, r, s.Runner.ReportFile(rn.ID))
}

// historyPage is how many runs the history shows at a time.
const historyPage = 50

// history is every run across projects, newest first, filtered by
// project, host and status.
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.Filter{Host: strings.TrimSpace(q.Get("host")), Status: q.Get("status")}
	f.ProjectID, _ = strconv.ParseInt(q.Get("project"), 10, 64)
	pg, _ := strconv.Atoi(q.Get("page"))
	pg = max(pg, 1)
	runs, err := s.Store.History(r.Context(), f, historyPage+1, (pg-1)*historyPage)
	if err != nil {
		s.fail(w, err)
		return
	}
	ps, err := s.Store.Projects(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	more := len(runs) > historyPage
	if more {
		runs = runs[:historyPage]
	}
	// The other pages keep the filters.
	link := func(n int) string {
		v := url.Values{}
		for k, val := range map[string]string{"project": q.Get("project"), "host": f.Host, "status": f.Status} {
			if val != "" {
				v.Set(k, val)
			}
		}
		v.Set("page", strconv.Itoa(n))
		return "/runs?" + v.Encode()
	}
	d := map[string]any{"Runs": runs, "Projects": ps, "Filter": f, "Page": pg,
		"Statuses": []string{store.StatusQueued, store.StatusRunning, store.StatusSucceeded, store.StatusFailed, store.StatusCancelled}}
	if pg > 1 {
		d["Prev"] = link(pg - 1)
	}
	if more {
		d["Next"] = link(pg + 1)
	}
	s.render(w, r, "runs", http.StatusOK, d, "")
}

func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	d, err := s.loadRun(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.execute(w, r, "run", "status", http.StatusOK, d, "")
}

// runEvents streams a run's lines as server-sent events, from the line
// after Last-Event-ID or ?after, and ends with a done event.
func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	rn, err := s.Store.Run(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	after, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	if after == 0 {
		after, _ = strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	}
	ch, stop := s.Runner.Subscribe(rn.ID)
	defer stop()
	lines, last, err := s.Store.Events(r.Context(), rn.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	send := func(seq int64, line []byte) {
		fmt.Fprintf(w, "id: %d\ndata: %s\n\n", seq, strings.ReplaceAll(lineText(line), "\n", "\ndata: "))
	}
	for i, l := range lines {
		if int64(i+1) > after {
			send(int64(i+1), l)
		}
	}
	done := func() { fmt.Fprint(w, "event: done\ndata: \n\n") }
	// The run may have finished between the subscribe and the read; the
	// status in the database is final either way.
	if rn, err = s.Store.Run(r.Context(), rn.ID); err == nil && rn.Finished() {
		done()
		rc.Flush()
		return
	}
	rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case l, ok := <-ch:
			if !ok {
				return // dropped as too slow; the browser reconnects
			}
			if l.Done {
				done()
				rc.Flush()
				return
			}
			if l.Seq > last {
				send(l.Seq, l.Data)
				rc.Flush()
			}
		}
	}
}

// lineText is a stream line as a person reads it: the message, with a
// diagnostic's detail, or the raw line when it isn't JSON.
func lineText(line []byte) string {
	var ev struct {
		Message    string `json:"@message"`
		Diagnostic *struct {
			Detail string `json:"detail"`
		} `json:"diagnostic"`
	}
	if json.Unmarshal(line, &ev) != nil || ev.Message == "" {
		return string(line)
	}
	if ev.Diagnostic != nil && ev.Diagnostic.Detail != "" {
		return ev.Message + "\n" + ev.Diagnostic.Detail
	}
	return ev.Message
}
