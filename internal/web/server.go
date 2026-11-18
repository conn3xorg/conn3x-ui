// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package web is the HTTP side: pages, forms, sign-in, roles, the audit log
// and the event stream.
package web

import (
	"cmp"
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

	"github.com/conn3xorg/conn3x-ui/internal/mail"
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
	// OIDC, when set, offers sign-in with an OpenID Connect provider.
	OIDC *OIDC
	// PasswordOff turns off sign-in with a password, leaving OIDC.
	PasswordOff bool
	pages       map[string]*template.Template
	mux         *http.ServeMux
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
	for _, name := range []string{"login", "projects", "project", "run", "runs", "users", "account", "audit", "forbidden"} {
		s.pages[name] = template.Must(template.New("").Funcs(template.FuncMap{"lineText": lineText, "credEnv": run.CredentialEnv, "atLeast": store.RoleAtLeast, "roles": func() []string { return store.Roles }}).
			ParseFS(files, "templates/layout.html", "templates/project_form.html", "templates/"+name+".html"))
	}
	s.mux.Handle("GET /static/", http.FileServerFS(files))
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("GET /login/oidc", s.oidcStart)
	s.mux.HandleFunc("GET /login/oidc/callback", s.oidcCallback)
	s.mux.HandleFunc("POST /logout", s.logout)
	s.mux.HandleFunc("GET /{$}", s.projects)
	s.mux.HandleFunc("POST /projects", s.createProject)
	s.mux.HandleFunc("GET /projects/{id}", s.project)
	s.mux.HandleFunc("POST /projects/{id}", s.updateProject)
	s.mux.HandleFunc("POST /projects/{id}/delete", s.deleteProject)
	s.mux.HandleFunc("POST /projects/{id}/plan", s.startPlan)
	s.mux.HandleFunc("POST /projects/{id}/drift", s.startDrift)
	s.mux.HandleFunc("POST /projects/{id}/credentials", s.setCredential)
	s.mux.HandleFunc("POST /projects/{id}/credentials/{name}/delete", s.deleteCredential)
	s.mux.HandleFunc("POST /projects/{id}/roles", s.setRole)
	s.mux.HandleFunc("POST /projects/{id}/events", s.createEventRule)
	s.mux.HandleFunc("POST /projects/{id}/events/{rule}/delete", s.deleteEventRule)
	s.mux.HandleFunc("POST /hooks/{id}", s.hook)
	s.mux.HandleFunc("GET /runs", s.history)
	s.mux.HandleFunc("GET /runs/{id}", s.runPage)
	s.mux.HandleFunc("GET /runs/{id}/report", s.runReport)
	s.mux.HandleFunc("POST /runs/{id}/apply", s.startApply)
	s.mux.HandleFunc("POST /runs/{id}/cancel", s.cancelRun)
	s.mux.HandleFunc("GET /runs/{id}/status", s.runStatus)
	s.mux.HandleFunc("GET /runs/{id}/events", s.runEvents)
	s.mux.HandleFunc("GET /users", s.users)
	s.mux.HandleFunc("POST /users", s.createUser)
	s.mux.HandleFunc("POST /users/{id}", s.updateUser)
	s.mux.HandleFunc("POST /users/{id}/password", s.resetPassword)
	s.mux.HandleFunc("GET /account", s.account)
	s.mux.HandleFunc("POST /account/password", s.changePassword)
	s.mux.HandleFunc("GET /audit", s.auditPage)
	s.mux.HandleFunc("GET /audit/export", s.auditExport)
	s.mux.HandleFunc("GET /api/v1/hosts", s.apiHosts)
	s.mux.HandleFunc("GET /api/v1/hosts/{host}/changes", s.apiHostChanges)
	s.mux.HandleFunc("GET /api/v1/steps", s.apiSteps)
	return s
}

// ServeHTTP signs the request in and checks CSRF, then routes it. Each
// handler checks the user's role itself.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No page may be framed, so a button can't be clicked through an overlay.
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.cop.Handler(http.HandlerFunc(s.serve)).ServeHTTP(w, r)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// An event signs in with its rule's secret, not a session.
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/hooks/") {
		s.mux.ServeHTTP(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/login/oidc") {
		if r.Method == http.MethodPost && !sameToken(r.PostFormValue("csrf"), cookie(r, "csrf")) {
			http.Error(w, "the sign-in form expired; go back and try again", http.StatusForbidden)
			return
		}
		s.mux.ServeHTTP(w, r)
		return
	}
	sess, err := s.session(r)
	if err != nil && strings.HasPrefix(r.URL.Path, "/api/") {
		apiError(w, http.StatusUnauthorized, "sign in first")
		return
	}
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

// forbid answers 403 with a page that says why.
func (s *Server) forbid(w http.ResponseWriter, r *http.Request, why string) {
	s.render(w, r, "forbidden", http.StatusForbidden, why, "")
}

// role is the user's role on a project: admin for a site admin, "" for
// someone with none.
func (s *Server) role(r *http.Request, projectID int64) (string, error) {
	if u := sess(r).user; u.Admin {
		return store.RoleAdmin, nil
	}
	return s.Store.Role(r.Context(), projectID, sess(r).user.ID)
}

// allowed loads a project and the user's role on it. When the role is
// below want, it answers 403 and returns false, as it does when the
// project can't be loaded.
func (s *Server) allowed(w http.ResponseWriter, r *http.Request, projectID int64, want string) (store.Project, string, bool) {
	p, err := s.Store.Project(r.Context(), projectID)
	if err != nil {
		s.fail(w, err)
		return p, "", false
	}
	role, err := s.role(r, p.ID)
	if err != nil {
		s.fail(w, err)
		return p, "", false
	}
	if !store.RoleAtLeast(role, want) {
		s.forbid(w, r, fmt.Sprintf("That needs the %s role on %s. A project admin can give it to you.", want, p.Name))
		return p, role, false
	}
	return p, role, true
}

// siteAdmin answers 403 and returns false unless the user is a site admin.
func (s *Server) siteAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !sess(r).user.Admin {
		s.forbid(w, r, "Only a site admin can do that.")
		return false
	}
	return true
}

// audit appends an action to the audit log. A failed write is logged, not
// shown: the action has happened already.
func (s *Server) audit(ctx context.Context, u store.User, p store.Project, action, detail string) {
	if err := s.Store.Audit(ctx, store.Entry{UserID: u.ID, UserName: u.Name, ProjectID: p.ID, ProjectName: p.Name, Action: action, Detail: detail}); err != nil {
		s.Log.Printf("audit %s: %v", action, err)
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
	s.loginForm(w, r, http.StatusOK, "")
}

// loginForm renders the sign-in page with a new CSRF token.
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	csrf := store.Token(32)
	setCookie(w, r, "csrf", csrf, time.Hour)
	s.loginRender(w, status, csrf, errMsg)
}

func (s *Server) loginRender(w http.ResponseWriter, status int, csrf, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	s.pages["login"].ExecuteTemplate(w, "layout", page{CSRF: csrf, Error: errMsg, Data: map[string]bool{"Password": !s.PasswordOff, "OIDC": s.OIDC != nil}})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.PasswordOff {
		http.Error(w, "sign-in with a password is off; use single sign-on", http.StatusForbidden)
		return
	}
	name := r.PostFormValue("name")
	tok, _, err := s.Store.Login(r.Context(), name, r.PostFormValue("password"), sessionTTL)
	// Only a name somebody has goes in the log, so a password typed into
	// the name field doesn't.
	u, uerr := s.Store.UserNamed(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		why := "wrong password"
		if uerr != nil {
			why, u = "unknown name", store.User{}
		} else if u.Disabled {
			why = "disabled user"
		}
		s.audit(r.Context(), u, store.Project{}, "sign-in failed", why)
		s.loginRender(w, http.StatusUnauthorized, cookie(r, "csrf"), "That name and password don't match.")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), u, store.Project{}, "sign-in", "")
	setCookie(w, r, "session", tok, sessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Store.Logout(r.Context(), sess(r).token)
	s.audit(r.Context(), sess(r).user, store.Project{}, "sign-out", "")
	setCookie(w, r, "session", "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// visibleProjects is every project for a site admin, and the ones the
// user has a role on for anyone else.
func (s *Server) visibleProjects(r *http.Request) ([]store.Project, error) {
	if u := sess(r).user; !u.Admin {
		return s.Store.MemberProjects(r.Context(), u.ID)
	}
	return s.Store.Projects(r.Context())
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	ps, err := s.visibleProjects(r)
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
	p.Schedule = strings.Join(strings.Fields(r.PostFormValue("schedule")), " ")
	if p.Schedule != "" {
		if _, err := run.ParseSchedule(p.Schedule); err != nil {
			return p, err
		}
	}
	if p.WebhookURL = f("webhook_url", ""); p.WebhookURL != "" {
		if err := run.ValidateWebhookURL(p.WebhookURL); err != nil {
			return p, err
		}
	}
	p.SelfApply = r.PostFormValue("self_apply") != ""
	switch p.ScheduleMode = f("schedule_mode", store.ModeReport); p.ScheduleMode {
	case store.ModeReport, store.ModeCorrect, store.ModeConverge:
	default:
		return p, errors.New("that isn't something a drift check can do")
	}
	n, err := strconv.Atoi(f("max_changes", "0"))
	if err != nil || n < 0 {
		return p, errors.New("the most changes a schedule may apply is a whole number, 0 for no limit")
	}
	p.MaxChanges = n
	if p.SplayMinutes, err = strconv.Atoi(f("splay_minutes", "0")); err != nil || p.SplayMinutes < 0 || p.SplayMinutes > 1440 {
		return p, errors.New("the splay is a whole number of minutes, from 0 to 1440")
	}
	to, err := mail.ParseAddresses(r.PostFormValue("notify_email"))
	if err != nil {
		return p, err
	}
	p.NotifyEmail = strings.Join(to, ", ")
	return p, nil
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	p, err := projectForm(r)
	if err == nil {
		p.ID, err = s.Store.CreateProject(r.Context(), p)
	}
	if err != nil {
		ps, _ := s.Store.Projects(r.Context())
		s.render(w, r, "projects", http.StatusBadRequest, map[string]any{"Projects": ps, "Form": p}, saveError(err))
		return
	}
	s.audit(r.Context(), sess(r).user, p, "project create", "")
	s.auditSchedule(r, p, store.Project{}, p)
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
	p, role, ok := s.allowed(w, r, id(r), store.RoleViewer)
	if !ok {
		return
	}
	s.projectPage(w, r, p, p, role, http.StatusOK, "")
}

// projectPage renders the project page with form in its settings. Only a
// project admin gets the settings, credentials and roles.
func (s *Server) projectPage(w http.ResponseWriter, r *http.Request, p, form store.Project, role string, status int, errMsg string) {
	s.projectPageWith(w, r, p, form, role, status, errMsg, nil)
}

// projectPageWith is projectPage with extra data for the template.
func (s *Server) projectPageWith(w http.ResponseWriter, r *http.Request, p, form store.Project, role string, status int, errMsg string, extra map[string]any) {
	runs, err := s.Store.Runs(r.Context(), p.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := map[string]any{"Project": p, "Form": form, "Runs": runs, "Role": role, "HasKey": s.Store.HasKey(), "HasMail": s.Runner != nil && s.Runner.Mailer != nil, "SiteAdmin": sess(r).user.Admin}
	for k, v := range extra {
		d[k] = v
	}
	if store.RoleAtLeast(role, store.RoleAdmin) {
		if d["Credentials"], err = s.Store.Credentials(r.Context(), p.ID); err == nil {
			if d["EventRules"], err = s.Store.EventRules(r.Context(), p.ID); err == nil {
				if d["Members"], err = s.Store.Members(r.Context(), p.ID); err == nil {
					d["Users"], err = s.Store.Users(r.Context())
				}
			}
		}
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	s.render(w, r, "project", status, d, errMsg)
}

// auditSchedule records a change to a project's drift check schedule or
// webhook. A webhook may hold a token, so only its host goes in.
func (s *Server) auditSchedule(r *http.Request, p, old, saved store.Project) {
	if old.Schedule != saved.Schedule {
		s.audit(r.Context(), sess(r).user, p, "schedule change", fmt.Sprintf("%q to %q", old.Schedule, saved.Schedule))
	}
	if was := cmp.Or(old.ScheduleMode, store.ModeReport); was != saved.ScheduleMode || old.MaxChanges != saved.MaxChanges {
		s.audit(r.Context(), sess(r).user, p, "schedule mode change", fmt.Sprintf("%s, at most %d changes, to %s, at most %d", was, old.MaxChanges, saved.ScheduleMode, saved.MaxChanges))
	}
	if old.WebhookURL != saved.WebhookURL {
		detail := "removed"
		if saved.WebhookURL != "" {
			detail = "set, to " + saved.WebhookHost()
		}
		s.audit(r.Context(), sess(r).user, p, "webhook change", detail)
	}
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	p, role, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	form, err := projectForm(r)
	form.ID = p.ID
	// The page never shows the saved webhook URL, so a blank field keeps it.
	if form.WebhookURL == "" && r.PostFormValue("webhook_clear") == "" {
		form.WebhookURL = p.WebhookURL
	}
	// What a run executes, and with what environment, can run commands on
	// this server and so reach every project's credentials; only a site
	// admin may change it.
	if err == nil && !sess(r).user.Admin && (form.GitURL != p.GitURL || form.Conn3xPath != p.Conn3xPath || form.Env != p.Env) {
		err = errors.New("only a site admin can change the Git URL, the Conn3x binary or the environment variables")
	}
	// The mode and its limit let the schedule change hosts with nobody
	// approving, so they're a site admin's call too.
	if err == nil && !sess(r).user.Admin && (form.ScheduleMode != p.ScheduleMode || form.MaxChanges != p.MaxChanges) {
		err = errors.New("only a site admin can change what a drift check does about drift, or how many changes it may apply")
	}
	if err == nil {
		err = s.Store.UpdateProject(r.Context(), form)
	}
	if err != nil {
		s.projectPage(w, r, p, form, role, http.StatusBadRequest, saveError(err))
		return
	}
	detail := ""
	if form.Name != p.Name {
		detail = "renamed from " + p.Name
	}
	s.audit(r.Context(), sess(r).user, form, "project edit", detail)
	s.auditSchedule(r, form, p, form)
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

// setCredential adds or replaces one of the project's credentials. The
// value is never shown again, not even when the form comes back with an
// error.
func (s *Server) setCredential(w http.ResponseWriter, r *http.Request) {
	p, role, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	name, kind := strings.TrimSpace(r.PostFormValue("name")), r.PostFormValue("kind")
	value := strings.ReplaceAll(r.PostFormValue("value"), "\r\n", "\n")
	if kind == store.CredEnv {
		value = strings.TrimRight(value, "\n")
	} else if !strings.HasSuffix(value, "\n") {
		value += "\n" // a pasted key loses its last newline, and ssh won't read a key without one
	}
	err := run.ValidateCredentialName(name)
	if err == nil && kind == store.CredEnv {
		err = run.ValidateCredentialEnv(name)
	}
	switch {
	case err != nil:
	case kind != store.CredFile && kind != store.CredEnv:
		err = errors.New("a credential is a file or an environment variable")
	case strings.TrimSpace(value) == "":
		err = errors.New("the credential needs a value")
	default:
		err = s.Store.SetCredential(r.Context(), p.ID, name, kind, []byte(value))
	}
	if err != nil {
		s.projectPage(w, r, p, p, role, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r.Context(), sess(r).user, p, "credential set", name+", as "+kind)
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	if err := s.Store.DeleteCredential(r.Context(), p.ID, r.PathValue("name")); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, p, "credential delete", r.PathValue("name"))
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

// setRole gives a user a role on the project, or takes it away when the
// role is blank.
func (s *Server) setRole(w http.ResponseWriter, r *http.Request) {
	p, role, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	userID, _ := strconv.ParseInt(r.PostFormValue("user"), 10, 64)
	u, err := s.Store.User(r.Context(), userID)
	if err != nil {
		s.projectPage(w, r, p, p, role, http.StatusBadRequest, "Pick a user.")
		return
	}
	newRole := r.PostFormValue("role")
	if err := s.Store.SetRole(r.Context(), p.ID, u.ID, newRole); err != nil {
		s.projectPage(w, r, p, p, role, http.StatusBadRequest, err.Error())
		return
	}
	if newRole == "" {
		newRole = "no role"
	}
	s.audit(r.Context(), sess(r).user, p, "role change", u.Name+": "+newRole)
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	runs, err := s.Store.Runs(r.Context(), p.ID)
	if err == nil {
		err = s.Store.DeleteProject(r.Context(), p.ID)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, rn := range runs {
		os.RemoveAll(path.Dir(s.Runner.PlanFile(rn.ID)))
	}
	s.audit(r.Context(), sess(r).user, p, "project delete", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) startPlan(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.allowed(w, r, id(r), store.RolePlanner)
	if !ok {
		return
	}
	runID, err := s.Runner.StartPlan(r.Context(), p, sess(r).user.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, p, "plan", fmt.Sprintf("run %d", runID))
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", runID), http.StatusSeeOther)
}

// startDrift runs a drift check now. It only looks: whatever the project's
// schedule mode, a check somebody starts never corrects or converges.
func (s *Server) startDrift(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.allowed(w, r, id(r), store.RolePlanner)
	if !ok {
		return
	}
	runID, err := s.Runner.StartDrift(r.Context(), p, sess(r).user.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, p, "drift check", fmt.Sprintf("run %d", runID))
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", runID), http.StatusSeeOther)
}

// mayApply says whether u, with role on p, may approve and apply plan. An
// approver applies a plan someone else made; a planner or approver may
// apply their own only when p allows it. An admin may apply any plan, so a
// project with one admin still works.
func mayApply(u store.User, role string, p store.Project, plan store.Run) bool {
	switch {
	case store.RoleAtLeast(role, store.RoleAdmin):
		return true
	case plan.CreatedBy.Valid && plan.CreatedBy.Int64 == u.ID:
		return p.SelfApply && store.RoleAtLeast(role, store.RolePlanner)
	default:
		return store.RoleAtLeast(role, store.RoleApprover)
	}
}

// cancelRole is the role that may cancel rn: an apply needs one that may
// apply, anything else one that may plan.
func cancelRole(rn store.Run) string {
	if rn.Kind == store.KindApply {
		return store.RoleApprover
	}
	return store.RolePlanner
}

// runData is the run page and its status partial.
type runData struct {
	Run     store.Run
	Project store.Project
	// Role is the user's role on Project.
	Role   string
	Lines  [][]byte
	Last   int64
	Result *run.Result
	// CanApply is true when the run is a plan this user may apply now.
	CanApply bool
	// CanCancel is true when the run is unfinished and this user may
	// cancel it.
	CanCancel bool
	// HasReport is true when the run is an apply that left a -report file.
	HasReport bool
	// Event is the body of the event that started the run, if one did.
	Event string
}

// runAllowed loads a run, its project and the user's role on it, as
// allowed does, answering 403 and returning false when the role is below
// a viewer.
func (s *Server) runAllowed(w http.ResponseWriter, r *http.Request) (store.Run, store.Project, string, bool) {
	rn, err := s.Store.Run(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return rn, store.Project{}, "", false
	}
	p, role, ok := s.allowed(w, r, rn.ProjectID, store.RoleViewer)
	return rn, p, role, ok
}

// loadRun loads the run page's data, answering the request itself and
// returning false when it can't.
func (s *Server) loadRun(w http.ResponseWriter, r *http.Request) (runData, bool) {
	var d runData
	var ok bool
	if d.Run, d.Project, d.Role, ok = s.runAllowed(w, r); !ok {
		return d, false
	}
	var err error
	if d.Lines, d.Last, err = s.Store.Events(r.Context(), d.Run.ID); err != nil {
		s.fail(w, err)
		return d, false
	}
	if d.Run.Finished() {
		res := run.Group(d.Lines)
		d.Result = &res
	}
	if _, err := os.Stat(s.Runner.ReportFile(d.Run.ID)); err == nil {
		d.HasReport = true
	}
	if d.Run.EventRule != "" {
		if d.Event, err = s.Store.EventBody(r.Context(), d.Run.ID); err != nil {
			s.fail(w, err)
			return d, false
		}
	}
	d.CanCancel = !d.Run.Finished() && store.RoleAtLeast(d.Role, cancelRole(d.Run))
	if d.Run.Kind == store.KindPlan && d.Run.Status == store.StatusSucceeded && d.Result.HasChanges() && mayApply(sess(r).user, d.Role, d.Project, d.Run) {
		if d.CanApply, err = s.Store.Applicable(r.Context(), d.Run.ID); err != nil {
			s.fail(w, err)
			return d, false
		}
	}
	return d, true
}

func (s *Server) startApply(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	if !mayApply(sess(r).user, d.Role, d.Project, d.Run) {
		why := fmt.Sprintf("Applying a plan someone else made needs the approver role on %s.", d.Project.Name)
		if d.Run.CreatedBy.Int64 == sess(r).user.ID {
			why = fmt.Sprintf("Someone else has to approve your plan: an approver on %s, or an admin. A project admin can let planners apply their own plans.", d.Project.Name)
		}
		s.forbid(w, r, why)
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
	s.audit(r.Context(), sess(r).user, d.Project, "apply", fmt.Sprintf("run %d, of plan %d", runID, d.Run.ID))
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", runID), http.StatusSeeOther)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	rn, p, role, ok := s.runAllowed(w, r)
	if !ok {
		return
	}
	if !store.RoleAtLeast(role, cancelRole(rn)) {
		s.forbid(w, r, fmt.Sprintf("Cancelling this %s needs the %s role on %s.", rn.Kind, cancelRole(rn), p.Name))
		return
	}
	err := s.Runner.Cancel(rn.ID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "this run isn't running", http.StatusConflict)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, p, "cancel", fmt.Sprintf("run %d", rn.ID))
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", rn.ID), http.StatusSeeOther)
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	s.render(w, r, "run", http.StatusOK, d, "")
}

// runReport serves an apply's -report file.
func (s *Server) runReport(w http.ResponseWriter, r *http.Request) {
	rn, _, _, ok := s.runAllowed(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="run-%d-report.json"`, rn.ID))
	http.ServeFile(w, r, s.Runner.ReportFile(rn.ID))
}

// historyPage is how many runs the history shows at a time.
const historyPage = 50

// history is every run across projects, newest first, filtered by
// project, host and status or drift check outcome.
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.Filter{Host: strings.TrimSpace(q.Get("host")), Status: q.Get("status")}
	f.ProjectID, _ = strconv.ParseInt(q.Get("project"), 10, 64)
	if u := sess(r).user; !u.Admin {
		f.UserID = u.ID
	}
	pg, _ := strconv.Atoi(q.Get("page"))
	pg = max(pg, 1)
	runs, err := s.Store.History(r.Context(), f, historyPage+1, (pg-1)*historyPage)
	if err != nil {
		s.fail(w, err)
		return
	}
	ps, err := s.visibleProjects(r)
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
		"Statuses": []string{store.StatusQueued, store.StatusRunning, store.StatusSucceeded, store.StatusFailed, store.StatusCancelled, store.OutcomeDrift, store.OutcomeClean}}
	if pg > 1 {
		d["Prev"] = link(pg - 1)
	}
	if more {
		d["Next"] = link(pg + 1)
	}
	s.render(w, r, "runs", http.StatusOK, d, "")
}

func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	s.execute(w, r, "run", "status", http.StatusOK, d, "")
}

// runEvents streams a run's lines as server-sent events, from the line
// after Last-Event-ID or ?after, and ends with a done event.
func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	rn, _, _, ok := s.runAllowed(w, r)
	if !ok {
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
