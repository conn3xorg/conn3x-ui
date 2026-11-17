// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"cmp"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

var userName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// minPassword is the shortest password a person may set.
const minPassword = 12

// newPassword is the form's password, or a generated one when it's blank.
// generated says which, so the page shows a generated one, once.
func newPassword(r *http.Request) (password string, generated bool, err error) {
	if password = r.PostFormValue("password"); password == "" {
		return store.Token(12), true, nil
	}
	if len(password) < minPassword {
		return "", false, fmt.Errorf("a password needs at least %d characters; leave it blank for a generated one", minPassword)
	}
	return password, false, nil
}

// usersPage renders the users page. shown is a generated password to show
// once, with the name it's for.
func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, status int, shown map[string]string, errMsg string) {
	us, err := s.Store.Users(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if shown != nil {
		w.Header().Set("Cache-Control", "no-store")
	}
	s.render(w, r, "users", status, map[string]any{"Users": us, "Shown": shown}, errMsg)
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if s.siteAdmin(w, r) {
		s.usersPage(w, r, http.StatusOK, nil, "")
	}
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	admin := r.PostFormValue("admin") != ""
	password, generated, err := newPassword(r)
	var id int64
	switch {
	case !userName.MatchString(name):
		err = errors.New("a user name is up to 64 letters, digits and . _ @ -")
	case err != nil:
	default:
		if id, err = s.Store.CreateUser(r.Context(), name, password); err == nil && admin {
			err = s.Store.SetUser(r.Context(), id, true, false)
		}
		if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
			err = errors.New("A user with that name already exists.")
		}
	}
	if err != nil {
		s.usersPage(w, r, http.StatusBadRequest, nil, err.Error())
		return
	}
	detail := name
	if admin {
		detail += ", site admin"
	}
	s.audit(r.Context(), sess(r).user, store.Project{}, "user create", detail)
	if generated {
		s.usersPage(w, r, http.StatusOK, map[string]string{"Name": name, "Password": password}, "")
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// updateUser makes a user a site admin or not, and disabled or not. Nobody
// does either to themselves, so the last admin can't lock everyone out.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	u, err := s.Store.User(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	admin, disabled := r.PostFormValue("admin") != "", r.PostFormValue("disabled") != ""
	if u.ID == sess(r).user.ID && (!admin || disabled) {
		s.usersPage(w, r, http.StatusBadRequest, nil, "You can't take away your own admin or disable yourself. Another admin can.")
		return
	}
	if err := s.Store.SetUser(r.Context(), u.ID, admin, disabled); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, store.Project{}, "user change", fmt.Sprintf("%s: site admin %s, disabled %s", u.Name, yesNo(admin), yesNo(disabled)))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// resetPassword sets another user's password and ends their sessions.
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	u, err := s.Store.User(r.Context(), id(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	password, generated, err := newPassword(r)
	if err != nil {
		s.usersPage(w, r, http.StatusBadRequest, nil, err.Error())
		return
	}
	if err := s.Store.SetPassword(r.Context(), u.ID, password, sess(r).token); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, store.Project{}, "password reset", u.Name)
	if generated {
		s.usersPage(w, r, http.StatusOK, map[string]string{"Name": u.Name, "Password": password}, "")
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "account", http.StatusOK, nil, "")
}

// changePassword sets the user's own password, given the one they have,
// and ends their other sessions.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	u := sess(r).user
	err := s.Store.CheckPassword(r.Context(), u.ID, r.PostFormValue("current"))
	if errors.Is(err, store.ErrNotFound) {
		err = errors.New("That isn't your current password.")
	} else if err == nil && len(r.PostFormValue("password")) < minPassword {
		err = fmt.Errorf("a password needs at least %d characters", minPassword)
	} else if err == nil {
		err = s.Store.SetPassword(r.Context(), u.ID, r.PostFormValue("password"), sess(r).token)
	}
	if err != nil {
		s.render(w, r, "account", http.StatusBadRequest, nil, err.Error())
		return
	}
	s.audit(r.Context(), u, store.Project{}, "password change", "")
	s.render(w, r, "account", http.StatusOK, "Your password is changed. Your other sessions are signed out.", "")
}

// auditExport writes every audit entry that matches the page's filters,
// oldest first, as JSON lines or CSV, for a SIEM or an auditor. after=ID
// starts past the last entry an earlier export got. The export is itself
// an audit entry.
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	var f store.AuditFilter
	f.UserID, _ = strconv.ParseInt(q.Get("user"), 10, 64)
	f.ProjectID, _ = strconv.ParseInt(q.Get("project"), 10, 64)
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	format := cmp.Or(q.Get("format"), "jsonl")
	if format != "jsonl" && format != "csv" {
		http.Error(w, "format is jsonl or csv", http.StatusBadRequest)
		return
	}
	s.audit(r.Context(), sess(r).user, store.Project{}, "audit export", fmt.Sprintf("%s, user %d, project %d, after %d", format, f.UserID, f.ProjectID, after))
	name := "conn3x-ui-audit." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	var write func(store.Entry) error
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		defer cw.Flush()
		cw.Write([]string{"id", "at", "user_id", "user", "project_id", "project", "action", "detail"})
		write = func(e store.Entry) error {
			return cw.Write([]string{strconv.FormatInt(e.ID, 10), e.At, strconv.FormatInt(e.UserID, 10), cell(e.UserName),
				strconv.FormatInt(e.ProjectID, 10), cell(e.ProjectName), cell(e.Action), cell(e.Detail)})
		}
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		write = func(e store.Entry) error {
			return enc.Encode(map[string]any{"id": e.ID, "at": e.At, "user_id": e.UserID, "user": e.UserName,
				"project_id": e.ProjectID, "project": e.ProjectName, "action": e.Action, "detail": e.Detail})
		}
	}
	if err := s.Store.AuditEach(r.Context(), f, after, write); err != nil {
		s.Log.Printf("audit export: %v", err)
	}
}

// cell keeps text a spreadsheet would run as a formula from being one:
// names and details come from users.
func cell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// auditPage is the audit log, newest first, filtered by user and project,
// for site admins.
func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	var f store.AuditFilter
	f.UserID, _ = strconv.ParseInt(q.Get("user"), 10, 64)
	f.ProjectID, _ = strconv.ParseInt(q.Get("project"), 10, 64)
	pg, _ := strconv.Atoi(q.Get("page"))
	pg = max(pg, 1)
	entries, err := s.Store.AuditLog(r.Context(), f, historyPage+1, (pg-1)*historyPage)
	if err != nil {
		s.fail(w, err)
		return
	}
	us, err := s.Store.Users(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	ps, err := s.Store.Projects(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	more := len(entries) > historyPage
	if more {
		entries = entries[:historyPage]
	}
	// The other pages keep the filters.
	link := func(n int) string {
		v := url.Values{}
		for _, k := range []string{"user", "project"} {
			if q.Get(k) != "" {
				v.Set(k, q.Get(k))
			}
		}
		v.Set("page", strconv.Itoa(n))
		return "/audit?" + v.Encode()
	}
	d := map[string]any{"Entries": entries, "Users": us, "Projects": ps, "Filter": f}
	if pg > 1 {
		d["Prev"] = link(pg - 1)
	}
	if more {
		d["Next"] = link(pg + 1)
	}
	s.render(w, r, "audit", http.StatusOK, d, "")
}
