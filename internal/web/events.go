package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// hookWindow is how far a signed request's timestamp may be from now.
const hookWindow = 5 * time.Minute

// hookMaxBody is the largest event a hook reads.
const hookMaxBody = 1 << 20

var (
	// deliveryID has no dot, the signature's separator, so text can't move
	// between the ID and the body and keep the same signature.
	deliveryID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	ruleName   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	labelName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	varName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	// hostName is one host, with no glob or list, so an alert can't widen
	// the run past the host it names.
	hostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
)

// ruleForm reads an event rule from the form, or says what's wrong with it.
func ruleForm(r *http.Request, projectID int64) (store.EventRule, error) {
	e := store.EventRule{
		ProjectID: projectID,
		Name:      strings.TrimSpace(r.PostFormValue("name")),
		Alertname: strings.TrimSpace(r.PostFormValue("alertname")),
		Labels:    strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("labels"), "\r\n", "\n")),
		Mode:      r.PostFormValue("mode"),
	}
	if !ruleName.MatchString(e.Name) {
		return e, errors.New("an event rule's name is 1 to 64 letters, digits, - and _")
	}
	if len(e.Alertname) > 200 {
		return e, errors.New("the alertname is longer than 200 characters")
	}
	for _, l := range strings.Split(e.Labels, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		k, _, ok := strings.Cut(l, "=")
		if !ok || !labelName.MatchString(strings.TrimSpace(k)) {
			return e, fmt.Errorf("%q isn't LABEL=VALUE with a Prometheus label name", l)
		}
	}
	e.LimitLabel = strings.TrimSpace(r.PostFormValue("limit_label"))
	if e.LimitLabel != "" && !labelName.MatchString(e.LimitLabel) {
		return e, fmt.Errorf("%q isn't a Prometheus label name", e.LimitLabel)
	}
	e.Vars = strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("vars"), "\r\n", "\n"))
	for _, l := range strings.Split(e.Vars, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		v, label, ok := strings.Cut(l, "=")
		if !ok || !varName.MatchString(strings.TrimSpace(v)) || !labelName.MatchString(strings.TrimSpace(label)) {
			return e, fmt.Errorf("%q isn't VARIABLE=LABEL", l)
		}
	}
	if (e.LimitLabel != "" || e.Vars != "") && e.Alertname == "" && e.Labels == "" {
		return e, errors.New("a rule that takes the host or variables from an alert needs an alertname or labels to match")
	}
	switch e.Mode {
	case store.ModeReport, store.ModeCorrect, store.ModeConverge:
	default:
		return e, errors.New("pick what a run the rule starts does about drift")
	}
	d, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("debounce")))
	if err != nil || d < 1 || d > 1440 {
		return e, errors.New("the debounce is 1 to 1440 minutes")
	}
	e.DebounceMinutes = d
	return e, nil
}

// createEventRule adds a rule to a project and shows its secret, once.
// A rule starts runs with nobody watching, so only a site admin makes one.
func (s *Server) createEventRule(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	p, role, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	e, err := ruleForm(r, p.ID)
	var secret []byte
	if err == nil {
		e, secret, err = s.Store.CreateEventRule(r.Context(), e)
	}
	if err != nil {
		s.projectPage(w, r, p, p, role, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r.Context(), sess(r).user, p, "event rule create", fmt.Sprintf("%s, mode %s, debounce %d minutes", e.Name, e.Mode, e.DebounceMinutes))
	s.projectPageWith(w, r, p, p, role, http.StatusOK, "", map[string]any{"NewRule": map[string]any{
		"Rule": e, "Secret": hex.EncodeToString(secret), "Path": fmt.Sprintf("/hooks/%d", e.ID),
	}})
}

// deleteEventRule removes a project's rule.
func (s *Server) deleteEventRule(w http.ResponseWriter, r *http.Request) {
	if !s.siteAdmin(w, r) {
		return
	}
	p, _, ok := s.allowed(w, r, id(r), store.RoleAdmin)
	if !ok {
		return
	}
	ruleID, _ := strconv.ParseInt(r.PathValue("rule"), 10, 64)
	name, err := s.Store.DeleteEventRule(r.Context(), p.ID, ruleID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), sess(r).user, p, "event rule delete", name)
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", p.ID), http.StatusSeeOther)
}

// hookAuthorized says whether a request carries the rule's secret: a
// bearer token, as Alertmanager sends, or an HMAC-SHA256 signature over
// the timestamp, the delivery ID and the body, as a webhook sender can.
// The ID is signed so a captured request can't be sent again under a new
// one.
func hookAuthorized(r *http.Request, body, secret []byte, now time.Time) (signed bool, ok bool) {
	want := hex.EncodeToString(secret)
	if tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found {
		return false, hmac.Equal([]byte(strings.TrimSpace(tok)), []byte(want))
	}
	sig, found := strings.CutPrefix(r.Header.Get("X-Conn3x-Signature"), "sha256=")
	ts := r.Header.Get("X-Conn3x-Timestamp")
	if !found || ts == "" || !deliveryID.MatchString(r.Header.Get("X-Conn3x-Delivery")) {
		return true, false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return true, false
	}
	if d := now.Sub(time.Unix(sec, 0)); d > hookWindow || d < -hookWindow {
		return true, false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "." + r.Header.Get("X-Conn3x-Delivery") + "."))
	mac.Write(body)
	return true, hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil))))
}

// alertmanager is the part of Alertmanager's webhook payload a rule reads.
type alertmanager struct {
	Alerts []struct {
		Status string            `json:"status"`
		Labels map[string]string `json:"labels"`
	} `json:"alerts"`
}

// matchingAlerts returns the labels of each firing alert in an
// Alertmanager payload that has the rule's alertname and labels, and says
// whether the event is one the rule runs for: with no alertname or labels,
// any event, with no alerts to read.
func matchingAlerts(e store.EventRule, body []byte) ([]map[string]string, bool) {
	pairs := e.LabelPairs()
	if e.Alertname == "" && len(pairs) == 0 {
		return nil, true
	}
	var am alertmanager
	if json.Unmarshal(body, &am) != nil {
		return nil, false
	}
	var out []map[string]string
	for _, a := range am.Alerts {
		if a.Status != "firing" || (e.Alertname != "" && a.Labels["alertname"] != e.Alertname) {
			continue
		}
		all := true
		for _, kv := range pairs {
			if a.Labels[kv[0]] != kv[1] {
				all = false
				break
			}
		}
		if all {
			out = append(out, a.Labels)
		}
	}
	return out, len(out) > 0
}

// eventInput is what a run takes from the alerts that matched: the hosts
// in the rule's limit label, joined for -limit as "=" terms, so each is
// that host by its exact name and never a group, and its variables. Each
// limit value is one host name, a port after it dropped, and the alerts
// must agree on each variable. It says why when they don't.
func eventInput(e store.EventRule, alerts []map[string]string) (store.EventInput, string) {
	var in store.EventInput
	if e.LimitLabel != "" {
		seen := map[string]bool{}
		var hosts []string
		for _, a := range alerts {
			h := a[e.LimitLabel]
			if i := strings.LastIndex(h, ":"); i > 0 {
				if _, err := strconv.Atoi(h[i+1:]); err == nil {
					h = h[:i]
				}
			}
			// "all" is every host to -limit.
			if !hostName.MatchString(h) || strings.EqualFold(h, "all") {
				return in, fmt.Sprintf("label %s is %q, which isn't one host name", e.LimitLabel, a[e.LimitLabel])
			}
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, "="+h)
			}
		}
		in.Limit = strings.Join(hosts, ",")
	}
	for _, kv := range e.VarPairs() {
		v := alerts[0][kv[1]]
		for _, a := range alerts[1:] {
			if a[kv[1]] != v {
				return in, fmt.Sprintf("the alerts disagree on label %s, which sets %s", kv[1], kv[0])
			}
		}
		if v == "" || len(v) > 1024 || strings.ContainsFunc(v, unicode.IsControl) {
			return in, fmt.Sprintf("label %s, which sets %s, is empty, longer than 1024 characters or has a control character", kv[1], kv[0])
		}
		in.Env = append(in.Env, "TF_VAR_"+kv[0]+"="+v)
	}
	return in, ""
}

// hookReply writes a hook's JSON answer.
func hookReply(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// hook takes an event for a rule and starts a drift check when it's
// signed, new, matches and isn't inside the rule's debounce. It needs no
// session: the rule's secret is the sign-in.
func (s *Server) hook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hookMaxBody))
	if err != nil {
		hookReply(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "the event is over 1 MiB"})
		return
	}
	ruleID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rule, secret, err := s.Store.EventRule(r.Context(), ruleID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.Log.Printf("hook %d: %v", ruleID, err)
	}
	signed, ok := false, false
	if err == nil {
		signed, ok = hookAuthorized(r, body, secret, time.Now())
		clear(secret)
	}
	// An unknown rule and a wrong secret look the same from outside.
	if !ok {
		hookReply(w, http.StatusUnauthorized, map[string]any{"error": "not signed with this rule's secret, or the timestamp is more than 5 minutes off"})
		return
	}
	if signed {
		fresh, err := s.Store.SeeDelivery(r.Context(), rule.ID, r.Header.Get("X-Conn3x-Delivery"))
		if err != nil {
			s.fail(w, err)
			return
		}
		if !fresh {
			hookReply(w, http.StatusConflict, map[string]any{"error": "this delivery ID has been seen already"})
			return
		}
	}
	alerts, matched := matchingAlerts(rule, body)
	if !matched {
		hookReply(w, http.StatusAccepted, map[string]any{"result": "no match"})
		return
	}
	in, why := eventInput(rule, alerts)
	if why != "" {
		hookReply(w, http.StatusUnprocessableEntity, map[string]any{"error": why})
		return
	}
	started, err := s.Store.ClaimEventRun(r.Context(), rule.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !started {
		hookReply(w, http.StatusAccepted, map[string]any{"result": "folded", "detail": fmt.Sprintf("this rule started a run less than %d minutes ago", rule.DebounceMinutes)})
		return
	}
	p, err := s.Store.Project(r.Context(), rule.ProjectID)
	if err != nil {
		s.fail(w, err)
		return
	}
	runID, err := s.Runner.StartEvent(r.Context(), p, rule, string(body), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	detail := fmt.Sprintf("drift check %d, mode %s", runID, rule.Mode)
	if in.Limit != "" {
		detail += ", limited to " + in.Limit
	}
	s.audit(r.Context(), store.User{Name: "event rule " + rule.Name}, p, "event run", detail)
	hookReply(w, http.StatusAccepted, map[string]any{"result": "started", "run": runID})
}
