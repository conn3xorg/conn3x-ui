package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// hookPost sends body to a rule's hook with the given headers and returns
// the status and the JSON answer.
func hookPost(t *testing.T, base string, ruleID int64, body string, h map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/hooks/%d", base, ruleID), strings.NewReader(body))
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func signed(secret []byte, body, delivery string, at time.Time) map[string]string {
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "." + body))
	return map[string]string{"X-Conn3x-Timestamp": ts, "X-Conn3x-Delivery": delivery, "X-Conn3x-Signature": "sha256=" + hex.EncodeToString(mac.Sum(nil))}
}

// An event rule starts a drift check for a signed request or a matching
// alert, once per debounce, and refuses anything unsigned, stale, replayed
// or for another rule. The run says which rule started it and keeps the
// event.
func TestEventRules(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.st.SetKey(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	pid, err := e.st.CreateProject(ctx, store.Project{Name: "web", GitURL: repo, GitRef: "main", Path: ".", Conn3xPath: exe, Env: "CONN3X_FAKE=drift"})
	if err != nil {
		t.Fatal(err)
	}
	anyRule, secret, err := e.st.CreateEventRule(ctx, store.EventRule{ProjectID: pid, Name: "any", Mode: store.ModeReport, DebounceMinutes: 10})
	if err != nil {
		t.Fatal(err)
	}
	disk, diskSecret, err := e.st.CreateEventRule(ctx, store.EventRule{ProjectID: pid, Name: "disk", Alertname: "DiskFull", Labels: "severity=critical", Mode: store.ModeReport, DebounceMinutes: 10})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e.login(t)

	for name, h := range map[string]map[string]string{
		"unsigned":        nil,
		"wrong secret":    signed([]byte("nope"), "{}", "d0", now),
		"stale":           signed(secret, "{}", "d0", now.Add(-10*time.Minute)),
		"no delivery ID":  func() map[string]string { h := signed(secret, "{}", "", now); delete(h, "X-Conn3x-Delivery"); return h }(),
		"wrong bearer":    {"Authorization": "Bearer " + hex.EncodeToString(diskSecret)},
		"other rule's ID": signed(diskSecret, "{}", "d0", now),
	} {
		if code, _ := hookPost(t, e.base, anyRule.ID, "{}", h); code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, code)
		}
	}
	if code, _ := hookPost(t, e.base, 9999, "{}", signed(secret, "{}", "d0", now)); code != http.StatusUnauthorized {
		t.Errorf("unknown rule: %d, want 401", code)
	}

	code, out := hookPost(t, e.base, anyRule.ID, "{}", signed(secret, "{}", "d1", now))
	if code != http.StatusAccepted || out["result"] != "started" {
		t.Fatalf("signed: %d %v", code, out)
	}
	if code, _ := hookPost(t, e.base, anyRule.ID, "{}", signed(secret, "{}", "d1", now)); code != http.StatusConflict {
		t.Errorf("replay: %d, want 409", code)
	}
	if code, out := hookPost(t, e.base, anyRule.ID, "{}", signed(secret, "{}", "d2", now)); code != http.StatusAccepted || out["result"] != "folded" {
		t.Errorf("inside the debounce: %d %v", code, out)
	}
	e.runner.Wait()
	runID := int64(out["run"].(float64))
	rn, err := e.st.Run(ctx, runID)
	if err != nil || rn.Kind != store.KindDrift || rn.EventRule != "any" || rn.Status != store.StatusSucceeded || rn.CreatedBy.Valid {
		t.Fatalf("run %+v, %v", rn, err)
	}
	if _, page := e.get(fmt.Sprintf("/runs/%d", runID)); !strings.Contains(page, "started by event rule any") || !strings.Contains(page, "The event that started it") {
		t.Errorf("run page doesn't say what started it:\n%s", page)
	}

	bearer := map[string]string{"Authorization": "Bearer " + hex.EncodeToString(diskSecret)}
	alert := func(status, name, severity string) string {
		return fmt.Sprintf(`{"alerts":[{"status":%q,"labels":{"alertname":%q,"severity":%q,"instance":"web1"}}]}`, status, name, severity)
	}
	for _, body := range []string{alert("firing", "DiskFull", "warning"), alert("resolved", "DiskFull", "critical"), alert("firing", "CPU", "critical"), "not json"} {
		if code, out := hookPost(t, e.base, disk.ID, body, bearer); code != http.StatusAccepted || out["result"] != "no match" {
			t.Errorf("%s: %d %v, want no match", body, code, out)
		}
	}
	if code, out := hookPost(t, e.base, disk.ID, alert("firing", "DiskFull", "critical"), bearer); code != http.StatusAccepted || out["result"] != "started" {
		t.Errorf("matching alert: %d %v", code, out)
	}
	e.runner.Wait()

	if code, _ := hookPost(t, e.base, anyRule.ID, strings.Repeat("x", hookMaxBody+1), signed(secret, "", "d3", now)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d, want 413", code)
	}
}

// Only a site admin adds or deletes a rule, the secret shows once, and both
// go in the audit log.
func TestEventRuleForm(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.st.SetKey(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	e.login(t)
	exe, _ := os.Executable()
	path := e.createProject(t, "web", "https://example.com/r.git", ".", exe, "")
	csrf := e.csrf(path)
	form := url.Values{"csrf": {csrf}, "name": {"disk-full"}, "alertname": {"DiskFull"}, "labels": {"severity=critical"}, "mode": {"correct"}, "debounce": {"15"}}

	resp, err := e.PostForm(e.base+path+"/events", form)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %v %v", resp, err)
	}
	var page bytes.Buffer
	page.ReadFrom(resp.Body)
	resp.Body.Close()
	if !strings.Contains(page.String(), "won't be shown again") {
		t.Fatalf("no secret shown:\n%s", page.String())
	}
	if _, again := e.get(path); strings.Contains(again, "won't be shown again") {
		t.Error("the secret shows again")
	}
	for _, bad := range []url.Values{
		{"name": {"has space"}, "mode": {"report"}, "debounce": {"10"}},
		{"name": {"x"}, "labels": {"not a pair"}, "mode": {"report"}, "debounce": {"10"}},
		{"name": {"x"}, "mode": {"apply-everything"}, "debounce": {"10"}},
		{"name": {"x"}, "mode": {"report"}, "debounce": {"0"}},
		{"name": {"disk-full"}, "mode": {"report"}, "debounce": {"10"}},
	} {
		bad.Set("csrf", csrf)
		if resp := e.post(path+"/events", bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: %d, want 400", bad, resp.StatusCode)
		}
	}

	pid, _ := strconv.ParseInt(strings.TrimPrefix(path, "/projects/"), 10, 64)
	rules, err := e.st.EventRules(ctx, pid)
	if err != nil || len(rules) != 1 || rules[0].Mode != store.ModeCorrect || rules[0].DebounceMinutes != 15 {
		t.Fatalf("rules %+v, %v", rules, err)
	}

	// A project admin who isn't a site admin can't add one.
	uid, _ := e.st.CreateUser(ctx, "pat", "pw2")
	if err := e.st.SetRole(ctx, pid, uid, store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	pat := newClient(t, e.base)
	pat.loginAs(t, "pat", "pw2")
	patCSRF := pat.csrf(path)
	if resp := pat.post(path+"/events", url.Values{"csrf": {patCSRF}, "name": {"mine"}, "mode": {"converge"}, "debounce": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("project admin: %d, want 403", resp.StatusCode)
	}
	if resp := pat.post(fmt.Sprintf("%s/events/%d/delete", path, rules[0].ID), url.Values{"csrf": {patCSRF}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("project admin delete: %d, want 403", resp.StatusCode)
	}

	if resp := e.post(fmt.Sprintf("%s/events/%d/delete", path, rules[0].ID), url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	log, err := e.st.AuditLog(ctx, store.AuditFilter{}, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, a := range log {
		actions = append(actions, a.Action)
	}
	if !strings.Contains(strings.Join(actions, ","), "event rule create") || !strings.Contains(strings.Join(actions, ","), "event rule delete") {
		t.Errorf("audit %v", actions)
	}
}

// A rule that corrects drift plans and applies as the schedule would, and
// the plan and the apply say which rule started them.
func TestEventRuleCorrects(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.st.SetKey(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	repo, _ := gitServer(t, map[string]string{"main.tf": "# circuits\n"})
	pid, err := e.st.CreateProject(ctx, store.Project{Name: "fix", GitURL: repo, GitRef: "main", Path: ".", Conn3xPath: exe, Env: "CONN3X_FAKE=driftfix"})
	if err != nil {
		t.Fatal(err)
	}
	rule, secret, err := e.st.CreateEventRule(ctx, store.EventRule{ProjectID: pid, Name: "fixer", Mode: store.ModeCorrect, DebounceMinutes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if code, out := hookPost(t, e.base, rule.ID, "{}", map[string]string{"Authorization": "Bearer " + hex.EncodeToString(secret)}); code != http.StatusAccepted || out["result"] != "started" {
		t.Fatalf("%d %v", code, out)
	}
	e.runner.Wait()
	for _, kind := range []string{store.KindPlan, store.KindApply} {
		rn, err := e.st.LastRun(ctx, pid, kind)
		if err != nil || rn.EventRule != "fixer" || rn.Status != store.StatusSucceeded {
			t.Errorf("%s: %+v, %v", kind, rn, err)
		}
	}
}
