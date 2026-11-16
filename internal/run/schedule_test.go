// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseSchedule(t *testing.T) {
	from := at("2026-11-13T10:07:30Z") // a Friday
	for sched, want := range map[string]string{
		"6h":             "2026-11-13T16:07:30Z",
		"30m":            "2026-11-13T10:37:30Z",
		"* * * * *":      "2026-11-13T10:08:00Z",
		"0 3 * * *":      "2026-11-14T03:00:00Z",
		"*/15 * * * *":   "2026-11-13T10:15:00Z",
		"5/20 10 * * *":  "2026-11-13T10:25:00Z",
		"0 9 * * 1-5":    "2026-11-16T09:00:00Z",
		"0 9 * * 7":      "2026-11-15T09:00:00Z",
		"0 0 1 1,6 *":    "2027-01-01T00:00:00Z",
		"0 0 1 * 1":      "2026-11-16T00:00:00Z", // day or weekday, as cron does
		"0  12 *  * 0,6": "2026-11-14T12:00:00Z",
	} {
		next, err := ParseSchedule(sched)
		if err != nil {
			t.Errorf("%q: %v", sched, err)
			continue
		}
		if got := next(from).Format(time.RFC3339); got != want {
			t.Errorf("%q: next %s, want %s", sched, got, want)
		}
	}
	for _, bad := range []string{"", "10s", "daily", "* * * *", "60 * * * *", "* 24 * * *", "0 0 0 * *", "*/0 * * * *", "5-1 * * * *", "x * * * *", "0 0 30 2 *"} {
		if _, err := ParseSchedule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDue(t *testing.T) {
	for _, c := range []struct {
		sched, last, now string
		want             bool
	}{
		{"1h", "2026-11-13T10:00:00Z", "2026-11-13T10:59:00Z", false},
		{"1h", "2026-11-13T10:00:00Z", "2026-11-13T11:00:00Z", true},
		// Down for a day: due once at start, and the check that runs then
		// moves the next one an hour on, not back to the missed slots.
		{"1h", "2026-11-12T10:00:00Z", "2026-11-13T10:00:30Z", true},
		{"1h", "2026-11-13T10:00:30Z", "2026-11-13T10:01:00Z", false},
		{"0 3 * * *", "2026-11-13T03:00:10Z", "2026-11-13T23:59:00Z", false},
		{"0 3 * * *", "2026-11-13T03:00:10Z", "2026-11-14T03:00:00Z", true},
	} {
		if got, err := Due(c.sched, at(c.last), at(c.now)); err != nil || got != c.want {
			t.Errorf("%+v: %v %v", c, got, err)
		}
	}
}

func TestPostWebhook(t *testing.T) {
	var got Notification
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		if r.URL.Path == "/fail" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	n := Notification{Project: "web", RunID: 3, Status: "succeeded", Outcome: "drift", Link: "/runs/3", Hosts: []string{"web1"}, Time: at("2026-11-13T10:00:00Z")}
	if err := postWebhook(srv.URL+"/hook", n); err != nil {
		t.Fatal(err)
	}
	if ct != "application/json" || got.RunID != 3 || got.Hosts[0] != "web1" || !got.Time.Equal(n.Time) {
		t.Errorf("%s %+v", ct, got)
	}
	if err := postWebhook(srv.URL+"/fail", n); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("500: %v", err)
	}
	// The error never carries the URL, which may hold a token.
	srv.Close()
	if err := postWebhook(srv.URL+"/T000/SECRET", n); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("closed server: %v", err)
	}
}

func TestValidateWebhookURL(t *testing.T) {
	for u, ok := range map[string]bool{"https://hooks.example.com/x": true, "http://10.0.0.5:8080/ntfy": true, "ftp://x/y": false, "https://": false, "hooks.example.com": false, "file:///etc/passwd": false} {
		if err := ValidateWebhookURL(u); (err == nil) != ok {
			t.Errorf("%q: %v", u, err)
		}
	}
}
