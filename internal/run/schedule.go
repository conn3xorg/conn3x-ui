// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// ParseSchedule reads a drift check schedule: an interval of a minute or
// more, such as 30m or 6h, or five cron fields, minute hour day month
// weekday, in UTC, such as "0 3 * * 1-5". A field is *, a number, a range
// like 1-5, a list of those, and any of them with a step like */15. It
// returns when the check is next due after a time.
func ParseSchedule(s string) (next func(time.Time) time.Time, err error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d < time.Minute {
			return nil, errors.New("a drift check schedule needs a minute or more between checks")
		}
		return func(t time.Time) time.Time { return t.Add(d) }, nil
	}
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return nil, fmt.Errorf("schedule %q isn't an interval such as 6h or five cron fields such as 0 3 * * *", s)
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	var sets [5]uint64
	for i, f := range fields {
		for _, part := range strings.Split(f, ",") {
			if sets[i], err = cronPart(sets[i], part, bounds[i][0], bounds[i][1]); err != nil {
				return nil, fmt.Errorf("schedule %q: %v", s, err)
			}
		}
	}
	if sets[4]&(1<<7) != 0 {
		sets[4] |= 1 // 7 is Sunday too
	}
	// As in cron, a day and a weekday both set match either one.
	either := !strings.HasPrefix(fields[2], "*") && !strings.HasPrefix(fields[4], "*")
	match := func(t time.Time) bool {
		day, wday := sets[2]&(1<<t.Day()) != 0, sets[4]&(1<<int(t.Weekday())) != 0
		return sets[0]&(1<<t.Minute()) != 0 && sets[1]&(1<<t.Hour()) != 0 && sets[3]&(1<<int(t.Month())) != 0 &&
			((either && (day || wday)) || (!either && day && wday))
	}
	next = func(after time.Time) time.Time {
		t := after.UTC().Truncate(time.Minute).Add(time.Minute)
		// shortcut: a minute at a time, fine for one schedule per project a
		// minute; skip ahead by day and hour if that ever shows up in a profile.
		for end := t.AddDate(5, 0, 0); t.Before(end); t = t.Add(time.Minute) {
			if match(t) {
				return t
			}
		}
		return time.Time{}
	}
	if next(time.Now()).IsZero() {
		return nil, fmt.Errorf("schedule %q never comes round", s)
	}
	return next, nil
}

// cronPart adds one comma-separated part of a cron field to set.
func cronPart(set uint64, part string, first, last int) (uint64, error) {
	rng, stepText, hasStep := strings.Cut(part, "/")
	lo, hi, step := first, last, 1
	var err error
	if rng != "*" {
		a, b, isRange := strings.Cut(rng, "-")
		if lo, err = strconv.Atoi(a); err != nil {
			return 0, fmt.Errorf("%q isn't a number", a)
		}
		switch {
		case isRange:
			if hi, err = strconv.Atoi(b); err != nil {
				return 0, fmt.Errorf("%q isn't a number", b)
			}
		case !hasStep:
			hi = lo
		}
	}
	if hasStep {
		if step, err = strconv.Atoi(stepText); err != nil || step < 1 {
			return 0, fmt.Errorf("step %q isn't a number above 0", stepText)
		}
	}
	if lo < first || hi > last || lo > hi {
		return 0, fmt.Errorf("%q is outside %d-%d", part, first, last)
	}
	for v := lo; v <= hi; v += step {
		set |= 1 << v
	}
	return set, nil
}

// Due says whether a project's drift check is due at now, given when its
// last one started, or when the project was last saved if it has none. A
// check missed while conn3x-ui was down is due once, not once a slot.
func Due(schedule string, last, now time.Time) (bool, error) {
	next, err := ParseSchedule(schedule)
	if err != nil {
		return false, err
	}
	return !next(last).After(now), nil
}

// Schedule queues each project's drift checks as they come due, checking
// once a minute and once at start, until ctx is done.
func (r *Runner) Schedule(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		r.Tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Tick queues a drift check of each project whose schedule is due at now
// and whose last check has finished.
func (r *Runner) Tick(ctx context.Context, now time.Time) {
	ps, err := r.Store.Projects(ctx)
	if err != nil {
		r.Log.Printf("schedule: %v", err)
		return
	}
	for _, p := range ps {
		if p.Schedule == "" {
			continue
		}
		since := p.UpdatedAt
		last, err := r.Store.LastRun(ctx, p.ID, store.KindDrift)
		if err == nil {
			if !last.Finished() {
				continue
			}
			since = last.CreatedAt
		} else if !errors.Is(err, store.ErrNotFound) {
			r.Log.Printf("schedule: project %d: %v", p.ID, err)
			continue
		}
		t, err := time.Parse(time.RFC3339, since)
		var due bool
		if err == nil {
			due, err = Due(p.Schedule, t, now)
		}
		if err != nil {
			r.Log.Printf("schedule: project %d: %v", p.ID, err)
			continue
		}
		if due && r.splay(p, now) {
			if _, err := r.StartDrift(ctx, p, 0); err != nil {
				r.Log.Printf("schedule: project %d: %v", p.ID, err)
			}
		}
	}
}

// splay says whether a due check of p should start at now. With a splay,
// the first time it's due picks a random delay up to that many minutes,
// fresh each time, so projects on the same schedule don't all start at
// once; the check starts once the delay has passed.
func (r *Runner) splay(p store.Project, now time.Time) bool {
	if p.SplayMinutes <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.splayed[p.ID]
	if !ok {
		at = now.Add(time.Duration(rand.Int64N(int64(p.SplayMinutes) * int64(time.Minute))))
		r.splayed[p.ID] = at
	}
	if now.Before(at) {
		return false
	}
	delete(r.splayed, p.ID)
	return true
}

// ValidateWebhookURL accepts an http or https URL with a host.
func ValidateWebhookURL(u string) error {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
		return errors.New("the webhook needs an http:// or https:// URL")
	}
	return nil
}

// Notification is the JSON a project's webhook gets when a drift check
// finds drift or fails. Link is the run's path on the UI. Text is a
// one-line summary, for chat webhooks that read a text field.
type Notification struct {
	Project string    `json:"project"`
	RunID   int64     `json:"run_id"`
	Status  string    `json:"status"`
	Outcome string    `json:"outcome"`
	Link    string    `json:"link"`
	Hosts   []string  `json:"hosts"`
	Time    time.Time `json:"time"`
	Text    string    `json:"text"`
	// URL is Link in full, when the UI was started with -public-url.
	URL string `json:"url,omitempty"`
}

var webhookClient = &http.Client{Timeout: 10 * time.Second}

// notify posts a finished drift check to p's webhook when it found drift
// or failed. A webhook that fails is logged, without its URL, and the run
// stands as it ended.
func (r *Runner) notify(id int64, p store.Project) {
	if p.WebhookURL == "" {
		return
	}
	bg := context.Background()
	rn, err := r.Store.Run(bg, id)
	if err != nil || (rn.Status != store.StatusFailed && rn.Outcome != store.OutcomeDrift) {
		return
	}
	lines, _, err := r.Store.Events(bg, id)
	if err != nil {
		r.Log.Printf("run %d: webhook: %v", id, err)
		return
	}
	n := Notification{Project: p.Name, RunID: id, Status: rn.Status, Outcome: rn.Outcome, Link: fmt.Sprintf("/runs/%d", id),
		Hosts: Group(lines).DriftedHosts(), Time: time.Now().UTC()}
	if n.Hosts == nil {
		n.Hosts = []string{}
	}
	if rn.Status == store.StatusFailed {
		n.Text = fmt.Sprintf("Conn3x: the drift check of %s failed (run %d)", p.Name, id)
	} else {
		n.Text = fmt.Sprintf("Conn3x: %s drifted on %s (run %d)", p.Name, strings.Join(n.Hosts, ", "), id)
	}
	r.withURL(&n)
	if err := postWebhook(p.WebhookURL, n); err != nil {
		r.Log.Printf("run %d: webhook: %v", id, err)
	}
}

// withURL fills in n's full link, and ends its text with it, when the UI
// knows its own address.
func (r *Runner) withURL(n *Notification) {
	if r.PublicURL == "" {
		return
	}
	n.URL = strings.TrimRight(r.PublicURL, "/") + n.Link
	n.Text += ": " + n.URL
}

// postWebhook posts n as JSON to u. Its error never holds u, which may
// carry a token.
func postWebhook(u string, n Notification) error {
	body, _ := json.Marshal(n)
	resp, err := webhookClient.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			return ue.Err
		}
		return errors.New("the request failed")
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the webhook answered %s", resp.Status)
	}
	return nil
}
