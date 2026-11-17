// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// The fleet store's read-only API, for the questions PuppetDB answers:
// which hosts have a fact, what changed on a host, which steps failed. It
// takes the same sign-in as the pages, and shows only the projects the
// person can view.

// apiLimit is the most step results one request returns.
const apiLimit = 1000

func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func apiJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// viewer is who the fleet store answers for: 0 for a site admin, who sees
// every project.
func viewer(r *http.Request) int64 {
	if u := sess(r).user; !u.Admin {
		return u.ID
	}
	return 0
}

// apiHosts lists hosts with their latest facts. Each fact=name:value must
// match, as os_id:rocky, or packages:openssl for a host that has it.
func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	var match []store.FactMatch
	for _, f := range r.URL.Query()["fact"] {
		name, value, ok := strings.Cut(f, ":")
		if !ok || name == "" {
			apiError(w, http.StatusBadRequest, "fact is name:value, such as os_id:rocky")
			return
		}
		match = append(match, store.FactMatch{Name: name, Value: value})
	}
	hosts, err := s.Store.Hosts(r.Context(), viewer(r), match)
	if err != nil {
		s.Log.Printf("api: %v", err)
		apiError(w, http.StatusInternalServerError, "the fleet store couldn't be read")
		return
	}
	apiJSON(w, map[string]any{"hosts": hosts})
}

// apiHostChanges lists what was applied to a host, and what drifted there,
// since a time or date, newest first.
func (s *Server) apiHostChanges(w http.ResponseWriter, r *http.Request) {
	s.apiResults(w, r, store.ResultFilter{Host: r.PathValue("host"), Since: r.URL.Query().Get("since")})
}

// apiSteps lists step results by circuit, host, outcome, kind and time.
func (s *Server) apiSteps(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.apiResults(w, r, store.ResultFilter{Host: q.Get("host"), Circuit: q.Get("circuit"), Outcome: q.Get("outcome"), Kind: q.Get("kind"), Since: q.Get("since")})
}

func (s *Server) apiResults(w http.ResponseWriter, r *http.Request, f store.ResultFilter) {
	results, err := s.Store.StepResults(r.Context(), viewer(r), f, apiLimit)
	if err != nil {
		s.Log.Printf("api: %v", err)
		apiError(w, http.StatusInternalServerError, "the fleet store couldn't be read")
		return
	}
	apiJSON(w, map[string]any{"results": results, "truncated": len(results) == apiLimit})
}
