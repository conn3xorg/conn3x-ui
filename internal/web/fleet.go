// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// The fleet store's pages: the same questions as /api/v1/, for people.

// hostRow is one host on the hosts page, across the projects that know it.
type hostRow struct {
	Host     string
	Projects []string
	OS       string
	Packages int
	At       string
}

// parseFacts reads "os_id:rocky packages:openssl" into matches, or says
// which word isn't name:value.
func parseFacts(q string) ([]store.FactMatch, string) {
	var match []store.FactMatch
	for _, f := range strings.Fields(q) {
		name, value, ok := strings.Cut(f, ":")
		if !ok || name == "" {
			return nil, fmt.Sprintf("%q isn't name:value, such as os_id:rocky", f)
		}
		match = append(match, store.FactMatch{Name: name, Value: value})
	}
	return match, ""
}

func (s *Server) hostsPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("facts"))
	match, bad := parseFacts(q)
	d := map[string]any{"Facts": q}
	if bad != "" {
		s.render(w, r, "hosts", http.StatusBadRequest, d, bad)
		return
	}
	hosts, err := s.Store.Hosts(r.Context(), viewer(r), match)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows := map[string]*hostRow{}
	for _, h := range hosts {
		row := rows[h.Host]
		if row == nil {
			row = &hostRow{Host: h.Host}
			rows[h.Host] = row
		}
		row.Projects = append(row.Projects, h.Project)
		if facts := h.Facts["conn3x_host"]; facts != nil && row.OS == "" {
			row.OS = strings.TrimSpace(fmt.Sprint(facts["os_id"]) + " " + fmt.Sprint(facts["os_version"]))
		}
		if pkgs, ok := h.Facts["conn3x_packages"]["packages"].(map[string]any); ok && len(pkgs) > row.Packages {
			row.Packages = len(pkgs)
		}
		if h.At > row.At {
			row.At = h.At
		}
	}
	list := make([]*hostRow, 0, len(rows))
	for _, row := range rows {
		list = append(list, row)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Host < list[j].Host })
	d["Hosts"] = list
	s.render(w, r, "hosts", http.StatusOK, d, "")
}

// hostFacts is one project's facts about a host, each source as indented
// JSON for the page.
type hostFacts struct {
	Project string
	At      string
	Sources map[string]string
}

func (s *Server) hostPage(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	hosts, err := s.Store.Hosts(r.Context(), viewer(r), nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	var facts []hostFacts
	for _, h := range hosts {
		if h.Host != host {
			continue
		}
		hf := hostFacts{Project: h.Project, At: h.At, Sources: map[string]string{}}
		for source, f := range h.Facts {
			b, _ := json.MarshalIndent(f, "", "  ")
			hf.Sources[source] = string(b)
		}
		facts = append(facts, hf)
	}
	results, err := s.Store.StepResults(r.Context(), viewer(r), store.ResultFilter{Host: host}, hostResults)
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(facts) == 0 && len(results) == 0 {
		s.render(w, r, "host", http.StatusNotFound, map[string]any{"Host": host}, "No project you can view knows a host called "+host+".")
		return
	}
	s.render(w, r, "host", http.StatusOK, map[string]any{"Host": host, "Facts": facts, "Results": results, "Truncated": len(results) == hostResults}, "")
}

// hostResults is how many step results a host's page shows.
const hostResults = 200
