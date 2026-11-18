// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// HostSummaries works out the OS and package count in SQL, and Host reads
// one host only; both keep to the projects a user can view.
func TestHostSummariesAndHost(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pid, _ := s.CreateProject(ctx, Project{Name: "web", GitURL: "https://e/w.git", GitRef: "main", Path: "."})
	other, _ := s.CreateProject(ctx, Project{Name: "other", GitURL: "https://e/o.git", GitRef: "main", Path: "."})
	run, _ := s.CreateRun(ctx, pid, KindDrift, 0)
	pkgs := map[string]any{}
	for i := range 1500 {
		pkgs[fmt.Sprintf("pkg%d", i)] = "1.0"
	}
	for i := range 500 {
		h := fmt.Sprintf("h%03d", i)
		must(t, s.SaveFacts(ctx, pid, h, "conn3x_host", map[string]any{"os_id": "rocky", "os_version": "10.0"}, run))
		must(t, s.SaveFacts(ctx, pid, h, "conn3x_packages", map[string]any{"packages": pkgs}, run))
	}
	must(t, s.SaveFacts(ctx, other, "secret1", "conn3x_host", map[string]any{"os_id": "debian"}, run))
	uid, _ := s.CreateUser(ctx, "pat", "pw")
	must(t, s.SetRole(ctx, pid, uid, RoleViewer))

	start := time.Now()
	sums, err := s.HostSummaries(ctx, uid)
	took := time.Since(start)
	if err != nil || len(sums) != 500 || sums[0] != (HostSummary{Host: "h000", Project: "web", OS: "rocky 10.0", Packages: 1500, At: sums[0].At}) {
		t.Fatalf("%d summaries, first %+v, %v", len(sums), sums[0], err)
	}
	start = time.Now()
	full, err := s.Hosts(ctx, uid, nil)
	tookFull := time.Since(start)
	if err != nil || len(full) != 500 {
		t.Fatal(err)
	}
	t.Logf("500 hosts x 1,500 packages: summaries %s, every host's facts %s", took, tookFull)

	one, err := s.Host(ctx, uid, "h042")
	if err != nil || len(one) != 1 || one[0].Host != "h042" || len(one[0].Facts["conn3x_packages"]["packages"].(map[string]any)) != 1500 {
		t.Fatalf("Host: %+v, %v", one, err)
	}
	if hidden, err := s.Host(ctx, uid, "secret1"); err != nil || len(hidden) != 0 {
		t.Errorf("a host from a project pat can't view: %+v, %v", hidden, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
