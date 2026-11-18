// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// api calls path with a bearer token and returns the status.
func api(t *testing.T, base, method, path, token string) int {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

var tokenRE = regexp.MustCompile(`c3ui_[A-Za-z0-9_-]{43}`)

// A token made on the account page reads the API as its user, shows once,
// can't write, and stops working when it's revoked or its user is
// disabled.
func TestAPITokens(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.login(t)
	csrf := e.csrf("/account")
	resp, err := e.PostForm(e.base+"/account/tokens", url.Values{"csrf": {csrf}, "name": {"inventory"}, "days": {"30"}})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %v %v", resp, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	tok := tokenRE.FindString(string(b))
	if tok == "" {
		t.Fatalf("no token shown:\n%s", b)
	}
	if _, page := e.get("/account"); strings.Contains(page, tok) {
		t.Error("the token shows again")
	}

	if code := api(t, e.base, "GET", "/api/v1/hosts", tok); code != http.StatusOK {
		t.Errorf("read with token: %d", code)
	}
	for name, c := range map[string]struct{ method, path, tok string }{
		"no token":    {"GET", "/api/v1/hosts", ""},
		"wrong token": {"GET", "/api/v1/hosts", "c3ui_" + strings.Repeat("A", 43)},
		"not a token": {"GET", "/api/v1/hosts", "something"},
		"a page":      {"GET", "/", tok},
	} {
		code := api(t, e.base, c.method, c.path, c.tok)
		if name == "a page" {
			if code != http.StatusSeeOther {
				t.Errorf("%s: %d, want a redirect to sign in", name, code)
			}
			continue
		}
		if code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, code)
		}
	}
	if code := api(t, e.base, "POST", "/api/v1/hosts", tok); code != http.StatusMethodNotAllowed {
		t.Errorf("write with token: %d, want 405", code)
	}

	for _, bad := range []url.Values{
		{"csrf": {csrf}, "name": {""}, "days": {"30"}},
		{"csrf": {csrf}, "name": {"x"}, "days": {"0"}},
		{"csrf": {csrf}, "name": {"x"}, "days": {"366"}},
		{"csrf": {csrf}, "name": {"inventory"}, "days": {"30"}},
	} {
		if resp := e.post("/account/tokens", bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: %d, want 400", bad, resp.StatusCode)
		}
	}

	toks, err := e.st.APITokens(ctx, 1)
	if err != nil || len(toks) != 1 || toks[0].LastUsedAt == "" {
		t.Fatalf("tokens %+v, %v", toks, err)
	}

	// A disabled user's token stops working, and works again when they're
	// enabled.
	uid, _ := e.st.CreateUser(ctx, "pat", "pw2")
	patTok, err := e.st.CreateAPIToken(ctx, uid, "x", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetUser(ctx, uid, false, true); err != nil {
		t.Fatal(err)
	}
	if code := api(t, e.base, "GET", "/api/v1/hosts", patTok); code != http.StatusUnauthorized {
		t.Errorf("disabled user's token: %d, want 401", code)
	}

	if resp := e.post("/account/tokens/"+strconv.FormatInt(toks[0].ID, 10)+"/delete", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("revoke: %d", resp.StatusCode)
	}
	if code := api(t, e.base, "GET", "/api/v1/hosts", tok); code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d, want 401", code)
	}
}
