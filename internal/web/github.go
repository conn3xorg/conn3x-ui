// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// GitHub signs people in with a GitHub OAuth app, github.com or GitHub
// Enterprise Server, and lets in only active members of one organisation:
// anyone can have a GitHub account. Its teams work as OIDC groups do:
// AdminTeam's members are site admins, and TeamRoles give roles on
// projects, checked at each sign-in.
type GitHub struct {
	// URL is GitHub's web address, https://github.com or a GitHub
	// Enterprise Server's. It's what users are linked to, as an OIDC
	// issuer is, with their numeric GitHub ID as the subject, so a login
	// renamed or reused can't take over an account.
	URL string
	// API is the REST API's address: https://api.github.com, or URL's
	// /api/v3 on GitHub Enterprise Server.
	API       string
	Org       string
	AdminTeam string
	TeamRoles []GroupRole
	oauth     oauth2.Config
	client    *http.Client
	key       []byte // signs the sign-in cookie; see OIDC.key
}

// NewGitHub sets up sign-in with the OAuth app clientID at base, for org's
// members. read:org lets it read their membership and teams.
func NewGitHub(base, clientID, clientSecret, redirectURL, org string) (*GitHub, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("-github-url %q isn't an https:// address", base)
	}
	if org == "" {
		return nil, errors.New("GitHub sign-in needs -github-org: without it, anyone with a GitHub account could sign in")
	}
	g := &GitHub{URL: u.String(), Org: org, client: &http.Client{Timeout: 10 * time.Second}, key: []byte(store.Token(32))}
	g.API = g.URL + "/api/v3"
	if u.Host == "github.com" {
		g.API = "https://api.github.com"
	}
	g.oauth = oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		Endpoint: oauth2.Endpoint{AuthURL: g.URL + "/login/oauth/authorize", TokenURL: g.URL + "/login/oauth/access_token"},
		Scopes:   []string{"read:org"},
	}
	return g, nil
}

// githubStart sends the browser to GitHub, with the state in a signed
// cookie only this UI reads back.
func (s *Server) githubStart(w http.ResponseWriter, r *http.Request) {
	if s.GitHub == nil {
		http.NotFound(w, r)
		return
	}
	state := store.Token(16)
	setCookie(w, r, "github", seal(s.GitHub.key, state), flowTTL)
	http.Redirect(w, r, s.GitHub.oauth.AuthCodeURL(state), http.StatusFound)
}

// githubCallback is where GitHub sends the browser back. No token is
// logged or kept: it's used for this sign-in's three reads and dropped.
func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	if s.GitHub == nil {
		http.NotFound(w, r)
		return
	}
	g, q := s.GitHub, r.URL.Query()
	setCookie(w, r, "github", "", -1)
	u, err := s.githubUser(r, g, q.Get("code"), q.Get("state"), q.Get("error"))
	if err != nil {
		s.audit(r.Context(), u, store.Project{}, "sign-in failed", "GitHub: "+err.Error())
		s.loginForm(w, r, http.StatusUnauthorized, "GitHub sign-in didn't work. Try again; if it keeps failing, a site admin can read why in the audit log.")
		return
	}
	tok, _, err := s.Store.OpenSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), u, store.Project{}, "sign-in", "GitHub, "+g.URL)
	setCookie(w, r, "session", tok, sessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// githubUser runs the callback's checks and returns the user to sign in,
// as oidcUser does.
func (s *Server) githubUser(r *http.Request, g *GitHub, code, state, providerErr string) (store.User, error) {
	flow := unseal(g.key, cookie(r, "github"), 1)
	switch {
	case providerErr != "":
		if !oauthError.MatchString(providerErr) {
			providerErr = "unreadable"
		}
		return store.User{}, errors.New("GitHub said " + providerErr)
	case flow == nil:
		return store.User{}, errors.New("no sign-in in progress, or it expired")
	case !sameToken(state, flow[0]):
		return store.User{}, errors.New("state mismatch")
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, g.client), 15*time.Second)
	defer cancel()
	tok, err := g.oauth.Exchange(ctx, code)
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && oauthError.MatchString(re.ErrorCode) {
			return store.User{}, errors.New("code exchange refused: " + re.ErrorCode)
		}
		s.Log.Printf("GitHub code exchange: %v", err)
		return store.User{}, errors.New("code exchange failed")
	}
	var me struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := g.get(ctx, tok.AccessToken, "/user", &me); err != nil {
		return store.User{}, err
	}
	if me.ID == 0 {
		return store.User{}, errors.New("GitHub returned no user ID")
	}
	var membership struct {
		State string `json:"state"`
	}
	if err := g.get(ctx, tok.AccessToken, "/user/memberships/orgs/"+url.PathEscape(g.Org), &membership); err != nil || membership.State != "active" {
		return store.User{Name: me.Login}, fmt.Errorf("%s isn't an active member of %s", me.Login, g.Org)
	}
	teams, err := g.teams(ctx, tok.AccessToken)
	if err != nil {
		return store.User{}, err
	}
	subject := strconv.FormatInt(me.ID, 10)
	u, err := s.Store.OIDCUser(r.Context(), g.URL, subject)
	if errors.Is(err, store.ErrNotFound) {
		u, err = s.createOIDCUser(r, g.URL, "GitHub", subject, me.Login, "")
	}
	if err != nil {
		return store.User{}, err
	}
	if u.Disabled {
		return u, errors.New("disabled user")
	}
	return s.syncGroups(r, g.AdminTeam, g.TeamRoles, "GitHub team", u, teams)
}

// maxTeamPages bounds how many pages of a user's teams a sign-in reads,
// at 100 a page.
const maxTeamPages = 10

// teams lists the slugs of the user's teams in g.Org.
func (g *GitHub) teams(ctx context.Context, token string) ([]string, error) {
	var out []string
	for page := 1; page <= maxTeamPages; page++ {
		var batch []struct {
			Slug         string `json:"slug"`
			Organization struct {
				Login string `json:"login"`
			} `json:"organization"`
		}
		if err := g.get(ctx, token, fmt.Sprintf("/user/teams?per_page=100&page=%d", page), &batch); err != nil {
			return nil, err
		}
		for _, t := range batch {
			if strings.EqualFold(t.Organization.Login, g.Org) {
				out = append(out, t.Slug)
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return out, nil
}

// get reads one GitHub API path into v. An error names the path and the
// status, never the token.
func (g *GitHub) get(ctx context.Context, token, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.API+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub %s: request failed", strings.SplitN(path, "?", 2)[0])
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub %s: %s", strings.SplitN(path, "?", 2)[0], res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(v)
}
