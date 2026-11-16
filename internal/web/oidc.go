// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// OIDC signs people in with one OpenID Connect provider: the authorization
// code flow with PKCE, a state and a nonce.
// shortcut: one provider, and no roles for its groups; more providers and
// group roles are the rest of #892.
type OIDC struct {
	// Issuer is the provider's issuer URL, as it states it.
	Issuer string
	// EmailDomain, when set, is the only domain whose verified emails may
	// sign in.
	EmailDomain string
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
	client      *http.Client
	// key signs the cookie that carries a sign-in to the callback. It's
	// made at start, so a restart drops sign-ins halfway through.
	key []byte
}

// flowTTL is how long a person has at the provider before the sign-in
// they started expires.
const flowTTL = 10 * time.Minute

// NewOIDC discovers the provider at issuer, from its
// /.well-known/openid-configuration.
func NewOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURL, emailDomain string) (*OIDC, error) {
	o := &OIDC{EmailDomain: strings.ToLower(strings.TrimPrefix(emailDomain, "@")), client: &http.Client{Timeout: 10 * time.Second}, key: []byte(store.Token(32))}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.client), issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	var meta struct {
		Issuer string `json:"issuer"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, err
	}
	o.Issuer = meta.Issuer
	o.oauth = oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL, Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	o.verifier = p.Verifier(&oidc.Config{ClientID: clientID})
	return o, nil
}

// seal signs values and an expiry into a cookie value. The values must
// not hold a dot.
func (o *OIDC) seal(values ...string) string {
	v := strings.Join(append(values, strconv.FormatInt(time.Now().Add(flowTTL).Unix(), 10)), ".")
	m := hmac.New(sha256.New, o.key)
	m.Write([]byte(v))
	return v + "." + hex.EncodeToString(m.Sum(nil))
}

// unseal checks a cookie value from seal and returns its n values, or nil
// when it's forged or expired.
func (o *OIDC) unseal(c string, n int) []string {
	i := strings.LastIndexByte(c, '.')
	if i < 0 {
		return nil
	}
	m := hmac.New(sha256.New, o.key)
	m.Write([]byte(c[:i]))
	if !hmac.Equal([]byte(hex.EncodeToString(m.Sum(nil))), []byte(c[i+1:])) {
		return nil
	}
	parts := strings.Split(c[:i], ".")
	if len(parts) != n+1 {
		return nil
	}
	if exp, err := strconv.ParseInt(parts[n], 10, 64); err != nil || time.Now().Unix() > exp {
		return nil
	}
	return parts[:n]
}

// oidcStart sends the browser to the provider, with the state, nonce and
// PKCE verifier in a signed cookie only this UI reads back.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	state, nonce, verifier := store.Token(16), store.Token(16), oauth2.GenerateVerifier()
	setCookie(w, r, "oidc", s.OIDC.seal(state, nonce, verifier), flowTTL)
	http.Redirect(w, r, s.OIDC.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

var oauthError = regexp.MustCompile(`^[a-z_]{1,64}$`)

// oidcCallback is where the provider sends the browser back. It checks the
// state, trades the code for tokens, verifies the ID token and its nonce,
// then signs in the user linked to its issuer and subject, making one the
// first time. No token is logged or kept.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	o, q := s.OIDC, r.URL.Query()
	setCookie(w, r, "oidc", "", -1)
	u, err := s.oidcUser(r, o, q.Get("code"), q.Get("state"), q.Get("error"))
	if err != nil {
		s.audit(r.Context(), u, store.Project{}, "sign-in failed", "OIDC: "+err.Error())
		s.loginForm(w, r, http.StatusUnauthorized, "Single sign-on didn't work. Try again; if it keeps failing, a site admin can read why in the audit log.")
		return
	}
	tok, _, err := s.Store.OpenSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), u, store.Project{}, "sign-in", "OIDC, "+o.Issuer)
	setCookie(w, r, "session", tok, sessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// oidcUser runs the callback's checks and returns the user to sign in.
// The error is the reason for the audit log, never a token; the user is
// set when the reason is about them.
func (s *Server) oidcUser(r *http.Request, o *OIDC, code, state, providerErr string) (store.User, error) {
	flow := o.unseal(cookie(r, "oidc"), 3)
	switch {
	case providerErr != "":
		if !oauthError.MatchString(providerErr) {
			providerErr = "unreadable"
		}
		return store.User{}, errors.New("the provider said " + providerErr)
	case flow == nil:
		return store.User{}, errors.New("no sign-in in progress, or it expired")
	case !sameToken(state, flow[0]):
		return store.User{}, errors.New("state mismatch")
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), o.client), 15*time.Second)
	defer cancel()
	tok, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(flow[2]))
	if err != nil {
		// A failed exchange's error has the provider's error code, no token.
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && oauthError.MatchString(re.ErrorCode) {
			return store.User{}, errors.New("code exchange refused: " + re.ErrorCode)
		}
		s.Log.Printf("OIDC code exchange: %v", err)
		return store.User{}, errors.New("code exchange failed")
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return store.User{}, errors.New("no ID token")
	}
	idt, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		// go-oidc's errors name the claim that failed, not the token.
		return store.User{}, fmt.Errorf("ID token rejected: %w", err)
	}
	if !sameToken(idt.Nonce, flow[1]) {
		return store.User{}, errors.New("nonce mismatch")
	}
	var c struct {
		Email             string `json:"email"`
		EmailVerified     any    `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&c); err != nil {
		return store.User{}, fmt.Errorf("ID token claims: %w", err)
	}
	if o.EmailDomain != "" {
		// Some providers send email_verified as the string "true".
		verified := c.EmailVerified == true || c.EmailVerified == "true"
		if _, domain, _ := strings.Cut(strings.ToLower(c.Email), "@"); !verified || domain != o.EmailDomain {
			return store.User{}, fmt.Errorf("no verified email in %s", o.EmailDomain)
		}
	}
	// The subject alone says who it is: an email or name may be reused.
	u, err := s.Store.OIDCUser(r.Context(), o.Issuer, idt.Subject)
	if errors.Is(err, store.ErrNotFound) {
		u, err = s.createOIDCUser(r, o, idt.Subject, c.PreferredUsername, c.Email)
	}
	if err != nil {
		return store.User{}, err
	}
	if u.Disabled {
		return u, errors.New("disabled user")
	}
	return u, nil
}

var notNameChar = regexp.MustCompile(`[^A-Za-z0-9._@-]+`)

// createOIDCUser makes the user for a subject's first sign-in, with no
// roles and not a site admin. Their name is the preferred username or
// email; when another user has it, a short hash of the subject goes on the
// end, so nobody takes over an account by picking its name.
func (s *Server) createOIDCUser(r *http.Request, o *OIDC, subject, username, email string) (store.User, error) {
	name := cmp.Or(notNameChar.ReplaceAllString(cmp.Or(username, email), ""), "user")
	name = name[:min(len(name), 50)]
	sum := sha256.Sum256([]byte(o.Issuer + " " + subject))
	var id int64
	var err error
	for _, n := range []string{name, name + "-" + hex.EncodeToString(sum[:4])} {
		if !userName.MatchString(n) {
			continue
		}
		if id, err = s.Store.CreateOIDCUser(r.Context(), n, o.Issuer, subject); err == nil {
			break
		}
		if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return store.User{}, err
		}
	}
	if id == 0 {
		return store.User{}, errors.New("no free user name for " + name)
	}
	u, err := s.Store.User(r.Context(), id)
	if err == nil {
		s.audit(r.Context(), u, store.Project{}, "user create", u.Name+", from OIDC, "+o.Issuer)
	}
	return u, err
}

// TurnPasswordOff readies the UI to start with password sign-in off. It
// refuses unless OIDC is set up and a site admin who isn't disabled signs
// in with it, since otherwise nobody could sign in to make one. Then it
// ends every session of a user with no OIDC link: those were opened with
// a password.
func TurnPasswordOff(ctx context.Context, st *store.Store, o *OIDC) error {
	if o == nil {
		return errors.New("password sign-in can only be turned off with OIDC set up")
	}
	n, err := st.OIDCAdmins(ctx, o.Issuer)
	if err == nil && n == 0 {
		err = errors.New("password sign-in stays on until a site admin signs in with OIDC: sign in with OIDC once, make that user a site admin under Users, then restart with password sign-in off")
	}
	if err != nil {
		return err
	}
	ended, err := st.EndPasswordSessions(ctx)
	if err == nil && ended > 0 {
		err = st.Audit(ctx, store.Entry{Action: "password sessions ended", Detail: fmt.Sprintf("%d, as password sign-in is off", ended)})
	}
	return err
}
