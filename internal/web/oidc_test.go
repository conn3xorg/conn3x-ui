// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package web

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/store"
)

// idp is a fake OIDC provider: discovery, a JWKS with one RSA key, and a
// token endpoint that checks the client secret and the PKCE verifier and
// hands back an ID token the test describes.
type idp struct {
	*httptest.Server
	key *rsa.PrivateKey
	mu  sync.Mutex
	// codes is what each code was issued for: the challenge, and the ID
	// token's claims.
	codes map[string]grant
	// issued is every token handed out, so the test can look for it.
	issued []string
}

type grant struct {
	challenge string
	claims    map[string]any
}

const clientID, clientSecret = "conn3x-ui", "client-secret-value"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
			"jwks_uri": p.URL + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
		}
		p.mu.Lock()
		g, found := p.codes[r.PostFormValue("code")]
		delete(p.codes, r.PostFormValue("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if id != clientID || secret != clientSecret || !found || b64(sum[:]) != g.challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		idToken := p.sign(t, g.claims)
		access := "access-" + store.Token(8)
		p.mu.Lock()
		p.issued = append(p.issued, idToken, access)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// sign makes an RS256 JWT of claims with the provider's key.
func (p *idp) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	msg := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return msg + "." + b64(sig)
}

// oidcEnv is a UI with OIDC from the fake provider, and the admin made
// at first start, who signs in with a password.
type oidcEnv struct {
	st  *store.Store
	srv *Server
	idp *idp
	*client
}

func setupOIDC(t *testing.T) oidcEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if id, err := st.CreateUser(context.Background(), "admin", "pw"); err != nil || st.SetUser(context.Background(), id, true, false) != nil {
		t.Fatal(err)
	}
	return startUI(t, st, newIDP(t), false, "")
}

// startUI serves a UI on st with OIDC from p, set up before it starts.
func startUI(t *testing.T, st *store.Store, p *idp, passwordOff bool, emailDomain string) oidcEnv {
	t.Helper()
	h := New(st, nil)
	srv := httptest.NewUnstartedServer(h)
	base := "http://" + srv.Listener.Addr().String()
	var err error
	if h.OIDC, err = NewOIDC(context.Background(), p.URL, clientID, clientSecret, base+"/login/oidc/callback", emailDomain); err != nil {
		t.Fatal(err)
	}
	h.PasswordOff = passwordOff
	srv.Start()
	t.Cleanup(srv.Close)
	return oidcEnv{st, h, p, newClient(t, base)}
}

// fresh is e with a new browser.
func (e oidcEnv) fresh() oidcEnv { return oidcEnv{e.st, e.srv, e.idp, newClient(e.t, e.base)} }

// signIn goes through the whole flow as the provider's user sub. edit
// changes the ID token's claims, or the callback's query, to break it.
func (e oidcEnv) signIn(t *testing.T, sub string, edit func(claims map[string]any, callback url.Values)) (*http.Response, string) {
	t.Helper()
	resp, _ := e.get("/login/oidc")
	auth, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || err != nil || !strings.HasPrefix(auth.String(), e.idp.URL+"/authorize") {
		t.Fatalf("start: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	q := auth.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("client_id") != clientID || q.Get("scope") != "openid email profile" || q.Get("response_type") != "code" {
		t.Fatalf("authorize request: %v", q)
	}
	claims := map[string]any{"iss": e.idp.URL, "aud": clientID, "sub": sub, "nonce": q.Get("nonce"),
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "preferred_username": sub, "email": sub + "@example.com", "email_verified": true}
	code := store.Token(8)
	callback := url.Values{"code": {code}, "state": {q.Get("state")}}
	if edit != nil {
		edit(claims, callback)
	}
	e.idp.mu.Lock()
	e.idp.codes[code] = grant{q.Get("code_challenge"), claims}
	e.idp.mu.Unlock()
	return e.get("/login/oidc/callback?" + callback.Encode())
}

func TestOIDCSignIn(t *testing.T) {
	e := setupOIDC(t)

	// The first sign-in makes a user with no roles; the next finds them.
	if resp, body := e.signIn(t, "sam", nil); resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("sign-in: %d\n%s", resp.StatusCode, body)
	}
	if _, body := e.get("/"); !strings.Contains(body, ">sam</small>") {
		t.Fatalf("home after sign-in:\n%s", body)
	}
	if resp, _ := e.get("/users"); resp.StatusCode != 403 {
		t.Errorf("a new OIDC user is a site admin: %d", resp.StatusCode)
	}
	if _, body := e.get("/account"); strings.Contains(body, "/account/password") {
		t.Error("an OIDC user is offered a password change")
	}
	if resp, _ := e.fresh().signIn(t, "sam", nil); resp.StatusCode != 303 {
		t.Fatalf("second sign-in: %d", resp.StatusCode)
	}
	if n, _ := e.st.UserCount(context.Background()); n != 2 {
		t.Errorf("%d users after two sign-ins as one subject", n)
	}

	// A subject named like a local user is a new user, never that one.
	other := e.fresh()
	if resp, _ := other.signIn(t, "mallory", func(c map[string]any, _ url.Values) { c["preferred_username"] = "admin" }); resp.StatusCode != 303 {
		t.Fatalf("sign-in named admin: %d", resp.StatusCode)
	}
	if _, body := other.get("/"); strings.Contains(body, ">admin</small>") || !strings.Contains(body, ">admin-") {
		t.Errorf("a subject named admin became the admin:\n%s", body)
	}
	if resp, _ := other.get("/users"); resp.StatusCode != 403 {
		t.Errorf("a subject named admin got site admin: %d", resp.StatusCode)
	}

	// Each broken callback is refused and leaves nobody signed in.
	bad := map[string]func(map[string]any, url.Values){
		"state mismatch":             func(_ map[string]any, q url.Values) { q.Set("state", "forged") },
		"nonce mismatch":             func(c map[string]any, _ url.Values) { c["nonce"] = "replayed" },
		`expected audience`:          func(c map[string]any, _ url.Values) { c["aud"] = "another-app" },
		"token is expired":           func(c map[string]any, _ url.Values) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"issued by a different":      func(c map[string]any, _ url.Values) { c["iss"] = "https://evil.example.com" },
		"code exchange refused":      func(_ map[string]any, q url.Values) { q.Set("code", "unknown") },
		"the provider said access_d": func(_ map[string]any, q url.Values) { q.Set("error", "access_denied") },
	}
	for why, edit := range bad {
		c := e.fresh()
		resp, body := c.signIn(t, "sam", edit)
		if resp.StatusCode != 401 || !strings.Contains(body, "Single sign-on didn&#39;t work") {
			t.Errorf("%s: %d\n%s", why, resp.StatusCode, body)
		}
		if resp, _ := c.get("/"); resp.StatusCode != 303 {
			t.Errorf("%s: signed in anyway", why)
		}
	}
	// A callback with no sign-in started, or a forged cookie, is refused.
	if resp, _ := newClient(t, e.base).get("/login/oidc/callback?code=x&state=y"); resp.StatusCode != 401 {
		t.Errorf("callback without a start: %d", resp.StatusCode)
	}
	if v := e.srv.OIDC.seal("a", "b", "c"); e.srv.OIDC.unseal(v, 3) == nil || e.srv.OIDC.unseal(strings.Replace(v, "a.", "z.", 1), 3) != nil {
		t.Error("the flow cookie's signature isn't checked")
	}

	// A disabled user can't sign in with OIDC either.
	sam, _ := e.st.OIDCUser(context.Background(), e.idp.URL, "sam")
	e.st.SetUser(context.Background(), sam.ID, false, true)
	if resp, _ := e.fresh().signIn(t, "sam", nil); resp.StatusCode != 401 {
		t.Errorf("disabled user: %d", resp.StatusCode)
	}

	got := auditLines(t, e.st)
	for _, want := range []string{
		"sam  user create sam, from OIDC, " + e.idp.URL,
		"sam  sign-in OIDC, " + e.idp.URL,
		"  sign-in failed OIDC: state mismatch",
		"  sign-in failed OIDC: nonce mismatch",
		"  sign-in failed OIDC: no sign-in in progress, or it expired",
		"  sign-in failed OIDC: code exchange refused: invalid_grant",
		"  sign-in failed OIDC: the provider said access_denied",
		"sam  sign-in failed OIDC: disabled user",
	} {
		if !strings.Contains(strings.Join(got, "\n"), want) {
			t.Errorf("audit log lacks %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	for _, l := range got {
		for _, s := range append(e.idp.issued, clientSecret, "eyJ") {
			if strings.Contains(l, s) {
				t.Errorf("audit entry %q holds a token or secret", l)
			}
		}
	}
}

func TestOIDCEmailDomain(t *testing.T) {
	e := setupOIDC(t)
	e = startUI(t, e.st, e.idp, false, "example.com")
	if resp, _ := e.fresh().signIn(t, "una", func(c map[string]any, _ url.Values) { c["email_verified"] = false }); resp.StatusCode != 401 {
		t.Errorf("unverified email: %d", resp.StatusCode)
	}
	if resp, _ := e.fresh().signIn(t, "out", func(c map[string]any, _ url.Values) { c["email"] = "out@elsewhere.com" }); resp.StatusCode != 401 {
		t.Errorf("other domain: %d", resp.StatusCode)
	}
	if resp, _ := e.fresh().signIn(t, "ina", nil); resp.StatusCode != 303 {
		t.Errorf("verified email in the domain: %d", resp.StatusCode)
	}
}

func TestPasswordOff(t *testing.T) {
	e := setupOIDC(t)
	ctx := context.Background()

	// Turning password sign-in off needs a site admin who signs in with
	// OIDC, so nobody is locked out.
	if TurnPasswordOff(ctx, e.st, nil) == nil {
		t.Error("password sign-in off without OIDC")
	}
	if TurnPasswordOff(ctx, e.st, e.srv.OIDC) == nil {
		t.Error("password sign-in off with no OIDC admin")
	}
	olive := e.fresh()
	olive.signIn(t, "olive", nil)
	ou, _ := e.st.OIDCUser(ctx, e.idp.URL, "olive")
	e.st.SetUser(ctx, ou.ID, true, false)
	e.login(t)
	if err := TurnPasswordOff(ctx, e.st, e.srv.OIDC); err != nil {
		t.Fatalf("password sign-in off with an OIDC admin: %v", err)
	}

	// Once off, a session opened with a password is gone and one opened
	// with OIDC isn't.
	off := startUI(t, e.st, e.idp, true, "")
	if resp, _ := (&client{t, off.base, e.Client}).get("/"); resp.StatusCode != 303 {
		t.Errorf("password session after passwords went off: %d", resp.StatusCode)
	}
	if resp, _ := (&client{t, off.base, olive.Client}).get("/"); resp.StatusCode != 200 {
		t.Errorf("OIDC session after passwords went off: %d", resp.StatusCode)
	}
	if got := strings.Join(auditLines(t, e.st), "\n"); !strings.Contains(got, "  password sessions ended 1, as password sign-in is off") {
		t.Errorf("audit log:\n%s", got)
	}

	// The page has no password form and a password post is refused; OIDC
	// still works.
	if _, body := off.get("/login"); strings.Contains(body, `name="password"`) || !strings.Contains(body, "/login/oidc") {
		t.Errorf("sign-in page with passwords off:\n%s", body)
	}
	u, _ := url.Parse(off.base)
	csrf := off.Jar.Cookies(u)[0].Value
	if resp, body := off.postBody("/login", url.Values{"csrf": {csrf}, "name": {"admin"}, "password": {"pw"}}); resp.StatusCode != 403 || !strings.Contains(body, "password is off") {
		t.Errorf("password sign-in while off: %d %s", resp.StatusCode, body)
	}
	if resp, _ := off.fresh().signIn(t, "olive", nil); resp.StatusCode != 303 {
		t.Errorf("OIDC sign-in while passwords are off: %d", resp.StatusCode)
	}
}
