// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Command conn3x-ui is the Conn3x web UI: projects in Git, plans from the
// browser, with the output live and grouped by host.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/run"
	"github.com/conn3xorg/conn3x-ui/internal/store"
	"github.com/conn3xorg/conn3x-ui/internal/web"
)

// version is the release, set at build time; a plain go build says dev.
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("conn3x-ui", version)
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "rotate-key" {
		fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
		data := fs.String("data", "data", "directory with the database")
		oldFile := fs.String("old-key-file", "", "file with the key the credentials are sealed with now; or set "+keyEnv)
		newFile := fs.String("new-key-file", "", "file with the key to seal them with from now on; or set "+newKeyEnv)
		fs.Parse(os.Args[2:])
		if err := rotateKey(*data, *oldFile, *newFile); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: conn3x-ui serve [-listen ADDR] [-data DIR] [-key-file FILE] [-public-url URL] [-oidc-issuer URL -oidc-client-id ID -oidc-redirect-url URL ...]\n       conn3x-ui rotate-key [-data DIR] -old-key-file FILE -new-key-file FILE\n       conn3x-ui version")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	data := fs.String("data", "data", "directory for the database and saved plans")
	keyFile := fs.String("key-file", "", "file with the base64 key that encrypts credentials; or set "+keyEnv)
	var oc oidcConfig
	fs.StringVar(&oc.issuer, "oidc-issuer", "", "OIDC provider's issuer URL; turns on single sign-on")
	fs.StringVar(&oc.clientID, "oidc-client-id", "", "OIDC client ID")
	fs.StringVar(&oc.secretFile, "oidc-client-secret-file", "", "file with the OIDC client secret; or set "+oidcSecretEnv)
	fs.StringVar(&oc.redirectURL, "oidc-redirect-url", "", "this UI's callback, https://HOST/login/oidc/callback, as registered with the provider")
	fs.StringVar(&oc.emailDomain, "oidc-email-domain", "", "only let in OIDC users with a verified email in this domain")
	fs.BoolVar(&oc.noPassword, "no-password-sign-in", false, "turn off sign-in with a password, once a site admin signs in with OIDC")
	publicURL := fs.String("public-url", "", "this UI's address, such as https://conn3x.example.com, for full links in webhooks")
	fs.Parse(os.Args[2:])
	if err := serve(*listen, *data, *keyFile, *publicURL, oc); err != nil {
		log.Fatal(err)
	}
}

// keyEnv holds the credentials key when -key-file doesn't, and newKeyEnv
// the one rotate-key moves to when -new-key-file doesn't.
const (
	keyEnv    = "CONN3X_UI_KEY"
	newKeyEnv = "CONN3X_UI_NEW_KEY"
)

// loadKey reads the credentials key from file, or from env when file is
// empty, and takes env out of the environment so no run inherits it. No
// key at all is nil: the UI runs without credentials.
func loadKey(file, env string) ([]byte, error) {
	b64 := os.Getenv(env)
	os.Unsetenv(env)
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		b64 = string(b)
	}
	if b64 == "" {
		return nil, nil
	}
	// The message never quotes what it read: that would be the key.
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("the credentials key must be 32 random bytes in base64. Make one with openssl rand -base64 32")
	}
	return key, nil
}

// oidcConfig is the serve flags for single sign-on.
type oidcConfig struct {
	issuer, clientID, secretFile, redirectURL, emailDomain string
	noPassword                                             bool
}

// oidcSecretEnv holds the OIDC client secret when -oidc-client-secret-file
// doesn't.
const oidcSecretEnv = "CONN3X_UI_OIDC_CLIENT_SECRET"

// setupOIDC discovers the provider when -oidc-issuer is set, and nil when
// it isn't. The client secret comes from its file or oidcSecretEnv, which
// is taken out of the environment so no run inherits it. A public client
// with PKCE has none.
func setupOIDC(ctx context.Context, oc oidcConfig) (*web.OIDC, error) {
	secret := os.Getenv(oidcSecretEnv)
	os.Unsetenv(oidcSecretEnv)
	if oc.issuer == "" {
		return nil, nil
	}
	if oc.clientID == "" || oc.redirectURL == "" {
		return nil, errors.New("OIDC needs -oidc-client-id and -oidc-redirect-url as well as -oidc-issuer")
	}
	if oc.secretFile != "" {
		b, err := os.ReadFile(oc.secretFile)
		if err != nil {
			return nil, err
		}
		secret = string(b)
	}
	return web.NewOIDC(ctx, oc.issuer, oc.clientID, strings.TrimSpace(secret), oc.redirectURL, oc.emailDomain)
}

// rotateKey re-seals every credential in data's database under the new
// key. Run it with the UI stopped: one still running has the old key.
func rotateKey(data, oldFile, newFile string) error {
	oldKey, err := loadKey(oldFile, keyEnv)
	if err != nil {
		return err
	}
	newKey, err := loadKey(newFile, newKeyEnv)
	if err != nil {
		return err
	}
	if oldKey == nil || newKey == nil {
		return errors.New("rotate-key needs the old key, from -old-key-file or " + keyEnv + ", and the new one, from -new-key-file or " + newKeyEnv)
	}
	path := filepath.Join(data, "conn3x-ui.db")
	if _, err := os.Stat(path); err != nil {
		return err
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetKey(oldKey); err != nil {
		return err
	}
	n, err := st.RotateKey(context.Background(), newKey)
	if err != nil {
		return err
	}
	log.Printf("re-sealed %d credentials under the new key. Start the UI with it from now on", n)
	return nil
}

func serve(listen, data, keyFile, publicURL string, oc oidcConfig) error {
	if publicURL != "" {
		if u, err := url.Parse(publicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("-public-url must be an http or https URL, such as https://conn3x.example.com")
		}
	}
	key, err := loadKey(keyFile, keyEnv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(data, "conn3x-ui.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	if key != nil {
		if err := st.SetKey(key); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	saved, err := st.CheckKey(ctx)
	if err != nil {
		return err
	}
	if key == nil && saved > 0 {
		log.Printf("no credentials key, but %d credentials are saved: runs of their projects will fail until the UI starts with the key they were saved with, from -key-file or %s", saved, keyEnv)
	} else if key == nil {
		log.Printf("no credentials key, so credentials are off. Make one with openssl rand -base64 32 > key, then start with -key-file key or set %s", keyEnv)
	}
	if n, err := st.UserCount(ctx); err != nil {
		return err
	} else if n == 0 {
		// The first admin's password is printed once; they make everyone
		// else's under Users.
		password := store.Token(12)
		id, err := st.CreateUser(ctx, "admin", password)
		if err == nil {
			err = st.SetUser(ctx, id, true, false)
		}
		if err != nil {
			return err
		}
		log.Printf("created the admin account. Sign in as admin with the password %s", password)
	}
	o, err := setupOIDC(ctx, oc)
	if err != nil {
		return err
	}
	if oc.noPassword {
		if err := web.TurnPasswordOff(ctx, st, o); err != nil {
			return err
		}
	}
	runner := run.New(ctx, st, data)
	runner.PublicURL = publicURL
	if n, err := runner.RemoveLeftovers(); err != nil {
		return err
	} else if n > 0 {
		log.Printf("removed %d credentials directories left by runs that stopped with the UI", n)
	}
	scheduled := make(chan struct{})
	go func() { runner.Schedule(ctx); close(scheduled) }()
	h := web.New(st, runner)
	h.OIDC, h.PasswordOff = o, oc.noPassword
	srv := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	log.Printf("conn3x-ui listening on http://%s", listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-scheduled   // so no drift check starts after Wait
	runner.Wait() // conn3x got the interrupt too; let it release its locks
	return nil
}
