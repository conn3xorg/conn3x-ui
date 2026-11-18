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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/mail"
	"github.com/conn3xorg/conn3x-ui/internal/run"
	"github.com/conn3xorg/conn3x-ui/internal/sandbox"
	"github.com/conn3xorg/conn3x-ui/internal/store"
	"github.com/conn3xorg/conn3x-ui/internal/web"
)

// version is the release, set at build time; a plain go build says dev.
var version = "dev"

func main() {
	sandbox.Exec() // returns unless this process is a run's sandboxed conn3x
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("conn3x-ui", version)
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "rotate-key" {
		fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
		data := fs.String("data", "data", "directory with the database")
		var oldKey, newKey keySource
		fs.StringVar(&oldKey.file, "old-key-file", "", "file with the key the credentials are sealed with now; or set "+keyEnv)
		fs.StringVar(&oldKey.command, "old-key-command", "", "command that prints that key, such as a KMS decrypt, in place of -old-key-file")
		fs.StringVar(&newKey.file, "new-key-file", "", "file with the key to seal them with from now on; or set "+newKeyEnv)
		fs.StringVar(&newKey.command, "new-key-command", "", "command that prints the new key, in place of -new-key-file")
		fs.Parse(os.Args[2:])
		if err := rotateKey(*data, oldKey, newKey); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: conn3x-ui serve [-listen ADDR] [-data DIR] [-key-file FILE | -key-command CMD] [-public-url URL] [-smtp-addr HOST:PORT -smtp-from ADDR ...] [-oidc-issuer URL -oidc-client-id ID -oidc-redirect-url URL ...] [-github-client-id ID -github-org ORG -github-redirect-url URL ...]\n       conn3x-ui rotate-key [-data DIR] (-old-key-file FILE | -old-key-command CMD) (-new-key-file FILE | -new-key-command CMD)\n       conn3x-ui version")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	data := fs.String("data", "data", "directory for the database and saved plans")
	var key keySource
	fs.StringVar(&key.file, "key-file", "", "file with the base64 key that encrypts credentials; or set "+keyEnv)
	fs.StringVar(&key.command, "key-command", "", "command that prints the base64 key, such as a KMS decrypt, in place of -key-file")
	var oc oidcConfig
	fs.StringVar(&oc.issuer, "oidc-issuer", "", "OIDC provider's issuer URL; turns on single sign-on")
	fs.StringVar(&oc.clientID, "oidc-client-id", "", "OIDC client ID")
	fs.StringVar(&oc.secretFile, "oidc-client-secret-file", "", "file with the OIDC client secret; or set "+oidcSecretEnv)
	fs.StringVar(&oc.redirectURL, "oidc-redirect-url", "", "this UI's callback, https://HOST/login/oidc/callback, as registered with the provider")
	fs.StringVar(&oc.emailDomain, "oidc-email-domain", "", "only let in OIDC users with a verified email in this domain")
	fs.BoolVar(&oc.noPassword, "no-password-sign-in", false, "turn off sign-in with a password, once a site admin signs in with OIDC or GitHub")
	fs.StringVar(&oc.groupsClaim, "oidc-groups-claim", "groups", "ID token claim that lists a user's groups")
	fs.StringVar(&oc.adminGroup, "oidc-admin-group", "", "OIDC group whose members are site admins, checked at each sign-in")
	fs.Var(&oc.roles, "oidc-role", "GROUP=PROJECT:ROLE gives the group's members that role on the project, checked at each sign-in; repeat it for more")
	var gc githubConfig
	fs.StringVar(&gc.clientID, "github-client-id", "", "GitHub OAuth app's client ID; turns on sign-in with GitHub, which needs -github-org")
	fs.StringVar(&gc.secretFile, "github-client-secret-file", "", "file with the GitHub OAuth app's client secret; or set "+githubSecretEnv)
	fs.StringVar(&gc.redirectURL, "github-redirect-url", "", "this UI's callback, https://HOST/login/github/callback, as set on the OAuth app")
	fs.StringVar(&gc.org, "github-org", "", "GitHub organisation whose active members may sign in")
	fs.StringVar(&gc.url, "github-url", "https://github.com", "GitHub's address; a GitHub Enterprise Server's for one")
	fs.StringVar(&gc.adminTeam, "github-admin-team", "", "numeric ID of the -github-org team whose members are site admins, checked at each sign-in")
	fs.Var(&gc.roles, "github-role", "TEAM_ID=PROJECT:ROLE gives a -github-org team's members that role on the project, checked at each sign-in; the team by its numeric ID; repeat it for more")
	publicURL := fs.String("public-url", "", "this UI's address, such as https://conn3x.example.com, for full links in webhooks")
	retention := fs.Duration("fleet-retention", 90*24*time.Hour, "how long the fleet store keeps step results; the latest facts per host are kept for good")
	var mc mailConfig
	fs.StringVar(&mc.addr, "smtp-addr", "", "SMTP server, host:port, for drift emails; STARTTLS is required except on loopback")
	fs.StringVar(&mc.from, "smtp-from", "", "address drift emails come from")
	fs.StringVar(&mc.user, "smtp-user", "", "user to sign in to the SMTP server as")
	fs.StringVar(&mc.passwordFile, "smtp-password-file", "", "file with the SMTP password; or set "+smtpPasswordEnv)
	sandboxMode := fs.String("sandbox", "auto", "run conn3x away from the UI's data and other runs, with Linux Landlock: on, off, or auto to when the kernel has it")
	fs.Parse(os.Args[2:])
	mailer, err := mc.mailer()
	if err != nil {
		log.Fatal(err)
	}
	sandboxed, err := sandboxRuns(*sandboxMode)
	if err != nil {
		log.Fatal(err)
	}
	if err := serve(*listen, *data, key, *publicURL, oc, gc, mailer, *retention, sandboxed); err != nil {
		log.Fatal(err)
	}
}

// keyEnv holds the credentials key when -key-file doesn't, and newKeyEnv
// the one rotate-key moves to when -new-key-file doesn't.
const (
	keyEnv    = "CONN3X_UI_KEY"
	newKeyEnv = "CONN3X_UI_NEW_KEY"
)

// keySource is where a credentials key comes from: a file, or a command
// that prints it, such as a KMS decrypt of a data key kept beside the UI.
type keySource struct{ file, command string }

// loadKey reads the credentials key from src, or from env when src is
// empty, and takes env out of the environment so no run inherits it. No
// key at all is nil: the UI runs without credentials.
func loadKey(src keySource, env string) ([]byte, error) {
	b64 := os.Getenv(env)
	os.Unsetenv(env)
	switch {
	case src.file != "" && src.command != "":
		return nil, errors.New("give the credentials key as a file or a command, not both")
	case src.file != "":
		b, err := os.ReadFile(src.file)
		if err != nil {
			return nil, err
		}
		b64 = string(b)
	case src.command != "":
		b, err := keyCommandOutput(src.command)
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

// keyCommandTimeout bounds a key command; a test shortens it.
var keyCommandTimeout = time.Minute

// keyCommandOutput runs command in the shell and returns what it prints.
// Its errors go to stderr, where a cloud CLI says what's wrong. No
// CONN3X_UI_ variable reaches it, so it sees no key and no other secret.
// At the timeout the whole process group is killed, and WaitDelay stops
// waiting on a pipe a child still holds, so a hung KMS call can't hold
// startup past it.
func keyCommandOutput(command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keyCommandTimeout)
	defer cancel()
	shell, flag := "sh", "-c"
	if runtime.GOOS == "windows" {
		shell, flag = "cmd", "/C"
	}
	cmd := exec.CommandContext(ctx, shell, flag, command)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "CONN3X_UI_") })
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 5 * time.Second
	killGroup(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("the key command failed: %w", err)
	}
	return out, nil
}

// oidcConfig is the serve flags for single sign-on.
type oidcConfig struct {
	issuer, clientID, secretFile, redirectURL, emailDomain string
	noPassword                                             bool
	groupsClaim, adminGroup                                string
	roles                                                  roleFlags
}

// roleFlags collects each -oidc-role.
type roleFlags []web.GroupRole

func (f *roleFlags) String() string { return fmt.Sprint(*f) }

func (f *roleFlags) Set(s string) error {
	gr, err := web.ParseGroupRole(s)
	if err == nil {
		*f = append(*f, gr)
	}
	return err
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
		if oc.adminGroup != "" || len(oc.roles) > 0 {
			return nil, errors.New("-oidc-admin-group and -oidc-role need -oidc-issuer")
		}
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
	o, err := web.NewOIDC(ctx, oc.issuer, oc.clientID, strings.TrimSpace(secret), oc.redirectURL, oc.emailDomain)
	if err == nil {
		o.GroupsClaim, o.AdminGroup, o.GroupRoles = oc.groupsClaim, oc.adminGroup, oc.roles
	}
	return o, err
}

// githubConfig is the serve flags for sign-in with GitHub.
type githubConfig struct {
	clientID, secretFile, redirectURL, org, url, adminTeam string
	roles                                                  roleFlags
}

// githubSecretEnv holds the GitHub client secret when
// -github-client-secret-file doesn't.
const githubSecretEnv = "CONN3X_UI_GITHUB_CLIENT_SECRET"

// setupGitHub sets up sign-in with GitHub when -github-client-id is set,
// and nil when it isn't. The secret is handled as setupOIDC's is.
func setupGitHub(gc githubConfig) (*web.GitHub, error) {
	secret := os.Getenv(githubSecretEnv)
	os.Unsetenv(githubSecretEnv)
	if gc.clientID == "" {
		if gc.org != "" || gc.adminTeam != "" || len(gc.roles) > 0 {
			return nil, errors.New("-github-org, -github-admin-team and -github-role need -github-client-id")
		}
		return nil, nil
	}
	if gc.redirectURL == "" {
		return nil, errors.New("GitHub sign-in needs -github-redirect-url as well as -github-client-id")
	}
	// Each ID is written back as GitHub writes it, so "0123" matches 123.
	teams := []*string{&gc.adminTeam}
	gc.roles = slices.Clone(gc.roles)
	for i := range gc.roles {
		teams = append(teams, &gc.roles[i].Group)
	}
	for _, t := range teams {
		if *t == "" {
			continue
		}
		id, err := strconv.ParseUint(*t, 10, 63)
		if err != nil {
			return nil, fmt.Errorf("GitHub teams are named by numeric ID, not slug, since any member can create a team with a free slug: %q. Find the ID with: gh api orgs/%s/teams/%s --jq .id", *t, gc.org, *t)
		}
		*t = strconv.FormatUint(id, 10)
	}
	if gc.secretFile != "" {
		b, err := os.ReadFile(gc.secretFile)
		if err != nil {
			return nil, err
		}
		secret = string(b)
	}
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("GitHub sign-in needs the OAuth app's client secret, from -github-client-secret-file or " + githubSecretEnv)
	}
	g, err := web.NewGitHub(gc.url, gc.clientID, strings.TrimSpace(secret), gc.redirectURL, gc.org)
	if err == nil {
		g.AdminTeam, g.TeamRoles = gc.adminTeam, gc.roles
	}
	return g, err
}

// rotateKey re-seals every credential in data's database under the new
// key. Run it with the UI stopped: one still running has the old key.
func rotateKey(data string, oldSrc, newSrc keySource) error {
	oldKey, err := loadKey(oldSrc, keyEnv)
	if err != nil {
		return err
	}
	newKey, err := loadKey(newSrc, newKeyEnv)
	if err != nil {
		return err
	}
	if oldKey == nil || newKey == nil {
		return errors.New("rotate-key needs the old key, from -old-key-file, -old-key-command or " + keyEnv + ", and the new one, from -new-key-file, -new-key-command or " + newKeyEnv)
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

// smtpPasswordEnv holds the SMTP password when -smtp-password-file doesn't.
const smtpPasswordEnv = "CONN3X_UI_SMTP_PASSWORD"

type mailConfig struct{ addr, from, user, passwordFile string }

// mailer is the Mailer the flags describe, or nil without -smtp-addr. The
// password comes from its file, or from the environment, which it's taken
// out of so no run inherits it.
func (mc mailConfig) mailer() (*mail.Mailer, error) {
	pw := os.Getenv(smtpPasswordEnv)
	os.Unsetenv(smtpPasswordEnv)
	if mc.addr == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(mc.addr); err != nil {
		return nil, fmt.Errorf("-smtp-addr must be host:port: %w", err)
	}
	from, err := mail.ParseAddresses(mc.from)
	if err != nil || len(from) != 1 {
		return nil, errors.New("-smtp-addr needs -smtp-from, one email address")
	}
	if mc.passwordFile != "" {
		b, err := os.ReadFile(mc.passwordFile)
		if err != nil {
			return nil, err
		}
		pw = strings.TrimRight(string(b), "\r\n")
	}
	return &mail.Mailer{Addr: mc.addr, From: from[0], User: mc.user, Password: pw}, nil
}

func serve(listen, data string, keySrc keySource, publicURL string, oc oidcConfig, gc githubConfig, mailer *mail.Mailer, retention time.Duration, sandboxed bool) error {
	if publicURL != "" {
		if u, err := url.Parse(publicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("-public-url must be an http or https URL, such as https://conn3x.example.com")
		}
	}
	key, err := loadKey(keySrc, keyEnv)
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
	g, err := setupGitHub(gc)
	if err != nil {
		return err
	}
	if oc.noPassword {
		var issuers []string
		if o != nil {
			issuers = append(issuers, o.Issuer)
		}
		if g != nil {
			issuers = append(issuers, g.URL)
		}
		if err := web.TurnPasswordOff(ctx, st, issuers...); err != nil {
			return err
		}
	}
	runner := run.New(ctx, st, data)
	runner.PublicURL = publicURL
	runner.Retention = retention
	runner.Sandbox = sandboxed
	if mailer != nil { // a nil *Mailer in the interface would look set
		runner.Mailer = mailer
	}
	if n, err := runner.RemoveLeftovers(); err != nil {
		return err
	} else if n > 0 {
		log.Printf("removed %d credentials directories left by runs that stopped with the UI", n)
	}
	scheduled := make(chan struct{})
	go func() { runner.Schedule(ctx); close(scheduled) }()
	h := web.New(st, runner)
	h.OIDC, h.GitHub, h.PasswordOff = o, g, oc.noPassword
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

// sandboxRuns says whether runs are sandboxed, for -sandbox's mode, and
// logs it.
func sandboxRuns(mode string) (bool, error) {
	switch mode {
	case "off":
		log.Print("runs aren't sandboxed (-sandbox=off): a run can read the UI's data")
		return false, nil
	case "on", "auto":
		v, err := sandbox.Available()
		if err == nil {
			log.Printf("runs are sandboxed with Landlock ABI %d", v)
			return true, nil
		}
		if mode == "on" {
			return false, fmt.Errorf("-sandbox=on, but runs can't be sandboxed: %v", err)
		}
		log.Printf("runs aren't sandboxed, so a run can read the UI's data: Landlock: %v", err)
		return false, nil
	}
	return false, fmt.Errorf("-sandbox is on, off or auto, not %q", mode)
}
