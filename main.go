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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/run"
	"github.com/conn3xorg/conn3x-ui/internal/store"
	"github.com/conn3xorg/conn3x-ui/internal/web"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: conn3x-ui serve [-listen ADDR] [-data DIR] [-key-file FILE]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	data := fs.String("data", "data", "directory for the database and saved plans")
	keyFile := fs.String("key-file", "", "file with the base64 key that encrypts credentials; or set "+keyEnv)
	fs.Parse(os.Args[2:])
	if err := serve(*listen, *data, *keyFile); err != nil {
		log.Fatal(err)
	}
}

// keyEnv holds the credentials key when -key-file doesn't.
const keyEnv = "CONN3X_UI_KEY"

// loadKey reads the credentials key from file, or from keyEnv when file is
// empty, and takes keyEnv out of the environment so no run inherits it. No
// key at all is nil: the UI runs without credentials.
func loadKey(file string) ([]byte, error) {
	b64 := os.Getenv(keyEnv)
	os.Unsetenv(keyEnv)
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

func serve(listen, data, keyFile string) error {
	key, err := loadKey(keyFile)
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
	if key == nil {
		log.Printf("no credentials key, so credentials are off. Make one with openssl rand -base64 32 > key, then start with -key-file key or set %s", keyEnv)
	} else if err := st.SetKey(key); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if n, err := st.UserCount(ctx); err != nil {
		return err
	} else if n == 0 {
		// shortcut: one admin with a printed password until #892 brings
		// OIDC sign-in and roles.
		password := store.Token(12)
		if _, err := st.CreateUser(ctx, "admin", password); err != nil {
			return err
		}
		log.Printf("created the admin account. Sign in as admin with the password %s", password)
	}
	runner := run.New(ctx, st, data)
	srv := &http.Server{Addr: listen, Handler: web.New(st, runner), ReadHeaderTimeout: 10 * time.Second}
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
	runner.Wait() // conn3x got the interrupt too; let it release its locks
	return nil
}
