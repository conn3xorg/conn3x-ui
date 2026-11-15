// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Command conn3x-ui is the Conn3x web UI: projects in Git, plans from the
// browser, with the output live and grouped by host.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/conn3xorg/conn3x-ui/internal/run"
	"github.com/conn3xorg/conn3x-ui/internal/store"
	"github.com/conn3xorg/conn3x-ui/internal/web"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: conn3x-ui serve [-listen ADDR] [-data DIR]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	data := fs.String("data", "data", "directory for the database and saved plans")
	fs.Parse(os.Args[2:])
	if err := serve(*listen, *data); err != nil {
		log.Fatal(err)
	}
}

func serve(listen, data string) error {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(data, "conn3x-ui.db"))
	if err != nil {
		return err
	}
	defer st.Close()
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
