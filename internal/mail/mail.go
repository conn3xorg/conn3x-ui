// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package mail sends the UI's notifications by SMTP.
package mail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Mailer sends plain-text mail through one SMTP server. It always uses
// STARTTLS, except to a server on the loopback address, as net/smtp's
// PlainAuth insists for a password too.
type Mailer struct {
	Addr     string // host:port
	From     string
	User     string // empty for a server that takes mail without signing in
	Password string
}

// ParseAddresses reads a comma-separated list of addresses, as a project's
// settings hold them, and returns them bare.
func ParseAddresses(s string) ([]string, error) {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		addr, err := mail.ParseAddress(a)
		if err != nil || strings.ContainsAny(addr.Address, "\r\n") {
			return nil, fmt.Errorf("%q isn't an email address", a)
		}
		out = append(out, addr.Address)
	}
	return out, nil
}

// header keeps a value on one line, so nothing a project's name holds can
// start another header.
func header(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Send mails subject and body to to.
func (m *Mailer) Send(to []string, subject, body string) error {
	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return err
	}
	return m.sendTo(host, to, subject, body)
}

// sendTo dials Addr and talks to it as host, the name TLS checks and that
// decides whether the server is on loopback.
func (m *Mailer) sendTo(host string, to []string, subject, body string) error {
	conn, err := net.DialTimeout("tcp", m.Addr, 10*time.Second)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	loopback := false
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	} else {
		loopback = host == "localhost"
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if !loopback {
		return errors.New("the SMTP server doesn't offer STARTTLS, and the UI won't send mail in the clear")
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		header(m.From), strings.Join(to, ", "), header(subject), time.Now().UTC().Format(time.RFC1123Z), strings.ReplaceAll(body, "\n", "\r\n"))
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
