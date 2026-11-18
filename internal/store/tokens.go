// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenPrefix starts every API token, so a scanner can spot a leaked one.
const TokenPrefix = "c3ui_"

// APIToken is a token a user made for scripts, without its value.
type APIToken struct {
	ID         int64
	Name       string
	CreatedAt  string
	ExpiresAt  string
	LastUsedAt string
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// CreateAPIToken makes a token for a user that expires after days, and
// returns it. Only its hash is kept, so it can't be shown again.
func (s *Store) CreateAPIToken(ctx context.Context, userID int64, name string, days int) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	t := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, "INSERT INTO api_tokens (user_id, name, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		userID, name, tokenHash(token), t.Format(time.RFC3339), t.AddDate(0, 0, days).Format(time.RFC3339))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return "", fmt.Errorf("you already have a token called %s", name)
	}
	return token, err
}

// APITokens returns a user's tokens, newest first.
func (s *Store) APITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, created_at, expires_at, last_used_at FROM api_tokens WHERE user_id=? ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes one of a user's tokens and returns its name.
func (s *Store) DeleteAPIToken(ctx context.Context, userID, id int64) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, "DELETE FROM api_tokens WHERE user_id=? AND id=? RETURNING name", userID, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return name, err
}

// TokenUser is the user a token signs in as, if it's unexpired and they
// aren't disabled. It notes when the token was used.
func (s *Store) TokenUser(ctx context.Context, token string) (User, error) {
	var u User
	if !strings.HasPrefix(token, TokenPrefix) {
		return u, ErrNotFound
	}
	h := tokenHash(token)
	err := s.db.QueryRowContext(ctx, "SELECT u.id, u.name, u.admin, u.disabled, u.oidc_subject IS NOT NULL FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.hash=? AND t.expires_at > ? AND u.disabled = 0",
		h, now()).Scan(&u.ID, &u.Name, &u.Admin, &u.Disabled, &u.OIDC)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at=? WHERE hash=?", now(), h)
	return u, err
}
