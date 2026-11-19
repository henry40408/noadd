package db

import (
	"context"
	"database/sql"
	"errors"
)

// apiKeyTouchIntervalSecs throttles last_used_at writes so a busy key does not
// take the writer on every request.
const apiKeyTouchIntervalSecs = 60

// NewAPIKey is an API key to store; TokenHash is the digest, never the token.
type NewAPIKey struct {
	UserID    int64
	Name      string
	TokenHash string
	Prefix    string
	CreatedAt int64
	ExpiresAt *int64
}

// APIKeyRow is a stored key as listed to its owner. Times are Unix seconds.
type APIKeyRow struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at"`
	ExpiresAt  *int64 `json:"expires_at"`
}

// InsertAPIKey stores a key and returns its id.
func (d *DB) InsertAPIKey(ctx context.Context, key NewAPIKey) (int64, error) {
	result, err := d.exec(ctx,
		`INSERT INTO api_keys (user_id, name, token_hash, prefix, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
		key.UserID, key.Name, key.TokenHash, key.Prefix, key.CreatedAt, key.ExpiresAt)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// ListAPIKeysForUser returns the user's keys ordered by id.
func (d *DB) ListAPIKeysForUser(ctx context.Context, userID int64) ([]APIKeyRow, error) {
	rows, err := d.reader.QueryContext(ctx,
		`SELECT id, name, prefix, created_at, last_used_at, expires_at
                     FROM api_keys WHERE user_id = ?1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(rows *sql.Rows) (row APIKeyRow, err error) {
		err = rows.Scan(&row.ID, &row.Name, &row.Prefix, &row.CreatedAt, &row.LastUsedAt, &row.ExpiresAt)
		return row, err
	})
}

// DeleteAPIKey removes a key scoped to its owner and reports whether a row
// went away.
func (d *DB) DeleteAPIKey(ctx context.Context, id, userID int64) (bool, error) {
	result, err := d.exec(ctx,
		"DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2", id, userID)
	if err != nil {
		return false, err
	}
	return rowsAffected(result) > 0, nil
}

// ValidateAPIKey resolves a presented key hash to its owner, rejecting expired
// keys. Lookup runs on a reader; the writer is taken only for the
// last_used_at refresh, at most once per minute. now is Unix seconds.
func (d *DB) ValidateAPIKey(ctx context.Context, tokenHash string, now int64) (userID int64, found bool, err error) {
	var id int64
	var expiresAt, lastUsedAt sql.NullInt64
	err = d.reader.QueryRowContext(ctx,
		`SELECT id, user_id, expires_at, last_used_at
                         FROM api_keys WHERE token_hash = ?1`, tokenHash).
		Scan(&id, &userID, &expiresAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if expiresAt.Valid && expiresAt.Int64 <= now {
		return 0, false, nil
	}
	stale := !lastUsedAt.Valid || now-lastUsedAt.Int64 >= apiKeyTouchIntervalSecs
	if !stale {
		return userID, true, nil
	}
	_, err = d.exec(ctx, "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2", now, id)
	if err != nil {
		return 0, false, err
	}
	return userID, true, nil
}

func rowsAffected(result sql.Result) int64 {
	n, err := result.RowsAffected()
	if err != nil {
		return 0
	}
	return n
}
