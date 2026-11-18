package db

import (
	"context"
	"database/sql"
)

// purgeExpiredSessionsSQL is shared by PurgeExpiredSessions and LoadSessions.
// It uses <=, not <, to agree at the exact boundary with the >= expiry in the
// session manager.
const purgeExpiredSessionsSQL = "DELETE FROM sessions WHERE created_at <= ?1 OR last_seen <= ?2"

// NewSession is a session to store; TokenHash is the digest, never the token.
type NewSession struct {
	TokenHash string
	UserID    int64
	CreatedAt int64
	LastSeen  int64
	IP        *string
	UserAgent *string
}

// SessionRow is a session as listed in the account page.
type SessionRow struct {
	ID        int64
	Username  string
	CreatedAt int64
	LastSeen  int64
	IP        *string
	UserAgent *string
	// TokenHash is the BLAKE2b digest of the session token, never the token.
	TokenHash string
}

// LoadedSession is a session restored into memory at startup.
type LoadedSession struct {
	TokenHash string
	ID        int64
	UserID    int64
	CreatedAt int64
	LastSeen  int64
}

// InsertSession stores a session and returns its id.
func (d *DB) InsertSession(ctx context.Context, session NewSession) (int64, error) {
	result, err := d.exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, last_seen, ip, user_agent)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
		session.TokenHash, session.UserID, session.CreatedAt, session.LastSeen, session.IP, session.UserAgent)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// DeleteSessionByTokenHash removes one session.
func (d *DB) DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error {
	_, err := d.exec(ctx, "DELETE FROM sessions WHERE token_hash = ?1", tokenHash)
	return err
}

// DeleteSessionByID removes the session and returns its token hash so the
// caller can evict the in-memory entry. RETURNING leaves no
// select-then-delete window for a concurrent revoke of the same id.
func (d *DB) DeleteSessionByID(ctx context.Context, id int64) (string, bool, error) {
	return queryOptional[string](context.WithoutCancel(ctx), d.writer,
		"DELETE FROM sessions WHERE id = ?1 RETURNING token_hash", id)
}

// DeleteAllSessions removes every session and returns how many.
func (d *DB) DeleteAllSessions(ctx context.Context) (int64, error) {
	result, err := d.exec(ctx, "DELETE FROM sessions")
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// DeleteSessionsExcept removes every session but one (log out other devices).
func (d *DB) DeleteSessionsExcept(ctx context.Context, keepTokenHash string) (int64, error) {
	result, err := d.exec(ctx,
		"DELETE FROM sessions WHERE token_hash != ?1", keepTokenHash)
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// DeleteUserSessionsExcept removes the user's sessions except keepTokenHash
// (nil removes all of them); other operators are untouched.
func (d *DB) DeleteUserSessionsExcept(ctx context.Context, userID int64, keepTokenHash *string) (int64, error) {
	var result sql.Result
	var err error
	if keepTokenHash == nil {
		result, err = d.exec(ctx, "DELETE FROM sessions WHERE user_id = ?1", userID)
	} else {
		result, err = d.exec(ctx,
			"DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", userID, *keepTokenHash)
	}
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// ListSessions returns every session, most recently seen first.
func (d *DB) ListSessions(ctx context.Context) ([]SessionRow, error) {
	rows, err := d.reader.QueryContext(ctx,
		`SELECT s.id, u.username, s.created_at, s.last_seen, s.ip, s.user_agent, s.token_hash
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     ORDER BY s.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var row SessionRow
		if err := rows.Scan(&row.ID, &row.Username, &row.CreatedAt, &row.LastSeen, &row.IP, &row.UserAgent, &row.TokenHash); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// PurgeExpiredSessions removes sessions past either timeout and returns how
// many. now and the timeouts are in seconds.
func (d *DB) PurgeExpiredSessions(ctx context.Context, maxAgeSecs, idleSecs, now int64) (int64, error) {
	result, err := d.exec(ctx, purgeExpiredSessionsSQL, now-maxAgeSecs, now-idleSecs)
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// LoadSessions purges expired sessions and returns the rest, in one writer
// transaction so the purge and the read agree.
func (d *DB) LoadSessions(ctx context.Context, maxAgeSecs, idleSecs, now int64) ([]LoadedSession, error) {
	var out []LoadedSession
	err := d.inWriteTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, purgeExpiredSessionsSQL, now-maxAgeSecs, now-idleSecs); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx,
			"SELECT token_hash, id, user_id, created_at, last_seen FROM sessions")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row LoadedSession
			if err := rows.Scan(&row.TokenHash, &row.ID, &row.UserID, &row.CreatedAt, &row.LastSeen); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// SessionLastSeen is one pending last_seen write-back.
type SessionLastSeen struct {
	TokenHash string
	LastSeen  int64
}

// FlushSessionsLastSeen writes every entry in one transaction.
func (d *DB) FlushSessionsLastSeen(ctx context.Context, entries []SessionLastSeen) error {
	if len(entries) == 0 {
		return nil
	}
	return d.inWriteTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		for _, entry := range entries {
			if _, err := tx.ExecContext(ctx,
				"UPDATE sessions SET last_seen = ?1 WHERE token_hash = ?2", entry.LastSeen, entry.TokenHash); err != nil {
				return err
			}
		}
		return nil
	})
}
