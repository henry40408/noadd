package db

import (
	"context"
	"database/sql"
	"errors"

	"modernc.org/sqlite"
)

// NoPasswordSentinel is the password_hash of a forward-auth-provisioned
// account: it is not a valid PHC string, so password login is impossible.
const NoPasswordSentinel = "!"

// sqliteConstraint is SQLITE_CONSTRAINT, the primary code of every
// constraint failure (extended codes keep it in the low byte).
const sqliteConstraint = 19

// IsUniqueViolation reports a SQLite constraint failure such as a duplicate
// users.username, so callers can answer 409 rather than 500.
func IsUniqueViolation(err error) bool {
	var sqliteErr *sqlite.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == sqliteConstraint
}

// UserRow is an operator without credentials.
type UserRow struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	CreatedAt int64  `json:"created_at"`
}

// UserAuth is what a password login needs.
type UserAuth struct {
	ID           int64
	PasswordHash string
}

// DeleteUserOutcome is the result of DeleteUser.
type DeleteUserOutcome int

// Outcomes of DeleteUser.
const (
	UserDeleted DeleteUserOutcome = iota
	// ErrLastOperator is refused: deleting the last operator would lock
	// everyone out.
	ErrLastOperator
	UserNotFound
)

// CreateUser inserts an operator and returns its id.
func (d *DB) CreateUser(ctx context.Context, username, passwordHash string, createdAt int64) (int64, error) {
	result, err := d.exec(ctx,
		"INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
		username, passwordHash, createdAt)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// CreateFirstUser inserts the first operator atomically: the row goes in only
// while users is empty, so concurrent first-run setups cannot both win. The
// bool is false when an account already exists.
func (d *DB) CreateFirstUser(ctx context.Context, username, passwordHash string, createdAt int64) (int64, bool, error) {
	result, err := d.exec(ctx,
		`INSERT INTO users (username, password_hash, created_at) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM users)`,
		username, passwordHash, createdAt)
	if err != nil {
		return 0, false, err
	}
	if rowsAffected(result) == 0 {
		return 0, false, nil
	}
	id, err := result.LastInsertId()
	return id, err == nil, err
}

// CreateUserNoPassword inserts a passwordless operator provisioned from a
// trusted forward-auth header.
func (d *DB) CreateUserNoPassword(ctx context.Context, username string, createdAt int64) (int64, error) {
	return d.CreateUser(ctx, username, NoPasswordSentinel, createdAt)
}

// GetUserAuth looks a user up by name, and returns false when there is none.
func (d *DB) GetUserAuth(ctx context.Context, username string) (UserAuth, bool, error) {
	var auth UserAuth
	err := d.reader.QueryRowContext(ctx,
		"SELECT id, password_hash FROM users WHERE username = ?1", username).
		Scan(&auth.ID, &auth.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return UserAuth{}, false, nil
	}
	return auth, err == nil, err
}

// GetUserPasswordHash returns the stored hash, and false when no such user.
func (d *DB) GetUserPasswordHash(ctx context.Context, id int64) (string, bool, error) {
	return queryOptional[string](ctx, d.reader, "SELECT password_hash FROM users WHERE id = ?1", id)
}

// UpdateUserPassword replaces a user's password hash.
func (d *DB) UpdateUserPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := d.exec(ctx,
		"UPDATE users SET password_hash = ?1 WHERE id = ?2", passwordHash, id)
	return err
}

// ListUsers returns every operator ordered by id.
func (d *DB) ListUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := d.reader.QueryContext(ctx, "SELECT id, username, created_at FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []UserRow
	for rows.Next() {
		var row UserRow
		if err := rows.Scan(&row.ID, &row.Username, &row.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// CountUsers returns the number of operators.
func (d *DB) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := d.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// DeleteUser removes an operator unless it is the last one. Count and delete
// share one transaction on the single writer connection, so two concurrent
// deletions cannot remove the last two operators.
func (d *DB) DeleteUser(ctx context.Context, id int64) (DeleteUserOutcome, error) {
	outcome := UserNotFound
	err := d.inWriteTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var count int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			outcome = ErrLastOperator
			return nil
		}
		result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?1", id)
		if err != nil {
			return err
		}
		if rowsAffected(result) > 0 {
			outcome = UserDeleted
		}
		return nil
	})
	return outcome, err
}

// GetUsername returns the user's name, and false when no such user.
func (d *DB) GetUsername(ctx context.Context, id int64) (string, bool, error) {
	return queryOptional[string](ctx, d.reader, "SELECT username FROM users WHERE id = ?1", id)
}
