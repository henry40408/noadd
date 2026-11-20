package db

import (
	"context"
	"database/sql"
	"errors"
)

// queryOptional runs a single-row query and reports whether a row existed.
func queryOptional[T any](ctx context.Context, pool *sql.DB, query string, args ...any) (T, bool, error) {
	var value T
	err := pool.QueryRowContext(ctx, query, args...).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		var zero T
		return zero, false, nil
	}
	if err != nil {
		var zero T
		return zero, false, err
	}
	return value, true, nil
}

// inWriteTx runs fn in one transaction on the writer connection and commits
// only when fn succeeds. Like exec it ignores the caller's cancellation; fn
// receives the detached context and must use it for its statements.
func (d *DB) inWriteTx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	ctx = context.WithoutCancel(ctx)
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// GetSetting returns the stored value, and false when the key is absent.
func (d *DB) GetSetting(ctx context.Context, key string) (string, bool, error) {
	return queryOptional[string](ctx, d.reader, "SELECT value FROM settings WHERE key = ?1", key)
}

// SetSetting inserts or replaces a setting.
func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := d.exec(ctx,
		"INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	return err
}

// queryColumn collects the first column of every row.
func queryColumn[T any](ctx context.Context, pool *sql.DB, query string, args ...any) ([]T, error) {
	rows, err := pool.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(rows *sql.Rows) (value T, err error) {
		err = rows.Scan(&value)
		return value, err
	})
}

// collectRows reads every row with scan and closes rows. A scan error returns
// no rows; an error from the iteration itself returns the rows read so far.
func collectRows[T any](rows *sql.Rows, scan func(*sql.Rows) (T, error)) ([]T, error) {
	defer func() { _ = rows.Close() }()
	var out []T
	for rows.Next() {
		row, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
