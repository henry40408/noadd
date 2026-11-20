package db

import (
	"context"
	"database/sql"
)

// DohTokenRow is one DoH access token; the token is stored in clear because
// it is a URL path segment the operator must be able to copy again.
type DohTokenRow struct {
	ID    int64  `json:"id"`
	Token string `json:"token"`
}

// GetDohTokens returns every token ordered by id.
func (d *DB) GetDohTokens(ctx context.Context) ([]DohTokenRow, error) {
	rows, err := d.reader.QueryContext(ctx, "SELECT id, token FROM doh_tokens ORDER BY id")
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(rows *sql.Rows) (row DohTokenRow, err error) {
		err = rows.Scan(&row.ID, &row.Token)
		return row, err
	})
}

// AddDohToken inserts a token and returns its id.
func (d *DB) AddDohToken(ctx context.Context, token string) (int64, error) {
	result, err := d.exec(ctx, "INSERT INTO doh_tokens (token) VALUES (?1)", token)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// DeleteDohToken removes a token by id.
func (d *DB) DeleteDohToken(ctx context.Context, id int64) error {
	_, err := d.exec(ctx, "DELETE FROM doh_tokens WHERE id = ?1", id)
	return err
}

// ValidateDohToken returns the token and true when it exists.
func (d *DB) ValidateDohToken(ctx context.Context, token string) (string, bool, error) {
	return queryOptional[string](ctx, d.reader, "SELECT token FROM doh_tokens WHERE token = ?1", token)
}
