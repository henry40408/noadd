package db

import "context"

// HasDohTokens reports whether any token exists.
func (d *DB) HasDohTokens(ctx context.Context) (bool, error) {
	var count int64
	err := d.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM doh_tokens").Scan(&count)
	return count > 0, err
}

// ListTables returns every user table name.
func (d *DB) ListTables(ctx context.Context) ([]string, error) {
	return queryColumn[string](ctx, d.reader,
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
}

// QueryTypeBreakdownSince counts queries per type, busiest first.
func (d *DB) QueryTypeBreakdownSince(ctx context.Context, since int64) ([]NameCount, error) {
	rows, err := d.metricsWindowSince(ctx, since)
	return queryTypesFromWindow(rows), err
}

// OutcomeBreakdownSince counts queries per outcome, busiest first.
func (d *DB) OutcomeBreakdownSince(ctx context.Context, since int64) ([]NameCount, error) {
	rows, err := d.metricsWindowSince(ctx, since)
	return outcomesFromWindow(rows), err
}
