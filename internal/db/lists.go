package db

import (
	"context"
	"database/sql"
)

// FilterListRow is one subscribed filter list.
type FilterListRow struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	LastUpdated int64  `json:"last_updated"`
	RuleCount   int64  `json:"rule_count"`
}

// AddFilterList inserts a list and returns its id.
func (d *DB) AddFilterList(ctx context.Context, name, url string, enabled bool) (int64, error) {
	result, err := d.exec(ctx,
		"INSERT INTO filter_lists (name, url, enabled) VALUES (?1, ?2, ?3)",
		name, url, boolToInt(enabled))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// FilterListURL returns one list's URL, and false when the id is unknown.
func (d *DB) FilterListURL(ctx context.Context, id int64) (string, bool, error) {
	return queryOptional[string](ctx, d.reader, "SELECT url FROM filter_lists WHERE id = ?1", id)
}

// GetFilterLists returns every list ordered by id.
func (d *DB) GetFilterLists(ctx context.Context) ([]FilterListRow, error) {
	rows, err := d.reader.QueryContext(ctx,
		"SELECT id, name, url, enabled, last_updated, rule_count FROM filter_lists ORDER BY id")
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(rows *sql.Rows) (row FilterListRow, err error) {
		var enabled int64
		err = rows.Scan(&row.ID, &row.Name, &row.URL, &enabled, &row.LastUpdated, &row.RuleCount)
		row.Enabled = enabled != 0
		return row, err
	})
}

// UpdateFilterList renames a list and changes its URL.
func (d *DB) UpdateFilterList(ctx context.Context, id int64, name, url string) error {
	_, err := d.exec(ctx,
		"UPDATE filter_lists SET name = ?1, url = ?2 WHERE id = ?3", name, url, id)
	return err
}

// UpdateFilterListEnabled turns a list on or off.
func (d *DB) UpdateFilterListEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := d.exec(ctx,
		"UPDATE filter_lists SET enabled = ?1 WHERE id = ?2", boolToInt(enabled), id)
	return err
}

// UpdateFilterListStats records the outcome of the last download.
func (d *DB) UpdateFilterListStats(ctx context.Context, id, lastUpdated, ruleCount int64) error {
	_, err := d.exec(ctx,
		"UPDATE filter_lists SET last_updated = ?1, rule_count = ?2 WHERE id = ?3",
		lastUpdated, ruleCount, id)
	return err
}

// DeleteFilterList removes a list. Like Rust, the two deletes are separate
// statements, not one transaction.
func (d *DB) DeleteFilterList(ctx context.Context, id int64) error {
	if _, err := d.exec(ctx, "DELETE FROM filter_lists WHERE id = ?1", id); err != nil {
		return err
	}
	_, err := d.exec(ctx, "DELETE FROM filter_list_content WHERE list_id = ?1", id)
	return err
}

// GetFilterListContent returns the stored list body, and false when none.
func (d *DB) GetFilterListContent(ctx context.Context, listID int64) (string, bool, error) {
	return queryOptional[string](ctx, d.reader,
		"SELECT content FROM filter_list_content WHERE list_id = ?1", listID)
}

// SetFilterListContent inserts or replaces a list body.
func (d *DB) SetFilterListContent(ctx context.Context, listID int64, content string) error {
	_, err := d.exec(ctx,
		"INSERT INTO filter_list_content (list_id, content) VALUES (?1, ?2) ON CONFLICT(list_id) DO UPDATE SET content = excluded.content",
		listID, content)
	return err
}

func boolToInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
