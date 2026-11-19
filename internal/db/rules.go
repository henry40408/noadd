package db

import "context"

// CustomRuleRow is one operator-written rule; RuleType is "block" or "allow".
type CustomRuleRow struct {
	ID       int64  `json:"id"`
	Rule     string `json:"rule"`
	RuleType string `json:"rule_type"`
}

// HasCustomRule reports whether the exact rule text exists.
func (d *DB) HasCustomRule(ctx context.Context, rule string) (bool, error) {
	var count int64
	err := d.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM custom_rules WHERE rule = ?1", rule).Scan(&count)
	return count > 0, err
}

// AddCustomRule inserts a rule and returns its id.
func (d *DB) AddCustomRule(ctx context.Context, rule, ruleType string) (int64, error) {
	result, err := d.exec(ctx,
		"INSERT INTO custom_rules (rule, rule_type) VALUES (?1, ?2)", rule, ruleType)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetAllCustomRules returns every rule ordered by id.
func (d *DB) GetAllCustomRules(ctx context.Context) ([]CustomRuleRow, error) {
	return d.scanCustomRules(ctx, "SELECT id, rule, rule_type FROM custom_rules ORDER BY id")
}

// GetCustomRulesByType returns the rules of one type ordered by id.
func (d *DB) GetCustomRulesByType(ctx context.Context, ruleType string) ([]CustomRuleRow, error) {
	return d.scanCustomRules(ctx,
		"SELECT id, rule, rule_type FROM custom_rules WHERE rule_type = ?1 ORDER BY id", ruleType)
}

func (d *DB) scanCustomRules(ctx context.Context, query string, args ...any) ([]CustomRuleRow, error) {
	rows, err := d.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []CustomRuleRow
	for rows.Next() {
		var row CustomRuleRow
		if err := rows.Scan(&row.ID, &row.Rule, &row.RuleType); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DeleteCustomRule removes a rule by id.
func (d *DB) DeleteCustomRule(ctx context.Context, id int64) error {
	_, err := d.exec(ctx, "DELETE FROM custom_rules WHERE id = ?1", id)
	return err
}
