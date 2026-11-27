package db

import (
	"cmp"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
)

// A released file is never edited: a change to the schema is a new file.
//
//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// migrationFileName is `<version>_<description>.sql`.
var migrationFileName = regexp.MustCompile(`^(\d+)_.+\.sql$`)

// migration brings the schema to version, which `PRAGMA user_version` records.
type migration struct {
	version int64
	sql     string
}

func migrate(ctx context.Context, writer *sql.DB) error {
	files, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		return err
	}
	migrations, err := loadMigrations(files)
	if err != nil {
		return err
	}
	return applyMigrations(ctx, writer, migrations)
}

// loadMigrations reads every `.sql` file in the root of fsys, ordered by version.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, errors.New("no migration files")
	}
	migrations := make([]migration, 0, len(names))
	for _, name := range names {
		m, err := readMigration(fsys, name)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, m)
	}
	slices.SortFunc(migrations, func(a, b migration) int {
		return cmp.Compare(a.version, b.version)
	})
	for i := 1; i < len(migrations); i++ {
		if migrations[i].version == migrations[i-1].version {
			return nil, fmt.Errorf("migrations share version %d", migrations[i].version)
		}
	}
	return migrations, nil
}

func readMigration(fsys fs.FS, name string) (migration, error) {
	parts := migrationFileName.FindStringSubmatch(name)
	if parts == nil {
		return migration{}, fmt.Errorf("migration file %q is not named <version>_<description>.sql", name)
	}
	// user_version is a signed 32-bit integer, and 0 means no migration yet.
	version, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return migration{}, fmt.Errorf("migration file %q: %w", name, err)
	}
	if version == 0 {
		return migration{}, fmt.Errorf("migration file %q: versions start at 1", name)
	}
	contents, err := fs.ReadFile(fsys, name)
	if err != nil {
		return migration{}, err
	}
	return migration{version: version, sql: string(contents)}, nil
}

// applyMigrations applies the migrations newer than the database, one transaction
// each. migrations is ordered.
func applyMigrations(ctx context.Context, writer *sql.DB, migrations []migration) error {
	latest := migrations[len(migrations)-1].version
	current, err := userVersion(ctx, writer)
	if err != nil {
		return err
	}
	if err := refuseNewer(current, latest); err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, writer, m, latest); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.version, err)
		}
	}
	return nil
}

func refuseNewer(current, latest int64) error {
	if current > latest {
		return fmt.Errorf("database schema version %d is newer than %d, the latest this noadd knows; run a newer noadd",
			current, latest)
	}
	return nil
}

// applyMigration runs the script and moves user_version in one transaction, so a
// failure leaves neither half behind.
func applyMigration(ctx context.Context, writer *sql.DB, m migration, latest int64) error {
	// The DSN's _txlock=immediate takes the write lock here, not at the first write.
	tx, err := writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Read again under the write lock: another process, maybe a newer noadd, may
	// have got here first.
	current, err := userVersion(ctx, tx)
	if err != nil {
		return err
	}
	if err := refuseNewer(current, latest); err != nil {
		return err
	}
	if current >= m.version {
		return nil
	}
	if current <= 0 {
		if err := requireEmpty(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	// A PRAGMA takes no bound parameters.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return err
	}
	return tx.Commit()
}

// rowQuerier is what *sql.DB and *sql.Tx share to read one row.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func userVersion(ctx context.Context, q rowQuerier) (int64, error) {
	var version int64
	if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

// requireEmpty refuses a database that holds something but no version: nothing
// says which migrations it has had.
func requireEmpty(ctx context.Context, q rowQuerier) error {
	var objects int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\'`).Scan(&objects)
	if err != nil {
		return fmt.Errorf("inspect database: %w", err)
	}
	if objects > 0 {
		return errors.New("the database is not empty but its PRAGMA user_version is 0; " +
			"after restoring a .dump, set user_version to the source database's value")
	}
	return nil
}
