// Package db owns the SQLite database: connections, schema and migrations.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// readPoolSize caps admin/stats query parallelism.
const readPoolSize = 4

const memoryPath = ":memory:"

// Pragmas every writer connection runs. journal_mode and synchronous are
// per-database or per-connection; foreign_keys is per-connection, so all of
// them go in the DSN to reach every new connection.
var writerPragmas = []string{
	"journal_mode(WAL)",
	"synchronous(NORMAL)",
	"foreign_keys(1)",
	"busy_timeout(5000)",
	"cache_size(-2000)",
	"mmap_size(268435456)",
	"temp_store(MEMORY)",
}

var readerPragmas = []string{
	"busy_timeout(5000)",
	"cache_size(-2000)",
	"mmap_size(268435456)",
	"temp_store(MEMORY)",
}

// exec runs a write on the writer connection. The write is detached from the
// caller's cancellation: a client disconnect must not interrupt it, or memory
// and the database would disagree about what was changed (as the Rust
// tokio-rusqlite calls, which always run to completion, do not).
func (d *DB) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.writer.ExecContext(context.WithoutCancel(ctx), query, args...)
}

// DB is one writer connection plus a pool of read-only connections. Under WAL
// the readers run concurrently with the writer and never see uncommitted rows.
type DB struct {
	path   string
	writer *sql.DB
	reader *sql.DB
}

// Open opens (creating if needed) the database at path and migrates it to the
// latest schema. The special path ":memory:" gives a private in-memory
// database whose readers share the writer.
func Open(ctx context.Context, path string) (*DB, error) {
	writer, err := openPool(path, writerPragmas, "", 1)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, writer); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	if path == memoryPath {
		return &DB{path: path, writer: writer, reader: writer}, nil
	}
	// A reader that fails to open aborts startup: falling back to the writer
	// would silently bring back the contention the pool removes.
	reader, err := openPool(path, readerPragmas, "ro", readPoolSize)
	if err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := warmUp(ctx, reader, readPoolSize); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	return &DB{path: path, writer: writer, reader: reader}, nil
}

// Close checkpoints the WAL back into the main file and closes every
// connection, so SQLite removes the -wal and -shm files. Readers close first
// so the writer is the only connection at the truncating checkpoint.
func (d *DB) Close(ctx context.Context) error {
	var errs []error
	if d.reader != d.writer {
		errs = append(errs, d.reader.Close())
	}
	_, err := d.writer.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	errs = append(errs, err, d.writer.Close())
	if d.path != memoryPath {
		errs = append(errs, removeIfExists(d.path+"-wal"), removeIfExists(d.path+"-shm"))
	}
	return errors.Join(errs...)
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func openPool(path string, pragmas []string, mode string, maxConns int) (*sql.DB, error) {
	pool, err := sql.Open("sqlite", dsn(path, pragmas, mode))
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(maxConns)
	pool.SetMaxIdleConns(maxConns)
	pool.SetConnMaxLifetime(0)
	pool.SetConnMaxIdleTime(0)
	return pool, nil
}

// dsn builds a file: URI. The path goes in as URI path so that '?', '#' and
// '%' in a file name cannot be read as URI syntax.
func dsn(path string, pragmas []string, mode string) string {
	query := url.Values{}
	for _, pragma := range pragmas {
		query.Add("_pragma", pragma)
	}
	if mode != "" {
		query.Set("mode", mode)
	}
	if path == memoryPath {
		// Each ":memory:" connection is its own database, which is why the
		// writer pool is capped at one connection and never recycles it.
		return "file::memory:?" + query.Encode()
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}
	return uri.String()
}

// warmUp opens count connections now, so a reader that cannot open fails Open
// instead of the first admin request.
func warmUp(ctx context.Context, pool *sql.DB, count int) error {
	conns := make([]*sql.Conn, 0, count)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for range count {
		conn, err := pool.Conn(ctx)
		if err != nil {
			return fmt.Errorf("open read connection: %w", err)
		}
		conns = append(conns, conn)
		if err := conn.PingContext(ctx); err != nil {
			return fmt.Errorf("open read connection: %w", err)
		}
	}
	return nil
}
