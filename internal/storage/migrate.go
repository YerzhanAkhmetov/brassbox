package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"

	"brassbox/internal/errs"
)

// Migration — шаг схемы: Version = номер из имени файла NNN_имя.sql.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

//go:embed migrations
var migrationsFS embed.FS

var migrationName = regexp.MustCompile(`^(\d{3})_([a-z0-9_]+)\.sql$`)

// Migrations — миграции программы (папка migrations/, вшита в бинарник).
func Migrations() ([]Migration, error) {
	return LoadMigrations(migrationsFS, "migrations")
}

// LoadMigrations — *.sql из dir; номера строго 1, 2, 3… без пропусков и повторов.
func LoadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var list []Migration
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %q: name must be NNN_name.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		list = append(list, Migration{Version: v, Name: m[2], SQL: string(body)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Version < list[j].Version })
	for i, m := range list {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration %03d_%s: want version %d (no gaps or duplicates)", m.Version, m.Name, i+1)
		}
	}
	return list, nil
}

// Version — версия схемы базы (PRAGMA user_version).
func Version(ctx context.Context, db DBTX) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("user_version: %w", err)
	}
	return v, nil
}

// Pending — сколько миграций ещё не применено. База новее программы — errs.VaultTooNew.
func Pending(ctx context.Context, db DBTX, list []Migration) (int, error) {
	v, err := Version(ctx, db)
	if err != nil {
		return 0, err
	}
	if v > len(list) {
		return 0, fmt.Errorf("%w: vault schema %d, app knows %d", errs.VaultTooNew, v, len(list))
	}
	return len(list) - v, nil
}

// Migrate применяет недостающие миграции. Каждая — в своей транзакции вместе с
// user_version: упала — откат, версия остаётся прежней. База новее — не трогаем.
func Migrate(ctx context.Context, db *sql.DB, list []Migration) error {
	v, err := Version(ctx, db)
	if err != nil {
		return err
	}
	if v > len(list) {
		return fmt.Errorf("%w: vault schema %d, app knows %d", errs.VaultTooNew, v, len(list))
	}
	for _, m := range list[v:] {
		if err := apply(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %03d begin: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback() }() // после Commit — ничего не делает

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("migration %03d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(m.Version)); err != nil {
		return fmt.Errorf("migration %03d user_version: %w", m.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %03d commit: %w", m.Version, err)
	}
	return nil
}
