// Package storage — доступ к файлу базы SQLite: открытие с шифрованием (Adiantum + сдвиг
// под заголовок), транзакции в context, миграции, копия базы.
// Инфраструктура без состояния модуля, поэтому плоский пакет (как errs, logger).
package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	"github.com/ncruces/go-sqlite3/ext/fts5"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
)

// PageSize — страница SQLite = блок Adiantum.
const PageSize = 4096

// Open открывает базу в файле path (файл уже есть: его создаёт header.Create).
// DEK должен быть проверен заранее (header) — здесь любая ошибка чтения = повреждение.
// Новая (пустая) база получает page_size 4096 и auto_vacuum FULL.
func Open(ctx context.Context, path string, dek []byte) (*sql.DB, error) {
	if len(dek) != crypto.KeySize {
		return nil, fmt.Errorf("%w: key length %d", errs.InvalidRequest, len(dek))
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: vault file", errs.ObjectNotFound)
	}
	registerVFS()

	// Ключ — PRAGMA hexkey в функции подключения, не в URI: так он не попадает в имя файла.
	hexKey := hex.EncodeToString(dek)
	dsn := fileURI(path, url.Values{"vfs": {VFSName}, "mode": {"rw"}})
	db, err := driver.Open(dsn, func(c *sqlite3.Conn) error {
		if err := c.Exec("PRAGMA hexkey='" + hexKey + "'"); err != nil {
			return fmt.Errorf("hexkey: %w", err)
		}
		if err := fts5.Register(c); err != nil {
			return fmt.Errorf("fts5: %w", err)
		}
		return c.Exec(`
			PRAGMA temp_store = memory;
			PRAGMA journal_mode = DELETE;
			PRAGMA synchronous = FULL;
			PRAGMA foreign_keys = ON;`)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", errs.VaultCorrupt, err)
	}
	db.SetMaxOpenConns(1) // одно соединение: программа однопользовательская
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := prepare(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// prepare — настройки новой базы и проверка целостности.
// Неверный ключ / испорченный файл видны только при первом чтении — проверяем сразу.
func prepare(ctx context.Context, db *sql.DB) error {
	var pages int
	if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return fmt.Errorf("%w: page_count: %w", errs.VaultCorrupt, err)
	}
	if pages == 0 {
		// Только до первой таблицы: потом auto_vacuum меняется лишь через VACUUM.
		if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA page_size = %d; PRAGMA auto_vacuum = FULL;", PageSize)); err != nil {
			return fmt.Errorf("new vault pragmas: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, "SELECT count(*) FROM sqlite_schema"); err != nil {
		return fmt.Errorf("%w: read schema: %w", errs.VaultCorrupt, err)
	}
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&res); err != nil {
		return fmt.Errorf("%w: quick_check: %w", errs.VaultCorrupt, err)
	}
	if res != "ok" {
		return fmt.Errorf("%w: quick_check: %s", errs.VaultCorrupt, res)
	}
	return nil
}

// fileURI — URI файла для SQLite: file:<путь ОС, экранированный>?параметры.
// Путь остаётся родным для ОС (на Windows — C:\…): VFS ncruces отдаёт его прямо в os.OpenFile,
// поэтому «file:/C:/…» (как у SQLite на C) ломается — 2026-11-17, тест на Windows.
func fileURI(path string, q url.Values) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}
