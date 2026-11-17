package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// DBTX — то, что нужно запросам (совпадает с интерфейсом, который генерирует sqlc).
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

var (
	_ DBTX = (*sql.DB)(nil)
	_ DBTX = (*sql.Tx)(nil)
)

type txKey struct{}

// TxManager — транзакция в context: repo берёт её через Q(ctx), сам о транзакциях не знает.
type TxManager struct {
	db func() (*sql.DB, error) // открытая сейчас база (меняется при переключении хранилищ)
}

// NewTxManager — db возвращает открытую базу или ошибку (errs.VaultNotOpen).
func NewTxManager(db func() (*sql.DB, error)) *TxManager {
	return &TxManager{db: db}
}

// Do выполняет fn в транзакции: ошибка или паника — откат, иначе коммит.
// Вложенный Do работает в той же транзакции.
func (m *TxManager) Do(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}
	db, err := m.db()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Q — транзакция из context или сама база.
func (m *TxManager) Q(ctx context.Context) (DBTX, error) {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx, nil
	}
	return m.db()
}
