// Package vault — открытое хранилище: одна активная база за раз.
// Создать / открыть / закрыть, миграции при открытии, автокопии.
// Каким ключом открывать (Keychain, пароль, .pvkey) — решает вызывающий: сюда приходит готовый DEK.
package vault

import (
	"context"
	"database/sql"
)

// Vault — что умеет модуль (витрина). Реализация — service.Service.
type Vault interface {
	// Create — новый файл (заголовок + пустая база) и сразу открыть его.
	Create(ctx context.Context, path string, master []byte, password string) error
	// Open — открыть базу DEK (errs.KeyWrong / errs.VaultCorrupt / errs.VaultTooNew).
	// Открытая до этого база закрывается только после успешного открытия новой.
	Open(ctx context.Context, path string, dek []byte) error
	// Close — закрыть активную базу, затереть DEK. Нет открытой — ничего.
	Close() error
	// Active — путь открытой базы.
	Active() (path string, ok bool)
	// DB — открытая база (errs.VaultNotOpen).
	DB() (*sql.DB, error)
	// SecretKey — ключ секретных полей = HKDF(DEK) (errs.VaultNotOpen).
	SecretKey() ([]byte, error)
	// CopyTo — копия открытой базы в новый файл dst (вместе с заголовком).
	CopyTo(ctx context.Context, dst string) error
}
